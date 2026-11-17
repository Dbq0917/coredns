package geoip

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestLoadSupportedFormats loads one database of every supported format and
// asserts that lookups return the expected metadata.
func TestLoadSupportedFormats(t *testing.T) {
	tests := []struct {
		dbPath        string
		label         string
		expectedValue string
	}{
		// MMDB city format, supported since the plugin exists.
		{cityDBPath, "geoip/city/name", "Cambridge"},
		{cityDBPath, "geoip/country/code", "GB"},
		// MMDB enterprise format with a database type unknown to the geoip2
		// library, e.g. newer database generations.
		{enterpriseDBPath, "geoip/city/name", "Cambridge"},
		{enterpriseDBPath, "geoip/country/code", "GB"},
		{enterpriseDBPath, "geoip/continent/code", "EU"},
		{enterpriseDBPath, "geoip/asn/number", "12345"},
		{enterpriseDBPath, "geoip/asn/org", "Test ASN Organization"},
		// MMDB country-only format.
		{countryDBPath, "geoip/country/code", "GB"},
		{countryDBPath, "geoip/country/name", "United Kingdom"},
		{countryDBPath, "geoip/continent/code", "EU"},
	}

	loaded := map[string]*GeoIP{}
	for _, tc := range tests {
		geoIP, ok := loaded[tc.dbPath]
		if !ok {
			var err error
			geoIP, err = newGeoIP(tc.dbPath, false)
			if err != nil {
				t.Fatalf("unable to load database %s: %v", tc.dbPath, err)
			}
			loaded[tc.dbPath] = geoIP
		}
		state := request.Request{
			Req: new(dns.Msg),
			W:   &test.ResponseWriter{RemoteIP: "81.2.69.142"},
		}
		testMetadata(t, state, geoIP, tc.label, tc.expectedValue)
	}

	// The version of every loaded database must be visible to operators at runtime.
	geoIP := loaded[enterpriseDBPath]
	version := fmt.Sprintf("%d", geoIP.groups[0].db.meta.BuildEpoch)
	if v := testutil.ToFloat64(databaseInfo.WithLabelValues(enterpriseDBPath, "GeoIP2-Precision-Enterprise", version)); v != 1 {
		t.Errorf("expected database_info metric to expose the loaded database version, got value %v", v)
	}
}

// TestLoadCorruptedDatabase asserts that a corrupted database file fails with
// an error naming the detected format, and that the service keeps working with
// the configured fallback policy.
func TestLoadCorruptedDatabase(t *testing.T) {
	_, err := loadDatabase(corruptedDBPath)
	if err == nil {
		t.Fatal("expected an error loading a corrupted database, got none")
	}
	if !strings.Contains(err.Error(), "MMDB") {
		t.Errorf("expected the error to name the detected database format, got: %v", err)
	}

	// Without a fallback policy, loading a corrupted database fails the setup.
	c := caddy.NewTestController("dns", fmt.Sprintf("%s %s\n", pluginName, corruptedDBPath))
	if _, err := geoipParse(c); err == nil {
		t.Error("expected setup to fail for a corrupted database without fallback policy")
	}

	// With fallback default, the service stays available and answers with the
	// configured default values, informing the business logic via geoip/fallback.
	c = caddy.NewTestController("dns", fmt.Sprintf(`%s %s {
	fallback default
	default country/code CN
	default country/name China
}`, pluginName, corruptedDBPath))
	geoIP, err := geoipParse(c)
	if err != nil {
		t.Fatalf("expected setup to succeed with fallback default, got: %v", err)
	}
	if geoIP.groups[0].db != nil {
		t.Fatal("expected no database to be loaded for a corrupted file")
	}

	state := request.Request{
		Req: new(dns.Msg),
		W:   &test.ResponseWriter{RemoteIP: "81.2.69.142"},
	}
	testMetadata(t, state, geoIP, "geoip/fallback", "true")
	testMetadata(t, state, geoIP, "geoip/country/code", "CN")
	testMetadata(t, state, geoIP, "geoip/country/name", "China")

	// The query chain must stay available.
	geoIP.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		return dns.RcodeSuccess, w.WriteMsg(m)
	})
	rec := &recorder{ResponseWriter: &test.ResponseWriter{}}
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	rcode, err := geoIP.ServeDNS(context.Background(), rec, req)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Errorf("expected the query chain to stay available, got rcode %d, err %v", rcode, err)
	}
	if rec.msg == nil || rec.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("expected a NOERROR answer, got %+v", rec.msg)
	}

	// The fallback must not be silent: an alertable metric counts every occurrence.
	if v := testutil.ToFloat64(fallbackTotal.WithLabelValues(corruptedDBPath, "", "default")); v == 0 {
		t.Error("expected the fallback metric to be incremented, fallback must not be silent")
	}
}

// TestFallbackRefuse asserts that the refuse fallback policy rejects resolution
// with SERVFAIL while keeping the rest of the service available.
func TestFallbackRefuse(t *testing.T) {
	c := caddy.NewTestController("dns", fmt.Sprintf(`%s %s {
	fallback refuse
}`, pluginName, corruptedDBPath))
	geoIP, err := geoipParse(c)
	if err != nil {
		t.Fatalf("expected setup to succeed with fallback refuse, got: %v", err)
	}

	rec := &recorder{ResponseWriter: &test.ResponseWriter{}}
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	rcode, err := geoIP.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL rcode, got %d", rcode)
	}
	if rec.msg == nil || rec.msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected a SERVFAIL answer, got %+v", rec.msg)
	}
	if v := testutil.ToFloat64(fallbackTotal.WithLabelValues(corruptedDBPath, "", "refuse")); v == 0 {
		t.Error("expected the fallback metric to be incremented, fallback must not be silent")
	}
}

// TestDomainGroups asserts that different domains can be configured with
// different databases.
func TestDomainGroups(t *testing.T) {
	c := caddy.NewTestController("dns", fmt.Sprintf(`%s {
	domain city.example.com {
		db %s
	}
	domain asn.example.org {
		db %s
	}
}`, pluginName, cityDBPath, asnDBPath))
	geoIP, err := geoipParse(c)
	if err != nil {
		t.Fatalf("expected no errors, but got: %v", err)
	}
	if len(geoIP.groups) != 2 {
		t.Fatalf("expected two domain groups, got %d", len(geoIP.groups))
	}

	tests := []struct {
		qname         string
		label         string
		expectedValue string
	}{
		{"www.city.example.com.", "geoip/city/name", "Cambridge"},
		{"www.asn.example.org.", "geoip/asn/number", "12345"},
	}
	for _, tc := range tests {
		req := new(dns.Msg)
		req.SetQuestion(tc.qname, dns.TypeA)
		state := request.Request{Req: req, W: &test.ResponseWriter{RemoteIP: "81.2.69.142"}}
		testMetadata(t, state, geoIP, tc.label, tc.expectedValue)
	}

	// A query name matching no domain group gets no geoip metadata.
	req := new(dns.Msg)
	req.SetQuestion("www.other.example.net.", dns.TypeA)
	state := request.Request{Req: req, W: &test.ResponseWriter{RemoteIP: "81.2.69.142"}}
	ctx := metadata.ContextWithMetadata(context.Background())
	geoIP.Metadata(ctx, state)
	if fn := metadata.ValueFunc(ctx, "geoip/country/code"); fn != nil {
		t.Errorf("expected no geoip metadata for an unmatched domain, got %q", fn())
	}
}

// recorder captures the message written by the plugin under test.
type recorder struct {
	*test.ResponseWriter
	msg *dns.Msg
}

func (r *recorder) WriteMsg(m *dns.Msg) error {
	r.msg = m
	return nil
}
