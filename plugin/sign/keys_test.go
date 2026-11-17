package sign

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestKeyParseDirectoryUsesNewestPair(t *testing.T) {
	keyDir := t.TempDir()
	writeTestKey(t, keyDir, time.Now().Add(-2*time.Hour))
	_, newTag := writeTestKey(t, keyDir, time.Now().Add(-time.Hour))

	signer := testSigner(t, keyDir, t.TempDir())
	keys := signer.keySnapshot()
	if len(keys) != 1 {
		t.Fatalf("expected one selected key, got %d", len(keys))
	}
	if keys[0].KeyTag != newTag {
		t.Fatalf("expected key tag %d, got %d", newTag, keys[0].KeyTag)
	}
}

func TestKeyDirectoryHotReload(t *testing.T) {
	keyDir := t.TempDir()
	writeTestKey(t, keyDir, time.Now().Add(-3*time.Hour))
	_, secondTag := writeTestKey(t, keyDir, time.Now().Add(-2*time.Hour))

	signer := testSigner(t, keyDir, t.TempDir())
	assertSignedWithTag(t, signer, secondTag)

	_, thirdTag := writeTestKey(t, keyDir, time.Now().Add(-time.Hour))
	changed, err := signer.reloadKeys()
	if err != nil {
		t.Fatalf("reload keys: %v", err)
	}
	if !changed {
		t.Fatal("expected key reload to report a change")
	}
	assertSignedWithTag(t, signer, thirdTag)
	if got := testutil.ToFloat64(activeKey.WithLabelValues(signer.origin)); got != float64(thirdTag) {
		t.Fatalf("active key metric = %v, want %d", got, thirdTag)
	}
}

func TestKeyDirectoryRefreshSignsWithoutRestart(t *testing.T) {
	keyDir := t.TempDir()
	outputDir := t.TempDir()
	_, firstTag := writeTestKey(t, keyDir, time.Now().Add(-time.Hour))
	signer := testSigner(t, keyDir, outputDir)
	signer.keyReload = 10 * time.Millisecond

	signAndLog(signer, errors.New("initial test signing"))
	signedFile := filepath.Join(outputDir, signer.signedfile)
	waitForSignedKeyTag(t, signedFile, firstTag)

	_, secondTag := writeTestKey(t, keyDir, time.Now())
	go signer.refresh(time.Hour)
	defer close(signer.stop)
	waitForSignedKeyTag(t, signedFile, secondTag)
}

func TestKeyDirectoryReloadErrorRetries(t *testing.T) {
	keyDir := t.TempDir()
	_, tag := writeTestKey(t, keyDir, time.Now().Add(-time.Hour))
	signer := testSigner(t, keyDir, t.TempDir())

	errorsBefore := testutil.ToFloat64(keyLoads.WithLabelValues(signer.origin, ErrorCodeKeyLoad))
	chmodUnreadable(t, keyDir)
	if _, err := signer.reloadKeys(); err == nil || !strings.Contains(err.Error(), "read key directory") {
		t.Fatalf("expected explicit directory read error, got %v", err)
	}
	errorsAfter := testutil.ToFloat64(keyLoads.WithLabelValues(signer.origin, ErrorCodeKeyLoad))
	if errorsAfter != errorsBefore+1 {
		t.Fatalf("key load error metric incremented by %v, want 1", errorsAfter-errorsBefore)
	}
	assertSignedWithTag(t, signer, tag)

	if err := os.Chmod(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	changed, err := signer.reloadKeys()
	if err != nil {
		t.Fatalf("retry reload keys: %v", err)
	}
	if changed {
		t.Fatal("retry without a key change should not report a change")
	}
	assertSignedWithTag(t, signer, tag)
}

func TestKeyDirectoryUnreadableAtParse(t *testing.T) {
	keyDir := t.TempDir()
	writeTestKey(t, keyDir, time.Now())
	chmodUnreadable(t, keyDir)

	input := fmt.Sprintf(`sign testdata/db.miek.nl miek.nl {
		key directory %s
	}`, keyDir)
	c := caddy.NewTestController("dns", input)
	if _, err := parse(c); err == nil || !strings.Contains(err.Error(), "read key directory") {
		t.Fatalf("expected explicit directory read error, got %v", err)
	}
}

func TestKeyDirectoryMissingReturnsError(t *testing.T) {
	input := `sign testdata/db.miek.nl miek.nl {
		key directory testdata/does-not-exist
	}`
	c := caddy.NewTestController("dns", input)
	if _, err := parse(c); err == nil || !strings.Contains(err.Error(), "read key directory") {
		t.Fatalf("expected missing directory error, got %v", err)
	}
}

func TestSignDisabled(t *testing.T) {
	keyDir := t.TempDir()
	writeTestKey(t, keyDir, time.Now())
	input := fmt.Sprintf(`sign testdata/db.miek.nl miek.nl {
		key directory %s
		disabled
	}`, keyDir)
	c := caddy.NewTestController("dns", input)
	sign, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if !sign.disabled || !sign.signers[0].disabled {
		t.Fatal("expected sign plugin and signer to be disabled")
	}
}

func TestKeyReloadDuration(t *testing.T) {
	keyDir := t.TempDir()
	writeTestKey(t, keyDir, time.Now())
	input := fmt.Sprintf(`sign testdata/db.miek.nl miek.nl {
		key directory %s
		key_reload 15s
	}`, keyDir)
	c := caddy.NewTestController("dns", input)
	sign, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := sign.signers[0].keyReload; got != 15*time.Second {
		t.Fatalf("key reload interval = %s, want 15s", got)
	}
}

func testSigner(t *testing.T, keyDir, outputDir string) *Signer {
	t.Helper()
	input := fmt.Sprintf(`sign testdata/db.miek.nl miek.nl {
		key directory %s
		directory %s
	}`, keyDir, outputDir)
	c := caddy.NewTestController("dns", input)
	sign, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(sign.signers) != 1 {
		t.Fatalf("expected one signer, got %d", len(sign.signers))
	}
	return sign.signers[0]
}

func assertSignedWithTag(t *testing.T, signer *Signer, want uint16) {
	t.Helper()
	z, err := signer.Sign(time.Now().UTC())
	if err != nil {
		t.Fatalf("sign zone: %v", err)
	}
	apex, ok := z.Search(signer.origin)
	if !ok {
		t.Fatalf("zone %q has no apex", signer.origin)
	}
	keys := apex.Type(dns.TypeDNSKEY)
	if len(keys) != 1 {
		t.Fatalf("expected one DNSKEY, got %d", len(keys))
	}
	if got := keys[0].(*dns.DNSKEY).KeyTag(); got != want {
		t.Fatalf("signed with key tag %d, want %d", got, want)
	}
}

func writeTestKey(t *testing.T, dir string, modified time.Time) (string, uint16) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, fmt.Sprintf("Kmiek.nl.+013+%05d", key.KeyTag()))
	if err := os.WriteFile(base+".key", []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".private", []byte(key.PrivateKeyString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{base + ".key", base + ".private"} {
		if err := os.Chtimes(name, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	return base, key.KeyTag()
}

func chmodUnreadable(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("filesystem permissions are not enforced for this user")
	}
}

func waitForSignedKeyTag(t *testing.T, signedFile string, want uint16) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tag, err := signedSOAKeyTag(signedFile); err == nil && tag == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	tag, err := signedSOAKeyTag(signedFile)
	t.Fatalf("signed file %q has SOA key tag %d (err=%v), want %d", signedFile, tag, err, want)
}

func signedSOAKeyTag(signedFile string) (uint16, error) {
	f, err := os.Open(signedFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	zp := dns.NewZoneParser(f, ".", signedFile)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		sig, ok := rr.(*dns.RRSIG)
		if ok && sig.TypeCovered == dns.TypeSOA {
			return sig.KeyTag, nil
		}
	}
	if err := zp.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("SOA RRSIG not found")
}
