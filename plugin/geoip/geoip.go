// Package geoip implements an MMDB database plugin for geo/network IP lookups.
package geoip

import (
	"context"
	"net/netip"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(pluginName)

// GeoIP is a plugin that adds geo location and network data to the request context by looking up
// an MMDB format database, and which data can be later consumed by other middlewares.
type GeoIP struct {
	Next   plugin.Handler
	groups []*dbGroup
}

// dbGroup binds a database file and its options to a domain. The group with an
// empty domain is the catch-all group used by the single-database syntax.
type dbGroup struct {
	domain   string // normalized (lower case, fqdn); empty matches every query name
	dbPath   string
	edns0    bool
	fallback fallbackPolicy
	defaults map[string]string
	db       *db
	loadErr  error
}

// fallbackPolicy defines how queries are answered when the database of a group
// failed to load.
type fallbackPolicy int

const (
	// fallbackNone aborts the server startup when the database fails to load.
	fallbackNone fallbackPolicy = iota
	// fallbackRefuse refuses to resolve queries (SERVFAIL) when the database failed to load.
	fallbackRefuse
	// fallbackDefault answers with the configured default metadata values when the
	// database failed to load, e.g. routing traffic to a default region.
	fallbackDefault
)

func (p fallbackPolicy) String() string {
	switch p {
	case fallbackRefuse:
		return "refuse"
	case fallbackDefault:
		return "default"
	}
	return "none"
}

func newGeoIP(dbPath string, edns0 bool) (*GeoIP, error) {
	group := &dbGroup{dbPath: dbPath, edns0: edns0}
	if err := group.load(); err != nil {
		return nil, err
	}
	return &GeoIP{groups: []*dbGroup{group}}, nil
}

// load opens the database file of the group, applying the configured fallback
// policy when loading fails. Load duration and database version are reported
// to metrics, and the outcome is logged with the file path and version.
func (g *dbGroup) load() error {
	start := time.Now()
	d, err := loadDatabase(g.dbPath)
	reportLoad(g.dbPath, d, err, time.Since(start))
	if err != nil {
		if g.fallback == fallbackNone {
			return err
		}
		g.loadErr = err
		log.Errorf("Failed to load database %q: %v", g.dbPath, err)
		log.Warningf("Database %q is unavailable, queries for domain %q are answered with the %q fallback policy; geoip routing is degraded and should be alerted on", g.dbPath, g.domainName(), g.fallback)
		return nil
	}
	g.db = d
	log.Infof("Loaded database %q: type=%q, version(build_epoch)=%d, ip_version=%d, nodes=%d, schemas=%s",
		g.dbPath, d.meta.DatabaseType, d.meta.BuildEpoch, d.meta.IPVersion, d.meta.NodeCount, d.schemas())
	return nil
}

func (g *dbGroup) domainName() string {
	if g.domain == "" {
		return "."
	}
	return g.domain
}

// groupFor returns the group with the longest domain suffix matching qname.
func (g GeoIP) groupFor(qname string) *dbGroup {
	qname = plugin.Name(qname).Normalize()
	var match *dbGroup
	for _, group := range g.groups {
		if group.domain == "" {
			if match == nil {
				match = group
			}
			continue
		}
		if plugin.Name(group.domain).Matches(qname) {
			if match == nil || len(group.domain) > len(match.domain) {
				match = group
			}
		}
	}
	return match
}

// ServeDNS implements the plugin.Handler interface.
func (g GeoIP) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	if group := g.groupFor(state.QName()); group != nil && group.db == nil && group.fallback == fallbackRefuse {
		group.reportFallback()
		log.Warningf("Refusing to resolve %s: database %q failed to load (%v), fallback policy is %q",
			state.QName(), group.dbPath, group.loadErr, group.fallback)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeServerFailure, nil
	}
	return plugin.NextOrFailure(pluginName, g.Next, ctx, w, r)
}

// Metadata implements the metadata.Provider Interface in the metadata plugin, and is used to store
// the data associated with the source IP of every request.
func (g GeoIP) Metadata(ctx context.Context, state request.Request) context.Context {
	group := g.groupFor(state.QName())
	if group == nil {
		return ctx
	}
	if group.db == nil {
		group.setFallbackMetadata(ctx)
		return ctx
	}

	srcIP, err := netip.ParseAddr(state.IP())
	if err != nil {
		log.Debugf("Failed to parse source IP %q: %v", state.IP(), err)
		return ctx
	}

	if group.edns0 {
		if o := state.Req.IsEdns0(); o != nil {
			for _, s := range o.Option {
				if e, ok := s.(*dns.EDNS0_SUBNET); ok {
					// e.Address is still a net.IP type
					if addr, ok := netip.AddrFromSlice(e.Address); ok {
						srcIP = addr
					} else {
						log.Debugf("Failed to parse EDNS0 subnet address %v", e.Address)
					}
					break
				}
			}
		}
	}

	if group.db.provides&city != 0 {
		data, err := group.db.City(srcIP)
		if err != nil {
			log.Debugf("Setting up city metadata failed due to database lookup error: %v", err)
		} else {
			g.setCityMetadata(ctx, data)
		}
	} else if group.db.provides&country != 0 {
		data, err := group.db.Country(srcIP)
		if err != nil {
			log.Debugf("Setting up country metadata failed due to database lookup error: %v", err)
		} else {
			g.setCountryMetadata(ctx, data)
		}
	}
	if group.db.provides&asn != 0 {
		data, err := group.db.ASN(srcIP)
		if err != nil {
			log.Debugf("Setting up asn metadata failed due to database lookup error: %v", err)
		} else {
			g.setASNMetadata(ctx, data)
		}
	}
	return ctx
}

// setFallbackMetadata answers a query whose database failed to load with the
// configured default values. The geoip/fallback label is always set so that
// downstream plugins and the business logic know the answer is degraded.
func (g *dbGroup) setFallbackMetadata(ctx context.Context) {
	if g.fallback != fallbackDefault {
		return
	}
	g.reportFallback()
	metadata.SetValueFunc(ctx, pluginName+"/fallback", func() string {
		return "true"
	})
	for label, value := range g.defaults {
		metadata.SetValueFunc(ctx, pluginName+"/"+label, func() string {
			return value
		})
	}
}

// Name implements the Handler interface.
func (g GeoIP) Name() string { return pluginName }
