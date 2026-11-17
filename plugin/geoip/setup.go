package geoip

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const pluginName = "geoip"

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	geoip, err := geoipParse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		geoip.Next = next
		return geoip
	})

	return nil
}

func geoipParse(c *caddy.Controller) (*GeoIP, error) {
	geoIP := &GeoIP{}
	for c.Next() {
		args := c.RemainingArgs()
		switch {
		case len(args) > 1:
			return nil, c.ArgErr()
		case len(args) == 1:
			// Single-database syntax: geoip DBFILE { ... }
			for _, group := range geoIP.groups {
				if group.domain == "" {
					return nil, c.Errf("configuring multiple databases is not supported")
				}
			}
			group := &dbGroup{dbPath: args[0]}
			if err := parseOptions(c, group); err != nil {
				return nil, err
			}
			geoIP.groups = append(geoIP.groups, group)
		default:
			// Per-domain syntax: geoip { domain example.com { ... } }
			if !c.NextBlock() {
				return nil, c.ArgErr()
			}
			for {
				if c.Val() != "domain" {
					return nil, c.Errf("unknown property %q", c.Val())
				}
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				group := &dbGroup{domain: plugin.Name(c.Val()).Normalize()}
				if len(c.RemainingArgs()) != 0 {
					return nil, c.ArgErr()
				}
				for _, existing := range geoIP.groups {
					if existing.domain == group.domain {
						return nil, c.Errf("domain %q is configured more than once", group.domain)
					}
				}
				if err := parseOptions(c, group); err != nil {
					return nil, err
				}
				if group.dbPath == "" {
					return nil, c.Errf("domain %q has no database configured", group.domain)
				}
				geoIP.groups = append(geoIP.groups, group)
				if !c.NextBlock() {
					break
				}
			}
		}
	}

	for _, group := range geoIP.groups {
		if err := group.load(); err != nil {
			return nil, c.Err(err.Error())
		}
	}
	if len(geoIP.groups) == 0 {
		return nil, c.Err("no database configured")
	}
	return geoIP, nil
}

// parseOptions parses the option block of a single database group.
func parseOptions(c *caddy.Controller, group *dbGroup) error {
	for c.NextBlock() {
		switch c.Val() {
		case "edns-subnet":
			group.edns0 = true
		case "db":
			if !c.NextArg() {
				return c.ArgErr()
			}
			if group.dbPath != "" {
				return c.Errf("configuring multiple databases is not supported")
			}
			group.dbPath = c.Val()
			if len(c.RemainingArgs()) != 0 {
				return c.ArgErr()
			}
		case "fallback":
			if !c.NextArg() {
				return c.ArgErr()
			}
			switch c.Val() {
			case "refuse":
				group.fallback = fallbackRefuse
			case "default":
				group.fallback = fallbackDefault
			default:
				return c.Errf("unknown fallback policy %q, expected %q or %q", c.Val(), "refuse", "default")
			}
			if len(c.RemainingArgs()) != 0 {
				return c.ArgErr()
			}
		case "default":
			if !c.NextArg() {
				return c.ArgErr()
			}
			label := c.Val()
			if !c.NextArg() {
				return c.ArgErr()
			}
			if group.defaults == nil {
				group.defaults = make(map[string]string)
			}
			group.defaults[label] = c.Val()
			if len(c.RemainingArgs()) != 0 {
				return c.ArgErr()
			}
		default:
			return c.Errf("unknown property %q", c.Val())
		}
	}
	return nil
}
