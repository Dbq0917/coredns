package sign

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("sign", setup) }

func setup(c *caddy.Controller) error {
	sign, err := parse(c)
	if err != nil {
		return plugin.Error("sign", err)
	}

	c.OnStartup(sign.OnStartup)
	c.OnStartup(func() error {
		if sign.disabled {
			return nil
		}
		for _, signer := range sign.signers {
			if signer.disabled {
				continue
			}
			go signer.refresh(durationRefreshHours)
		}
		return nil
	})
	c.OnShutdown(func() error {
		for _, signer := range sign.signers {
			close(signer.stop)
		}
		return nil
	})

	// Don't call AddPlugin, *sign* is not a plugin.
	return nil
}

func parse(c *caddy.Controller) (*Sign, error) {
	sign := &Sign{}
	config := dnsserver.GetConfig(c)

	for c.Next() {
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		dbfile := c.Val()
		if !filepath.IsAbs(dbfile) && config.Root != "" {
			dbfile = filepath.Join(config.Root, dbfile)
		}

		// Validate dbfile token to avoid infinite signing loops caused by invalid paths
		if strings.ContainsRune(dbfile, '\uFFFD') {
			return nil, fmt.Errorf("dbfile %q contains invalid characters", dbfile)
		}

		origins := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
		signers := make([]*Signer, len(origins))
		for i := range origins {
			signers[i] = &Signer{
				dbfile:      dbfile,
				origin:      origins[i],
				jitterIncep: time.Duration(float32(durationInceptionJitter) * rand.Float32()),     // #nosec G404 -- non-cryptographic jitter.
				jitterExpir: time.Duration(float32(durationExpirationDayJitter) * rand.Float32()), // #nosec G404 -- non-cryptographic jitter.
				directory:   "/var/lib/coredns",
				keyReload:   durationKeyReload,
				stop:        make(chan struct{}),
				signedfile:  fmt.Sprintf("db.%ssigned", origins[i]), // origins[i] is a fqdn, so it ends with a dot, hence %ssigned.
			}
		}

		for c.NextBlock() {
			switch c.Val() {
			case "key":
				keyCfg, err := parseKeyConfig(c)
				if err != nil {
					return sign, err
				}
				for i := range signers {
					inlineKeys := append(signers[i].inlineKeys, pairsForOrigin(keyCfg.inlinePairs, signers[i].origin)...)
					dirs := append(append([]string(nil), signers[i].keyDirs...), keyCfg.directories...)
					var directoryKeys []Pair
					var keyHash string
					if len(dirs) > 0 {
						pairs, hash, err := loadNewestKeyPair(dirs)
						if err != nil {
							return sign, err
						}
						directoryKeys = pairsForOrigin(pairs, signers[i].origin)
						keyHash = hash
					}
					keys := append(append([]Pair(nil), inlineKeys...), directoryKeys...)
					signers[i].setKeys(keys, inlineKeys, dirs, keyHash)
					if len(directoryKeys) > 0 {
						activeKey.WithLabelValues(signers[i].origin).Set(float64(directoryKeys[len(directoryKeys)-1].KeyTag))
					}
				}
			case "key_reload":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return sign, fmt.Errorf("can only be one argument after %q", "key_reload")
				}
				interval, err := time.ParseDuration(args[0])
				if err != nil || interval <= 0 {
					return sign, fmt.Errorf("invalid %q duration %q", "key_reload", args[0])
				}
				for i := range signers {
					signers[i].keyReload = interval
				}
			case "disable", "disabled":
				args := c.RemainingArgs()
				if len(args) > 1 {
					return sign, fmt.Errorf("can only be one argument after %q", c.Val())
				}
				disabled := true
				if len(args) == 1 {
					var err error
					disabled, err = strconv.ParseBool(args[0])
					if err != nil {
						return sign, fmt.Errorf("invalid %q value %q", c.Val(), args[0])
					}
				}
				sign.disabled = disabled
				for i := range signers {
					signers[i].disabled = disabled
				}
			case "directory":
				dir := c.RemainingArgs()
				if len(dir) == 0 || len(dir) > 1 {
					return sign, fmt.Errorf("can only be one argument after %q", "directory")
				}
				if !filepath.IsAbs(dir[0]) && config.Root != "" {
					dir[0] = filepath.Join(config.Root, dir[0])
				}
				for i := range signers {
					signers[i].directory = dir[0]
					signers[i].signedfile = fmt.Sprintf("db.%ssigned", signers[i].origin)
				}
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
		sign.signers = append(sign.signers, signers...)
	}

	return sign, nil
}
