package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

// Pair holds DNSSEC key information, both the public and private components are stored here.
type Pair struct {
	Public  *dns.DNSKEY
	KeyTag  uint16
	Private crypto.Signer
}

type keyConfig struct {
	pairs       []Pair
	inlinePairs []Pair
	directories []string
}

// keyParse reads the public and private keys from disk.
func keyParse(c *caddy.Controller) ([]Pair, error) {
	cfg, err := parseKeyConfig(c)
	if err != nil {
		return nil, err
	}
	return cfg.pairs, nil
}

// parseKeyConfig reads a key directive and keeps enough information for directory-backed
// keys to be reloaded later without changing the existing inline key behavior.
func parseKeyConfig(c *caddy.Controller) (keyConfig, error) {
	if !c.NextArg() {
		return keyConfig{}, c.ArgErr()
	}
	cfg := keyConfig{}
	config := dnsserver.GetConfig(c)

	switch c.Val() {
	case "file":
		ks := c.RemainingArgs()
		if len(ks) == 0 {
			return keyConfig{}, c.ArgErr()
		}
		for _, k := range ks {
			base := k
			// Kmiek.nl.+013+26205.key, handle .private or without extension: Kmiek.nl.+013+26205
			if strings.HasSuffix(k, ".key") {
				base = k[:len(k)-4]
			}
			if strings.HasSuffix(k, ".private") {
				base = k[:len(k)-8]
			}
			if !filepath.IsAbs(base) && config.Root != "" {
				base = filepath.Join(config.Root, base)
			}

			pair, err := readKeyPair(base+".key", base+".private")
			if err != nil {
				return keyConfig{}, err
			}
			cfg.pairs = append(cfg.pairs, pair)
			cfg.inlinePairs = append(cfg.inlinePairs, pair)
		}
	case "directory":
		ds := c.RemainingArgs()
		if len(ds) == 0 {
			return keyConfig{}, c.ArgErr()
		}
		for _, d := range ds {
			if !filepath.IsAbs(d) && config.Root != "" {
				d = filepath.Join(config.Root, d)
			}
			cfg.directories = append(cfg.directories, filepath.Clean(d))
		}
		pairs, _, err := loadNewestKeyPair(cfg.directories)
		if err != nil {
			return keyConfig{}, err
		}
		cfg.pairs = append(cfg.pairs, pairs...)
	default:
		return keyConfig{}, c.Errf("unknown key source '%s'", c.Val())
	}

	return cfg, nil
}

func readKeyPair(public, private string) (Pair, error) {
	pair, _, err := readKeyPairWithFingerprint(public, private)
	return pair, err
}

func readKeyPairWithFingerprint(public, private string) (Pair, string, error) {
	public = filepath.Clean(public)
	private = filepath.Clean(private)

	keyData, err := os.ReadFile(filepath.Clean(public))
	if err != nil {
		return Pair{}, "", fmt.Errorf("read public key %q: %w", public, err)
	}
	privateData, err := os.ReadFile(filepath.Clean(private))
	if err != nil {
		return Pair{}, "", fmt.Errorf("read private key %q: %w", private, err)
	}

	dnskey, err := dns.NewRR(string(keyData))
	if err != nil {
		return Pair{}, "", fmt.Errorf("parse public key %q: %w", public, err)
	}
	if _, ok := dnskey.(*dns.DNSKEY); !ok {
		return Pair{}, "", fmt.Errorf("RR in %q is not a DNSKEY: %d", public, dnskey.Header().Rrtype)
	}
	ksk := dnskey.(*dns.DNSKEY).Flags&(1<<8) == (1<<8) && dnskey.(*dns.DNSKEY).Flags&1 == 1
	if !ksk {
		return Pair{}, "", fmt.Errorf("DNSKEY in %q is not a CSK/KSK", public)
	}

	privkey, err := dnskey.(*dns.DNSKEY).ReadPrivateKey(strings.NewReader(string(privateData)), private)
	if err != nil {
		return Pair{}, "", fmt.Errorf("parse private key %q: %w", private, err)
	}

	fingerprint := sha256.New()
	fingerprint.Write(keyData)
	fingerprint.Write([]byte{0})
	fingerprint.Write(privateData)
	hash := hex.EncodeToString(fingerprint.Sum(nil))

	switch signer := privkey.(type) {
	case *ecdsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, hash, nil
	case ed25519.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, hash, nil
	case *rsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, hash, nil
	default:
		return Pair{}, "", fmt.Errorf("unsupported algorithm %s", signer)
	}
}

type keyCandidate struct {
	base     string
	modified time.Time
}

// loadNewestKeyPair finds complete K<name>+<alg>+<id>.key/.private pairs in dirs and
// returns the most recently modified pair. The newest pair is the only one used so a
// key rollover is deterministic and does not sign with both old and new keys.
func loadNewestKeyPair(dirs []string) ([]Pair, string, error) {
	candidates := []keyCandidate{}
	privateKeys := map[string]struct{}{}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, "", fmt.Errorf("read key directory %q: %w", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "K") {
				continue
			}
			switch {
			case strings.HasSuffix(name, ".key"):
				base := filepath.Join(dir, strings.TrimSuffix(name, ".key"))
				keyInfo, err := os.Stat(base + ".key")
				if err != nil {
					return nil, "", fmt.Errorf("stat public key %q: %w", base+".key", err)
				}
				if !keyInfo.Mode().IsRegular() {
					return nil, "", fmt.Errorf("public key %q is not a regular file", base+".key")
				}
				privateInfo, err := os.Stat(base + ".private")
				if err != nil {
					return nil, "", fmt.Errorf("stat private key %q: %w", base+".private", err)
				}
				if !privateInfo.Mode().IsRegular() {
					return nil, "", fmt.Errorf("private key %q is not a regular file", base+".private")
				}
				modified := keyInfo.ModTime()
				if privateInfo.ModTime().After(modified) {
					modified = privateInfo.ModTime()
				}
				candidates = append(candidates, keyCandidate{base: base, modified: modified})
			case strings.HasSuffix(name, ".private"):
				base := filepath.Join(dir, strings.TrimSuffix(name, ".private"))
				privateKeys[base] = struct{}{}
			}
		}
	}

	for base := range privateKeys {
		if _, err := os.Stat(base + ".key"); err != nil {
			return nil, "", fmt.Errorf("private key %q has no matching public key: %w", base+".private", err)
		}
	}
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("no DNSSEC key pairs found in key directories %q", dirs)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modified.Equal(candidates[j].modified) {
			return candidates[i].base < candidates[j].base
		}
		return candidates[i].modified.After(candidates[j].modified)
	})

	pair, fingerprint, err := readKeyPairWithFingerprint(candidates[0].base+".key", candidates[0].base+".private")
	if err != nil {
		return nil, "", fmt.Errorf("load newest key pair %q: %w", candidates[0].base, err)
	}
	return []Pair{pair}, fingerprint, nil
}

func pairsForOrigin(pairs []Pair, origin string) []Pair {
	out := make([]Pair, 0, len(pairs))
	for _, pair := range pairs {
		pair.Public = dns.Copy(pair.Public).(*dns.DNSKEY)
		pair.Public.Header().Name = origin
		out = append(out, pair)
	}
	return out
}

// keyTag returns the key tags of the keys in ps as a formatted string.
func keyTag(ps []Pair) string {
	if len(ps) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, p := range ps {
		sb.WriteString(strconv.Itoa(int(p.KeyTag)) + ",")
	}
	s := sb.String()
	return s[:len(s)-1]
}
