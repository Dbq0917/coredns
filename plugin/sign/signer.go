package sign

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/file/tree"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("sign")

// Signer holds the data needed to sign a zone file.
type Signer struct {
	keysMu      sync.RWMutex
	keys        []Pair
	inlineKeys  []Pair
	keyDirs     []string
	keyHash     string
	origin      string
	dbfile      string
	directory   string
	jitterIncep time.Duration
	jitterExpir time.Duration
	keyReload   time.Duration
	disabled    bool

	signedfile string
	stop       chan struct{}
}

// Sign signs a zone file according to the parameters in s.
func (s *Signer) Sign(now time.Time) (*file.Zone, error) {
	keys := s.keySnapshot()
	if len(keys) == 0 {
		return nil, errors.New("no signing keys available")
	}

	rd, err := os.Open(s.dbfile)
	if err != nil {
		return nil, err
	}
	defer rd.Close()

	z, err := Parse(rd, s.origin, s.dbfile)
	if err != nil {
		return nil, err
	}

	mttl := z.SOA.Minttl
	ttl := z.SOA.Header().Ttl
	inception, expiration := lifetime(now, s.jitterIncep, s.jitterExpir)
	z.SOA.Serial = uint32(now.Unix()) // #nosec G115 -- Unix time to SOA serial, Year 2106 problem accepted

	for _, pair := range keys {
		public := dns.Copy(pair.Public).(*dns.DNSKEY)
		public.Header().Ttl = ttl // set TTL on key so it matches the RRSIG.
		z.Insert(public)
		z.Insert(public.ToDS(dns.SHA1).ToCDS())
		z.Insert(public.ToDS(dns.SHA256).ToCDS())
		z.Insert(public.ToCDNSKEY())
	}

	names := names(s.origin, z)
	ln := len(names)

	for _, pair := range keys {
		rrsig, err := pair.signRRs([]dns.RR{z.SOA}, s.origin, ttl, inception, expiration)
		if err != nil {
			return nil, err
		}
		z.Insert(rrsig)
		// NS apex may not be set if RR's have been discarded because the origin doesn't match.
		if len(z.NS) > 0 {
			rrsig, err = pair.signRRs(z.NS, s.origin, ttl, inception, expiration)
			if err != nil {
				return nil, err
			}
			z.Insert(rrsig)
		}
	}

	// We are walking the tree in the same direction, so names[] can be used here to indicated the next element.
	i := 1
	err = z.AuthWalk(func(e *tree.Elem, zrrs map[uint16][]dns.RR, auth bool) error {
		if !auth {
			return nil
		}

		if e.Name() == s.origin {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], mttl, append(e.Types(), dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC))
			z.Insert(nsec)
		} else {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], mttl, append(e.Types(), dns.TypeRRSIG, dns.TypeNSEC))
			z.Insert(nsec)
		}

		for t, rrs := range zrrs {
			// RRSIGs are not signed and NS records are not signed because we are never authoratiative for them.
			// The zone's apex nameservers records are not kept in this tree and are signed separately.
			if t == dns.TypeRRSIG || t == dns.TypeNS {
				continue
			}
			for _, pair := range keys {
				rrsig, err := pair.signRRs(rrs, s.origin, rrs[0].Header().Ttl, inception, expiration)
				if err != nil {
					return err
				}
				e.Insert(rrsig)
			}
		}
		i++
		return nil
	})
	return z, err
}

// resign checks if the signed zone exists, or needs resigning.
func (s *Signer) resign() error {
	signedfile := filepath.Join(s.directory, s.signedfile)
	rd, err := os.Open(filepath.Clean(signedfile))
	if err != nil {
		return err
	}
	defer rd.Close()

	now := time.Now().UTC()
	return resign(rd, now)
}

// resign will scan rd and check the signature on the SOA record. We will resign on the basis
// of 2 conditions:
// * either the inception is more than 6 days ago, or
// * we only have 1 week left on the signature
//
// All SOA signatures will be checked. If the SOA isn't found in the first 100
// records, we will resign the zone.
func resign(rd io.Reader, now time.Time) (why error) {
	zp := dns.NewZoneParser(rd, ".", "resign")
	zp.SetIncludeAllowed(true)
	i := 0

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if x, ok := rr.(*dns.RRSIG); ok {
			if x.TypeCovered != dns.TypeSOA {
				continue
			}
			incep, _ := time.Parse("20060102150405", dns.TimeToString(x.Inception))
			// If too long ago, resign.
			if now.Sub(incep) >= 0 && now.Sub(incep) > durationResignDays {
				return fmt.Errorf("inception %q was more than: %s ago from %s: %s", incep.Format(timeFmt), durationResignDays, now.Format(timeFmt), now.Sub(incep))
			}
			// Inception hasn't even start yet.
			if now.Sub(incep) < 0 {
				return fmt.Errorf("inception %q date is in the future: %s", incep.Format(timeFmt), now.Sub(incep))
			}

			expire, _ := time.Parse("20060102150405", dns.TimeToString(x.Expiration))
			if expire.Sub(now) < durationExpireDays {
				return fmt.Errorf("expiration %q is less than: %s away from %s: %s", expire.Format(timeFmt), durationExpireDays, now.Format(timeFmt), expire.Sub(now))
			}
		}
		i++
		if i > 100 {
			// 100 is a random number. A SOA record should be the first in the zonefile, but RFC 1035 doesn't actually mandate this. So it could
			// be 3rd or even later. The number 100 looks crazy high enough that it will catch all weird zones, but not high enough to keep the CPU
			// busy with parsing all the time.
			return fmt.Errorf("no SOA RRSIG found in first 100 records")
		}
	}

	return zp.Err()
}

func signAndLog(s *Signer, why error) {
	now := time.Now().UTC()
	z, err := s.Sign(now)
	log.Infof("Signing %q because %s", s.origin, why)
	if err != nil {
		code := signingErrorCode(err)
		signOperations.WithLabelValues(s.origin, code).Inc()
		log.Warningf("Error signing %q with key tags %q in %s: %s (code=%s), next: %s", s.origin, keyTag(s.keySnapshot()), time.Since(now), err, code, now.Add(durationRefreshHours).Format(timeFmt))
		return
	}

	if err := s.write(z); err != nil {
		signOperations.WithLabelValues(s.origin, ErrorCodeWrite).Inc()
		log.Warningf("Error signing %q: failed to move zone file into place: %s (code=%s)", s.origin, err, ErrorCodeWrite)
		return
	}
	signOperations.WithLabelValues(s.origin, ResultSuccess).Inc()
	signLastSuccess.WithLabelValues(s.origin).Set(float64(now.Unix()))
	log.Infof("Successfully signed zone %q in %q with key tags %q and %d SOA serial, elapsed %f, next: %s", s.origin, filepath.Join(s.directory, s.signedfile), keyTag(s.keySnapshot()), z.SOA.Serial, time.Since(now).Seconds(), now.Add(durationRefreshHours).Format(timeFmt))
}

// refresh checks every val if some zones need to be resigned.
func (s *Signer) refresh(val time.Duration) {
	tick := time.NewTicker(val)
	defer tick.Stop()
	keyTick := time.NewTicker(s.keyReloadInterval())
	defer keyTick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-keyTick.C:
			if s.reloadKeysAndLog() {
				signAndLog(s, fmt.Errorf("key directory changed to key tags %q", keyTag(s.keySnapshot())))
			}
		case <-tick.C:
			if s.reloadKeysAndLog() {
				signAndLog(s, fmt.Errorf("key directory changed to key tags %q", keyTag(s.keySnapshot())))
				continue
			}
			why := s.resign()
			if why == nil {
				continue
			}
			signReason.WithLabelValues(s.origin, resignReasonCode(why)).Inc()
			signAndLog(s, why)
		}
	}
}

func (s *Signer) keyReloadInterval() time.Duration {
	if s.keyReload <= 0 {
		return durationKeyReload
	}
	return s.keyReload
}

func (s *Signer) keySnapshot() []Pair {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return append([]Pair(nil), s.keys...)
}

func (s *Signer) setKeys(keys, inlineKeys []Pair, dirs []string, hash string) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	s.keys = append([]Pair(nil), keys...)
	s.inlineKeys = append([]Pair(nil), inlineKeys...)
	s.keyDirs = append([]string(nil), dirs...)
	s.keyHash = hash
}

// reloadKeys refreshes directory-backed keys. Inline keys are left untouched. A failed
// load keeps the last known good snapshot and is reported to the caller so it can be
// retried on the next interval.
func (s *Signer) reloadKeys() (bool, error) {
	s.keysMu.RLock()
	dirs := append([]string(nil), s.keyDirs...)
	currentHash := s.keyHash
	inlineKeys := append([]Pair(nil), s.inlineKeys...)
	s.keysMu.RUnlock()

	if len(dirs) == 0 {
		return false, nil
	}

	pairs, hash, err := loadNewestKeyPair(dirs)
	if err != nil {
		keyLoads.WithLabelValues(s.origin, ErrorCodeKeyLoad).Inc()
		keyLoadLastError.WithLabelValues(s.origin).Set(float64(time.Now().UTC().Unix()))
		return false, err
	}
	keyLoads.WithLabelValues(s.origin, ResultSuccess).Inc()
	keyLoadLastSuccess.WithLabelValues(s.origin).Set(float64(time.Now().UTC().Unix()))
	if hash == currentHash {
		return false, nil
	}

	keys := append(append([]Pair(nil), inlineKeys...), pairsForOrigin(pairs, s.origin)...)
	s.setKeys(keys, inlineKeys, dirs, hash)
	activeKey.WithLabelValues(s.origin).Set(float64(keys[len(keys)-1].KeyTag))
	return true, nil
}

func (s *Signer) reloadKeysAndLog() bool {
	changed, err := s.reloadKeys()
	if err != nil {
		log.Warningf("Failed to reload keys for %q: %s (code=%s); keeping last known good keys and retrying in %s", s.origin, err, ErrorCodeKeyLoad, s.keyReloadInterval())
		return false
	}
	if changed {
		log.Infof("Reloaded key directory for %q, now using key tags %q", s.origin, keyTag(s.keySnapshot()))
	}
	return changed
}

func signingErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if err.Error() == "no signing keys available" {
		return ErrorCodeKeyLoad
	}
	return ErrorCodeSigning
}

func resignReasonCode(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case os.IsNotExist(err):
		return ErrorCodeSignedZoneMissing
	case strings.Contains(err.Error(), "expiration"):
		return ErrorCodeSignatureExpired
	case strings.Contains(err.Error(), "inception"):
		return ErrorCodeSignatureNotYetValid
	case strings.Contains(err.Error(), "no SOA RRSIG"):
		return ErrorCodeSignatureMissing
	default:
		return ErrorCodeResign
	}
}

func lifetime(now time.Time, jitterInception, jitterExpiration time.Duration) (uint32, uint32) {
	incep := uint32(now.Add(durationSignatureInceptionHours).Add(jitterInception).Unix()) // #nosec G115 -- DNSSEC signature inception, Year 2106 problem accepted
	expir := uint32(now.Add(durationSignatureExpireDays).Add(jitterExpiration).Unix())    // #nosec G115 -- DNSSEC signature expiration, Year 2106 problem accepted
	return incep, expir
}
