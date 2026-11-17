package geoip

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/oschwald/geoip2-golang/v2"
	"github.com/oschwald/maxminddb-golang/v2"
)

// geoDatabase abstracts the lookup methods provided by a geo database,
// regardless of how the database file was opened.
type geoDatabase interface {
	City(netip.Addr) (*geoip2.City, error)
	Country(netip.Addr) (*geoip2.Country, error)
	ASN(netip.Addr) (*geoip2.ASN, error)
	Close() error
}

// db is a loaded database file, together with the schemas it provides and the
// metadata read from the file, used for logging and metrics.
type db struct {
	geoDatabase
	// provides defines the schemas that can be obtained by querying this database, by using
	// bitwise operations.
	provides int
	path     string
	meta     maxminddb.Metadata
}

const (
	city = 1 << iota
	asn
	country
)

var probingIP = netip.MustParseAddr("127.0.0.1")

// mmdbMarker prefixes the metadata section found at the end of every MMDB database file.
var mmdbMarker = []byte("\xab\xcd\xefMaxMind.com")

// loadDatabase opens the database file at path and determines which schemas it provides.
func loadDatabase(path string) (*db, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		var unknownType geoip2.UnknownDatabaseTypeError
		if errors.As(err, &unknownType) {
			// The file is a valid MMDB database, but its database type is not
			// known to the geoip2 library, e.g. newer database generations or
			// vendor specific types. Open it directly instead of failing.
			return loadGenericDatabase(path, unknownType.DatabaseType)
		}
		return nil, fmt.Errorf("failed to open database file: %w (%s)", err, detectFormat(path))
	}
	d := &db{geoDatabase: reader, path: path, meta: reader.Metadata()}
	if err := d.probeSchemas(); err != nil {
		reader.Close()
		return nil, err
	}
	return d, nil
}

// probeSchemas queries the database to figure out which schemas it provides.
func (d *db) probeSchemas() error {
	schemas := []struct {
		name     string
		provides int
		validate func() error
	}{
		{name: "city", provides: city, validate: func() error { _, err := d.City(probingIP); return err }},
		{name: "country", provides: country, validate: func() error { _, err := d.Country(probingIP); return err }},
		{name: "asn", provides: asn, validate: func() error { _, err := d.ASN(probingIP); return err }},
	}
	for _, schema := range schemas {
		if err := schema.validate(); err != nil {
			// If we get an InvalidMethodError then we know this database does not provide that schema.
			var invalidMethod geoip2.InvalidMethodError
			if !errors.As(err, &invalidMethod) {
				return fmt.Errorf("unexpected failure looking up database %q schema %q: %w", filepath.Base(d.path), schema.name, err)
			}
		} else {
			d.provides |= schema.provides
		}
	}

	if d.provides == 0 {
		return fmt.Errorf("database %q (type %q) does not provide any supported schema (city, country, asn)", d.path, d.meta.DatabaseType)
	}
	return nil
}

// loadGenericDatabase opens a valid MMDB database whose database type is not
// known to the geoip2 library, decoding records directly with maxminddb. The
// provided schemas are derived from the database type declared in the file.
func loadGenericDatabase(path, dbType string) (*db, error) {
	provides := providesForType(dbType)
	if provides == 0 {
		return nil, fmt.Errorf("unsupported database type %q in database file %q: the database type does not indicate any supported schema (city, country, asn)", dbType, path)
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database file: %w (%s)", err, detectFormat(path))
	}
	return &db{geoDatabase: genericDatabase{reader}, provides: provides, path: path, meta: reader.Metadata}, nil
}

// providesForType derives the provided schemas from a database type name, e.g.
// "GeoIP2-Precision-Enterprise" provides the city, country and asn schemas.
func providesForType(dbType string) int {
	t := strings.ToLower(dbType)
	switch {
	case strings.Contains(t, "enterprise"):
		return city | country | asn
	case strings.Contains(t, "city"):
		return city | country
	case strings.Contains(t, "country"):
		return country
	case strings.Contains(t, "asn"):
		return asn
	}
	return 0
}

// genericDatabase reads any MMDB database file directly, decoding records into
// the geoip2 schemas regardless of the database type declared in the metadata.
type genericDatabase struct{ *maxminddb.Reader }

func (g genericDatabase) City(ip netip.Addr) (*geoip2.City, error) {
	var city geoip2.City
	if err := g.Lookup(ip).Decode(&city); err != nil {
		return nil, err
	}
	return &city, nil
}

func (g genericDatabase) Country(ip netip.Addr) (*geoip2.Country, error) {
	var country geoip2.Country
	if err := g.Lookup(ip).Decode(&country); err != nil {
		return nil, err
	}
	return &country, nil
}

func (g genericDatabase) ASN(ip netip.Addr) (*geoip2.ASN, error) {
	var asn geoip2.ASN
	if err := g.Lookup(ip).Decode(&asn); err != nil {
		return nil, err
	}
	return &asn, nil
}

// detectFormat inspects a database file that failed to open and describes the
// detected format, so that load errors name the actual problem instead of
// failing with a generic message.
func detectFormat(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("cannot inspect database format: %v", err)
	}
	defer f.Close()

	// The MMDB metadata section, starting with the MaxMind marker, is located
	// at the end of the file.
	const tailSize = 1 << 20
	var buf []byte
	if info, err := f.Stat(); err == nil && info.Size() > tailSize {
		if _, err := f.Seek(-tailSize, io.SeekEnd); err != nil {
			return fmt.Sprintf("cannot inspect database format: %v", err)
		}
	}
	if buf, err = io.ReadAll(f); err != nil {
		return fmt.Sprintf("cannot inspect database format: %v", err)
	}
	if bytes.Contains(buf, mmdbMarker) {
		return "file declares the MMDB (MaxMind DB) format but could not be parsed, the file is likely corrupted"
	}
	return "file does not contain the MMDB (MaxMind DB) metadata marker, the supported database format is MMDB"
}

// schemas returns a human readable list of the schemas provided by the database.
func (d *db) schemas() string {
	names := make([]string, 0, 3)
	if d.provides&city != 0 {
		names = append(names, "city")
	}
	if d.provides&country != 0 {
		names = append(names, "country")
	}
	if d.provides&asn != 0 {
		names = append(names, "asn")
	}
	return strings.Join(names, ",")
}
