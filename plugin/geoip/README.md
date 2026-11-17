# geoip

## Name

*geoip* - Lookup `.mmdb` ([MaxMind db file format](https://maxmind.github.io/MaxMind-DB/)) databases using the client IP, then add associated geoip data to the context request.

## Description

The *geoip* plugin allows you to enrich the data associated with Client IP addresses, e.g. geoip information like City, Country, and Network ASN. GeoIP data is commonly available in the `.mmdb` format, a database format that maps IPv4 and IPv6 addresses to data records using a binary search tree.

The data is added leveraging the *metadata* plugin, values can then be retrieved using it as well.

**Longitude example:**

```go
import (
    "strconv"
    "github.com/coredns/coredns/plugin/metadata"
)
// ...
if getLongitude := metadata.ValueFunc(ctx, "geoip/longitude"); getLongitude != nil {
    if longitude, err := strconv.ParseFloat(getLongitude(), 64); err == nil {
        // Do something useful with longitude.
    }
} else {
    // The metadata label geoip/longitude for some reason, was not set.
}
// ...
```

**City example:**

```go
import (
    "github.com/coredns/coredns/plugin/metadata"
)
// ...
if getCity := metadata.ValueFunc(ctx, "geoip/city/name"); getCity != nil {
    city := getCity()
    // Do something useful with city.
} else {
    // The metadata label geoip/city/name for some reason, was not set.
}
// ...
```

**ASN example:**

```go
import (
    "strconv"
    "github.com/coredns/coredns/plugin/metadata"
)
// ...
if getASN := metadata.ValueFunc(ctx, "geoip/asn/number"); getASN != nil {
    if asn, err := strconv.ParseUint(getASN(), 10, 32); err == nil {
        // Do something useful with asn.
    }
}
if getASNOrg := metadata.ValueFunc(ctx, "geoip/asn/org"); getASNOrg != nil {
    asnOrg := getASNOrg()
    // Do something useful with asnOrg.
}
// ...
```

## Databases

The supported databases use city schema such as `ASN`, `City`, `Country`, and `Enterprise`. `.mmdb` files are generally supported, as long as their field names correctly map to the Metadata Labels below.

Databases whose `database_type` is not known to the underlying geoip2 library, e.g. newer database
generations or vendor specific types, are loaded directly as MMDB files when the declared type
indicates a supported schema (`city`, `country`, `asn` or `enterprise`). Databases that cannot be
loaded fail with an error naming the detected database type and format.

Free and commercial GeoIP `.mmdb` files are commonly available from vendors like [MaxMind](https://dev.maxmind.com/geoip/docs/databases), [IPinfo](https://ipinfo.io/developers/database-download), and [IPtoASN](https://iptoasn.com/) which is [Public Domain-licensed](https://opendatacommons.org/licenses/pddl/1-0/).

## Syntax

```text
geoip [DBFILE]
```

or

```text
geoip [DBFILE] {
    edns-subnet
    fallback [refuse|default]
    default [LABEL] [VALUE]
}
```

* **DBFILE** the `mmdb` database file path. We recommend updating your `mmdb` database periodically for more accurate results.
* `edns-subnet`: Optional. Use [EDNS0 subnet](https://en.wikipedia.org/wiki/EDNS_Client_Subnet) (if present) for Geo IP instead of the source IP of the DNS request. This helps identifying the closest source IP address through intermediary DNS resolvers, and it also makes GeoIP testing easy: `dig +subnet=1.2.3.4 @dns-server.example.com www.geo-aware.com`.

  **NOTE:** due to security reasons, recursive DNS resolvers may mask a few bits off of the clients' IP address, which can cause inaccuracies in GeoIP resolution.

  There is no defined mask size in the standards, but there are examples: [RFC 7871's example](https://www.rfc-editor.org/info/rfc7871/#section-13) conceals the last 72 bits of an IPv6 source address, and NS1 Help Center [mentions](https://help.ns1.com/hc/en-us/articles/360020256573-About-the-EDNS-Client-Subnet-ECS-DNS-extension) that ECS-enabled DNS resolvers send only the first three octets (eg. /24) of the source IPv4 address.
* `fallback`: Optional. Defines how queries are answered when **DBFILE** fails to load. Without
  this option a database that fails to load prevents the server from starting.
  * `refuse`: refuse to resolve queries (answer `SERVFAIL`).
  * `default`: answer with the default metadata values configured with `default`, e.g. to route
    traffic to a default region.
* `default` **LABEL** **VALUE**: Optional, can be repeated. Sets the metadata label
  `geoip/LABEL` to **VALUE** when answering under the `default` fallback policy, e.g.
  `default country/code CN`. The label `geoip/fallback` is always set to `true` in this case, so
  downstream plugins can tell the answer is degraded.

Databases can also be grouped per domain, so that different domains use different database files:

```text
geoip {
    domain example.com {
        db DBFILE
        edns-subnet
        fallback default
        default country/code CN
    }
    domain example.org {
        db DBFILE2
        fallback refuse
    }
}
```

* `domain` **DOMAIN**: binds the options in its block to **DOMAIN** and its subdomains. The
  longest matching domain wins. Query names matching no `domain` get no geoip metadata. Every
  domain block requires a `db` option.
* `db` **DBFILE**: the `mmdb` database file path used for this domain.

## Examples

The following configuration configures the `City` database, and looks up geolocation based on EDNS0 subnet if present.

```txt
. {
    geoip /opt/geoip2/db/GeoLite2-City.mmdb {
      edns-subnet
    }
    metadata # Note that metadata plugin must be enabled as well.
}
```

The *view* plugin can use *geoip* metadata as selection criteria to provide GSLB functionality.
In this example, clients from the city "Exampleshire" will receive answers for `example.com` from the zone defined in 
`example.com.exampleshire-db`. All other clients will receive answers from the zone defined in `example.com.db`.
Note that the order of the two `example.com` server blocks below is important; the default viewless server block
must be last.

```txt
example.com {
    view exampleshire {
      expr metadata('geoip/city/name') == 'Exampleshire'
    }
    geoip /opt/geoip2/db/GeoLite2-City.mmdb
    metadata
    file example.com.exampleshire-db
}

example.com {
    file example.com.db
}
```

The following configuration keeps the service available when the database cannot be loaded:
queries fall back to the default region `CN`, and the `geoip/fallback` metadata label tells
downstream plugins (and the business logic) that the answer is degraded.

```txt
. {
    geoip /opt/geoip2/db/GeoLite2-City.mmdb {
        fallback default
        default country/code CN
    }
    metadata
}
```

## Metrics

If monitoring is enabled (via the *prometheus* plugin) the following metrics are exported:

* `coredns_geoip_database_info{path, type, version}` - information about every loaded database
  file: its path, its database type and its version (build epoch). Use it to probe at runtime
  which database version is in use.
* `coredns_geoip_database_load_duration_seconds{path, result}` - histogram of the time taken to
  load a database file, with `result` being `success` or `error`.
* `coredns_geoip_fallback_total{path, domain, policy}` - counter of queries answered using a
  fallback policy because the database failed to load. This should be alerted on: a fallback
  means traffic may be routed to the default region or refused.

Every database load is logged with the database file path, its type, version (build epoch) and
provided schemas, so that logs show exactly which database file and version is in use.

## Metadata Labels

A limited set of fields will be exported as labels, all values are stored using strings **regardless of their underlying value type**, and therefore you may have to convert it back to its original type, note that numeric values are always represented in base 10.

| Label                                | Type      | Example          | Description
| :----------------------------------- | :-------- | :--------------  | :------------------
| `geoip/fallback`                     | `bool`    | `true`           | Set to `true` only when answering under a fallback policy because the database failed to load.
| `geoip/city/name`                    | `string`  | `Cambridge`      | Then city name in English language.
| `geoip/country/code`                 | `string`  | `GB`             | Country [ISO 3166-1](https://en.wikipedia.org/wiki/ISO_3166-1) code.
| `geoip/country/name`                 | `string`  | `United Kingdom` | The country name in English language.
| `geoip/country/is_in_european_union` | `bool`    | `false`          | Either `true` or `false`.
| `geoip/continent/code`               | `string`  | `EU`             | See [Continent codes](#continent-codes).
| `geoip/continent/name`               | `string`  | `Europe`         | The continent name in English language.
| `geoip/latitude`                     | `float64` | `52.2242`        | Base 10, max available precision.
| `geoip/longitude`                    | `float64` | `0.1315`         | Base 10, max available precision.
| `geoip/timezone`                     | `string`  | `Europe/London`  | The timezone.
| `geoip/postalcode`                   | `string`  | `CB4`            | The postal code.
| `geoip/subdivisions/code`            | `string`  | `ENG,TWH`        | Comma separated [ISO 3166-2](https://en.wikipedia.org/wiki/ISO_3166-2) subdivision(region) codes, e.g. first level (province), second level (state).
| `geoip/asn/number`                   | `uint`    | `396982`         | The autonomous system number.
| `geoip/asn/org`                      | `string`  | `GOOGLE-CLOUD-PLATFORM` | The autonomous system organization.

## Continent Codes

| Value | Continent (EN) |
| :---- | :------------- |
| AF    | Africa         |
| AN    | Antarctica     |
| AS    | Asia           |
| EU    | Europe         |
| NA    | North America  |
| OC    | Oceania        |
| SA    | South America  |

## Notable changes

- In CoreDNS v1.13.2, the `geoip` plugin was upgraded to use [`oschwald/geoip2-golang/v2`](https://github.com/oschwald/geoip2-golang/blob/main/MIGRATION.md), the Go library that reads and parses [`.mmdb`](https://maxmind.github.io/MaxMind-DB/) databases. It has a small, but possibly-breaking change, where the `Location.Latitude` and `Location.Longitude` structs changed from value types to pointers (`float64` → `*float64`). In `oschwald/geoip2-golang` v1, missing coordinates returned "0" (which is a [valid location](https://en.wikipedia.org/wiki/Null_Island)), and in v2 they now return an empty string "".
