package geoip

import (
	"context"
	"strconv"

	"github.com/coredns/coredns/plugin/metadata"

	"github.com/oschwald/geoip2-golang/v2"
)

func (g GeoIP) setCountryMetadata(ctx context.Context, data *geoip2.Country) {
	setCountryMetadataValues(ctx, data.Country, data.Continent)
}

// setCountryMetadataValues sets the country and continent labels shared by the
// city and country schemas.
func setCountryMetadataValues(ctx context.Context, country geoip2.CountryRecord, continent geoip2.Continent) {
	countryName := country.Names.English
	metadata.SetValueFunc(ctx, pluginName+"/country/name", func() string {
		return countryName
	})
	continentName := continent.Names.English
	metadata.SetValueFunc(ctx, pluginName+"/continent/name", func() string {
		return continentName
	})

	countryCode := country.ISOCode
	metadata.SetValueFunc(ctx, pluginName+"/country/code", func() string {
		return countryCode
	})

	isInEurope := strconv.FormatBool(country.IsInEuropeanUnion)
	metadata.SetValueFunc(ctx, pluginName+"/country/is_in_european_union", func() string {
		return isInEurope
	})
	continentCode := continent.Code
	metadata.SetValueFunc(ctx, pluginName+"/continent/code", func() string {
		return continentCode
	})
}
