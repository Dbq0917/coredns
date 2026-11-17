package geoip

import (
	"strconv"
	"time"

	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// databaseInfo exposes the path, type and version (build epoch) of every loaded
	// database, allowing operators to probe at runtime which database version is in use.
	databaseInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "database_info",
		Help:      "Information about the loaded geoip database files, the value is always 1.",
	}, []string{"path", "type", "version"})
	// databaseLoadDuration measures how long loading a database file takes.
	databaseLoadDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "database_load_duration_seconds",
		Help:      "The time taken to load a geoip database file.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
	}, []string{"path", "result"})
	// fallbackTotal counts queries answered using a fallback policy because the
	// configured database failed to load. It should be alerted on: a fallback
	// means traffic may be routed to the default region or refused.
	fallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "fallback_total",
		Help:      "The count of queries served using a fallback policy because the geoip database failed to load.",
	}, []string{"path", "domain", "policy"})
)

// reportLoad records the load duration and, on success, the database version info.
func reportLoad(path string, d *db, loadErr error, elapsed time.Duration) {
	result := "success"
	if loadErr != nil {
		result = "error"
	}
	databaseLoadDuration.WithLabelValues(path, result).Observe(elapsed.Seconds())
	if d != nil {
		databaseInfo.WithLabelValues(path, d.meta.DatabaseType, strconv.FormatUint(uint64(d.meta.BuildEpoch), 10)).Set(1)
	}
}

// reportFallback counts a query served under a fallback policy.
func (g *dbGroup) reportFallback() {
	fallbackTotal.WithLabelValues(g.dbPath, g.domain, g.fallback.String()).Inc()
}
