package sign

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Result and error codes are stable values intended for logs, alerts, and dashboards.
const (
	ResultSuccess = "success"

	ErrorCodeKeyLoad              = "key_load_error"
	ErrorCodeSigning              = "signing_error"
	ErrorCodeWrite                = "write_error"
	ErrorCodeSignedZoneMissing    = "signed_zone_missing"
	ErrorCodeSignatureExpired     = "signature_expired"
	ErrorCodeSignatureNotYetValid = "signature_not_yet_valid"
	ErrorCodeSignatureMissing     = "signature_missing"
	ErrorCodeResign               = "resign_required"
)

var (
	keyLoads = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "key_loads_total",
		Help:      "Total number of key directory load attempts by result.",
	}, []string{"zone", "result"})
	keyLoadLastError = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "key_load_last_error_timestamp_seconds",
		Help:      "Unix timestamp of the last failed key directory load.",
	}, []string{"zone"})
	keyLoadLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "key_load_last_success_timestamp_seconds",
		Help:      "Unix timestamp of the last successful key directory load.",
	}, []string{"zone"})
	activeKey = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "active_key_key_tag",
		Help:      "Key tag of the currently selected directory-backed signing key.",
	}, []string{"zone"})
	signOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "operations_total",
		Help:      "Total number of signing operations by result.",
	}, []string{"zone", "result"})
	signLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "last_success_timestamp_seconds",
		Help:      "Unix timestamp of the last successful zone signing operation.",
	}, []string{"zone"})
	signReason = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "resign_reasons_total",
		Help:      "Total number of resign checks by reason.",
	}, []string{"zone", "reason"})
	signEnabled = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "sign",
		Name:      "enabled",
		Help:      "Whether the signer is enabled for the zone.",
	}, []string{"zone"})
)
