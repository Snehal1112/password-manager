// Package metrics provides Prometheus instrumentation for cryptographic operations.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CryptoMetrics records latency for key crypto operations.
type CryptoMetrics interface {
	// RecordOp observes one operation's duration.
	// op: sign|verify|encrypt|decrypt|wrap_key|unwrap_key
	// keyType: RSA|ECDSA|ES256K|oct|pkcs11
	// cacheHit: whether the key material was served from cache
	RecordOp(op, keyType string, cacheHit bool, dur time.Duration)
}

// PrometheusCryptoMetrics records operations via a Prometheus HistogramVec.
type PrometheusCryptoMetrics struct {
	histogram *prometheus.HistogramVec
}

// NewPrometheusCryptoMetrics creates a PrometheusCryptoMetrics using a new
// (non-default) Prometheus registry so tests do not conflict.
func NewPrometheusCryptoMetrics() *PrometheusCryptoMetrics {
	reg := prometheus.NewRegistry()
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rocketvault_crypto_op_duration_seconds",
		Help: "Latency of key cryptographic operations.",
		Buckets: []float64{
			0.001, 0.005, 0.010, 0.025,
			0.050, 0.100, 0.250, 0.500,
		},
	}, []string{"op", "key_type", "cache_hit"})
	reg.MustRegister(h)
	return &PrometheusCryptoMetrics{histogram: h}
}

// NewDefaultPrometheusCryptoMetrics registers the histogram on the default
// Prometheus registry. Call once at application startup via the DI container.
func NewDefaultPrometheusCryptoMetrics() *PrometheusCryptoMetrics {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rocketvault_crypto_op_duration_seconds",
		Help: "Latency of key cryptographic operations.",
		Buckets: []float64{
			0.001, 0.005, 0.010, 0.025,
			0.050, 0.100, 0.250, 0.500,
		},
	}, []string{"op", "key_type", "cache_hit"})
	prometheus.MustRegister(h)
	return &PrometheusCryptoMetrics{histogram: h}
}

// RecordOp observes dur under the labels {op, keyType, cacheHit}.
func (p *PrometheusCryptoMetrics) RecordOp(op, keyType string, cacheHit bool, dur time.Duration) {
	hit := "false"
	if cacheHit {
		hit = "true"
	}
	p.histogram.WithLabelValues(op, keyType, hit).Observe(dur.Seconds())
}
