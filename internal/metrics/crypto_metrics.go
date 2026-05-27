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

// cryptoHistogramOpts is the single definition of the histogram descriptor.
var cryptoHistogramOpts = prometheus.HistogramOpts{
	Name: "rocketvault_crypto_op_duration_seconds",
	Help: "Latency of key cryptographic operations.",
	Buckets: []float64{
		0.001, 0.005, 0.010, 0.025,
		0.050, 0.100, 0.250, 0.500,
	},
}

// cryptoHistogramLabels are the label names for the histogram.
var cryptoHistogramLabels = []string{"op", "key_type", "cache_hit"}

// NewPrometheusCryptoMetrics creates a PrometheusCryptoMetrics using a new
// (non-default) Prometheus registry so tests do not conflict.
func NewPrometheusCryptoMetrics() *PrometheusCryptoMetrics {
	reg := prometheus.NewRegistry()
	h := prometheus.NewHistogramVec(cryptoHistogramOpts, cryptoHistogramLabels)
	reg.MustRegister(h)
	return &PrometheusCryptoMetrics{histogram: h}
}

// NewDefaultPrometheusCryptoMetrics registers the histogram on the default
// Prometheus registry. Safe to call more than once — returns the existing
// collector if the metric is already registered (e.g. in integration tests that
// construct the DI container multiple times).
func NewDefaultPrometheusCryptoMetrics() *PrometheusCryptoMetrics {
	h := prometheus.NewHistogramVec(cryptoHistogramOpts, cryptoHistogramLabels)
	if err := prometheus.Register(h); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			h = are.ExistingCollector.(*prometheus.HistogramVec)
		} else {
			panic(err)
		}
	}
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
