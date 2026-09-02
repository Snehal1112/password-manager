package metrics

import "github.com/prometheus/client_golang/prometheus"

// VaultRateLimitMetrics counts requests rejected by the per-vault rate limiter.
// It answers the operational question the limiter creates: which tenant is
// being throttled, and how often.
type VaultRateLimitMetrics interface {
	// RecordVaultRateLimitRejection counts one rejected request for a vault.
	RecordVaultRateLimitRejection(vaultID string)
}

// vaultRateLimitCounterOpts is the single definition of the counter descriptor.
var vaultRateLimitCounterOpts = prometheus.CounterOpts{
	Name: "rocketvault_vault_rate_limit_exceeded_total",
	Help: "Requests rejected by the per-vault rate limiter, by vault.",
}

// vaultRateLimitCounterLabels are the label names for the counter.
var vaultRateLimitCounterLabels = []string{"vault"}

// PrometheusVaultRateLimitMetrics counts rejections in a Prometheus CounterVec.
type PrometheusVaultRateLimitMetrics struct {
	rejections *prometheus.CounterVec
}

// NewPrometheusVaultRateLimitMetrics creates a recorder on a new (non-default)
// Prometheus registry so tests do not conflict.
func NewPrometheusVaultRateLimitMetrics() *PrometheusVaultRateLimitMetrics {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounterVec(vaultRateLimitCounterOpts, vaultRateLimitCounterLabels)
	reg.MustRegister(c)
	return &PrometheusVaultRateLimitMetrics{rejections: c}
}

// NewDefaultPrometheusVaultRateLimitMetrics registers the counter on the default
// Prometheus registry, so it is exported by the /metrics endpoint. Safe to call
// more than once — returns the existing collector if already registered.
func NewDefaultPrometheusVaultRateLimitMetrics() *PrometheusVaultRateLimitMetrics {
	c := prometheus.NewCounterVec(vaultRateLimitCounterOpts, vaultRateLimitCounterLabels)
	if err := prometheus.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			c = are.ExistingCollector.(*prometheus.CounterVec)
		} else {
			panic(err)
		}
	}
	return &PrometheusVaultRateLimitMetrics{rejections: c}
}

// RecordVaultRateLimitRejection increments the counter for vaultID.
func (p *PrometheusVaultRateLimitMetrics) RecordVaultRateLimitRejection(vaultID string) {
	p.rejections.WithLabelValues(vaultID).Inc()
}

// RejectionCounter exposes the counter for assertions in tests.
func (p *PrometheusVaultRateLimitMetrics) RejectionCounter() *prometheus.CounterVec {
	return p.rejections
}

// NopVaultRateLimitMetrics is a no-op recorder used when metrics are disabled.
type NopVaultRateLimitMetrics struct{}

// NewNopVaultRateLimitMetrics returns a NopVaultRateLimitMetrics.
func NewNopVaultRateLimitMetrics() VaultRateLimitMetrics { return &NopVaultRateLimitMetrics{} }

// RecordVaultRateLimitRejection does nothing.
func (n *NopVaultRateLimitMetrics) RecordVaultRateLimitRejection(_ string) {}
