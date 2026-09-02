package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestPrometheusVaultRateLimitMetrics_CountsPerVault verifies each vault gets
// its own counter, so an operator can tell which tenant is being throttled.
func TestPrometheusVaultRateLimitMetrics_CountsPerVault(t *testing.T) {
	m := NewPrometheusVaultRateLimitMetrics()

	m.RecordVaultRateLimitRejection("vault-a")
	m.RecordVaultRateLimitRejection("vault-a")
	m.RecordVaultRateLimitRejection("vault-b")

	assert.Equal(t, float64(2), testutil.ToFloat64(m.RejectionCounter().WithLabelValues("vault-a")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.RejectionCounter().WithLabelValues("vault-b")))
}

// TestNopVaultRateLimitMetrics_DoesNothing pins that the no-op recorder is safe
// to use when metrics are disabled.
func TestNopVaultRateLimitMetrics_DoesNothing(t *testing.T) {
	m := NewNopVaultRateLimitMetrics()
	m.RecordVaultRateLimitRejection("vault-a")
	// Reaching here without a panic is the assertion.
}
