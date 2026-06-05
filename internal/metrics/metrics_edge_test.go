package metrics_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/metrics"
)

// TestNewDefaultPrometheusCryptoMetrics_FirstCall verifies the metric is created
// and registered on the default registry successfully.
func TestNewDefaultPrometheusCryptoMetrics_FirstCall(t *testing.T) {
	m := metrics.NewDefaultPrometheusCryptoMetrics()
	require.NotNil(t, m)
	// Verify we can record without panic.
	m.RecordOp("sign", "RSA", false, 1*time.Millisecond)
}

// TestNewDefaultPrometheusCryptoMetrics_AlreadyRegistered verifies that calling
// NewDefaultPrometheusCryptoMetrics a second time reuses the existing collector
// rather than panicking.
func TestNewDefaultPrometheusCryptoMetrics_AlreadyRegistered(t *testing.T) {
	// First call registers the metric.
	m1 := metrics.NewDefaultPrometheusCryptoMetrics()
	assert.NotNil(t, m1)

	// Second call must not panic and must return a valid instance.
	m2 := metrics.NewDefaultPrometheusCryptoMetrics()
	assert.NotNil(t, m2)

	// Both instances should work.
	m1.RecordOp("encrypt", "ECDSA", true, 2*time.Millisecond)
	m2.RecordOp("decrypt", "RSA", false, 3*time.Millisecond)
}
