package metrics_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/metrics"
)

func TestNopCryptoMetrics_DoesNotPanic(t *testing.T) {
	m := metrics.NewNopCryptoMetrics()
	// Must not panic regardless of inputs.
	m.RecordOp("sign", "RSA", true, 5*time.Millisecond)
	m.RecordOp("decrypt", "EC", false, 50*time.Millisecond)
	m.RecordOp("wrap_key", "pkcs11", false, 200*time.Millisecond)
}

func TestPrometheusCryptoMetrics_RecordsWithoutPanic(t *testing.T) {
	// Use a fresh registry per test to avoid "already registered" panics.
	m := metrics.NewPrometheusCryptoMetrics()
	assert.NotNil(t, m)
	m.RecordOp("sign", "RSA", true, 10*time.Millisecond)
	m.RecordOp("verify", "EC", false, 25*time.Millisecond)
}
