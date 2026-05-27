package metrics

import "time"

// NopCryptoMetrics is a no-op CryptoMetrics used in tests and when metrics
// are disabled.
type NopCryptoMetrics struct{}

// NewNopCryptoMetrics returns a NopCryptoMetrics.
func NewNopCryptoMetrics() CryptoMetrics { return &NopCryptoMetrics{} }

// RecordOp does nothing.
func (n *NopCryptoMetrics) RecordOp(_, _ string, _ bool, _ time.Duration) {}
