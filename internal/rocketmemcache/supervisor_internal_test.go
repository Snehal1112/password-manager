// White-box tests for the unexported backoff helpers used by RunSupervisor
// (supervisor.go). Split from supervisor_test.go, which is package
// rocketmemcache_test (black-box, matching client_test.go's style) and so
// cannot see unexported functions -- addJitter and growBackoff need direct
// access to be tested deterministically.
package rocketmemcache

import (
	"testing"
	"time"
)

// TestGrowBackoff_CapsAtMax proves repeated growth never exceeds max and
// settles at exactly max once the multiplier would otherwise overshoot it.
func TestGrowBackoff_CapsAtMax(t *testing.T) {
	current := 10 * time.Millisecond
	max := 100 * time.Millisecond

	for i := 0; i < 20; i++ {
		current = growBackoff(current, 2.0, max)
		if current > max {
			t.Fatalf("growBackoff exceeded max: got %v, max %v", current, max)
		}
	}
	if current != max {
		t.Fatalf("expected growBackoff to settle at max after repeated growth, got %v", current)
	}
}

// TestAddJitter_WithinExpectedRange proves addJitter always returns >= d and
// < d*1.3 (up to 30% additive jitter, as documented on addJitter).
func TestAddJitter_WithinExpectedRange(t *testing.T) {
	d := 100 * time.Millisecond
	upper := time.Duration(float64(d) * 1.30001) // small epsilon for float rounding

	for i := 0; i < 50; i++ {
		got := addJitter(d)
		if got < d {
			t.Fatalf("addJitter returned less than base duration: got %v, base %v", got, d)
		}
		if got > upper {
			t.Fatalf("addJitter exceeded expected 30%% ceiling: got %v, upper bound %v", got, upper)
		}
	}
}
