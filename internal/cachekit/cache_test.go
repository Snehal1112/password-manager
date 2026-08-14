// internal/cachekit/cache_test.go
package cachekit_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

// testValue is a minimal Cloneable+Zeroable value for exercising Cache[K,V]
// without depending on any real domain type.
//
// zeroed is an *atomic.Bool rather than a plain *bool: Zero() is called from
// the background sweep goroutine, and tests observe it from the main test
// goroutine after a time.Sleep. A plain bool has no happens-before edge
// between that write and this read, so the race detector (correctly) flags
// it as a data race; atomic.Bool provides the required synchronization.
type testValue struct {
	N      int
	zeroed *atomic.Bool // optional: set by tests that need to observe Zero() calls
}

func (v testValue) Clone() testValue { return testValue{N: v.N, zeroed: v.zeroed} }
func (v testValue) Zero() {
	if v.zeroed != nil {
		v.zeroed.Store(true)
	}
}

func newCache(t *testing.T, cfg cachekit.Config) *cachekit.Cache[string, testValue] {
	t.Helper()
	c := cachekit.New[string, testValue](cfg)
	t.Cleanup(c.Stop)
	return c
}

func TestCache_SetThenGet_Hit(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	got, ok := c.Get("a")
	require.True(t, ok)
	assert.Equal(t, 1, got.N)
}

func TestCache_Get_MissForUnknownKey(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	_, ok := c.Get("missing")
	assert.False(t, ok)
}

func TestCache_Get_MissAfterTTLExpiry(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: 20 * time.Millisecond, CleanupInterval: 5 * time.Millisecond, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	time.Sleep(60 * time.Millisecond)

	_, ok := c.Get("a")
	assert.False(t, ok, "entry must have expired")
}

func TestCache_GetReturnsClone_MutatingResultDoesNotAffectCache(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	got, _ := c.Get("a")
	got.N = 999 // mutate the returned value

	again, _ := c.Get("a")
	assert.Equal(t, 1, again.N, "mutating a Get result must not affect the stored entry")
}

func TestCache_Invalidate_RemovesEntry(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})
	c.Invalidate("a")

	_, ok := c.Get("a")
	assert.False(t, ok)
}

func TestCache_InvalidateAll_RemovesEverything(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})
	c.Set("b", testValue{N: 2})
	c.InvalidateAll()

	_, ok := c.Get("a")
	assert.False(t, ok)
	_, ok = c.Get("b")
	assert.False(t, ok)
}

func TestCache_Invalidate_CallsZeroOnRemovedValue(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	var zeroed atomic.Bool
	c.Set("a", testValue{N: 1, zeroed: &zeroed})

	c.Invalidate("a")

	assert.True(t, zeroed.Load(), "Invalidate must call Zero() on the removed value")
}

func TestCache_Set_OverwriteCallsZeroOnDisplacedValue(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	var zeroed atomic.Bool
	c.Set("a", testValue{N: 1, zeroed: &zeroed})

	c.Set("a", testValue{N: 2}) // overwrite the same key with a new value

	assert.True(t, zeroed.Load(), "Set overwriting an existing key must call Zero() on the displaced value")

	got, ok := c.Get("a")
	require.True(t, ok)
	assert.Equal(t, 2, got.N, "the new value must be the one actually stored")
}

func TestCache_TTLSweep_CallsZeroOnExpiredValue(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: 15 * time.Millisecond, CleanupInterval: 5 * time.Millisecond, MaxEntries: 10})
	var zeroed atomic.Bool
	c.Set("a", testValue{N: 1, zeroed: &zeroed})

	time.Sleep(60 * time.Millisecond) // let the background sweep run at least once

	assert.True(t, zeroed.Load(), "the background TTL sweep must call Zero() on expired entries")
}

func TestCache_Range_VisitsEveryLiveEntry(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})
	c.Set("b", testValue{N: 2})

	seen := map[string]int{}
	c.Range(func(k string, v testValue) bool {
		seen[k] = v.N
		return true
	})

	assert.Equal(t, map[string]int{"a": 1, "b": 2}, seen)
}

func TestCache_Stats_CountsTotalAndExpired(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Hour, CleanupInterval: time.Minute, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	stats := c.Stats()
	assert.Equal(t, 1, stats.TotalEntries)
	assert.Equal(t, 0, stats.ExpiredEntries)
}

func TestCache_Stop_IdempotentDouble(t *testing.T) {
	c := cachekit.New[string, testValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Stop()
	c.Stop() // must not panic
}

func TestCache_Set_EvictsLeastRecentlyTouchedWhenOverMaxEntries(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 2})

	c.Set("a", testValue{N: 1})
	c.Set("b", testValue{N: 2})
	// Touch "a" so it's more recently used than "b".
	_, _ = c.Get("a")

	c.Set("c", testValue{N: 3}) // pushes count to 3, over the cap of 2

	// "b" was least-recently-touched and must be evicted.
	_, ok := c.Get("b")
	assert.False(t, ok, "least-recently-touched entry must be evicted")

	_, ok = c.Get("a")
	assert.True(t, ok, "recently-touched entry must survive")
	_, ok = c.Get("c")
	assert.True(t, ok, "just-inserted entry must survive")
}

func TestCache_MaxEntriesZero_NeverEvicts(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	for i := 0; i < 50; i++ {
		c.Set(string(rune('a'+i%26))+string(rune(i)), testValue{N: i})
	}
	stats := c.Stats()
	assert.Equal(t, 50, stats.TotalEntries, "MaxEntries=0 must mean unbounded")
}

// Compile-time interface compliance.
var _ cachekit.Interface[string, testValue] = (*cachekit.Cache[string, testValue])(nil)
