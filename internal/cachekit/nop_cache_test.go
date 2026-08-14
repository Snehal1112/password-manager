// internal/cachekit/nop_cache_test.go
package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

func TestNopCache_NeverHits(t *testing.T) {
	c := cachekit.NewNopCache[string, testValue]()

	c.Set("a", testValue{N: 1})
	_, ok := c.Get("a")
	assert.False(t, ok, "NopCache must never return a hit")

	c.Invalidate("a")
	c.InvalidateAll()
	c.Range(func(string, testValue) bool { t.Fatal("Range must never visit anything"); return true })
	c.Stop()

	assert.Equal(t, cachekit.Stats{}, c.Stats())
}

func TestNewFromConfig_EnabledReturnsRealCache(t *testing.T) {
	c := cachekit.NewFromConfig[string, testValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	defer c.Stop()

	c.Set("a", testValue{N: 1})
	_, ok := c.Get("a")
	assert.True(t, ok, "enabled config must produce a real, functioning cache")
}

func TestNewFromConfig_DisabledReturnsNopCache(t *testing.T) {
	c := cachekit.NewFromConfig[string, testValue](cachekit.Config{Enabled: false, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	defer c.Stop()

	c.Set("a", testValue{N: 1})
	_, ok := c.Get("a")
	assert.False(t, ok, "disabled config must produce a cache that never hits")
}

// TestNewFromConfig_InvalidConfigReturnsNopCache proves that an enabled but
// invalid Config (here, CleanupInterval == TTL, which Validate rejects since
// the cleanup interval must be strictly less than the TTL) does not panic
// New's background sweeper goroutine on an unusable ticker interval. Instead
// NewFromConfig must fail safe and hand back an inert NopCache.
func TestNewFromConfig_InvalidConfigReturnsNopCache(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Minute, MaxEntries: 10}
	require.Error(t, cfg.Validate(), "test setup: cfg must actually be invalid")

	c := cachekit.NewFromConfig[string, testValue](cfg)
	defer c.Stop()

	c.Set("a", testValue{N: 1})
	_, ok := c.Get("a")
	assert.False(t, ok, "invalid config must produce a cache that never hits, not a panic")
}

var _ cachekit.Interface[string, testValue] = (*cachekit.NopCache[string, testValue])(nil)
