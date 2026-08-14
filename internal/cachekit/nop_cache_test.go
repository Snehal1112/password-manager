// internal/cachekit/nop_cache_test.go
package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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

var _ cachekit.Interface[string, testValue] = (*cachekit.NopCache[string, testValue])(nil)
