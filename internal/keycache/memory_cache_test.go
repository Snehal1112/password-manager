package keycache_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/keycache"
)

func TestNewCache_GetSetInvalidate(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id := uuid.New()
	entry := &keycache.Entry{KeyType: "RSA", Version: 1}

	_, hit := c.Get(id, 1)
	assert.False(t, hit)

	c.Set(id, 1, entry)
	got, hit := c.Get(id, 1)
	require.True(t, hit)
	assert.Equal(t, "RSA", got.KeyType)

	_, hit = c.Get(id, 2)
	assert.False(t, hit, "different version is a miss")

	c.Set(id, 2, &keycache.Entry{KeyType: "RSA", Version: 2})
	c.Invalidate(id)
	_, hit = c.Get(id, 1)
	assert.False(t, hit, "invalidate must remove all versions")
	_, hit = c.Get(id, 2)
	assert.False(t, hit)
}

func TestNopCache_NeverHits(t *testing.T) {
	c := keycache.NewNopCache()
	id := uuid.New()

	_, hit := c.Get(id, 1)
	assert.False(t, hit)

	c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1})
	_, hit = c.Get(id, 1)
	assert.False(t, hit, "nop cache must never return a hit")

	c.Invalidate(id)
	c.InvalidateAll()
	c.Stop()

	stats := c.Stats()
	assert.Equal(t, 0, stats.TotalEntries)
}

func TestMemoryCache_GetSetInvalidate(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id := uuid.New()
	entry := &keycache.Entry{KeyType: "RSA", Version: 1}

	// miss before set
	_, hit := c.Get(id, 1)
	assert.False(t, hit)

	// hit after set
	c.Set(id, 1, entry)
	got, hit := c.Get(id, 1)
	require.True(t, hit)
	assert.Equal(t, "RSA", got.KeyType)

	// different version is a miss
	_, hit = c.Get(id, 2)
	assert.False(t, hit)

	// invalidate removes all versions
	c.Set(id, 2, &keycache.Entry{KeyType: "RSA", Version: 2})
	c.Invalidate(id)
	_, hit = c.Get(id, 1)
	assert.False(t, hit)
	_, hit = c.Get(id, 2)
	assert.False(t, hit)
}

func TestMemoryCache_TTLExpiry(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 50 * time.Millisecond, CleanupInterval: 10 * time.Millisecond, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id := uuid.New()
	c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1})

	_, hit := c.Get(id, 1)
	require.True(t, hit)

	time.Sleep(100 * time.Millisecond)

	_, hit = c.Get(id, 1)
	assert.False(t, hit, "entry should have expired")
}

func TestMemoryCache_Stats(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id1, id2 := uuid.New(), uuid.New()
	c.Set(id1, 1, &keycache.Entry{KeyType: "RSA", Version: 1})
	c.Set(id2, 1, &keycache.Entry{KeyType: "EC", Version: 1})

	stats := c.Stats()
	assert.Equal(t, 2, stats.TotalEntries)
}

func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 1000}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	ids := make([]uuid.UUID, 50)
	for i := range ids {
		ids[i] = uuid.New()
	}

	done := make(chan struct{})
	for g := 0; g < 10; g++ {
		go func() {
			for i, id := range ids {
				c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1})
				c.Get(id, 1)
				if i%5 == 0 {
					c.Invalidate(id)
				}
			}
			done <- struct{}{}
		}()
	}
	for g := 0; g < 10; g++ {
		<-done
	}
}
