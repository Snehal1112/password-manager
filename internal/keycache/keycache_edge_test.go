package keycache_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/keycache"
)

// TestDefaultKeyCacheConfig checks that the defaults are sane.
func TestDefaultKeyCacheConfig(t *testing.T) {
	cfg := keycache.DefaultKeyCacheConfig()
	require.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 60*time.Second, cfg.TTL)
	assert.Equal(t, 500, cfg.MaxEntries)
	assert.Equal(t, 30*time.Second, cfg.CleanupInterval)
}

// TestMemoryCache_InvalidateAll verifies that InvalidateAll clears every entry.
func TestMemoryCache_InvalidateAll(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Minute,
	}
	c := keycache.NewMemoryCache(cfg)
	defer c.Stop()

	id1 := uuid.New()
	id2 := uuid.New()
	exp := time.Now().Add(5 * time.Minute)

	c.Set(id1, 1, &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: exp})
	c.Set(id2, 1, &keycache.Entry{KeyType: "EC", Version: 1, ExpiresAt: exp})

	stats := c.Stats()
	require.Equal(t, 2, stats.TotalEntries)

	c.InvalidateAll()

	stats = c.Stats()
	assert.Equal(t, 0, stats.TotalEntries, "all entries must be removed by InvalidateAll")

	_, hit := c.Get(id1, 1)
	assert.False(t, hit)
	_, hit = c.Get(id2, 1)
	assert.False(t, hit)
}

// TestMemoryCache_Stats_ExpiredEntries checks that Stats counts expired entries correctly.
func TestMemoryCache_Stats_ExpiredEntries(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Hour, // Disable sweeper interference.
	}
	c := keycache.NewMemoryCache(cfg)
	defer c.Stop()

	id := uuid.New()
	// Store an already-expired entry directly.
	c.Set(id, 1, &keycache.Entry{
		KeyType:   "RSA",
		Version:   1,
		ExpiresAt: time.Now().Add(-1 * time.Second),
	})

	stats := c.Stats()
	assert.Equal(t, 1, stats.TotalEntries)
	assert.Equal(t, 1, stats.ExpiredEntries)
}

// TestMemoryCache_Get_ExpiredZeroesKeys checks that Get zeroes key material on expiry.
func TestMemoryCache_Get_ExpiredZeroesKeys(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Hour,
	}
	c := keycache.NewMemoryCache(cfg)
	defer c.Stop()

	id := uuid.New()
	privKey := []byte("private-key-data")
	pubKey := []byte("public-key-data")
	entry := &keycache.Entry{
		KeyType:    "RSA",
		Version:    1,
		ExpiresAt:  time.Now().Add(-1 * time.Millisecond),
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}
	c.Set(id, 1, entry)

	// Get must return a miss and zero the entry's key material.
	_, hit := c.Get(id, 1)
	assert.False(t, hit, "expired entry must not be returned")

	// The entry pointer's keys should now be nil.
	assert.Nil(t, entry.PrivateKey, "PrivateKey must be zeroed after expiry")
	assert.Nil(t, entry.PublicKey, "PublicKey must be zeroed after expiry")
}

// TestMemoryCache_Stop_IdempotentDouble verifies Stop can be called multiple times.
func TestMemoryCache_Stop_IdempotentDouble(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             time.Minute,
		MaxEntries:      10,
		CleanupInterval: time.Minute,
	}
	c := keycache.NewMemoryCache(cfg)
	c.Stop()
	c.Stop() // Must not panic.
}
