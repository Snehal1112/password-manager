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

func TestEntry_Clone_IndependentCopy(t *testing.T) {
	e := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: "original"},
		KeyType:    "RSA",
		Version:    1,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	clone := e.Clone()

	clone.KeyType = "ECDSA"
	assert.Equal(t, "RSA", e.KeyType, "mutating the clone must not affect the original")
	assert.Equal(t, keycache.PEMKey{PEM: "original"}, clone.PrivateKey)
}

func TestEntry_Zero_ClearsKeyMaterial(t *testing.T) {
	e := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: "secret"},
		PublicKey:  keycache.PEMKey{PEM: "public"},
	}
	e.Zero()
	assert.Nil(t, e.PrivateKey)
	assert.Nil(t, e.PublicKey)
}

// TestMemoryCache_InvalidateAll verifies that InvalidateAll clears every entry.
func TestMemoryCache_InvalidateAll(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	c := keycache.NewCache(cfg)
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

// TestMemoryCache_Stats_ExpiredEntries checks that Stats counts expired
// entries correctly.
//
// Deviation from the task brief: cachekit.Cache.Set always computes its
// internal expiry as now+cfg.TTL and never reads the stored value's own
// ExpiresAt field (see internal/cachekit/cache.go's Set), so backdating
// Entry.ExpiresAt before Set — the pre-migration memoryCache's mechanism
// for simulating an already-expired entry — no longer has any effect. This
// test instead drives real expiry with a short TTL and a sleep, the same
// pattern TestMemoryCache_TTLExpiry already uses. CleanupInterval is kept
// long so the background sweeper hasn't purged the entry before Stats()
// observes it as present-but-expired.
func TestMemoryCache_Stats_ExpiredEntries(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 10 * time.Millisecond, CleanupInterval: time.Hour, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id := uuid.New()
	c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1})

	time.Sleep(50 * time.Millisecond)

	stats := c.Stats()
	assert.Equal(t, 1, stats.TotalEntries)
	assert.Equal(t, 1, stats.ExpiredEntries)
}

// TestMemoryCache_Get_ExpiredZeroesKeys checks that Get reports a miss once
// an entry's TTL has elapsed.
//
// Deviation from the task brief: beyond the same backdated-ExpiresAt issue
// TestMemoryCache_Stats_ExpiredEntries hits (see its comment), Cloneable's
// contract means cachekit.Cache.Set always stores value.Clone(), never the
// caller's original pointer (internal/cachekit/cachekit.go's Cloneable doc:
// "the cache never hands out or accepts a pointer a caller could mutate").
// So the entry this test's caller holds is never the object cachekit's
// remove() actually zeroes on expiry — asserting entry.PrivateKey/PublicKey
// are nil on that original pointer can never observe the zero, no matter
// how expiry is triggered. That guarantee is covered elsewhere instead:
// TestEntry_Zero_ClearsKeyMaterial proves Zero() itself clears the fields,
// and cachekit's own TestCache_TTLSweep_CallsZeroOnExpiredValue proves
// Zero() fires on TTL expiry. This test keeps the half that remains
// observable through keycache's public Cache interface: a miss after TTL.
func TestMemoryCache_Get_ExpiredZeroesKeys(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 10 * time.Millisecond, CleanupInterval: time.Hour, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id := uuid.New()
	c.Set(id, 1, &keycache.Entry{
		KeyType:    "RSA",
		Version:    1,
		PrivateKey: []byte("private-key-data"),
		PublicKey:  []byte("public-key-data"),
	})

	time.Sleep(50 * time.Millisecond)

	_, hit := c.Get(id, 1)
	assert.False(t, hit, "expired entry must not be returned")
}

// TestMemoryCache_Stop_IdempotentDouble verifies Stop can be called multiple times.
func TestMemoryCache_Stop_IdempotentDouble(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Minute, MaxEntries: 10}
	c := keycache.NewCache(cfg)
	c.Stop()
	c.Stop() // Must not panic.
}
