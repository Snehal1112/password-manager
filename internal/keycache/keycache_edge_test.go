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
		PrivateKey: keycache.PEMKey{PEM: []byte("original")},
		KeyType:    "RSA",
		Version:    1,
	}
	clone := e.Clone()

	clone.KeyType = "ECDSA"
	assert.Equal(t, "RSA", e.KeyType, "mutating the clone must not affect the original")
	assert.Equal(t, keycache.PEMKey{PEM: []byte("original")}, clone.PrivateKey)
}

// TestEntry_Clone_PEMBytesAreIndependent proves Clone deep-copies the PEMKey
// byte slice rather than sharing the original's backing array — required
// because []byte is mutable, unlike the string PEMKey used to wrap: mutating
// (or Zero()-ing) one clone must never corrupt another clone's view of the
// same logical entry.
func TestEntry_Clone_PEMBytesAreIndependent(t *testing.T) {
	e := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: []byte("original")},
		PublicKey:  keycache.PEMKey{PEM: []byte("public")},
	}
	clone := e.Clone()

	clonePriv := clone.PrivateKey.(keycache.PEMKey)
	for i := range clonePriv.PEM {
		clonePriv.PEM[i] = 'X'
	}

	origPriv := e.PrivateKey.(keycache.PEMKey)
	assert.Equal(t, "original", string(origPriv.PEM), "mutating the clone's PEM bytes must not affect the original's backing array")

	clone.Zero()
	origPriv = e.PrivateKey.(keycache.PEMKey)
	assert.Equal(t, "original", string(origPriv.PEM), "zeroing the clone must not affect the original")
}

func TestEntry_Zero_ClearsKeyMaterial(t *testing.T) {
	e := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: []byte("secret")},
		PublicKey:  keycache.PEMKey{PEM: []byte("public")},
	}
	e.Zero()
	assert.Nil(t, e.PrivateKey)
	assert.Nil(t, e.PublicKey)
}

// TestEntry_Zero_OverwritesPEMBytes proves Zero() scrubs the underlying byte
// slice in place — not just drops the Entry's reference to it — so a
// separate holder of the same backing array (e.g. a concurrent reader that
// captured the PEMKey before eviction) sees the plaintext overwritten rather
// than merely unreachable from this Entry.
func TestEntry_Zero_OverwritesPEMBytes(t *testing.T) {
	pemBytes := []byte("top-secret-private-key-pem")
	e := &keycache.Entry{PrivateKey: keycache.PEMKey{PEM: pemBytes}}

	e.Zero()

	for i, b := range pemBytes {
		assert.Equal(t, byte(0), b, "byte %d of the original backing array must be zeroed, not just dereferenced", i)
	}
}

// TestMemoryCache_InvalidateAll verifies that InvalidateAll clears every entry.
func TestMemoryCache_InvalidateAll(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id1 := uuid.New()
	id2 := uuid.New()

	c.Set(id1, 1, &keycache.Entry{KeyType: "RSA", Version: 1})
	c.Set(id2, 1, &keycache.Entry{KeyType: "EC", Version: 1})

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
// pattern TestMemoryCache_TTLExpiry already uses.
//
// The config can no longer disable the sweeper via an out-of-spec
// CleanupInterval (e.g. CleanupInterval > TTL) to hold the entry present-but-
// expired indefinitely: cachekit.NewFromConfig now calls Config.Validate
// first, which rejects CleanupInterval >= TTL, and would silently fall back
// to a NopCache that never stores anything — defeating this test instead of
// failing it loudly. So this uses a Validate-legal config (CleanupInterval <
// TTL) and instead times the read to land inside the real, bounded window
// between TTL expiry and the next scheduled sweep tick: expiry at 150ms,
// sweep ticks at 100ms (too early, not yet expired) and 200ms (removes it),
// so 175ms lands inside the ~50ms present-but-expired window with margin on
// both sides.
func TestMemoryCache_Stats_ExpiredEntries(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 150 * time.Millisecond, CleanupInterval: 100 * time.Millisecond, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id := uuid.New()
	c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1})

	time.Sleep(175 * time.Millisecond)

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
//
// The config must satisfy cachekit.Config.Validate (CleanupInterval < TTL):
// NewFromConfig now validates before constructing a real cache, and an
// invalid config would silently produce a NopCache that always misses,
// making this assertion pass for the wrong reason instead of exercising
// real TTL expiry.
func TestMemoryCache_Get_ExpiredZeroesKeys(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 10 * time.Millisecond, CleanupInterval: 5 * time.Millisecond, MaxEntries: 100}
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
