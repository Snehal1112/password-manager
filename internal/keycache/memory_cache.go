// internal/keycache/memory_cache.go
package keycache

import (
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/cachekit"
)

// keyCacheKey is the compound key for one (keyID, version) entry.
type keyCacheKey struct {
	ID      uuid.UUID
	Version int
}

// cacheImpl adapts cachekit's generic Interface to keycache's domain-specific
// Cache interface (uuid.UUID + int args, not a single struct key).
type cacheImpl struct {
	core cachekit.Interface[keyCacheKey, *Entry]
}

// NewCache creates a Cache from cfg. Always returns a usable Cache: a real
// one when cfg.Enabled, a no-op one otherwise.
func NewCache(cfg cachekit.Config) Cache {
	return &cacheImpl{core: cachekit.NewFromConfig[keyCacheKey, *Entry](cfg)}
}

// NewCacheWithL2 creates a Cache backed by a TieredCache: cfg's in-process
// cache as L1, l2 as the shared Rocket-mem tier (l2TTL is that tier's own
// entry lifetime). Uses entryCodec (not the generic EncryptedJSONCodec) so
// Entry's interface-typed PrivateKey/PublicKey fields round-trip correctly
// -- see l2_codec.go. Used only when cache.rocket_mem is enabled;
// NewCache's behavior is unchanged.
//
// Mirrors cachekit.NewFromConfig's own enabled/valid branching exactly: if
// this domain's own cache is disabled or its config is invalid, this falls
// back to the plain NewCache path instead of building a live TieredCache --
// an operator's cache.keys.enabled: false must not be silently overridden by
// cache.rocket_mem.enabled: true.
func NewCacheWithL2(cfg cachekit.Config, l2 cachekit.L2, l2TTL time.Duration) Cache {
	if !cfg.Enabled || cfg.Validate() != nil {
		return NewCache(cfg)
	}
	l1 := cachekit.NewFromConfig[keyCacheKey, *Entry](cfg)
	codec := entryCodec{encrypt: common.EncryptSecret, decrypt: common.DecryptSecret}
	return &cacheImpl{
		core: cachekit.NewTieredCache[keyCacheKey, *Entry](l1, l2, codec, keyCacheKeyCodec(), "rocketvault:key:", l2TTL),
	}
}

// NewNopCache returns a Cache that never hits, for explicit use outside
// config-driven construction (e.g. PKCS#11 key paths that never cache).
func NewNopCache() Cache {
	return &cacheImpl{core: cachekit.NewNopCache[keyCacheKey, *Entry]()}
}

func (c *cacheImpl) Get(keyID uuid.UUID, version int) (*Entry, bool) {
	return c.core.Get(keyCacheKey{ID: keyID, Version: version})
}

func (c *cacheImpl) Set(keyID uuid.UUID, version int, entry *Entry) {
	c.core.Set(keyCacheKey{ID: keyID, Version: version}, entry)
}

// Invalidate evicts every version for keyID. cachekit has no notion of
// compound keys, so this enumerates entries and matches on ID — O(n) over
// cached entries, but n is bounded by MaxEntries (default 500), same
// reasoning the pre-migration implementation already relied on.
func (c *cacheImpl) Invalidate(keyID uuid.UUID) {
	var toRemove []keyCacheKey
	c.core.Range(func(k keyCacheKey, _ *Entry) bool {
		if k.ID == keyID {
			toRemove = append(toRemove, k)
		}
		return true
	})
	for _, k := range toRemove {
		c.core.Invalidate(k)
	}
}

func (c *cacheImpl) InvalidateAll() {
	c.core.InvalidateAll()
}

func (c *cacheImpl) Stats() CacheStats {
	s := c.core.Stats()
	return CacheStats{TotalEntries: s.TotalEntries, ExpiredEntries: s.ExpiredEntries}
}

func (c *cacheImpl) Stop() {
	c.core.Stop()
}
