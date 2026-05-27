package keycache

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// memoryCache is a sync.Map-backed Cache with TTL and a background sweeper.
type memoryCache struct {
	entries sync.Map
	cfg     *KeyCacheConfig
	stopCh  chan struct{}
	once    sync.Once
}

// cacheKey produces a stable string key for (keyID, version).
func cacheKey(keyID uuid.UUID, version int) string {
	return fmt.Sprintf("%s:%d", keyID.String(), version)
}

// NewMemoryCache creates a started MemoryCache using cfg.
func NewMemoryCache(cfg *KeyCacheConfig) Cache {
	c := &memoryCache{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
	go c.sweep()
	return c
}

// Get returns the entry for (keyID, version) if present and unexpired.
func (c *memoryCache) Get(keyID uuid.UUID, version int) (*Entry, bool) {
	v, ok := c.entries.Load(cacheKey(keyID, version))
	if !ok {
		return nil, false
	}
	e := v.(*Entry)
	if time.Now().After(e.ExpiresAt) {
		c.entries.Delete(cacheKey(keyID, version))
		return nil, false
	}
	return e, true
}

// Set stores entry under (keyID, version).
func (c *memoryCache) Set(keyID uuid.UUID, version int, entry *Entry) {
	c.entries.Store(cacheKey(keyID, version), entry)
}

// Invalidate evicts all versions for keyID by scanning for entries with the
// matching UUID prefix. This is O(n) over cached entries but n is bounded by
// MaxEntries (500) so it is acceptable.
func (c *memoryCache) Invalidate(keyID uuid.UUID) {
	prefix := keyID.String() + ":"
	c.entries.Range(func(k, _ any) bool {
		if key, ok := k.(string); ok {
			if len(key) > len(prefix) && key[:len(prefix)] == prefix {
				c.entries.Delete(k)
			}
		}
		return true
	})
}

// InvalidateAll removes every entry.
func (c *memoryCache) InvalidateAll() {
	c.entries.Range(func(k, _ any) bool {
		c.entries.Delete(k)
		return true
	})
}

// Stats returns current entry counts without modifying state.
func (c *memoryCache) Stats() CacheStats {
	total := 0
	expired := 0
	now := time.Now()
	c.entries.Range(func(_, v any) bool {
		total++
		if e, ok := v.(*Entry); ok && now.After(e.ExpiresAt) {
			expired++
		}
		return true
	})
	return CacheStats{TotalEntries: total, ExpiredEntries: expired}
}

// Stop shuts down the background sweeper. Safe to call multiple times.
func (c *memoryCache) Stop() {
	c.once.Do(func() { close(c.stopCh) })
}

// sweep periodically removes expired entries.
func (c *memoryCache) sweep() {
	ticker := time.NewTicker(c.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			c.entries.Range(func(k, v any) bool {
				if e, ok := v.(*Entry); ok && now.After(e.ExpiresAt) {
					// Zero private key material before deletion to reduce in-memory exposure window.
					e.PrivateKey = nil
					e.PublicKey = nil
					c.entries.Delete(k)
				}
				return true
			})
		}
	}
}
