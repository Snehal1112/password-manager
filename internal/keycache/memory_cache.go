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
	k := cacheKey(keyID, version)
	v, ok := c.entries.Load(k)
	if !ok {
		return nil, false
	}
	e := v.(*Entry)
	if time.Now().After(e.ExpiresAt) {
		if val, loaded := c.entries.LoadAndDelete(k); loaded {
			// Zero private key material after atomic removal to reduce in-memory exposure window.
			if expired, ok := val.(*Entry); ok {
				expired.PrivateKey = nil
				expired.PublicKey = nil
			}
		}
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
				// LoadAndDelete atomically removes the entry; zero after removal so
				// the write is exclusive (no other goroutine holds a reference via
				// the map at this point).
				if v, loaded := c.entries.LoadAndDelete(k); loaded {
					if e, ok := v.(*Entry); ok {
						e.PrivateKey = nil
						e.PublicKey = nil
					}
				}
			}
		}
		return true
	})
}

// InvalidateAll removes every entry.
func (c *memoryCache) InvalidateAll() {
	c.entries.Range(func(k, _ any) bool {
		if v, loaded := c.entries.LoadAndDelete(k); loaded {
			// Zero private key material after atomic removal to reduce in-memory exposure window.
			if e, ok := v.(*Entry); ok {
				e.PrivateKey = nil
				e.PublicKey = nil
			}
		}
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
					if val, loaded := c.entries.LoadAndDelete(k); loaded {
						// Zero private key material after atomic removal to reduce in-memory exposure window.
						if expired, ok := val.(*Entry); ok {
							expired.PrivateKey = nil
							expired.PublicKey = nil
						}
					}
				}
				return true
			})
		}
	}
}
