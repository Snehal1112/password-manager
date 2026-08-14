// internal/cachekit/cache.go
package cachekit

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// cacheEntry holds one stored value plus its expiry and last-access time.
// lastAccess is updated via atomic store on every Get so read-path
// bookkeeping never takes a lock.
type cacheEntry[V any] struct {
	value      V
	expiresAt  time.Time
	lastAccess int64 // unix nanoseconds, atomic
}

// Cache is a generic, sync.Map-backed TTL+LRU cache. Zero value is not
// usable; construct with New.
type Cache[K comparable, V Cloneable[V]] struct {
	data     sync.Map // K -> *cacheEntry[V]
	count    atomic.Int64
	cfg      Config
	evictMu  sync.Mutex
	stopCh   chan struct{}
	stopOnce sync.Once
}

// New creates a started Cache using cfg. The background TTL sweep begins
// immediately; call Stop when done to release its goroutine.
func New[K comparable, V Cloneable[V]](cfg Config) *Cache[K, V] {
	c := &Cache[K, V]{cfg: cfg, stopCh: make(chan struct{})}
	go c.sweep()
	return c
}

// Get returns a clone of the value stored under key, if present and unexpired.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	var zero V
	v, ok := c.data.Load(key)
	if !ok {
		return zero, false
	}
	e := v.(*cacheEntry[V])
	if time.Now().After(e.expiresAt) {
		c.remove(key)
		return zero, false
	}
	atomic.StoreInt64(&e.lastAccess, time.Now().UnixNano())
	return e.value.Clone(), true
}

// Set stores a clone of value under key, replacing any existing entry, then
// evicts down to MaxEntries if the store is now over the cap.
func (c *Cache[K, V]) Set(key K, value V) {
	e := &cacheEntry[V]{
		value:      value.Clone(),
		expiresAt:  time.Now().Add(c.cfg.TTL),
		lastAccess: time.Now().UnixNano(),
	}
	_, loaded := c.data.Swap(key, e)
	if !loaded {
		c.count.Add(1)
	}

	if c.cfg.MaxEntries > 0 && c.count.Load() > int64(c.cfg.MaxEntries) {
		c.evictLRU()
	}
}

// Invalidate evicts the entry stored under key, if any.
func (c *Cache[K, V]) Invalidate(key K) {
	c.remove(key)
}

// InvalidateAll evicts every entry.
func (c *Cache[K, V]) InvalidateAll() {
	c.data.Range(func(k, _ any) bool {
		c.remove(k.(K))
		return true
	})
}

// Range calls fn for every live entry (including not-yet-swept-but-expired
// ones — callers that care about expiry should check Get's bool instead).
func (c *Cache[K, V]) Range(fn func(key K, value V) bool) {
	c.data.Range(func(k, v any) bool {
		e := v.(*cacheEntry[V])
		return fn(k.(K), e.value.Clone())
	})
}

// Stats returns current entry counts without modifying state.
func (c *Cache[K, V]) Stats() Stats {
	total := 0
	expired := 0
	now := time.Now()
	c.data.Range(func(_, v any) bool {
		total++
		if e, ok := v.(*cacheEntry[V]); ok && now.After(e.expiresAt) {
			expired++
		}
		return true
	})
	return Stats{TotalEntries: total, ExpiredEntries: expired}
}

// Stop shuts down the background sweeper. Safe to call more than once.
func (c *Cache[K, V]) Stop() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// remove atomically deletes key and, if the removed value implements
// Zeroable, scrubs it. Safe to call on a key that isn't present.
func (c *Cache[K, V]) remove(key K) {
	v, loaded := c.data.LoadAndDelete(key)
	if !loaded {
		return
	}
	c.count.Add(-1)
	if e, ok := v.(*cacheEntry[V]); ok {
		// Method-set caveat: see Zeroable's doc comment — this only fires if
		// V's concrete type's method set actually includes Zero().
		if z, ok := any(e.value).(Zeroable); ok {
			z.Zero()
		}
	}
}

// evictLRU removes the least-recently-touched entries until the store is at
// or under MaxEntries. Guarded by TryLock so at most one goroutine evicts at
// a time; others proceed without waiting — the cap can overshoot briefly
// under heavy concurrent writes, which is still strictly better than the
// zero enforcement both predecessor caches had.
func (c *Cache[K, V]) evictLRU() {
	if !c.evictMu.TryLock() {
		return
	}
	defer c.evictMu.Unlock()

	target := int64(c.cfg.MaxEntries)
	over := c.count.Load() - target
	if over <= 0 {
		return
	}

	type candidate struct {
		key        K
		lastAccess int64
	}
	candidates := make([]candidate, 0, c.count.Load())
	c.data.Range(func(k, v any) bool {
		e := v.(*cacheEntry[V])
		candidates = append(candidates, candidate{key: k.(K), lastAccess: atomic.LoadInt64(&e.lastAccess)})
		return true
	})
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].lastAccess < candidates[j].lastAccess })

	n := int(over)
	if n > len(candidates) {
		n = len(candidates)
	}
	for i := 0; i < n; i++ {
		c.remove(candidates[i].key)
	}
}

// sweep periodically removes expired entries in the background.
func (c *Cache[K, V]) sweep() {
	ticker := time.NewTicker(c.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			c.data.Range(func(k, v any) bool {
				if e, ok := v.(*cacheEntry[V]); ok && now.After(e.expiresAt) {
					c.remove(k.(K))
				}
				return true
			})
		}
	}
}
