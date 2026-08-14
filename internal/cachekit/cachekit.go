// Package cachekit provides a generic, thread-safe, TTL+LRU in-memory cache
// used by every domain cache in RocketVault (secrets, keys, vaults).
package cachekit

import (
	"fmt"
	"time"
)

// Cloneable is required of every value type stored in a Cache. Get and Set
// always clone: the cache never hands out or accepts a pointer a caller
// could mutate to corrupt a concurrent reader or a not-yet-persisted write.
type Cloneable[T any] interface {
	Clone() T
}

// Zeroable is optional. If a cached value implements it, Cache calls Zero()
// on the removed value after any internal removal (TTL sweep, LRU eviction,
// Invalidate, InvalidateAll) — after the value is exclusively held (no other
// goroutine can still read it via the map at that point), before it becomes
// unreachable. Used by the key cache to scrub private key material eagerly
// rather than waiting for GC.
type Zeroable interface {
	Zero()
}

// Config controls one domain cache's TTL, cleanup cadence, and size cap.
type Config struct {
	Enabled         bool
	TTL             time.Duration
	CleanupInterval time.Duration
	MaxEntries      int
}

// Validate reports whether cfg's durations and cap are usable. MaxEntries
// of 0 is valid and means unbounded (no LRU eviction).
func (c Config) Validate() error {
	if c.TTL <= 0 {
		return fmt.Errorf("cachekit: ttl must be positive, got %s", c.TTL)
	}
	if c.CleanupInterval <= 0 {
		return fmt.Errorf("cachekit: cleanup_interval must be positive, got %s", c.CleanupInterval)
	}
	if c.CleanupInterval >= c.TTL {
		return fmt.Errorf("cachekit: cleanup_interval (%s) must be less than ttl (%s)", c.CleanupInterval, c.TTL)
	}
	if c.MaxEntries < 0 {
		return fmt.Errorf("cachekit: max_entries cannot be negative, got %d", c.MaxEntries)
	}
	return nil
}

// Stats holds observable cache counters.
type Stats struct {
	TotalEntries   int
	ExpiredEntries int
}

// Interface is satisfied by both Cache[K,V] and NopCache[K,V], so callers
// can depend on it without caring whether caching is enabled.
type Interface[K comparable, V Cloneable[V]] interface {
	// Get returns a clone of the value stored under key, if present and unexpired.
	Get(key K) (V, bool)
	// Set stores a clone of value under key, replacing any existing entry.
	Set(key K, value V)
	// Invalidate evicts the entry stored under key, if any.
	Invalidate(key K)
	// InvalidateAll evicts every entry.
	InvalidateAll()
	// Range calls fn for every live entry, in no particular order. fn
	// receives the same clone semantics as Get. Stops early if fn returns false.
	Range(fn func(key K, value V) bool)
	// Stats returns current counters without modifying state.
	Stats() Stats
	// Stop shuts down the background sweeper goroutine. Safe to call more than once.
	Stop()
}
