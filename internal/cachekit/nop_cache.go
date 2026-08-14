// internal/cachekit/nop_cache.go
package cachekit

// NopCache is a no-op Interface[K,V] implementation used when a domain's
// cache is disabled. Get always misses; every other method is a no-op.
type NopCache[K comparable, V Cloneable[V]] struct{}

// NewNopCache returns a NopCache.
func NewNopCache[K comparable, V Cloneable[V]]() *NopCache[K, V] {
	return &NopCache[K, V]{}
}

func (n *NopCache[K, V]) Get(_ K) (V, bool) {
	var zero V
	return zero, false
}
func (n *NopCache[K, V]) Set(_ K, _ V)                      {}
func (n *NopCache[K, V]) Invalidate(_ K)                    {}
func (n *NopCache[K, V]) InvalidateAll()                    {}
func (n *NopCache[K, V]) Range(_ func(key K, value V) bool) {}
func (n *NopCache[K, V]) Stats() Stats                      { return Stats{} }
func (n *NopCache[K, V]) Stop()                             {}

// NewFromConfig is the one place the enabled/disabled branch lives: every
// domain wrapper calls this instead of repeating the if/else itself.
//
// An invalid cfg (e.g. CleanupInterval <= 0) would otherwise reach New's
// background sweeper goroutine and panic on time.NewTicker with no useful
// diagnostic. Fail safe instead: hand back an inert NopCache, matching the
// disabled-cache path, rather than crashing the process.
func NewFromConfig[K comparable, V Cloneable[V]](cfg Config) Interface[K, V] {
	if !cfg.Enabled {
		return NewNopCache[K, V]()
	}
	if err := cfg.Validate(); err != nil {
		return NewNopCache[K, V]()
	}
	return New[K, V](cfg)
}
