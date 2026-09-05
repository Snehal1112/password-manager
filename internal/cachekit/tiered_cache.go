package cachekit

import "time"

// L2 is a network-backed second cache tier. Every method must degrade
// gracefully on failure (network timeout, connection refused, malformed
// data): Get returns false, Set/Invalidate are silent no-ops, Keys returns
// an empty slice. Never generic over K -- every operation is already
// wire-string-keyed. Implemented by internal/rocketmemcache for the real
// Rocket-mem backend (Plan 03); implemented by a fake in-memory double
// here for tests.
type L2 interface {
	Get(wireKey string) ([]byte, bool)
	Set(wireKey string, payload []byte, ttl time.Duration)
	Invalidate(wireKey string)
	// Keys returns every live wire key matching prefix. Used only by
	// TieredCache.Range/InvalidateAll, never a hot path.
	Keys(prefix string) []string
}

// KeyCodec turns a domain's cache key K into a wire string and back.
// FromWire reports ok=false for anything malformed or foreign -- callers
// must skip such entries, never treat it as an error.
type KeyCodec[K comparable] struct {
	ToWire   func(K) string
	FromWire func(string) (K, bool)
}
