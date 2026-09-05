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

// TieredCache implements Interface[K,V] over an in-process L1 (unchanged
// today's cache) and a network L2. Every L2 failure degrades to a plain
// miss (Get) or silent no-op (Set/Invalidate) -- it never returns an error,
// matching Interface[K,V]'s existing zero-error contract, so an L2 outage
// can never break a read that L1 (or a source-of-truth fallback one layer
// up) can still serve.
type TieredCache[K comparable, V Cloneable[V]] struct {
	l1     Interface[K, V]
	l2     L2
	codec  Codec[V]
	keys   KeyCodec[K]
	prefix string
	ttl    time.Duration
}

// NewTieredCache builds a TieredCache. prefix namespaces this domain's keys
// on the shared L2 (e.g. "rocketvault:secret:"); ttl is the L2 entry
// lifetime, independent of l1's own TTL.
func NewTieredCache[K comparable, V Cloneable[V]](
	l1 Interface[K, V], l2 L2, codec Codec[V], keys KeyCodec[K], prefix string, ttl time.Duration,
) *TieredCache[K, V] {
	return &TieredCache[K, V]{l1: l1, l2: l2, codec: codec, keys: keys, prefix: prefix, ttl: ttl}
}

func (t *TieredCache[K, V]) wireKey(key K) string {
	return t.prefix + t.keys.ToWire(key)
}

func (t *TieredCache[K, V]) Get(key K) (V, bool) {
	if v, ok := t.l1.Get(key); ok {
		return v, true
	}
	var zero V
	payload, ok := t.l2.Get(t.wireKey(key))
	if !ok {
		return zero, false
	}
	v, err := t.codec.Decode(payload)
	if err != nil {
		return zero, false
	}
	t.l1.Set(key, v)
	return v, true
}

func (t *TieredCache[K, V]) Set(key K, value V) {
	t.l1.Set(key, value)
	payload, err := t.codec.Encode(value)
	if err != nil {
		return
	}
	t.l2.Set(t.wireKey(key), payload, t.ttl)
}

func (t *TieredCache[K, V]) Invalidate(key K) {
	t.l1.Invalidate(key)
	t.l2.Invalidate(t.wireKey(key))
}

func (t *TieredCache[K, V]) InvalidateAll() {
	t.l1.InvalidateAll()
	for _, wireKey := range t.l2.Keys(t.prefix) {
		t.l2.Invalidate(wireKey)
	}
}

func (t *TieredCache[K, V]) Stats() Stats {
	return t.l1.Stats()
}

// Stop stops only this TieredCache's L1 background sweep. The L2
// connection is a single client shared across every domain's TieredCache
// and is owned and closed exactly once by the container (see the design
// spec) -- not here.
func (t *TieredCache[K, V]) Stop() {
	t.l1.Stop()
}
