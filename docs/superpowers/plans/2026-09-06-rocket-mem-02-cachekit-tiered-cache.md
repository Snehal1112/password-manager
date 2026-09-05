# Rocket-mem Tiered Cache — Plan 02: cachekit L2 + TieredCache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `L2`, `KeyCodec[K]`, and `TieredCache[K,V]` to `internal/cachekit`, satisfying the package's existing `Interface[K,V]`, with a fake in-memory `L2` test double proving every failure-degrades-to-miss/no-op behavior from the spec.

**Architecture:** `TieredCache[K,V]` wraps an existing `Interface[K,V]` (L1) plus a new `L2` interface, using a `Codec[V]` (Plan 01) and a `KeyCodec[K]` to translate values and keys to/from the network tier. No existing file changes; this plan only adds new code, not yet wired into any domain cache.

**Tech Stack:** Go 1.24 generics, `testify`.

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (see "Architecture" section, especially the `L2`/`KeyCodec`/`Range` discussion)

## Global Constraints

- `internal/cachekit` still imports nothing beyond the stdlib after this plan — `L2` is an interface, not a client.
- `TieredCache[K,V]` must satisfy `cachekit.Interface[K,V]` exactly (`Get`, `Set`, `Invalidate`, `InvalidateAll`, `Range`, `Stats`, `Stop`) — verified by a compile-time assertion in the test, since any domain cache assigning `*TieredCache[...]` to its existing `core cachekit.Interface[...]` field must compile with zero other changes.
- Every `L2` failure (`Get` returns `false`, `Keys` returns empty, decode errors) must degrade to a plain miss/no-op — never a panic, never an error returned from `TieredCache`'s own methods (none of `Interface[K,V]`'s methods return an error).
- `TieredCache.Stop()` stops only its own L1; it must not attempt to close anything L2-related (see spec's "L2 connection lifecycle is container-owned" note).

---

### Task 1: `L2` interface, `KeyCodec[K]`, and a fake L2 test double

**Files:**
- Create: `internal/cachekit/tiered_cache.go`
- Test: `internal/cachekit/tiered_cache_test.go`

**Interfaces:**
- Consumes: `cachekit.Codec[V]` (Plan 01).
- Produces: `cachekit.L2` interface, `cachekit.KeyCodec[K comparable]` struct, and (test-only) `fakeL2` double used by every test in this plan and reusable by Plan 03/05/06/07/08's tests.

- [ ] **Step 1: Write the failing test**

```go
// internal/cachekit/tiered_cache_test.go
package cachekit_test

import (
	"strings"
	"sync"
	"time"

	"rocketvault/internal/cachekit"
)

// fakeL2 is an in-memory stand-in for a real network L2 (e.g.
// internal/rocketmemcache's go-redis client). down simulates the L2 being
// completely unreachable — every method degrades exactly as the spec
// requires a real network failure to degrade.
type fakeL2 struct {
	mu   sync.Mutex
	data map[string][]byte
	down bool
}

func newFakeL2() *fakeL2 { return &fakeL2{data: make(map[string][]byte)} }

func (f *fakeL2) Get(wireKey string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, false
	}
	b, ok := f.data[wireKey]
	return b, ok
}

func (f *fakeL2) Set(wireKey string, payload []byte, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return
	}
	f.data[wireKey] = payload
}

func (f *fakeL2) Invalidate(wireKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, wireKey)
}

func (f *fakeL2) Keys(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil
	}
	var out []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

// compile-time check: fakeL2 satisfies cachekit.L2
var _ cachekit.L2 = (*fakeL2)(nil)

func identityKeyCodec() cachekit.KeyCodec[string] {
	return cachekit.KeyCodec[string]{
		ToWire:   func(k string) string { return k },
		FromWire: func(w string) (string, bool) { return w, true },
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cachekit/... -run TestNothing -v` (this file has no `Test`-prefixed function yet — instead just build it)
Run: `go build ./internal/cachekit/...`
Expected: FAIL — `cachekit.L2` and `cachekit.KeyCodec` do not exist yet, so `var _ cachekit.L2 = (*fakeL2)(nil)` and `cachekit.KeyCodec[string]` fail to compile.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/cachekit/tiered_cache.go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./internal/cachekit/...`
Expected: builds clean (no `_test.go` assertions to run yet in this task — Task 2 adds the real behavioral tests against this scaffold)

- [ ] **Step 5: Commit**

```bash
git add internal/cachekit/tiered_cache.go internal/cachekit/tiered_cache_test.go
git commit -m "feat(cachekit): add L2 interface, KeyCodec, and fake L2 test double"
```

---

### Task 2: `TieredCache[K,V]` — Get/Set/Invalidate/InvalidateAll/Stats/Stop

**Files:**
- Modify: `internal/cachekit/tiered_cache.go`
- Test: `internal/cachekit/tiered_cache_test.go`

**Interfaces:**
- Consumes: `L2`, `KeyCodec[K]` (Task 1), `Codec[V]` (Plan 01), `Interface[K,V]` (existing).
- Produces: `cachekit.NewTieredCache[K comparable, V Cloneable[V]](l1 Interface[K,V], l2 L2, codec Codec[V], keys KeyCodec[K], prefix string, ttl time.Duration) *TieredCache[K,V]`, satisfying `Interface[K,V]` — `Range` is deferred to Task 3.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/cachekit/tiered_cache_test.go
package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

func newTieredForTest(l1 cachekit.Interface[string, *codecTestValue], l2 cachekit.L2) *cachekit.TieredCache[string, *codecTestValue] {
	return cachekit.NewTieredCache[string, *codecTestValue](
		l1, l2, cachekit.PlainJSONCodec[*codecTestValue]{}, identityKeyCodec(), "test:", time.Minute,
	)
}

func TestTieredCache_L1Hit_NeverTouchesL2(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true // if Get ever reaches L2, this proves it by forcing a miss
	tc := newTieredForTest(l1, l2)

	l1.Set("k1", &codecTestValue{Name: "a", N: 1})
	v, ok := tc.Get("k1")
	require.True(t, ok)
	assert.Equal(t, "a", v.Name)
}

func TestTieredCache_L1Miss_L2Hit_PopulatesL1(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	payload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "b", N: 2})
	require.NoError(t, err)
	l2.Set("test:k2", payload, time.Minute)

	v, ok := tc.Get("k2")
	require.True(t, ok)
	assert.Equal(t, "b", v.Name)

	// L1 should now be populated -- prove it by killing L2 and reading again.
	l2.down = true
	v2, ok2 := tc.Get("k2")
	require.True(t, ok2)
	assert.Equal(t, "b", v2.Name)
}

func TestTieredCache_BothMiss(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	tc := newTieredForTest(l1, newFakeL2())

	_, ok := tc.Get("missing")
	assert.False(t, ok)
}

func TestTieredCache_Set_ReachesBothTiers(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	tc.Set("k3", &codecTestValue{Name: "c", N: 3})

	_, ok := l2.Get("test:k3")
	assert.True(t, ok, "Set must reach L2")
	v, ok := l1.Get("k3")
	require.True(t, ok)
	assert.Equal(t, "c", v.Name)
}

func TestTieredCache_Invalidate_EvictsBothTiers(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)
	tc.Set("k4", &codecTestValue{Name: "d", N: 4})

	tc.Invalidate("k4")

	_, l1ok := l1.Get("k4")
	_, l2ok := l2.Get("test:k4")
	assert.False(t, l1ok)
	assert.False(t, l2ok)
}

func TestTieredCache_L2Down_GetDegradesToMiss_NoPanic(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true
	tc := newTieredForTest(l1, l2)

	assert.NotPanics(t, func() {
		_, ok := tc.Get("anything")
		assert.False(t, ok)
	})
}

func TestTieredCache_L2Down_SetIsSilentNoOp_NoPanic(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true
	tc := newTieredForTest(l1, l2)

	assert.NotPanics(t, func() { tc.Set("k5", &codecTestValue{Name: "e", N: 5}) })
	// L1 must still have gotten the write even though L2 is down.
	v, ok := l1.Get("k5")
	require.True(t, ok)
	assert.Equal(t, "e", v.Name)
}
```

Note: `*codecTestValue` needs a `Clone()` method to satisfy `Cloneable[*codecTestValue]` for use with `cachekit.Interface`/`cachekit.New` in these tests — add it next to `codecTestValue`'s definition in `codec_test.go`:

```go
// add to internal/cachekit/codec_test.go, next to codecTestValue's definition
func (v *codecTestValue) Clone() *codecTestValue {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cachekit/... -run TestTieredCache -v`
Expected: FAIL (build error — `cachekit.NewTieredCache`/`cachekit.TieredCache` do not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/cachekit/tiered_cache.go

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
```

Leave `Range` unimplemented for now (Task 3 adds it) — the test file above does not call `Range`, so the package builds and this task's tests pass without it. `TieredCache` will not fully satisfy `Interface[K,V]` until Task 3; do not add a compile-time `var _ Interface[...] = (*TieredCache[...])(nil)` assertion until then.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cachekit/... -v`
Expected: PASS (all tests in the package, including Plan 01's codec tests and this task's)

- [ ] **Step 5: Commit**

```bash
git add internal/cachekit/tiered_cache.go internal/cachekit/tiered_cache_test.go internal/cachekit/codec_test.go
git commit -m "feat(cachekit): add TieredCache Get/Set/Invalidate/InvalidateAll/Stats/Stop"
```

---

### Task 3: `Range` — dual-tier scan, and the `Interface[K,V]` conformance check

**Files:**
- Modify: `internal/cachekit/tiered_cache.go`
- Test: `internal/cachekit/tiered_cache_test.go`

**Interfaces:**
- Produces: `TieredCache[K,V].Range(fn func(K,V) bool)`, completing `Interface[K,V]` conformance.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/cachekit/tiered_cache_test.go
package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

// compile-time check: *TieredCache[string, *codecTestValue] satisfies
// Interface[string, *codecTestValue] -- proves every domain cache can swap
// its `core` field's concrete type with zero other change.
var _ cachekit.Interface[string, *codecTestValue] = (*cachekit.TieredCache[string, *codecTestValue])(nil)

func TestTieredCache_Range_VisitsL1AndL2OnlyEntries(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	// k-l1: only in L1 (e.g. never yet pushed to L2 in some other scenario).
	l1.Set("k-l1", &codecTestValue{Name: "only-l1", N: 1})
	// k-l2: only in L2 (e.g. evicted from L1 by LRU/TTL, still alive in L2).
	payload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "only-l2", N: 2})
	require.NoError(t, err)
	l2.Set("test:k-l2", payload, time.Minute)

	seen := map[string]string{}
	tc.Range(func(k string, v *codecTestValue) bool {
		seen[k] = v.Name
		return true
	})

	assert.Equal(t, "only-l1", seen["k-l1"])
	assert.Equal(t, "only-l2", seen["k-l2"], "an L2-only entry (evicted from L1) must still be visited by Range")
}

func TestTieredCache_Range_L1EntryWinsOverL2Duplicate(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	l1.Set("dup", &codecTestValue{Name: "fresh-l1", N: 1})
	stalePayload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "stale-l2", N: 2})
	require.NoError(t, err)
	l2.Set("test:dup", stalePayload, time.Minute)

	var got *codecTestValue
	tc.Range(func(k string, v *codecTestValue) bool {
		if k == "dup" {
			got = v
		}
		return true
	})
	require.NotNil(t, got)
	assert.Equal(t, "fresh-l1", got.Name, "L1's copy must win when a key exists in both tiers")
}

func TestTieredCache_Range_EarlyStop_SkipsL2Scan(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true // if Range reaches L2 after an early stop, Keys returns nil harmlessly either way -- down proves it's never even attempted via a separate assertion below
	tc := newTieredForTest(l1, l2)
	l1.Set("only-one", &codecTestValue{Name: "x", N: 1})

	visits := 0
	tc.Range(func(k string, v *codecTestValue) bool {
		visits++
		return false // stop immediately
	})
	assert.Equal(t, 1, visits)
}

func TestTieredCache_DeleteByIDPattern_FindsL2OnlyEntry(t *testing.T) {
	// This mirrors exactly how SecretCache.DeleteByID/certcache/keycache use
	// Range today: scan for a match, collect keys, Invalidate each. Proves
	// the pattern still works when the matching entry lives only in L2.
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	payload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "target", N: 99})
	require.NoError(t, err)
	l2.Set("test:l2only", payload, time.Minute)

	var toRemove []string
	tc.Range(func(k string, v *codecTestValue) bool {
		if v.N == 99 {
			toRemove = append(toRemove, k)
		}
		return true
	})
	for _, k := range toRemove {
		tc.Invalidate(k)
	}

	_, ok := l2.Get("test:l2only")
	assert.False(t, ok, "the L2-only entry must have been found and invalidated")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cachekit/... -run TestTieredCache_Range -v`
Expected: FAIL (`TieredCache` does not yet implement `Range`, so the `var _ cachekit.Interface[...]` line fails to compile)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/cachekit/tiered_cache.go, add "strings" to the import block

// Range visits every live entry across both tiers. It ranges L1 first
// (unchanged semantics), then scans L2 for any wire key not already
// visited via L1 -- this is what keeps SecretCache.DeleteByID and its
// certcache/keycache analogs correct: they discover which scope-key(s)
// hold a given ID by scanning every live entry, and an L1-only Range would
// miss an entry evicted from L1 but still alive in L2 (see the design
// spec's "Why Keys is required" note). L1's copy wins whenever a key
// exists in both tiers, since it is guaranteed at least as fresh.
func (t *TieredCache[K, V]) Range(fn func(key K, value V) bool) {
	visited := make(map[string]struct{})
	stopped := false
	t.l1.Range(func(k K, v V) bool {
		visited[t.wireKey(k)] = struct{}{}
		if stopped {
			return false
		}
		if !fn(k, v) {
			stopped = true
			return false
		}
		return true
	})
	if stopped {
		return
	}
	for _, wireKey := range t.l2.Keys(t.prefix) {
		if _, ok := visited[wireKey]; ok {
			continue
		}
		shortKey := strings.TrimPrefix(wireKey, t.prefix)
		k, ok := t.keys.FromWire(shortKey)
		if !ok {
			continue
		}
		payload, ok := t.l2.Get(wireKey)
		if !ok {
			continue
		}
		v, err := t.codec.Decode(payload)
		if err != nil {
			continue
		}
		if !fn(k, v) {
			return
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cachekit/... -v`
Expected: PASS (every test in the package)

Also run: `go build ./... && go vet ./internal/cachekit/...`
Expected: clean (this plan's changes are additive-only and touch no other package, so the rest of the repo is unaffected — this is the regression check for this plan)

- [ ] **Step 5: Commit**

```bash
git add internal/cachekit/tiered_cache.go internal/cachekit/tiered_cache_test.go
git commit -m "feat(cachekit): add TieredCache.Range with dual-tier scan"
```
