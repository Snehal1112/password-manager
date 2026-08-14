# Generic Cache Config Implementation Plan — Part 1 of 4: cachekit core

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and fully test the generic `internal/cachekit` package: `Cloneable[T]`/`Zeroable`/`Config`/`Interface[K,V]`, the real `Cache[K,V]` implementation (TTL sweep, clone-on-access, Zeroable-on-remove, LRU eviction), and `NopCache[K,V]` + `NewFromConfig[K,V]`.

**Architecture:** `cachekit.Cache[K,V]` is `sync.Map`-backed with an atomic per-entry last-access timestamp for lock-free LRU bookkeeping on the read path; eviction only runs inside `Set` when over `MaxEntries`, guarded by a `TryLock` so at most one goroutine evicts at a time. This package is purely additive in this plan — nothing else in the repo references it yet, so it can be built, tested, and reviewed in complete isolation.

**Tech Stack:** Go 1.25 generics, `sync.Map`, `sync/atomic`.

**Spec:** `docs/superpowers/specs/2026-08-14-generic-cache-config-design.md` — read it alongside this plan.

## Sequence

This is **Part 1 of 4** in the generic-cache-config implementation. Execute in order:
1. **Part 1 (this file)** — `internal/cachekit` core (Tasks 1–3)
2. Part 2 — migrate `internal/keycache` + `internal/cache` (secrets) onto cachekit, add `internal/vaultcache` (Tasks 4–6)
3. Part 3 — wire vault caching into `VaultService`, add `config.CacheConfig`/`LoadCacheConfig` (Tasks 7–8)
4. Part 4 — rewire the DI container, update docs/config, final whole-repo verification (Tasks 9–10)

This part is fully self-contained: `go build ./... && go test ./...` for the whole repo stays clean throughout, since `internal/cachekit` has no consumers yet.

## Global Constraints

- Every cached value must implement `cachekit.Cloneable[T]` (`Clone() T`) — `Get`/`Set` always clone. No exceptions, no per-domain opt-out (spec's "always clone" decision).
- `MaxEntries` must be genuinely enforced via LRU eviction — it is a no-op today in both existing caches; this plan closes that gap.
- No lock on the `Get` read path — LRU bookkeeping uses an atomic per-entry timestamp, never a mutex touched by `Get`.
- Preserve the "zero sensitive fields on removal" property via the optional `Zeroable` interface (needed by the key cache migration in Part 2, but the mechanism is built here).
- Go build/vet/test/gofmt must stay clean after every task (this repo's existing bar — see CLAUDE.md).

---

## File Structure (this part)

**New:**
- `internal/cachekit/cachekit.go` — `Cloneable[T]`, `Zeroable`, `Config`+`Validate()`, `Stats`, `Interface[K,V]`
- `internal/cachekit/cache.go` — `Cache[K,V]` (the real implementation)
- `internal/cachekit/nop_cache.go` — `NopCache[K,V]` + `NewFromConfig[K,V]`
- `internal/cachekit/cachekit_test.go`, `cache_test.go`, `nop_cache_test.go`

---

### Task 1: `internal/cachekit` foundation types

**Files:**
- Create: `internal/cachekit/cachekit.go`
- Test: `internal/cachekit/cachekit_test.go`

**Interfaces:**
- Produces: `Cloneable[T any] interface{ Clone() T }`, `Zeroable interface{ Zero() }`, `Config{ Enabled bool; TTL, CleanupInterval time.Duration; MaxEntries int }` + `(Config) Validate() error`, `Stats{ TotalEntries, ExpiredEntries int }`, `Interface[K comparable, V Cloneable[V]] interface{ Get(K)(V,bool); Set(K,V); Invalidate(K); InvalidateAll(); Range(func(K,V) bool); Stats() Stats; Stop() }`.

  Note: `Range` is not in the original spec's `Interface` listing — needed once translating "keycache.Invalidate(keyID) evicts every version" into working generic code: with a struct key (`keyCacheKey{ID,Version}`) there's no string-prefix trick left, so `keycache`'s wrapper (Task 4) needs to enumerate matching entries itself. `Range` is the natural, minimal way to expose that without cachekit knowing about compound keys.

- [ ] **Step 1: Write the failing test for `Config.Validate()`**

```go
// internal/cachekit/cachekit_test.go
package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/cachekit"
)

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: 10 * time.Second, MaxEntries: 100}
	assert.NoError(t, cfg.Validate())
}

func TestConfig_Validate_TTLNotPositive(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 0, CleanupInterval: time.Second, MaxEntries: 100}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_CleanupIntervalNotPositive(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: 0, MaxEntries: 100}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_CleanupIntervalNotLessThanTTL(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_MaxEntriesNegative(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: -1}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_MaxEntriesZeroIsValid(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0}
	assert.NoError(t, cfg.Validate(), "0 means unbounded, not invalid")
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/cachekit/... -run TestConfig_Validate -v`
Expected: build failure — `undefined: cachekit.Config` (package doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/cachekit/cachekit.go

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
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/cachekit/... -run TestConfig_Validate -v`
Expected: all 6 subtests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cachekit/cachekit.go internal/cachekit/cachekit_test.go
git commit -m "feat(cachekit): add Cloneable/Zeroable/Config/Interface foundation types"
```

---

### Task 2: `cachekit.Cache[K,V]` — TTL, Get/Set/Invalidate, Zeroable-on-remove

**Files:**
- Create: `internal/cachekit/cache.go`
- Test: `internal/cachekit/cache_test.go`

**Interfaces:**
- Consumes: `Cloneable[T]`, `Zeroable`, `Config`, `Stats`, `Interface[K,V]` from Task 1.
- Produces: `func New[K comparable, V Cloneable[V]](cfg Config) *Cache[K, V]`, `(*Cache[K,V])` satisfying `Interface[K,V]`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/cachekit/cache_test.go
package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

// testValue is a minimal Cloneable+Zeroable value for exercising Cache[K,V]
// without depending on any real domain type.
type testValue struct {
	N        int
	zeroed   *bool // optional: set by tests that need to observe Zero() calls
}

func (v testValue) Clone() testValue { return testValue{N: v.N, zeroed: v.zeroed} }
func (v testValue) Zero() {
	if v.zeroed != nil {
		*v.zeroed = true
	}
}

func newCache(t *testing.T, cfg cachekit.Config) *cachekit.Cache[string, testValue] {
	t.Helper()
	c := cachekit.New[string, testValue](cfg)
	t.Cleanup(c.Stop)
	return c
}

func TestCache_SetThenGet_Hit(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	got, ok := c.Get("a")
	require.True(t, ok)
	assert.Equal(t, 1, got.N)
}

func TestCache_Get_MissForUnknownKey(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	_, ok := c.Get("missing")
	assert.False(t, ok)
}

func TestCache_Get_MissAfterTTLExpiry(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: 20 * time.Millisecond, CleanupInterval: 5 * time.Millisecond, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	time.Sleep(60 * time.Millisecond)

	_, ok := c.Get("a")
	assert.False(t, ok, "entry must have expired")
}

func TestCache_GetReturnsClone_MutatingResultDoesNotAffectCache(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	got, _ := c.Get("a")
	got.N = 999 // mutate the returned value

	again, _ := c.Get("a")
	assert.Equal(t, 1, again.N, "mutating a Get result must not affect the stored entry")
}

func TestCache_Invalidate_RemovesEntry(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})
	c.Invalidate("a")

	_, ok := c.Get("a")
	assert.False(t, ok)
}

func TestCache_InvalidateAll_RemovesEverything(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})
	c.Set("b", testValue{N: 2})
	c.InvalidateAll()

	_, ok := c.Get("a")
	assert.False(t, ok)
	_, ok = c.Get("b")
	assert.False(t, ok)
}

func TestCache_Invalidate_CallsZeroOnRemovedValue(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	zeroed := false
	c.Set("a", testValue{N: 1, zeroed: &zeroed})

	c.Invalidate("a")

	assert.True(t, zeroed, "Invalidate must call Zero() on the removed value")
}

func TestCache_TTLSweep_CallsZeroOnExpiredValue(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: 15 * time.Millisecond, CleanupInterval: 5 * time.Millisecond, MaxEntries: 10})
	zeroed := false
	c.Set("a", testValue{N: 1, zeroed: &zeroed})

	time.Sleep(60 * time.Millisecond) // let the background sweep run at least once

	assert.True(t, zeroed, "the background TTL sweep must call Zero() on expired entries")
}

func TestCache_Range_VisitsEveryLiveEntry(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Set("a", testValue{N: 1})
	c.Set("b", testValue{N: 2})

	seen := map[string]int{}
	c.Range(func(k string, v testValue) bool {
		seen[k] = v.N
		return true
	})

	assert.Equal(t, map[string]int{"a": 1, "b": 2}, seen)
}

func TestCache_Stats_CountsTotalAndExpired(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Hour, CleanupInterval: time.Minute, MaxEntries: 10})
	c.Set("a", testValue{N: 1})

	stats := c.Stats()
	assert.Equal(t, 1, stats.TotalEntries)
	assert.Equal(t, 0, stats.ExpiredEntries)
}

func TestCache_Stop_IdempotentDouble(t *testing.T) {
	c := cachekit.New[string, testValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	c.Stop()
	c.Stop() // must not panic
}

// Compile-time interface compliance.
var _ cachekit.Interface[string, testValue] = (*cachekit.Cache[string, testValue])(nil)
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/cachekit/... -run TestCache_ -v`
Expected: build failure — `undefined: cachekit.New`, `undefined: cachekit.Cache`.

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/cachekit/cache.go
package cachekit

import (
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
```

Add `"sort"` to the import block (used by `evictLRU`).

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/cachekit/... -run TestCache_ -v -race`
Expected: all subtests PASS, including under `-race`.

- [ ] **Step 5: Commit**

```bash
git add internal/cachekit/cache.go internal/cachekit/cache_test.go
git commit -m "feat(cachekit): add Cache[K,V] with TTL sweep, clone-on-access, and Zeroable-on-remove"
```

---

### Task 3: LRU eviction test + `NopCache[K,V]` + `NewFromConfig`

**Files:**
- Create: `internal/cachekit/nop_cache.go`
- Modify: `internal/cachekit/cache_test.go` (add LRU-specific test)
- Test: `internal/cachekit/nop_cache_test.go`

**Interfaces:**
- Produces: `NopCache[K,V]` satisfying `Interface[K,V]`; `func NewFromConfig[K comparable, V Cloneable[V]](cfg Config) Interface[K, V]` — the one place the "enabled → real cache, disabled → no-op" branch lives, so no domain wrapper repeats it.

- [ ] **Step 1: Write the failing LRU test**

Append to `internal/cachekit/cache_test.go`:

```go
func TestCache_Set_EvictsLeastRecentlyTouchedWhenOverMaxEntries(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 2})

	c.Set("a", testValue{N: 1})
	c.Set("b", testValue{N: 2})
	// Touch "a" so it's more recently used than "b".
	_, _ = c.Get("a")

	c.Set("c", testValue{N: 3}) // pushes count to 3, over the cap of 2

	// "b" was least-recently-touched and must be evicted.
	_, ok := c.Get("b")
	assert.False(t, ok, "least-recently-touched entry must be evicted")

	_, ok = c.Get("a")
	assert.True(t, ok, "recently-touched entry must survive")
	_, ok = c.Get("c")
	assert.True(t, ok, "just-inserted entry must survive")
}

func TestCache_MaxEntriesZero_NeverEvicts(t *testing.T) {
	c := newCache(t, cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	for i := 0; i < 50; i++ {
		c.Set(string(rune('a'+i%26))+string(rune(i)), testValue{N: i})
	}
	stats := c.Stats()
	assert.Equal(t, 50, stats.TotalEntries, "MaxEntries=0 must mean unbounded")
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/cachekit/... -run TestCache_Set_Evicts -v`
Expected: FAIL — `TestCache_Set_EvictsLeastRecentlyTouchedWhenOverMaxEntries` fails because eviction isn't wired to a real cap check trigger yet... Actually the implementation from Task 2 already includes `evictLRU` — **this step should already pass** if Task 2 was implemented correctly. Run it anyway to confirm: if it passes immediately, that's expected (Task 2's `Set` already calls `evictLRU`); this test exists to lock the behavior in, not to drive new code.

- [ ] **Step 3: (only if Step 2 failed) fix `evictLRU`, otherwise skip to Step 4**

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/cachekit/... -run TestCache_ -v -race`
Expected: all PASS.

- [ ] **Step 5: Write the failing test for `NopCache` and `NewFromConfig`**

```go
// internal/cachekit/nop_cache_test.go
package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/cachekit"
)

func TestNopCache_NeverHits(t *testing.T) {
	c := cachekit.NewNopCache[string, testValue]()

	c.Set("a", testValue{N: 1})
	_, ok := c.Get("a")
	assert.False(t, ok, "NopCache must never return a hit")

	c.Invalidate("a")
	c.InvalidateAll()
	c.Range(func(string, testValue) bool { t.Fatal("Range must never visit anything"); return true })
	c.Stop()

	assert.Equal(t, cachekit.Stats{}, c.Stats())
}

func TestNewFromConfig_EnabledReturnsRealCache(t *testing.T) {
	c := cachekit.NewFromConfig[string, testValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	defer c.Stop()

	c.Set("a", testValue{N: 1})
	_, ok := c.Get("a")
	assert.True(t, ok, "enabled config must produce a real, functioning cache")
}

func TestNewFromConfig_DisabledReturnsNopCache(t *testing.T) {
	c := cachekit.NewFromConfig[string, testValue](cachekit.Config{Enabled: false, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 10})
	defer c.Stop()

	c.Set("a", testValue{N: 1})
	_, ok := c.Get("a")
	assert.False(t, ok, "disabled config must produce a cache that never hits")
}

var _ cachekit.Interface[string, testValue] = (*cachekit.NopCache[string, testValue])(nil)
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/cachekit/... -run "TestNopCache|TestNewFromConfig" -v`
Expected: build failure — `undefined: cachekit.NewNopCache`, `undefined: cachekit.NewFromConfig`.

- [ ] **Step 7: Write the minimal implementation**

```go
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
func (n *NopCache[K, V]) Set(_ K, _ V)                       {}
func (n *NopCache[K, V]) Invalidate(_ K)                     {}
func (n *NopCache[K, V]) InvalidateAll()                     {}
func (n *NopCache[K, V]) Range(_ func(key K, value V) bool)  {}
func (n *NopCache[K, V]) Stats() Stats                        { return Stats{} }
func (n *NopCache[K, V]) Stop()                               {}

// NewFromConfig is the one place the enabled/disabled branch lives: every
// domain wrapper calls this instead of repeating the if/else itself.
func NewFromConfig[K comparable, V Cloneable[V]](cfg Config) Interface[K, V] {
	if !cfg.Enabled {
		return NewNopCache[K, V]()
	}
	return New[K, V](cfg)
}
```

- [ ] **Step 8: Run to verify it passes**

Run: `go test ./internal/cachekit/... -v -race`
Expected: every test in the package PASSes, including `-race`.

- [ ] **Step 9: Commit**

```bash
git add internal/cachekit/nop_cache.go internal/cachekit/nop_cache_test.go internal/cachekit/cache_test.go
git commit -m "feat(cachekit): add NopCache and NewFromConfig, lock in LRU eviction behavior"
```

---


## Self-Review Notes (this part)

**Spec coverage:** covers the spec's `cachekit` foundation section in full — `Cloneable`/`Zeroable`/`Config`/`Interface[K,V]` (Task 1), `Cache[K,V]` mechanics including TTL, clone-on-access, and Zeroable-on-remove (Task 2), LRU eviction and `NopCache`/`NewFromConfig` (Task 3).

**Type consistency:** `Interface[K,V]`'s method set (Task 1) matches exactly what `Cache[K,V]` (Task 2) and `NopCache[K,V]` (Task 3) both implement — verified via the compile-time `var _ Interface[...] = (*Cache[...])(nil)` / `(*NopCache[...])(nil)` checks in each task's tests.

**No placeholders:** every step has complete, runnable code.

## Next step

Once this part's tasks are all committed and `go test ./internal/cachekit/... -v -race` is clean, proceed to **Part 2**: `docs/superpowers/plans/2026-08-14-generic-cache-config-2-migrate-caches.md`.
