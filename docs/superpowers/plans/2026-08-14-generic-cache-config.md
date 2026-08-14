# Generic Cache Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two independent, hand-rolled caches (secrets, keys) with domain wrappers over one generic `internal/cachekit` core, close the uncached vault-lookup gap with a new `internal/vaultcache`, and unify all cache configuration under one `cache.<domain>.*` YAML schema.

**Architecture:** A new generic `cachekit.Cache[K,V]` (sync.Map-backed, TTL + LRU eviction, clone-on-access) becomes the single implementation all three domain caches wrap. `internal/cache` (secrets) and `internal/keycache` (keys) keep their existing external APIs and domain-specific composition (scope keys + reverse index; keyID+version keys) but delegate storage/eviction/TTL to `cachekit`. `internal/vaultcache` is new, wired into `VaultService` to close the gap where `VaultResolutionMiddleware` hits the DB on almost every request.

**Tech Stack:** Go 1.25 generics, `sync.Map`, `sync/atomic`, existing `github.com/spf13/viper` config loading pattern.

**Spec:** `docs/superpowers/specs/2026-08-14-generic-cache-config-design.md` — read it alongside this plan; this plan implements it exactly, plus one addition discovered while writing concrete code (see Task 1's `Range` method note).

## Global Constraints

- Every cached value must implement `cachekit.Cloneable[T]` (`Clone() T`) — `Get`/`Set` always clone. No exceptions, no per-domain opt-out (spec's "always clone" decision).
- `MaxEntries` must be genuinely enforced via LRU eviction — it is a no-op today in both existing caches; this plan closes that gap.
- No lock on the `Get` read path — LRU bookkeeping uses an atomic per-entry timestamp, never a mutex touched by `Get`.
- `key_cache.*` YAML keys are removed with no back-compat alias — replaced by `cache.keys.*`. Same breaking-rename treatment for `cache.*` (secrets) which was never actually read from YAML before this work.
- Certificates and Users get a reserved YAML config slot (`cache.certificates.*`, `cache.users.*`, default `enabled: false`) but **no** new Go cache wrapper type — no caller exists yet, and this project removes dead code on sight (2026-07-19 orphan-code cleanup).
- Preserve exact current behavior for the two existing caches: scope-isolated secret keys + `byID` reverse-index eviction, keyID+version isolation for keys, and — found while reading the full `internal/keycache` source, not in the original spec draft — **zeroing `PrivateKey`/`PublicKey` immediately after any entry removal** (TTL expiry, LRU eviction, explicit invalidation). This plan's `cachekit.Zeroable` interface (Task 1) covers it.
- Go build/vet/test/gofmt must stay clean after every task (this repo's existing bar — see CLAUDE.md).

---

## File Structure

**New:**
- `internal/cachekit/cachekit.go` — `Cloneable[T]`, `Zeroable`, `Config`+`Validate()`, `Stats`, `Interface[K,V]`
- `internal/cachekit/cache.go` — `Cache[K,V]` (the real implementation)
- `internal/cachekit/nop_cache.go` — `NopCache[K,V]` + `NewFromConfig[K,V]`
- `internal/cachekit/cachekit_test.go`, `cache_test.go`, `nop_cache_test.go`
- `internal/vaultcache/cache.go` — `Cache` wrapping `cachekit.Interface[string, *model.Vault]`
- `internal/vaultcache/cache_test.go`

**Modified:**
- `model/secret.go` — add `Clone()`, `cloneTimePtr()` (replaces `internal/cache`'s private `cloneSecret`/`cloneTime`)
- `model/vault.go` — add `Clone()`
- `internal/cache/secret_cache.go` — rewritten internals, same external API
- `internal/cache/secret_cache_test.go` — adapted
- `internal/cache/cache_integration.go` — no signature change, verified in Task 5
- `internal/keycache/cache.go` — `Entry.Clone()`, `Entry.Zero()`, `keyCacheKey`
- `internal/keycache/memory_cache.go` — rewritten to wrap `cachekit`, absorbs `nop_cache.go`
- `internal/keycache/*_test.go` — adapted
- `internal/services/vaults/vault_service.go` — `VaultCacheInterface`, `SetVaultCache`, cache-aware `getByName`, invalidation in Update/Delete/Recover/Purge
- `internal/services/secrets/rotation_service.go` — remove dead nil-check (line 129)
- `internal/services/secrets/versioning_service.go` — remove dead nil-check (line 89)
- `config/config.go` — `CacheConfig` struct + `LoadCacheConfig()`
- `config/config_test.go` — new tests
- `internal/container/service_container.go` — rewired construction, removed `cacheContext`/`cacheCancel`, always-non-nil caches
- `internal/container/container_test.go` — updated nil-vs-NopCache assertions, new vault-cache assertions
- `.rocketvault.yaml` — `key_cache:` → `cache:` (5 domains)
- `CLAUDE.md` — architecture tree + cache descriptions
- `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` — new breaking-change section

**Deleted:**
- `internal/cache/config.go` (replaced by `cachekit.Config` + `config.LoadCacheConfig`)
- `internal/keycache/config.go` (same)
- `internal/keycache/nop_cache.go` (folded into `memory_cache.go`)

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

### Task 4: Migrate `internal/keycache` onto `cachekit`

**Files:**
- Modify: `internal/keycache/cache.go` (add `Clone`, `Zero`, `keyCacheKey`; remove `Cache` interface's dependency on nothing external — interface itself is unchanged)
- Modify: `internal/keycache/memory_cache.go` (rewrite `cacheImpl` to wrap `cachekit.Interface[keyCacheKey, *Entry]`; absorb `NewNopCache`)
- Delete: `internal/keycache/config.go`, `internal/keycache/nop_cache.go`
- Modify: `internal/keycache/keycache_edge_test.go`, `internal/keycache/memory_cache_test.go` (adapt to new constructor; remove `TestDefaultKeyCacheConfig`)

**Interfaces:**
- Consumes: `cachekit.Config`, `cachekit.Interface[K,V]`, `cachekit.NewFromConfig[K,V]` from Tasks 1–3.
- Produces: `func NewCache(cfg cachekit.Config) Cache` (replaces `NewMemoryCache(cfg *KeyCacheConfig) Cache`), `func NewNopCache() Cache` (signature unchanged — existing call sites `key_service.go:144`, `crypto_service.go:162` need no changes), `(*Entry) Clone() *Entry`, `(*Entry) Zero()`. The exported `Cache` interface (`Get(keyID uuid.UUID, version int) (*Entry, bool)` etc.) is unchanged — this is an internals-only migration.

- [ ] **Step 1: Write the failing tests for `Entry.Clone`/`Entry.Zero`**

```go
// Add to internal/keycache/keycache_edge_test.go
func TestEntry_Clone_IndependentCopy(t *testing.T) {
	e := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: "original"},
		KeyType:    "RSA",
		Version:    1,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	clone := e.Clone()

	clone.KeyType = "ECDSA"
	assert.Equal(t, "RSA", e.KeyType, "mutating the clone must not affect the original")
	assert.Equal(t, keycache.PEMKey{PEM: "original"}, clone.PrivateKey)
}

func TestEntry_Zero_ClearsKeyMaterial(t *testing.T) {
	e := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: "secret"},
		PublicKey:  keycache.PEMKey{PEM: "public"},
	}
	e.Zero()
	assert.Nil(t, e.PrivateKey)
	assert.Nil(t, e.PublicKey)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/keycache/... -run "TestEntry_Clone|TestEntry_Zero" -v`
Expected: build failure — `e.Clone undefined`, `e.Zero undefined`.

- [ ] **Step 3: Implement `Clone`/`Zero` on `Entry`**

In `internal/keycache/cache.go`, after the `Entry` struct definition, add:

```go
// Clone returns a shallow copy of e. Safe because PrivateKey/PublicKey hold
// either nil or a PEMKey{PEM: string} — Go strings are immutable, so copying
// the interface value copies a read-only reference, not mutable state.
func (e *Entry) Clone() *Entry {
	cp := *e
	return &cp
}

// Zero clears key material in place. Called by cachekit after an entry is
// removed (TTL expiry, LRU eviction, invalidation) to shrink the in-memory
// exposure window rather than waiting for GC.
func (e *Entry) Zero() {
	e.PrivateKey = nil
	e.PublicKey = nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/keycache/... -run "TestEntry_Clone|TestEntry_Zero" -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for the new `NewCache(cfg cachekit.Config)` constructor**

Replace the top of `internal/keycache/memory_cache_test.go`'s config-construction pattern. Add this new test (keep the file's other tests for now — Step 9 adapts them):

```go
// Add to internal/keycache/memory_cache_test.go
func TestNewCache_GetSetInvalidate(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	c := keycache.NewCache(cfg)
	defer c.Stop()

	id := uuid.New()
	entry := &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: time.Now().Add(5 * time.Minute)}

	_, hit := c.Get(id, 1)
	assert.False(t, hit)

	c.Set(id, 1, entry)
	got, hit := c.Get(id, 1)
	require.True(t, hit)
	assert.Equal(t, "RSA", got.KeyType)

	_, hit = c.Get(id, 2)
	assert.False(t, hit, "different version is a miss")

	c.Set(id, 2, &keycache.Entry{KeyType: "RSA", Version: 2, ExpiresAt: time.Now().Add(time.Minute)})
	c.Invalidate(id)
	_, hit = c.Get(id, 1)
	assert.False(t, hit, "invalidate must remove all versions")
	_, hit = c.Get(id, 2)
	assert.False(t, hit)
}
```

Add `"rocketvault/internal/cachekit"` to this test file's imports.

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/keycache/... -run TestNewCache_GetSetInvalidate -v`
Expected: build failure — `undefined: keycache.NewCache`.

- [ ] **Step 7: Rewrite `memory_cache.go`, delete `nop_cache.go` and `config.go`**

```go
// internal/keycache/memory_cache.go
package keycache

import (
	"github.com/google/uuid"

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
```

Delete `internal/keycache/nop_cache.go` and `internal/keycache/config.go`:

```bash
git rm internal/keycache/nop_cache.go internal/keycache/config.go
```

- [ ] **Step 8: Run to verify Step 5's test passes**

Run: `go test ./internal/keycache/... -run TestNewCache_GetSetInvalidate -v`
Expected: PASS.

- [ ] **Step 9: Adapt the remaining existing tests to the new constructor**

In `internal/keycache/keycache_edge_test.go` and `internal/keycache/memory_cache_test.go`, replace every:

```go
cfg := &keycache.KeyCacheConfig{
    Enabled:         true,
    TTL:             X,
    MaxEntries:      Y,
    CleanupInterval: Z,
}
c := keycache.NewMemoryCache(cfg)
```

with:

```go
cfg := cachekit.Config{Enabled: true, TTL: X, CleanupInterval: Z, MaxEntries: Y}
c := keycache.NewCache(cfg)
```

(same X/Y/Z values each test already uses — only the constructor call shape changes). Add `"rocketvault/internal/cachekit"` to both files' imports.

Delete `TestDefaultKeyCacheConfig` from `keycache_edge_test.go` — `DefaultKeyCacheConfig` no longer exists; its default-value assertions move to `config` package tests in Task 8.

`TestMemoryCache_Get_ExpiredZeroesKeys` (in `keycache_edge_test.go`) already exercises exactly the `Zero()`-on-expiry behavior Task 1/2 built generically — keep it as-is; it should pass unchanged since `cacheImpl.Get` delegates to `cachekit.Cache.Get`, which already zeroes on expiry via `remove`.

- [ ] **Step 10: Run the full package test suite**

Run: `go test ./internal/keycache/... -v -race`
Expected: every test PASSes, including the pre-existing `TestMemoryCache_ConcurrentAccess`, `TestMemoryCache_Get_ExpiredZeroesKeys`, `TestNopCache_NeverHits` (still valid — `NewNopCache()`'s external behavior is unchanged).

- [ ] **Step 11: Verify no remaining references to the deleted types**

Run: `grep -rn "KeyCacheConfig\|DefaultKeyCacheConfig\|NewMemoryCache" --include="*.go" .`
Expected: no output (all call sites updated).

- [ ] **Step 12: Commit**

```bash
git add internal/keycache/
git commit -m "refactor(keycache): migrate onto cachekit.Cache, preserve external Cache interface and Zero-on-remove behavior"
```

---

### Task 5: Migrate `internal/cache` (secrets) onto `cachekit`

**Files:**
- Modify: `model/secret.go` (add `Clone()`, `cloneTimePtr()`)
- Modify: `internal/cache/secret_cache.go` (rewrite internals; external API unchanged)
- Delete: `internal/cache/config.go`
- Modify: `internal/cache/secret_cache_test.go` (adapt constructor calls)
- Verify unchanged: `internal/cache/cache_integration.go` (no edits expected — confirm in Step 9)

**Interfaces:**
- Consumes: `cachekit.Config`, `cachekit.Interface[K,V]`, `cachekit.NewFromConfig[K,V]`.
- Produces: `func NewSecretCache(cfg cachekit.Config, logger *logrus.Logger) *SecretCache` (replaces `NewSecretCache(ttl time.Duration, logger *logrus.Logger) *SecretCache`). All other `SecretCache` methods (`Get`, `Set`, `DeleteByID`, `Flush`, `GetStats`) keep their exact existing signatures. `Clear`/`StartCleanup` are removed — `cachekit.Cache` self-manages its TTL sweep from construction, same as `keycache` always did, so callers no longer call `StartCleanup` separately. Adds `(*SecretCache) Stop()`.

- [ ] **Step 1: Write the failing test for `model.Secret.Clone()`**

```go
// Add to model/secret_test.go (create the file if it doesn't exist yet — check first: `ls model/secret_test.go`)
package model_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestSecret_Clone_IndependentCopy(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	s := &model.Secret{
		ID:        uuid.New(),
		Name:      "original",
		Tags:      []string{"a", "b"},
		ExpiresAt: &exp,
	}
	clone := s.Clone()

	clone.Name = "changed"
	clone.Tags[0] = "mutated"
	*clone.ExpiresAt = time.Now().Add(2 * time.Hour)

	assert.Equal(t, "original", s.Name, "mutating the clone's Name must not affect the original")
	assert.Equal(t, "a", s.Tags[0], "mutating the clone's Tags must not affect the original's backing array")
	assert.NotEqual(t, *s.ExpiresAt, *clone.ExpiresAt, "mutating the clone's ExpiresAt must not affect the original's pointee")
}

func TestSecret_Clone_NilPointerFieldsStayNil(t *testing.T) {
	s := &model.Secret{ID: uuid.New(), Name: "x"}
	clone := s.Clone()
	assert.Nil(t, clone.ExpiresAt)
	assert.Nil(t, clone.NotBefore)
	assert.Nil(t, clone.DeletedAt)
	assert.Nil(t, clone.ScheduledPurgeAt)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./model/... -run TestSecret_Clone -v`
Expected: build failure — `s.Clone undefined`.

- [ ] **Step 3: Implement `Clone`/`cloneTimePtr` on `model.Secret`**

In `model/secret.go`, after the `Secret` struct's existing methods (`IsExpired`/`IsActive`/`IsAccessible`/`DaysUntilExpiration`), add:

```go
// Clone returns a copy of s that shares no mutable state with the original:
// the struct itself, its tag slice, and every time pointer are all
// independently copied. Used by SecretCache so a caller that mutates a
// fetched secret before persisting an update can never corrupt a cache entry
// or race a concurrent reader.
func (s *Secret) Clone() *Secret {
	cp := *s
	if s.Tags != nil {
		cp.Tags = append([]string(nil), s.Tags...)
	}
	cp.ExpiresAt = cloneTimePtr(s.ExpiresAt)
	cp.NotBefore = cloneTimePtr(s.NotBefore)
	cp.DeletedAt = cloneTimePtr(s.DeletedAt)
	cp.ScheduledPurgeAt = cloneTimePtr(s.ScheduledPurgeAt)
	return &cp
}

// cloneTimePtr copies an optional timestamp, preserving nil. Shared by
// Secret.Clone and Vault.Clone (Task 6).
func cloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./model/... -run TestSecret_Clone -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for the new `NewSecretCache(cfg, logger)` constructor**

```go
// Add to internal/cache/secret_cache_test.go — check the file's existing
// imports/helpers first (`cat internal/cache/secret_cache_test.go`) and
// match its existing scope-construction helpers rather than duplicating them.
func TestNewSecretCache_GetSetDeleteByID(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	logger := logrus.New()
	c := cache.NewSecretCache(cfg, logger)
	defer c.Stop()

	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID)
	secret := &model.Secret{ID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "v1"}

	_, found := c.Get(context.Background(), secret.ID, scope)
	assert.False(t, found)

	require.NoError(t, c.Set(context.Background(), secret, scope))
	got, found := c.Get(context.Background(), secret.ID, scope)
	require.True(t, found)
	assert.Equal(t, "s1", got.Name)

	require.NoError(t, c.DeleteByID(context.Background(), secret.ID))
	_, found = c.Get(context.Background(), secret.ID, scope)
	assert.False(t, found, "DeleteByID must evict the entry")
}
```

Check whether `model.NewVaultScope` is the actual constructor name used elsewhere in this test file (`grep -n "NewVaultScope\|model.Scope{" internal/cache/secret_cache_test.go`) and match it exactly — don't guess if the existing file uses a different helper.

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/cache/... -run TestNewSecretCache_GetSetDeleteByID -v`
Expected: build failure — `cache.NewSecretCache` signature mismatch (old signature takes `time.Duration`, not `cachekit.Config`).

- [ ] **Step 7: Rewrite `secret_cache.go`, delete `config.go`**

```go
// internal/cache/secret_cache.go
// Package cache provides in-memory caching functionality for secrets
// with TTL support for performance optimization and reduced database load.
package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// SecretCache provides thread-safe in-memory caching for secrets with TTL
// support. Entries are keyed by (scope, secret id), so a value admitted under
// one scope can never satisfy a read under another. A byID reverse index lets
// a single mutation evict every scoped view of a secret. Wraps cachekit.Cache
// for storage/TTL/LRU; the scope-key + reverse-index logic here is secret-
// domain-specific composition on top.
type SecretCache struct {
	core   cachekit.Interface[string, *model.Secret]
	byIDMu sync.Mutex
	byID   map[uuid.UUID]map[string]struct{}
	logger *logrus.Logger
}

// NewSecretCache creates a SecretCache from cfg. Always returns a usable
// cache: a real one (self-managing its own TTL sweep from construction) when
// cfg.Enabled, a no-op one otherwise.
func NewSecretCache(cfg cachekit.Config, logger *logrus.Logger) *SecretCache {
	return &SecretCache{
		core:   cachekit.NewFromConfig[string, *model.Secret](cfg),
		byID:   make(map[uuid.UUID]map[string]struct{}),
		logger: logger,
	}
}

// scopeCacheKey builds the compound cache key for a scoped read. It reports
// false for scopes that must never be cached: ScopeAdmin, which has no
// predicate, and any invalid scope.
func scopeCacheKey(secretID uuid.UUID, scope model.Scope) (string, bool) {
	if scope.Validate() != nil {
		return "", false
	}
	switch scope.Kind() {
	case model.ScopeVault:
		return "v|" + scope.VaultID().String() + "|" + secretID.String(), true
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		if !ok {
			return "", false
		}
		return "o|" + ownerID.String() + "|" + secretID.String(), true
	default:
		return "", false
	}
}

// Get retrieves a secret cached under the given scope, if it has not expired.
func (c *SecretCache) Get(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, bool) {
	key, cacheable := scopeCacheKey(secretID, scope)
	if !cacheable {
		return nil, false
	}
	secret, ok := c.core.Get(key)
	if !ok {
		c.logger.WithField("secret_id", secretID).Debug("Cache miss")
		return nil, false
	}
	c.logger.WithField("secret_id", secretID).Debug("Cache hit")
	return secret, true
}

// Set stores a secret under the given scope with TTL expiration. Scopes that
// must not be cached are a silent no-op.
func (c *SecretCache) Set(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	if secret == nil {
		return fmt.Errorf("cannot cache nil secret")
	}
	key, cacheable := scopeCacheKey(secret.ID, scope)
	if !cacheable {
		return nil
	}
	c.core.Set(key, secret)

	c.byIDMu.Lock()
	if c.byID[secret.ID] == nil {
		c.byID[secret.ID] = make(map[string]struct{})
	}
	c.byID[secret.ID][key] = struct{}{}
	c.byIDMu.Unlock()

	c.logger.WithFields(logrus.Fields{"secret_id": secret.ID, "scope": scope.String()}).Debug("Secret cached successfully")
	return nil
}

// DeleteByID evicts every scoped view of a secret. It is the invalidation
// primitive: a mutation authorized under one scope must not leave a stale
// entry visible under another.
func (c *SecretCache) DeleteByID(ctx context.Context, secretID uuid.UUID) error {
	c.byIDMu.Lock()
	keys := c.byID[secretID]
	delete(c.byID, secretID)
	c.byIDMu.Unlock()

	for key := range keys {
		c.core.Invalidate(key)
	}
	c.logger.WithField("secret_id", secretID).Debug("Secret removed from cache")
	return nil
}

// Flush removes every entry from the cache unconditionally, live or
// expired — the correct primitive for callers that need a guaranteed-empty
// cache (e.g. a vault delete/recover cascade that writes secrets directly).
func (c *SecretCache) Flush(ctx context.Context) error {
	c.core.InvalidateAll()
	c.byIDMu.Lock()
	removed := len(c.byID)
	c.byID = make(map[uuid.UUID]map[string]struct{})
	c.byIDMu.Unlock()
	c.logger.WithField("removed_count", removed).Debug("Cache flushed")
	return nil
}

// GetStats returns cache statistics.
func (c *SecretCache) GetStats() map[string]interface{} {
	s := c.core.Stats()
	return map[string]interface{}{
		"total_entries":   s.TotalEntries,
		"expired_entries": s.ExpiredEntries,
	}
}

// Stop shuts down the background TTL sweep. Safe to call more than once.
func (c *SecretCache) Stop() {
	c.core.Stop()
}
```

`cloneSecret`/`cloneTime` are gone — replaced by `model.Secret.Clone()`, called automatically inside `cachekit.Cache.Get`/`Set`. `Clear`/`StartCleanup` are gone — `cachekit.Cache`'s own background sweep (started in `New`, called from `NewFromConfig`) replaces the caller-driven `StartCleanup(ctx, interval)` dance.

Delete `internal/cache/config.go`:

```bash
git rm internal/cache/config.go
```

- [ ] **Step 8: Run to verify Step 5's test passes**

Run: `go test ./internal/cache/... -run TestNewSecretCache_GetSetDeleteByID -v`
Expected: PASS.

- [ ] **Step 9: Verify `cache_integration.go` needs no changes**

Read `internal/cache/cache_integration.go`. `CachedSecretService.GetSecret` calls `s.cache.Get(ctx, secretID, scope)`, `s.cache.DeleteByID(ctx, secretID)`, `s.cache.Set(ctx, secret, scope)` — all three signatures are unchanged by this migration. Confirm with:

Run: `go build ./internal/cache/...`
Expected: no errors (if there were a signature mismatch, this would fail to compile).

- [ ] **Step 10: Adapt the rest of `secret_cache_test.go`**

Read the full existing file first: `cat internal/cache/secret_cache_test.go`. For every test that calls `cache.NewSecretCache(<ttl>, <logger>)`, change to `cache.NewSecretCache(cachekit.Config{Enabled: true, TTL: <ttl>, CleanupInterval: <some interval less than ttl>, MaxEntries: 1000}, <logger>)` — pick a `CleanupInterval` proportionally smaller than whatever TTL each existing test already used (e.g. TTL/10, minimum 1ms), preserving each test's original intent. Remove any test that specifically exercises the old `StartCleanup`/`Clear` two-step API (e.g. a test named like `TestSecretCache_StartCleanup` or `TestSecretCache_Clear`) — replace it with an equivalent TTL-expiry assertion using `Get` after a `time.Sleep`, matching the pattern already used in `internal/cachekit/cache_test.go`'s `TestCache_Get_MissAfterTTLExpiry`, since expiry is now `cachekit`'s responsibility and already covered there; a domain-level test here should only confirm the SecretCache wrapper still calls through correctly, not re-prove the underlying sweep mechanics. Add `"rocketvault/internal/cachekit"` to the file's imports; remove `"time"` from imports if it becomes unused.

- [ ] **Step 11: Run the full package test suite**

Run: `go test ./internal/cache/... -v -race`
Expected: every test PASSes.

- [ ] **Step 12: Verify no remaining references to deleted symbols**

Run: `grep -rn "cache.DefaultCacheConfig\|cache.DevelopmentCacheConfig\|cache.ProductionCacheConfig\|cache.CacheConfig\b" --include="*.go" . | grep -v _test.go`
Expected: no output outside test/container files not yet updated (container updates happen in Task 9 — if this grep hits `internal/container/service_container.go`, that's expected at this point in the plan and will be resolved there).

- [ ] **Step 13: Commit**

```bash
git add model/secret.go internal/cache/ $(test -f model/secret_test.go && echo model/secret_test.go)
git commit -m "refactor(cache): migrate SecretCache onto cachekit.Cache, add model.Secret.Clone()"
```

---

### Task 6: New `internal/vaultcache` package

**Files:**
- Modify: `model/vault.go` (add `Clone()`)
- Create: `internal/vaultcache/cache.go`
- Test: `internal/vaultcache/cache_test.go`

**Interfaces:**
- Consumes: `cachekit.Config`, `cachekit.Interface[K,V]`, `cachekit.NewFromConfig[K,V]`, `cloneTimePtr` is package-private to `model` — `Vault.Clone()` reuses it directly (same package).
- Produces: `func NewCache(cfg cachekit.Config) *Cache`, `(*Cache) Get(name string) (*model.Vault, bool)`, `(*Cache) Set(name string, v *model.Vault)`, `(*Cache) Invalidate(name string)`, `(*Cache) Stop()`.

- [ ] **Step 1: Write the failing test for `model.Vault.Clone()`**

```go
// model/vault_test.go — check first whether this file exists (`ls model/vault_test.go`); create if not.
package model_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestVault_Clone_IndependentCopy(t *testing.T) {
	updatedBy := uuid.New()
	v := &model.Vault{
		ID:        uuid.New(),
		Name:      "original",
		Tags:      map[string]string{"env": "prod"},
		UpdatedBy: &updatedBy,
	}
	clone := v.Clone()

	clone.Name = "changed"
	clone.Tags["env"] = "mutated"
	*clone.UpdatedBy = uuid.New()

	assert.Equal(t, "original", v.Name)
	assert.Equal(t, "prod", v.Tags["env"], "mutating the clone's Tags must not affect the original's backing map")
	assert.NotEqual(t, *v.UpdatedBy, *clone.UpdatedBy)
}

func TestVault_Clone_NilFieldsStayNil(t *testing.T) {
	v := &model.Vault{ID: uuid.New(), Name: "x"}
	clone := v.Clone()
	assert.Nil(t, clone.Tags)
	assert.Nil(t, clone.DeletedAt)
	assert.Nil(t, clone.ScheduledPurgeAt)
	assert.Nil(t, clone.UpdatedAt)
	assert.Nil(t, clone.UpdatedBy)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./model/... -run TestVault_Clone -v`
Expected: build failure — `v.Clone undefined`.

- [ ] **Step 3: Implement `Clone` on `model.Vault`**

In `model/vault.go`, after the `ValidateVaultTags` function, add:

```go
// Clone returns a copy of v that shares no mutable state with the original —
// the struct itself, its Tags map, and every pointer field are independently
// copied. Used by vaultcache.Cache so a caller that mutates a fetched vault
// before persisting an update (VaultService.UpdateVault does exactly this)
// can never corrupt a cache entry.
func (v *Vault) Clone() *Vault {
	cp := *v
	if v.Tags != nil {
		cp.Tags = make(map[string]string, len(v.Tags))
		for k, val := range v.Tags {
			cp.Tags[k] = val
		}
	}
	cp.DeletedAt = cloneTimePtr(v.DeletedAt)
	cp.ScheduledPurgeAt = cloneTimePtr(v.ScheduledPurgeAt)
	cp.UpdatedAt = cloneTimePtr(v.UpdatedAt)
	if v.UpdatedBy != nil {
		id := *v.UpdatedBy
		cp.UpdatedBy = &id
	}
	return &cp
}
```

(`cloneTimePtr` was added to `model/secret.go` in Task 5 — same package, no new helper needed.)

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./model/... -run TestVault_Clone -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `vaultcache.Cache`**

```go
// internal/vaultcache/cache_test.go
package vaultcache_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/vaultcache"
	"rocketvault/model"
)

func TestCache_SetThenGet_Hit(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	v := &model.Vault{ID: uuid.New(), Name: "myvault"}
	c.Set("myvault", v)

	got, ok := c.Get("myvault")
	require.True(t, ok)
	assert.Equal(t, "myvault", got.Name)
}

func TestCache_Get_MissForUnknownName(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	_, ok := c.Get("nonexistent")
	assert.False(t, ok)
}

func TestCache_Invalidate_RemovesEntry(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	c.Set("myvault", &model.Vault{ID: uuid.New(), Name: "myvault"})
	c.Invalidate("myvault")

	_, ok := c.Get("myvault")
	assert.False(t, ok)
}

func TestCache_Get_ReturnsClone(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	c.Set("myvault", &model.Vault{ID: uuid.New(), Name: "myvault", Enabled: true})

	got, _ := c.Get("myvault")
	got.Enabled = false // mutate the returned value

	again, _ := c.Get("myvault")
	assert.True(t, again.Enabled, "mutating a Get result must not affect the stored entry")
}

func TestCache_Disabled_NeverHits(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: false, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	c.Set("myvault", &model.Vault{ID: uuid.New(), Name: "myvault"})
	_, ok := c.Get("myvault")
	assert.False(t, ok)
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/vaultcache/... -v`
Expected: build failure — package `internal/vaultcache` doesn't exist yet.

- [ ] **Step 7: Write the minimal implementation**

```go
// internal/vaultcache/cache.go

// Package vaultcache caches vault records by name, closing the gap where
// VaultResolutionMiddleware resolved every request's vault by name with no
// caching layer at all — the single most-frequently-repeated DB lookup in
// the codebase.
package vaultcache

import (
	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// Cache caches *model.Vault by name.
type Cache struct {
	core cachekit.Interface[string, *model.Vault]
}

// NewCache creates a Cache from cfg. Always returns a usable cache: a real
// one when cfg.Enabled, a no-op one otherwise.
func NewCache(cfg cachekit.Config) *Cache {
	return &Cache{core: cachekit.NewFromConfig[string, *model.Vault](cfg)}
}

// Get returns a clone of the vault cached under name, if present and unexpired.
func (c *Cache) Get(name string) (*model.Vault, bool) {
	return c.core.Get(name)
}

// Set stores a clone of v under name.
func (c *Cache) Set(name string, v *model.Vault) {
	c.core.Set(name, v)
}

// Invalidate evicts the entry cached under name, if any.
func (c *Cache) Invalidate(name string) {
	c.core.Invalidate(name)
}

// Stop shuts down the background TTL sweep. Safe to call more than once.
func (c *Cache) Stop() {
	c.core.Stop()
}
```

- [ ] **Step 8: Run to verify it passes**

Run: `go test ./internal/vaultcache/... -v -race`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add model/vault.go internal/vaultcache/ $(test -f model/vault_test.go && echo model/vault_test.go)
git commit -m "feat(vaultcache): add vault-by-name cache; add model.Vault.Clone()"
```

---

### Task 7: Wire `vaultcache.Cache` into `VaultService`

**Files:**
- Modify: `internal/services/vaults/vault_service.go`
- Test: `internal/services/vaults/vault_cache_test.go` (new file — check first whether existing vault service tests live in one file or several: `ls internal/services/vaults/*_test.go`)

**Interfaces:**
- Consumes: `*vaultcache.Cache` (satisfies the new `VaultCacheInterface` below) from Task 6.
- Produces: `VaultCacheInterface interface{ Get(name string)(*model.Vault,bool); Set(name string, v *model.Vault); Invalidate(name string) }` (declared in the `vaults` package, mirroring the existing `SecretCacheFlusher`/`CascadeRepository` consumer-side-interface pattern already in this file), `(s *vaultService) SetVaultCache(c VaultCacheInterface)`, added to the `VaultService` interface.

- [ ] **Step 1: Write the failing tests**

Check the existing test setup pattern first: `grep -n "func newTestVaultService\|type fakeVaultRepo\|type mockVaultRepo" internal/services/vaults/*_test.go` — reuse whatever fake/mock repo constructor already exists rather than inventing a new one. The examples below assume a `newTestService(t)` helper exists that returns a `*vaultService`-backed `VaultService` with an in-memory fake repo pre-seeded with one vault named `"myvault"`; adapt the setup lines to match whatever helper actually exists in the file you find.

```go
// internal/services/vaults/vault_cache_test.go
package vaults

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// spyVaultCache records calls so tests can assert on cache-vs-repo behavior
// without depending on the real vaultcache.Cache implementation.
type spyVaultCache struct {
	store      map[string]*model.Vault
	getCalls   int
	setCalls   int
	invalidated []string
}

func newSpyVaultCache() *spyVaultCache {
	return &spyVaultCache{store: make(map[string]*model.Vault)}
}

func (s *spyVaultCache) Get(name string) (*model.Vault, bool) {
	s.getCalls++
	v, ok := s.store[name]
	return v, ok
}
func (s *spyVaultCache) Set(name string, v *model.Vault) {
	s.setCalls++
	cp := *v
	s.store[name] = &cp
}
func (s *spyVaultCache) Invalidate(name string) {
	s.invalidated = append(s.invalidated, name)
	delete(s.store, name)
}

func TestGetVault_PopulatesCacheOnMiss(t *testing.T) {
	svc, repo := newTestServiceWithVault(t, "myvault") // adapt to the real helper name found above
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	v, err := svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	assert.Equal(t, "myvault", v.Name)
	assert.Equal(t, 1, spy.setCalls, "a repo hit must populate the cache")
	_ = repo
}

func TestGetVault_SecondCallHitsCacheNotRepo(t *testing.T) {
	svc, repo := newTestServiceWithVault(t, "myvault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	_, err := svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	callsBefore := repo.readByNameCalls // adapt field name to whatever the fake repo tracks

	_, err = svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	assert.Equal(t, callsBefore, repo.readByNameCalls, "second GetVault must be served from cache, not the repo")
}

func TestUpdateVault_InvalidatesCache(t *testing.T) {
	svc, _ := newTestServiceWithVault(t, "myvault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	_, err := svc.GetVault(context.Background(), "myvault") // populate the cache
	require.NoError(t, err)

	enabled := false
	_, err = svc.UpdateVault(context.Background(), "myvault", model.UpdateVaultRequest{Enabled: &enabled}, uuid.New())
	require.NoError(t, err)

	assert.Contains(t, spy.invalidated, "myvault", "UpdateVault must invalidate the cache entry")
}

func TestUpdateVault_MutatingResultDoesNotCorruptPriorCacheEntry(t *testing.T) {
	svc, _ := newTestServiceWithVault(t, "myvault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	first, err := svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	require.True(t, first.Enabled)

	enabled := false
	_, err = svc.UpdateVault(context.Background(), "myvault", model.UpdateVaultRequest{Enabled: &enabled}, uuid.New())
	require.NoError(t, err)

	// The spy's cached copy (from the Set during the first GetVault) must be
	// untouched by UpdateVault's later in-place mutation of the pointer it
	// got back from getByName — proving Get returns an independent value.
	cached := spy.store["myvault"]
	require.NotNil(t, cached)
	assert.True(t, cached.Enabled, "the stale cache entry must survive until explicit Invalidate, not be corrupted by the live mutation")
}

func TestDeleteVault_InvalidatesCache(t *testing.T) {
	svc, _ := newTestServiceWithVault(t, "notdefault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	_, err := svc.GetVault(context.Background(), "notdefault")
	require.NoError(t, err)

	err = svc.DeleteVault(context.Background(), "notdefault")
	require.NoError(t, err)

	assert.Contains(t, spy.invalidated, "notdefault")
}
```

Note: `TestUpdateVault_MutatingResultDoesNotCorruptPriorCacheEntry` will only pass once `spyVaultCache.Set` stores its own defensive copy (it does, above — `cp := *v`) *and* `getByName` is wired to prefer the cache. If the real `vaultcache.Cache` from Task 6 is used instead of this spy in a follow-up integration test, its `Clone()`-on-`Set`/`Get` gives the same guarantee automatically.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/services/vaults/... -run "TestGetVault_PopulatesCacheOnMiss|TestGetVault_SecondCallHitsCacheNotRepo|TestUpdateVault_InvalidatesCache|TestUpdateVault_MutatingResultDoesNotCorruptPriorCacheEntry|TestDeleteVault_InvalidatesCache" -v`
Expected: build failure — `svc.(*vaultService).SetVaultCache undefined`.

- [ ] **Step 3: Implement the wiring in `vault_service.go`**

Add near the top, after the existing `SecretCacheFlusher` interface:

```go
// VaultCacheInterface caches vault records by name. Satisfied by
// *vaultcache.Cache. Declared here (not imported from internal/vaultcache)
// to keep this package import-cycle-free, matching the existing
// SecretCacheFlusher pattern in this same file.
type VaultCacheInterface interface {
	Get(name string) (*model.Vault, bool)
	Set(name string, v *model.Vault)
	Invalidate(name string)
}
```

Add `vaultCache VaultCacheInterface` to the `vaultService` struct:

```go
type vaultService struct {
	repo        repositories.VaultRepositoryInterface
	cascade     CascadeRepository
	policies    PolicyCleaner
	txBeginner  TxBeginner
	secretCache SecretCacheFlusher
	vaultCache  VaultCacheInterface
	log         *logging.Logger
}
```

Add `SetVaultCache(c VaultCacheInterface)` to the `VaultService` interface:

```go
type VaultService interface {
	CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error)
	GetVault(ctx context.Context, name string) (*model.Vault, error)
	ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error)
	UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RecoverVault(ctx context.Context, name string) error
	PurgeVault(ctx context.Context, name string) error
	SetPolicyCleaner(p PolicyCleaner)
	SetTxBeginner(tb TxBeginner)
	SetSecretCacheFlusher(f SecretCacheFlusher)
	SetVaultCache(c VaultCacheInterface)
}
```

Add the setter, next to `SetSecretCacheFlusher`:

```go
// SetVaultCache attaches an optional vault-by-name cache. When set,
// getByName consults it before the repository and populates it on a miss;
// Update/Delete/Recover/Purge invalidate the entry after a successful write.
// Unset means vault caching is disabled.
func (s *vaultService) SetVaultCache(c VaultCacheInterface) { s.vaultCache = c }
```

Rewrite `getByName`:

```go
func (s *vaultService) getByName(ctx context.Context, name string) (*model.Vault, error) {
	if s.vaultCache != nil {
		if v, ok := s.vaultCache.Get(name); ok {
			return v, nil
		}
	}
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)
		}
		return nil, fmt.Errorf("get vault %q: %w", name, err)
	}
	if s.vaultCache != nil {
		s.vaultCache.Set(name, v)
	}
	return v, nil
}
```

In `UpdateVault`, after the existing `if err := s.repo.Update(ctx, v); err != nil { return nil, ... }` block, before the `if s.log != nil` block, add:

```go
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
```

In `DeleteVault`, right after the existing `s.flushSecretCache(ctx, v.ID, "vault delete")` line, add:

```go
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
```

In `RecoverVault`, right after the existing `s.flushSecretCache(ctx, v.ID, "vault recover")` line, add:

```go
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
```

In `PurgeVault`, right after the existing `if err := s.repo.Purge(ctx, v.ID); err != nil { return err }` block, before the `access_policies` cleanup comment, add:

```go
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/services/vaults/... -v -race`
Expected: every test PASSes, including the five new ones and every pre-existing test in the package (confirming `getByName`'s cache-check is a no-op when `SetVaultCache` was never called — `s.vaultCache` stays nil, so every pre-existing test that never calls `SetVaultCache` exercises exactly the old code path).

- [ ] **Step 5: Commit**

```bash
git add internal/services/vaults/
git commit -m "feat(vaults): wire vault-by-name caching into VaultService via optional VaultCacheInterface"
```

---

### Task 8: `config.CacheConfig` + `config.LoadCacheConfig()`

**Files:**
- Modify: `config/config.go`
- Modify: `config/config_test.go`

**Interfaces:**
- Consumes: `cachekit.Config` (Task 1).
- Produces: `type CacheConfig struct{ Secrets, Keys, Vaults, Certificates, Users cachekit.Config }`, `func LoadCacheConfig() (CacheConfig, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// Add to config/config_test.go
func TestLoadCacheConfig_Defaults(t *testing.T) {
	reset()

	cfg, err := LoadCacheConfig()
	require.NoError(t, err)

	assert.True(t, cfg.Secrets.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.Secrets.TTL)
	assert.Equal(t, time.Minute, cfg.Secrets.CleanupInterval)
	assert.Equal(t, 1000, cfg.Secrets.MaxEntries)

	assert.True(t, cfg.Keys.Enabled)
	assert.Equal(t, 60*time.Second, cfg.Keys.TTL)
	assert.Equal(t, 30*time.Second, cfg.Keys.CleanupInterval)
	assert.Equal(t, 500, cfg.Keys.MaxEntries)

	assert.True(t, cfg.Vaults.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.Vaults.TTL)
	assert.Equal(t, time.Minute, cfg.Vaults.CleanupInterval)
	assert.Equal(t, 500, cfg.Vaults.MaxEntries)

	assert.False(t, cfg.Certificates.Enabled, "certificates has no consumer yet, must default off")
	assert.False(t, cfg.Users.Enabled, "users has no consumer yet, must default off")
}

func TestLoadCacheConfig_OverridesRead(t *testing.T) {
	reset()
	viper.Set("cache.secrets.enabled", false)
	viper.Set("cache.keys.ttl", "10s")
	viper.Set("cache.vaults.max_entries", 999)
	viper.Set("cache.certificates.enabled", true)

	cfg, err := LoadCacheConfig()
	require.NoError(t, err)

	assert.False(t, cfg.Secrets.Enabled)
	assert.Equal(t, 10*time.Second, cfg.Keys.TTL)
	assert.Equal(t, 999, cfg.Vaults.MaxEntries)
	assert.True(t, cfg.Certificates.Enabled)
}

func TestLoadCacheConfig_InvalidTTLReturnsError(t *testing.T) {
	reset()
	viper.Set("cache.secrets.ttl", "0s")

	_, err := LoadCacheConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache.secrets")
}
```

Add `require` to the test file's imports if not already present (`github.com/stretchr/testify/require`).

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./config/... -run TestLoadCacheConfig -v`
Expected: build failure — `undefined: LoadCacheConfig`.

- [ ] **Step 3: Implement `CacheConfig` and `LoadCacheConfig`**

In `config/config.go`, add `"rocketvault/internal/cachekit"` to imports, then add after `LoadMonitoringConfig` (or after `LoadSoftDeleteConfig` if `LoadMonitoringConfig` isn't present in this file — match whatever loader function already sits last in the file):

```go
// CacheConfig holds cachekit.Config for every domain that caches records.
type CacheConfig struct {
	Secrets      cachekit.Config
	Keys         cachekit.Config
	Vaults       cachekit.Config
	Certificates cachekit.Config
	Users        cachekit.Config
}

// loadCacheDomainConfig reads one domain's cache.<prefix>.* keys from Viper,
// overriding def field-by-field for whichever keys are explicitly set.
func loadCacheDomainConfig(prefix string, def cachekit.Config) cachekit.Config {
	cfg := def
	if viper.IsSet(prefix + ".enabled") {
		cfg.Enabled = viper.GetBool(prefix + ".enabled")
	}
	if viper.IsSet(prefix + ".ttl") {
		cfg.TTL = viper.GetDuration(prefix + ".ttl")
	}
	if viper.IsSet(prefix + ".cleanup_interval") {
		cfg.CleanupInterval = viper.GetDuration(prefix + ".cleanup_interval")
	}
	if viper.IsSet(prefix + ".max_entries") {
		cfg.MaxEntries = viper.GetInt(prefix + ".max_entries")
	}
	return cfg
}

// LoadCacheConfig reads cache.<domain>.* settings from Viper for all five
// domains, falling back to safe per-domain defaults, and validates each one.
// certificates/users default Enabled: false — no cache wrapper consumes them
// yet (see docs/superpowers/specs/2026-08-14-generic-cache-config-design.md).
func LoadCacheConfig() (CacheConfig, error) {
	cfg := CacheConfig{
		Secrets:      loadCacheDomainConfig("cache.secrets", cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 1000}),
		Keys:         loadCacheDomainConfig("cache.keys", cachekit.Config{Enabled: true, TTL: 60 * time.Second, CleanupInterval: 30 * time.Second, MaxEntries: 500}),
		Vaults:       loadCacheDomainConfig("cache.vaults", cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
		Certificates: loadCacheDomainConfig("cache.certificates", cachekit.Config{Enabled: false, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
		Users:        loadCacheDomainConfig("cache.users", cachekit.Config{Enabled: false, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
	}

	domains := []struct {
		name string
		cfg  cachekit.Config
	}{
		{"secrets", cfg.Secrets}, {"keys", cfg.Keys}, {"vaults", cfg.Vaults},
		{"certificates", cfg.Certificates}, {"users", cfg.Users},
	}
	for _, d := range domains {
		if err := d.cfg.Validate(); err != nil {
			return CacheConfig{}, fmt.Errorf("cache.%s: %w", d.name, err)
		}
	}
	return cfg, nil
}
```

Add `"fmt"` to imports if not already present.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./config/... -run TestLoadCacheConfig -v`
Expected: all 3 subtests PASS.

- [ ] **Step 5: Run the full config package suite**

Run: `go test ./config/... -v`
Expected: no regressions in existing `TestLoadSoftDeleteConfig_*`/`TestLoadMonitoringConfig_*` tests.

- [ ] **Step 6: Commit**

```bash
git add config/config.go config/config_test.go
git commit -m "feat(config): add CacheConfig + LoadCacheConfig, unifying cache.<domain>.* YAML schema"
```

---

### Task 9: Rewire `internal/container/service_container.go`

**Files:**
- Modify: `internal/container/service_container.go`
- Modify: `internal/container/container_test.go`
- Modify: `internal/services/secrets/rotation_service.go` (remove dead nil-check)
- Modify: `internal/services/secrets/versioning_service.go` (remove dead nil-check)

**Interfaces:**
- Consumes: `config.CacheConfig`/`config.LoadCacheConfig()` (Task 8), `cache.NewSecretCache(cfg cachekit.Config, logger)` (Task 5), `keycache.NewCache(cfg cachekit.Config)` (Task 4), `vaultcache.NewCache(cfg cachekit.Config)` (Task 6), `vaultService.SetVaultCache` (Task 7).
- Produces: `ServiceContainer.GetSecretCache()`, `GetKeyCache()`, and a new `GetVaultCache() *vaultcache.Cache` all always return a real, non-nil object (real-or-Nop internally). `GetCacheConfig()` now returns `config.CacheConfig` (value, not `*cache.CacheConfig`).

- [ ] **Step 1: Read the current state of everything this task touches**

```bash
sed -n '1,35p' internal/container/service_container.go
grep -n "cacheConfig\|cacheContext\|cacheCancel\|secretCache\|keyCache\|vaultCache\|CacheConfig" internal/container/service_container.go
```

Confirm line numbers match what was read earlier in this planning session before making edits — file may have shifted slightly; use the printed grep output as ground truth, not the numbers written in this plan.

- [ ] **Step 2: Update imports**

In `internal/container/service_container.go`, add:

```go
rvconfig "rocketvault/config"
"rocketvault/internal/vaultcache"
```

The alias `rvconfig` is required because `NewServiceContainer(config Config)`'s parameter is itself named `config`, which would otherwise shadow the `rocketvault/config` package inside that function.

- [ ] **Step 3: Update the `Config` and `ServiceContainer` struct fields**

Change:

```go
type Config struct {
	Database    *sql.DB
	Logger      *logging.Logger
	CacheConfig *cache.CacheConfig
	Viper       *viper.Viper
}
```

to:

```go
type Config struct {
	Database    *sql.DB
	Logger      *logging.Logger
	CacheConfig *rvconfig.CacheConfig
	Viper       *viper.Viper
}
```

Change the `ServiceContainer` struct's cache fields:

```go
	// Cache infrastructure
	secretCache         *cache.SecretCache
	cachedSecretService secrets.SecretService
	cacheConfig         *cache.CacheConfig
	cacheContext        context.Context
	cacheCancel         context.CancelFunc
```

to:

```go
	// Cache infrastructure
	secretCache         *cache.SecretCache
	cachedSecretService secrets.SecretService
	cacheConfig         rvconfig.CacheConfig
	vaultCache          *vaultcache.Cache
```

(dropping `cacheContext`/`cacheCancel` — `cachekit.Cache` self-manages its sweep goroutine from construction via `Stop()`, the same lifecycle keycache already used, so the separate context-cancellation plumbing is no longer needed).

- [ ] **Step 4: Update `NewServiceContainer`'s config-loading block**

Change:

```go
	container := &ServiceContainer{
		db:           config.Database,
		conn:         conn,
		logger:       config.Logger,
		viper:        config.Viper,
		cacheContext: cacheCtx,
		cacheCancel:  cacheCancel,
	}

	// Set default cache config if not provided
	if config.CacheConfig == nil {
		config.CacheConfig = cache.DefaultCacheConfig()
	}
	container.cacheConfig = config.CacheConfig
```

to:

```go
	container := &ServiceContainer{
		db:     config.Database,
		conn:   conn,
		logger: config.Logger,
		viper:  config.Viper,
	}

	if config.CacheConfig == nil {
		loaded, err := rvconfig.LoadCacheConfig()
		if err != nil {
			return nil, fmt.Errorf("load cache config: %w", err)
		}
		config.CacheConfig = &loaded
	}
	container.cacheConfig = *config.CacheConfig
```

Also remove the now-unused `cacheCtx, cacheCancel := context.WithCancel(context.Background())` line above this block, and the `cacheCancel()` call inside the `if err := container.initializeServices(); err != nil { ... }` branch a few lines down (just `return nil, fmt.Errorf(...)` remains, no cleanup call needed since nothing was started yet at that point).

- [ ] **Step 5: Replace the secret-cache initialization block**

Change:

```go
	// Initialize cache if enabled
	if c.cacheConfig.Enabled {
		// Create secret cache
		c.secretCache = cache.NewSecretCache(c.cacheConfig.TTL, c.logger.Logger)

		// Start background cleanup if configured
		if c.cacheConfig.CleanupInterval > 0 {
			c.secretCache.StartCleanup(c.cacheContext, c.cacheConfig.CleanupInterval)
		}

		// The vault delete/recover cascade writes the secrets table directly,
		// so it needs its own invalidation hook. Set only when the cache
		// exists: a typed-nil *SecretCache in the interface would panic.
		c.vaultService.SetSecretCacheFlusher(c.secretCache)
	}
```

to:

```go
	// Secret cache is always constructed: a real cache when enabled, a
	// no-op one otherwise, so downstream code never nil-checks it.
	c.secretCache = cache.NewSecretCache(c.cacheConfig.Secrets, c.logger.Logger)
	c.vaultService.SetSecretCacheFlusher(c.secretCache)
```

- [ ] **Step 6: Replace the `if c.cacheConfig.Enabled { ... } else { ... }` secret-service-wrapping block**

Change:

```go
	// Wrap with cache if enabled
	if c.cacheConfig.Enabled {
		c.cachedSecretService = cache.NewCachedSecretService(retryEnabledSecretService, c.secretCache, c.logger.Logger)
		c.secretService = c.cachedSecretService
	} else {
		c.secretService = retryEnabledSecretService
	}
```

to:

```go
	// Always wrap: on a disabled (no-op) cache, CachedSecretService's Get
	// always misses and falls through to retryEnabledSecretService, which is
	// functionally identical to not wrapping — one fewer branch to reason about.
	c.cachedSecretService = cache.NewCachedSecretService(retryEnabledSecretService, c.secretCache, c.logger.Logger)
	c.secretService = c.cachedSecretService
```

- [ ] **Step 7: Replace the key-cache initialization block**

Change:

```go
	// Initialize key cache from configuration.
	keyCacheConfig := keycache.DefaultKeyCacheConfig()
	if viperCfg.IsSet("key_cache.enabled") {
		keyCacheConfig.Enabled = viperCfg.GetBool("key_cache.enabled")
	}
	if viperCfg.IsSet("key_cache.ttl") {
		keyCacheConfig.TTL = viperCfg.GetDuration("key_cache.ttl")
	}
	if viperCfg.IsSet("key_cache.max_entries") {
		keyCacheConfig.MaxEntries = viperCfg.GetInt("key_cache.max_entries")
	}
	if viperCfg.IsSet("key_cache.cleanup_interval") {
		keyCacheConfig.CleanupInterval = viperCfg.GetDuration("key_cache.cleanup_interval")
	}

	if keyCacheConfig.Enabled {
		c.keyCache = keycache.NewMemoryCache(keyCacheConfig)
	} else {
		c.keyCache = keycache.NewNopCache()
	}
```

to:

```go
	// Key cache is always constructed via the unified cache.keys.* config.
	c.keyCache = keycache.NewCache(c.cacheConfig.Keys)
```

- [ ] **Step 8: Wire up the vault cache**

Immediately after the existing `c.vaultService.SetTxBeginner(c.conn)` line (found via the Step 1 grep), add:

```go
	c.vaultCache = vaultcache.NewCache(c.cacheConfig.Vaults)
	c.vaultService.SetVaultCache(c.vaultCache)
```

- [ ] **Step 9: Update the getter methods**

Change:

```go
func (c *ServiceContainer) GetSecretCache() *cache.SecretCache {
	return c.secretCache
}

// GetCacheConfig returns the cache configuration.
func (c *ServiceContainer) GetCacheConfig() *cache.CacheConfig {
	return c.cacheConfig
}
```

to:

```go
func (c *ServiceContainer) GetSecretCache() *cache.SecretCache {
	return c.secretCache
}

// GetCacheConfig returns the cache configuration.
func (c *ServiceContainer) GetCacheConfig() rvconfig.CacheConfig {
	return c.cacheConfig
}

// GetVaultCache returns the vault-by-name cache.
func (c *ServiceContainer) GetVaultCache() *vaultcache.Cache {
	return c.vaultCache
}
```

Update the `ServiceContainerInterface` (near the top of the file) to match: change `GetCacheConfig() *cache.CacheConfig` to `GetCacheConfig() rvconfig.CacheConfig`, and add `GetVaultCache() *vaultcache.Cache`.

- [ ] **Step 10: Update `Close()`**

Change:

```go
func (c *ServiceContainer) Close() error {
	// Cancel cache context to stop background operations.
	if c.cacheCancel != nil {
		c.cacheCancel()
	}

	// Stop the key cache background sweeper.
	if c.keyCache != nil {
		c.keyCache.Stop()
	}
```

to:

```go
func (c *ServiceContainer) Close() error {
	if c.secretCache != nil {
		c.secretCache.Stop()
	}
	if c.keyCache != nil {
		c.keyCache.Stop()
	}
	if c.vaultCache != nil {
		c.vaultCache.Stop()
	}
```

- [ ] **Step 11: Remove the dead nil-checks in rotation_service.go and versioning_service.go**

In `internal/services/secrets/rotation_service.go`, find the block around what was line 129 (re-locate via `grep -n "cacheInv == nil" internal/services/secrets/rotation_service.go` since line numbers may have shifted):

```go
	if s.cacheInv == nil {
		return
	}
	if err := s.cacheInv.DeleteByID(ctx, secretID); err != nil {
```

Change to:

```go
	if err := s.cacheInv.DeleteByID(ctx, secretID); err != nil {
```

Do the same in `internal/services/secrets/versioning_service.go` (`grep -n "cacheInv == nil" internal/services/secrets/versioning_service.go`).

This is safe now because `c.secretCache` (which satisfies `SecretCacheInvalidator`) is always constructed in the container — `cacheInv` is never nil in production. Existing unit tests for these two services that construct them directly with `cacheInv: nil` (check via `grep -rn "cacheInv:\s*nil\|NewRotationService(.*nil)\|NewVersioningService(.*nil)" internal/services/secrets/*_test.go`) would now panic on a nil interface call — if any such test exists, update it to pass a no-op fake (e.g. a tiny test double whose `DeleteByID` returns `nil`) instead of `nil`, matching how production code now always provides a real (possibly no-op-backed) invalidator.

- [ ] **Step 12: Update `container_test.go`'s disabled-cache assertions**

Find (via `grep -n "GetSecretCache()\|GetCacheConfig()\|GetCachedSecretService()\|GetKeyCache()" internal/container/container_test.go`) every assertion of the shape `assert.Nil(t, c.GetSecretCache(), ...)` / `assert.Nil(t, container.GetCachedSecretService(), ...)` made when caching is disabled. Change them to assert non-nil instead, since these getters now always return a real (possibly no-op-internally) object:

```go
// Before (disabled-cache test):
assert.Nil(t, c.GetSecretCache(), "GetSecretCache")
assert.Nil(t, c.GetCacheConfig(), "GetCacheConfig")

// After:
assert.NotNil(t, c.GetSecretCache(), "GetSecretCache must always be non-nil (real or no-op)")
assert.NotNil(t, c.GetCacheConfig(), "GetCacheConfig")
```

For the zero-value `ServiceContainer{}` test (the one asserting many getters are nil before `NewServiceContainer` runs, e.g. `TestNewServiceContainer_ZeroValue` or similar), leave `GetSecretCache()`/`GetKeyCache()`/`GetVaultCache()` as `assert.Nil` there — an unconstructed zero-value container genuinely has nil fields; only the *disabled-but-constructed* case changes.

Also find any test constructing `Config{CacheConfig: cache.DefaultCacheConfig()}` (the old type) and change to `Config{CacheConfig: &rvconfig.CacheConfig{Secrets: cachekit.Config{Enabled: true, TTL: 5*time.Minute, CleanupInterval: time.Minute, MaxEntries: 1000}, Keys: cachekit.Config{Enabled: true, TTL: 60*time.Second, CleanupInterval: 30*time.Second, MaxEntries: 500}, Vaults: cachekit.Config{Enabled: true, TTL: 5*time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}}}` (or, more simply, call `rvconfig.LoadCacheConfig()` in the test setup and pass its address — prefer this if the test file already imports `config`/can add the import cleanly, since it avoids duplicating the default literal). Add `rvconfig "rocketvault/config"` and `"rocketvault/internal/cachekit"` to the test file's imports as needed.

Add one new test:

```go
func TestNewServiceContainer_VaultCacheAlwaysNonNil(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")

	container, err := NewServiceContainer(Config{
		Database: openSQLite(t),
		Logger:   newTestLogger(),
		Viper:    v,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })

	assert.NotNil(t, container.GetVaultCache(), "GetVaultCache must always be non-nil")
}
```

- [ ] **Step 13: Run the full build and container test suite**

Run: `go build ./... && go test ./internal/container/... ./internal/services/secrets/... -v -race`
Expected: clean build, no failures.

- [ ] **Step 14: Run the entire repository test suite**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tee /tmp/full-test-output.log && grep -c FAIL /tmp/full-test-output.log`
Expected: build and vet clean; `grep -c FAIL` prints `0`.

- [ ] **Step 15: Commit**

```bash
git add internal/container/ internal/services/secrets/rotation_service.go internal/services/secrets/versioning_service.go
git commit -m "refactor(container): rewire cache construction through config.LoadCacheConfig, wire in vault caching, remove dead cacheInv nil-checks"
```

---

### Task 10: Config files, docs, and final verification

**Files:**
- Modify: `.rocketvault.yaml`
- Modify: `CLAUDE.md`
- Modify: `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`

**Interfaces:** none (docs/config only).

- [ ] **Step 1: Update `.rocketvault.yaml`**

Replace:

```yaml
key_cache:
  enabled: true
  ttl: "60s"
  max_entries: 500
  cleanup_interval: "30s"
```

with:

```yaml
# Unified cache config for secrets, keys, vaults, and (reserved for future
# use) certificates/users. See docs/superpowers/specs/2026-08-14-generic-cache-config-design.md.
cache:
  secrets:
    enabled: true
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 1000
  keys:
    enabled: true
    ttl: "60s"
    cleanup_interval: "30s"
    max_entries: 500
  vaults:
    enabled: true
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
  certificates:
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
  users:
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
```

- [ ] **Step 2: Update `CLAUDE.md`**

In the architecture tree near `internal/keycache/`, add sibling entries:

```
│   ├── cachekit/          # Generic TTL+LRU cache core (Cloneable/Zeroable, sync.Map-backed) shared by all domain caches
│   ├── keycache/          # In-process decrypted key cache for crypto operations, wraps cachekit
│   ├── vaultcache/        # In-process vault-by-name cache, wraps cachekit
```

Find `internal/cache/` in the same tree (secrets caching layer) and update its description line to note it also wraps `cachekit`:

```
│   ├── cache/              # Secret caching layer, wraps cachekit
```

Add a short note near the Key Management or a new "Caching" section documenting: `key_cache.*` is gone as of this change, replaced by `cache.keys.*`; all cache config now lives under one `cache:` YAML section covering secrets/keys/vaults, with certificates/users reserved for future use.

- [ ] **Step 3: Add the breaking-change section to release notes**

Append to `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`:

```markdown
## Breaking: `key_cache.*` renamed to `cache.keys.*`

Cache configuration is now unified under one `cache:` YAML section covering
secrets, keys, and (new) vaults, with `certificates`/`users` reserved for
future use. `key_cache.enabled`/`ttl`/`max_entries`/`cleanup_interval` no
longer exist — set `cache.keys.enabled`/`ttl`/`max_entries`/`cleanup_interval`
instead. No deprecated alias; update `.rocketvault.yaml` before upgrading.

Vault lookups (the vault named in every request's URL) are now cached too —
`VaultResolutionMiddleware` previously hit the database on nearly every API
request with no caching layer at all. Configure via `cache.vaults.*`, same
shape as the other domains.

Full design: `docs/superpowers/specs/2026-08-14-generic-cache-config-design.md`.
```

- [ ] **Step 4: Full build, vet, format, and test sweep**

Run: `gofmt -l $(git diff --name-only main -- '*.go') 2>/dev/null; go build ./... && go vet ./... && go test ./... -race 2>&1 | tail -60`

Expected: `gofmt -l` prints nothing (no unformatted files); build and vet clean; full suite green under `-race`.

- [ ] **Step 5: Live smoke test — confirm the vault cache actually reduces DB traffic**

Start the dev server on a scratch port (do not touch any already-running instance — check with `ss -ltnp | grep 8774` first and pick a free port if occupied), hit a vault-scoped endpoint twice, and confirm both succeed:

```bash
go run main.go serve --listen 127.0.0.1:18777 > /tmp/cache-smoke.log 2>&1 &
sleep 5
curl -s -o /dev/null -w "first: %{http_code}\n" http://127.0.0.1:18777/api/v1/vault
curl -s -o /dev/null -w "second: %{http_code}\n" http://127.0.0.1:18777/api/v1/vault
kill %1
```

This confirms the server starts and serves requests correctly with the new config — it does not, by itself, prove the second request was cache-served rather than repo-served (that fact is proven by Task 7's `TestGetVault_SecondCallHitsCacheNotRepo`, not by a black-box HTTP smoke test, per the design spec's own testing section).

- [ ] **Step 6: Commit**

```bash
git add .rocketvault.yaml CLAUDE.md docs/release-notes/v4.1.0-role-parity-and-authz-fix.md
git commit -m "docs: document cache.* unified config schema and key_cache.* breaking rename"
```

---

## Self-Review Notes

**Spec coverage:** every spec section has a task — foundation types (Task 1), Cache[K,V] mechanics incl. LRU (Tasks 2–3), keycache migration (Task 4), secrets migration (Task 5), new vaultcache (Task 6), VaultService wiring (Task 7), config schema (Task 8), container rewiring + cleanup (Task 9), docs/config files (Task 10). The `Zeroable` addition (found mid-planning, not in the original spec draft) is covered in Task 1/2/4 and was already back-ported into the committed spec before this plan was written.

**Type consistency checked across tasks:** `cachekit.Config` (Task 1) is the exact type threaded through Tasks 4–9 with no renaming. `cachekit.Interface[K,V]`'s method set (Task 1: `Get/Set/Invalidate/InvalidateAll/Range/Stats/Stop`) matches what `Cache[K,V]` (Task 2) and `NopCache[K,V]` (Task 3) both implement, and what `keycache.cacheImpl` (Task 4) and `vaultcache.Cache` (Task 6) consume. `VaultCacheInterface` (Task 7) matches `*vaultcache.Cache`'s public method set (Task 6) exactly (`Get(string)(*model.Vault,bool)`, `Set(string,*model.Vault)`, `Invalidate(string)`).

**No placeholders:** every step has real, complete code — no "add appropriate error handling," no "similar to Task N" without the actual code repeated.
