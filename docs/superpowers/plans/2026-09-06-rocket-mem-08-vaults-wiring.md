# Rocket-mem Tiered Cache — Plan 08: Wire vaultcache onto TieredCache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `NewCacheWithL2` for `internal/vaultcache`, backed by `cachekit.TieredCache` with the plain codec — `model.Vault` carries no secret material.

**Architecture:** `vaultcache.Cache` is the simplest of the four domain caches: no `ctx`/`scope` parameters, no logger, keyed directly by vault name (no scope-composite key, no `DeleteByID`/`Range` wrapper — `Invalidate(name)` already evicts the single relevant entry directly). This plan mirrors Plan 07's shape with those simplifications.

**Tech Stack:** Go 1.25 generics (existing package).

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (Problem Statement table: vaults use the plain codec)

## Global Constraints

- `NewCache`'s signature, behavior, and every existing test in `internal/vaultcache/` must be unchanged and still pass, untouched, after this plan.
- This domain uses `PlainJSONCodec` — vaults carry no secret material at all (see spec).
- `go build ./...` and `go test ./...` must stay green after every task.

---

### Task 1: `NewCacheWithL2`

**Files:**
- Modify: `internal/vaultcache/cache.go`
- Test: `internal/vaultcache/cache_l2_test.go` (new file)

**Interfaces:**
- Consumes: `cachekit.TieredCache`/`KeyCodec`/`PlainJSONCodec`/`L2` (Plans 01-02).
- Produces: `vaultcache.NewCacheWithL2(cfg cachekit.Config, l2 cachekit.L2, l2TTL time.Duration) *Cache`.

- [ ] **Step 1: Write the failing test**

```go
// internal/vaultcache/cache_l2_test.go
package vaultcache

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// fakeL2 mirrors internal/cachekit's own test double -- see the note in
// internal/cache/secret_cache_l2_test.go about each package keeping a
// small local copy.
type fakeL2 struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeL2() *fakeL2 { return &fakeL2{data: make(map[string][]byte)} }
func (f *fakeL2) Get(wireKey string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.data[wireKey]
	return b, ok
}
func (f *fakeL2) Set(wireKey string, payload []byte, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	var out []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

var _ cachekit.L2 = (*fakeL2)(nil)

func TestNewCacheWithL2_RoundTrip_PlainCodec(t *testing.T) {
	l2 := newFakeL2()
	c := NewCacheWithL2(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0}, l2, time.Minute)
	defer c.Stop()

	v := &model.Vault{Name: "acme", Enabled: true}
	c.Set("acme", v)

	got, ok := c.Get("acme")
	require.True(t, ok)
	assert.Equal(t, "acme", got.Name)

	found := false
	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:vault:") {
			found = true
			assert.Contains(t, string(payload), "acme")
		}
	}
	assert.True(t, found, "Set must have written something to L2 under the rocketvault:vault: prefix")

	c.Invalidate("acme")
	_, ok = c.Get("acme")
	assert.False(t, ok)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultcache/... -run TestNewCacheWithL2 -v`
Expected: FAIL (build error — `NewCacheWithL2` does not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/vaultcache/cache.go, add "time" to the import block

// NewCacheWithL2 creates a Cache backed by a TieredCache: cfg's in-process
// cache as L1, l2 as the shared Rocket-mem tier (l2TTL is that tier's own
// entry lifetime). Uses PlainJSONCodec -- model.Vault carries no secret
// material (see the design spec). Used only when cache.rocket_mem is
// enabled; NewCache's behavior is unchanged.
func NewCacheWithL2(cfg cachekit.Config, l2 cachekit.L2, l2TTL time.Duration) *Cache {
	l1 := cachekit.NewFromConfig[string, *model.Vault](cfg)
	var codec cachekit.PlainJSONCodec[*model.Vault]
	keys := cachekit.KeyCodec[string]{
		ToWire:   func(k string) string { return k },
		FromWire: func(w string) (string, bool) { return w, true },
	}
	return &Cache{core: cachekit.NewTieredCache[string, *model.Vault](l1, l2, codec, keys, "rocketvault:vault:", l2TTL)}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultcache/... -v`
Expected: PASS (all tests in the package, including this new one)

- [ ] **Step 5: Commit**

```bash
git add internal/vaultcache/cache.go internal/vaultcache/cache_l2_test.go
git commit -m "feat(vaultcache): add NewCacheWithL2 (plain codec, Rocket-mem-backed)"
```

---

### Task 2: Container wiring + regression check

**Files:**
- Modify: `internal/container/service_container.go`

**Interfaces:**
- Consumes: `vaultcache.NewCacheWithL2` (Task 1), `c.rocketMemClient` (Plan 04).

- [ ] **Step 1: Write the failing test**

No new test file — proven by the existing container test suite (regression) plus Task 1's test at the `Cache` level. Skip to Step 3.

- [ ] **Step 2: (n/a — see above)**

- [ ] **Step 3: Write minimal implementation**

In `internal/container/service_container.go`, replace the existing line (around line 312, per the earlier grep — note this line runs early in `initializeServices`, but `c.rocketMemClient` is already set by then since it's constructed in `NewServiceContainer` before `initializeServices()` is called, per Plan 04 Task 2):

```go
c.vaultCache = vaultcache.NewCache(c.cacheConfig.Vaults)
```

with:

```go
if c.rocketMemClient != nil {
	c.vaultCache = vaultcache.NewCacheWithL2(c.cacheConfig.Vaults, c.rocketMemClient, c.cacheConfig.Vaults.TTL)
} else {
	c.vaultCache = vaultcache.NewCache(c.cacheConfig.Vaults)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go vet ./... && go test ./...` (whole repo, no tags)
Expected: identical outcome to before this plan started — `c.rocketMemClient` is `nil` by default, so the unchanged `vaultcache.NewCache` branch is taken.

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): use vaultcache.NewCacheWithL2 when rocket_mem is enabled"
```
