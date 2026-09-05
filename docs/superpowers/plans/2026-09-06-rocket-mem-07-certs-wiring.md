# Rocket-mem Tiered Cache — Plan 07: Wire certcache onto TieredCache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `NewCacheWithL2` for `internal/certcache`, backed by `cachekit.TieredCache` with the **plain** (non-encrypting) codec, since `GetCertificate` never decrypts `Certificate.PrivateKey` — it stays ciphertext, so nothing decrypted ever reaches this cache (confirmed when `internal/certcache` was first built).

**Architecture:** `model.Certificate` has no interface-typed fields (unlike `keycache.Entry`), so the generic `cachekit.PlainJSONCodec[*model.Certificate]{}` applies directly — no custom codec needed here, unlike Plan 06.

**Tech Stack:** Go 1.25 generics (existing package).

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (Problem Statement table: certs use the plain codec)

## Global Constraints

- `NewCache`'s signature, behavior, and every existing test in `internal/certcache/` must be unchanged and still pass, untouched, after this plan.
- This domain must use `PlainJSONCodec`, never `EncryptedJSONCodec` — encrypting a value that was never decrypted in the first place would be pointless overhead with no security benefit (see spec rationale).
- `go build ./...` and `go test ./...` must stay green after every task.

---

### Task 1: `NewCacheWithL2`

**Files:**
- Modify: `internal/certcache/cache.go`
- Test: `internal/certcache/cache_l2_test.go` (new file)

**Interfaces:**
- Consumes: `cachekit.TieredCache`/`KeyCodec`/`PlainJSONCodec`/`L2` (Plans 01-02).
- Produces: `certcache.NewCacheWithL2(cfg cachekit.Config, logger *logrus.Logger, l2 cachekit.L2, l2TTL time.Duration) *Cache`.

- [ ] **Step 1: Write the failing test**

```go
// internal/certcache/cache_l2_test.go
package certcache

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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
	c := NewCacheWithL2(
		cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0},
		logrus.New(), l2, time.Minute,
	)
	defer c.Stop()

	ctx := context.Background()
	vaultID, certID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: certID, VaultID: vaultID, Name: "n", Certificate: "PUBLIC-PEM", PrivateKey: "encrypted-ciphertext", Enabled: true, CreatedAt: time.Now()}

	require.NoError(t, c.Set(ctx, cert, scope))
	got, ok := c.Get(ctx, certID, scope)
	require.True(t, ok)
	assert.Equal(t, "PUBLIC-PEM", got.Certificate)
	assert.Equal(t, "encrypted-ciphertext", got.PrivateKey)

	found := false
	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:cert:") {
			found = true
			// Plain codec: readable JSON is expected here (no decrypted
			// secret ever enters this cache -- PrivateKey is already
			// ciphertext), unlike internal/cache's encrypted codec.
			assert.Contains(t, string(payload), "encrypted-ciphertext")
		}
	}
	assert.True(t, found, "Set must have written something to L2 under the rocketvault:cert: prefix")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/certcache/... -run TestNewCacheWithL2 -v`
Expected: FAIL (build error — `NewCacheWithL2` does not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/certcache/cache.go, add "time" to the import block

// NewCacheWithL2 creates a Cache backed by a TieredCache: cfg's in-process
// cache as L1, l2 as the shared Rocket-mem tier (l2TTL is that tier's own
// entry lifetime). Uses PlainJSONCodec, never the encrypting codec --
// GetCertificate never decrypts Certificate.PrivateKey (it stays
// ciphertext), so nothing decrypted ever reaches this cache, matching this
// package's existing "no Zero() needed" rationale. Used only when
// cache.rocket_mem is enabled; NewCache's behavior is unchanged.
func NewCacheWithL2(cfg cachekit.Config, logger *logrus.Logger, l2 cachekit.L2, l2TTL time.Duration) *Cache {
	l1 := cachekit.NewFromConfig[string, *model.Certificate](cfg)
	var codec cachekit.PlainJSONCodec[*model.Certificate]
	keys := cachekit.KeyCodec[string]{
		ToWire:   func(k string) string { return k },
		FromWire: func(w string) (string, bool) { return w, true },
	}
	return &Cache{
		core:   cachekit.NewTieredCache[string, *model.Certificate](l1, l2, codec, keys, "rocketvault:cert:", l2TTL),
		logger: logger,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/certcache/... -v`
Expected: PASS (all tests in the package, including this new one)

- [ ] **Step 5: Commit**

```bash
git add internal/certcache/cache.go internal/certcache/cache_l2_test.go
git commit -m "feat(certcache): add NewCacheWithL2 (plain codec, Rocket-mem-backed)"
```

---

### Task 2: Container wiring + regression check

**Files:**
- Modify: `internal/container/service_container.go`

**Interfaces:**
- Consumes: `certcache.NewCacheWithL2` (Task 1), `c.rocketMemClient` (Plan 04).

- [ ] **Step 1: Write the failing test**

No new test file — proven by the existing container test suite (regression) plus Task 1's test at the `Cache` level. Skip to Step 3.

- [ ] **Step 2: (n/a — see above)**

- [ ] **Step 3: Write minimal implementation**

In `internal/container/service_container.go`, replace the existing line (around line 346, per the earlier grep):

```go
c.certCache = certcache.NewCache(c.cacheConfig.Certificates, c.logger.Logger)
```

with:

```go
if c.rocketMemClient != nil {
	c.certCache = certcache.NewCacheWithL2(c.cacheConfig.Certificates, c.logger.Logger, c.rocketMemClient, c.cacheConfig.Certificates.TTL)
} else {
	c.certCache = certcache.NewCache(c.cacheConfig.Certificates, c.logger.Logger)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go vet ./... && go test ./...` (whole repo, no tags)
Expected: identical outcome to before this plan started — `c.rocketMemClient` is `nil` by default, so the unchanged `certcache.NewCache` branch is taken.

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): use certcache.NewCacheWithL2 when rocket_mem is enabled"
```
