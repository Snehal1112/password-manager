# Rocket-mem Tiered Cache — Plan 05: Wire SecretCache onto TieredCache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `NewSecretCacheWithL2` constructor so `SecretCache` can be backed by `cachekit.TieredCache` (L1 in-process + L2 Rocket-mem, encrypted), while `NewSecretCache` (used by every existing caller) is untouched.

**Architecture:** `SecretCache.core`'s field type is already `cachekit.Interface[string, *model.Secret]` — `TieredCache` satisfies that same interface (Plan 02), so this is purely an additional constructor plus one conditional branch in the container. `EncryptedJSONCodec`'s `Encrypt`/`Decrypt` fields are `common.EncryptSecret`/`common.DecryptSecret` directly — the exact primitive already used for this secret's DB-at-rest encryption.

**Tech Stack:** Go 1.25 generics (existing package).

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (Problem Statement table: secrets require the encrypting codec)

## Global Constraints

- `NewSecretCache`'s signature, behavior, and every existing test in `internal/cache/secret_cache_test.go` must be unchanged and still pass, untouched, after this plan — regression safety for the (default) non-rocket-mem path.
- Cached values must never reach L2 as plaintext: `EncryptedJSONCodec` is mandatory for this domain, never `PlainJSONCodec`.
- `go build ./...` and `go test ./...` must stay green after every task.

---

### Task 1: `NewSecretCacheWithL2`

**Files:**
- Modify: `internal/cache/secret_cache.go`
- Test: `internal/cache/secret_cache_l2_test.go` (new file)

**Interfaces:**
- Consumes: `cachekit.TieredCache`/`KeyCodec`/`EncryptedJSONCodec`/`L2` (Plans 01-02), `common.EncryptSecret`/`common.DecryptSecret` (existing).
- Produces: `cache.NewSecretCacheWithL2(cfg cachekit.Config, logger *logrus.Logger, l2 cachekit.L2, l2TTL time.Duration) *SecretCache`.

- [ ] **Step 1: Write the failing test**

```go
// internal/cache/secret_cache_l2_test.go
package cache

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

// fakeL2 mirrors internal/cachekit's own test double (unexported there too
// -- each package keeps a small local copy rather than exporting a
// test-only type from a production package).
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

func TestNewSecretCacheWithL2_RoundTrip_AndCiphertextOnWire(t *testing.T) {
	l2 := newFakeL2()
	c := NewSecretCacheWithL2(
		cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0},
		logrus.New(), l2, time.Minute,
	)
	defer c.Stop()

	ctx := context.Background()
	vaultID, secretID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	secret := &model.Secret{ID: secretID, VaultID: vaultID, Name: "n", Value: "TOP-SECRET-PLAINTEXT", Version: 1, CreatedAt: time.Now(), Enabled: true}

	require.NoError(t, c.Set(ctx, secret, scope))

	got, ok := c.Get(ctx, secretID, scope)
	require.True(t, ok)
	assert.Equal(t, "TOP-SECRET-PLAINTEXT", got.Value, "round-trip through L1+L2 must reproduce the exact plaintext")

	// Inspect what actually landed on the wire in L2 -- it must never
	// contain the plaintext substring.
	found := false
	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:secret:") {
			found = true
			assert.False(t, strings.Contains(string(payload), "TOP-SECRET-PLAINTEXT"),
				"secret plaintext must never appear in the L2 wire payload")
		}
	}
	assert.True(t, found, "Set must have written something to L2 under the rocketvault:secret: prefix")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/... -run TestNewSecretCacheWithL2 -v`
Expected: FAIL (build error — `NewSecretCacheWithL2` does not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/cache/secret_cache.go, add "time" and "rocketvault/common" to the import block

// NewSecretCacheWithL2 creates a SecretCache backed by a TieredCache: cfg's
// in-process cache as L1, l2 as the shared Rocket-mem tier (l2TTL is that
// tier's own entry lifetime). GetSecret hands this cache already-decrypted
// plaintext (see cache_integration.go), so values are JSON-marshaled and
// then encrypted via common.EncryptSecret/DecryptSecret -- the same
// primitive already used for this secret's DB-at-rest encryption -- before
// ever reaching l2 (see the design spec's Problem Statement table: this is
// the mandatory case, never PlainJSONCodec). Used only when
// cache.rocket_mem is enabled; NewSecretCache's behavior is unchanged.
func NewSecretCacheWithL2(cfg cachekit.Config, logger *logrus.Logger, l2 cachekit.L2, l2TTL time.Duration) *SecretCache {
	l1 := cachekit.NewFromConfig[string, *model.Secret](cfg)
	codec := cachekit.EncryptedJSONCodec[*model.Secret]{
		Encrypt: common.EncryptSecret,
		Decrypt: common.DecryptSecret,
	}
	keys := cachekit.KeyCodec[string]{
		ToWire:   func(k string) string { return k },
		FromWire: func(w string) (string, bool) { return w, true },
	}
	return &SecretCache{
		core:   cachekit.NewTieredCache[string, *model.Secret](l1, l2, codec, keys, "rocketvault:secret:", l2TTL),
		logger: logger,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cache/... -v`
Expected: PASS (every existing test in the package, plus this new one)

- [ ] **Step 5: Commit**

```bash
git add internal/cache/secret_cache.go internal/cache/secret_cache_l2_test.go
git commit -m "feat(cache): add NewSecretCacheWithL2 (encrypted, Rocket-mem-backed)"
```

---

### Task 2: Container wiring + regression check

**Files:**
- Modify: `internal/container/service_container.go`

**Interfaces:**
- Consumes: `cache.NewSecretCacheWithL2` (Task 1), `c.rocketMemClient` (Plan 04).

- [ ] **Step 1: Write the failing test**

No new test file — this task is a container wiring change proven by the existing container test suite (regression) plus a manual verification step below, since standing up a full container against a fake L2 is already covered at the `SecretCache` level (Task 1) and at the container-skeleton level (Plan 04). Skip to Step 3.

- [ ] **Step 2: (n/a — see above)**

- [ ] **Step 3: Write minimal implementation**

In `internal/container/service_container.go`, replace the existing line (around line 341, per the earlier grep):

```go
c.secretCache = cache.NewSecretCache(c.cacheConfig.Secrets, c.logger.Logger)
```

with:

```go
if c.rocketMemClient != nil {
	c.secretCache = cache.NewSecretCacheWithL2(c.cacheConfig.Secrets, c.logger.Logger, c.rocketMemClient, c.cacheConfig.Secrets.TTL)
} else {
	c.secretCache = cache.NewSecretCache(c.cacheConfig.Secrets, c.logger.Logger)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go vet ./... && go test ./...` (whole repo, no tags)
Expected: identical outcome to before this plan started — `c.rocketMemClient` is `nil` by default (Plan 04's `cache.rocket_mem.enabled` defaults `false`), so every existing container-construction path takes the unchanged `cache.NewSecretCache` branch.

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): use NewSecretCacheWithL2 when rocket_mem is enabled"
```
