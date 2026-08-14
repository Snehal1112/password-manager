# Generic Cache Config Implementation Plan — Part 2 of 4: migrate existing caches, add vaultcache

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate `internal/keycache` and `internal/cache` (secrets) onto `internal/cachekit`, preserving their exact external APIs and domain-specific composition (scope keys + reverse index for secrets; keyID+version isolation for keys), and add the new `internal/vaultcache` package.

**Architecture:** Each domain package keeps its existing exported surface — `keycache.Cache`, `cache.SecretCache` — but delegates storage/TTL/LRU to `cachekit.Interface[K,V]` internally. `internal/vaultcache` is a new, smaller package with the same wrapping pattern, keyed by vault name.

**Tech Stack:** Go 1.25 generics, `sync.Map` (via cachekit), existing project logging (`logrus`/`internal/logging`).

**Spec:** `docs/superpowers/specs/2026-08-14-generic-cache-config-design.md`

## Sequence

This is **Part 2 of 4**. Requires **Part 1** (`docs/superpowers/plans/2026-08-14-generic-cache-config-1-cachekit-core.md`) complete and merged — this part imports `internal/cachekit` throughout.

1. Part 1 — `internal/cachekit` core
2. **Part 2 (this file)** — migrate keycache + secrets cache, add vaultcache (Tasks 4–6)
3. Part 3 — wire vault caching into `VaultService`, add `config.CacheConfig`/`LoadCacheConfig` (Tasks 7–8)
4. Part 4 — rewire the DI container, update docs/config, final whole-repo verification (Tasks 9–10)

**Known intermediate state — read before starting:** this part deletes `internal/cache/config.go` and `internal/keycache/config.go`/`nop_cache.go`. `internal/container/service_container.go` still references the deleted symbols (`cache.DefaultCacheConfig`, `keycache.DefaultKeyCacheConfig`, `keycache.NewMemoryCache`) until **Part 4** rewires it. This means **`go build ./...` for the whole repository will fail** between finishing this part and starting Part 4 — that is expected, not a mistake. Verify success at the package level instead: `go build ./internal/cachekit/... ./internal/keycache/... ./internal/cache/... ./internal/vaultcache/... ./model/...` and `go test` on those same packages, exactly as each task below specifies. Do not attempt to fix `internal/container` in this part — that is Part 4's job.

## Global Constraints

- Every cached value must implement `cachekit.Cloneable[T]` (`Clone() T`) — no exceptions.
- Preserve exact current behavior: scope-isolated secret keys + `byID` reverse-index eviction; keyID+version isolation for keys; **zeroing `PrivateKey`/`PublicKey` immediately after any entry removal** (TTL expiry, LRU eviction, explicit invalidation) via `cachekit.Zeroable`, built in Part 1.
- `key_cache.*` / `internal/cache`'s hardcoded config are being retired — don't reintroduce a new YAML-reading path here; that's Part 3/4's job (`config.LoadCacheConfig`). These migrated constructors take a `cachekit.Config` value directly.
- Go vet/gofmt must stay clean for every package this part touches after every task.

---

## File Structure (this part)

**New:**
- `internal/vaultcache/cache.go` — `Cache` wrapping `cachekit.Interface[string, *model.Vault]`
- `internal/vaultcache/cache_test.go`
- `model/secret_test.go`, `model/vault_test.go` (create if they don't already exist)

**Modified:**
- `model/secret.go` — add `Clone()`, `cloneTimePtr()`
- `model/vault.go` — add `Clone()`
- `internal/cache/secret_cache.go` — rewritten internals, same external API
- `internal/cache/secret_cache_test.go` — adapted
- `internal/cache/cache_integration.go` — no signature change, verify only
- `internal/keycache/cache.go` — `Entry.Clone()`, `Entry.Zero()`, `keyCacheKey`
- `internal/keycache/memory_cache.go` — rewritten to wrap `cachekit`, absorbs `nop_cache.go`
- `internal/keycache/*_test.go` — adapted

**Deleted:**
- `internal/cache/config.go`
- `internal/keycache/config.go`
- `internal/keycache/nop_cache.go`

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


## Self-Review Notes (this part)

**Spec coverage:** covers the spec's keycache migration, secrets cache migration, and new vaultcache package in full, including the `Zeroable`-preserving behavior found while reading the full `keycache` source.

**Type consistency:** `keycache.NewCache(cfg cachekit.Config) Cache` and `keycache.NewNopCache() Cache` (Task 4) keep the exact pre-existing `keycache.Cache` interface signature — verified by `internal/services/keys`' call sites needing zero changes. `cache.NewSecretCache(cfg cachekit.Config, logger *logrus.Logger) *SecretCache` (Task 5) keeps every other `SecretCache` method signature (`Get`/`Set`/`DeleteByID`/`Flush`/`GetStats`) identical to pre-migration, verified in Task 5 Step 9 by confirming `cache_integration.go` needs no edits. `vaultcache.Cache` (Task 6) exposes exactly `Get(string)(*model.Vault,bool)`/`Set(string,*model.Vault)`/`Invalidate(string)`/`Stop()`, which Part 3 depends on verbatim.

**No placeholders:** every step has complete, runnable code.

## Next step

Once this part's tasks are all committed and `go test ./internal/keycache/... ./internal/cache/... ./internal/vaultcache/... ./model/... -v -race` is clean (whole-repo build is expected to still be broken — see "Known intermediate state" above), proceed to **Part 3**: `docs/superpowers/plans/2026-08-14-generic-cache-config-3-vault-wiring-and-config.md`.
