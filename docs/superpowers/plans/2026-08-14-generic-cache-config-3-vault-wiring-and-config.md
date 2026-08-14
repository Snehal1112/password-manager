# Generic Cache Config Implementation Plan — Part 3 of 4: vault wiring + unified config

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `internal/vaultcache.Cache` into `VaultService` (closing the gap where `VaultResolutionMiddleware` hits the DB on almost every request), and add the unified `config.CacheConfig`/`LoadCacheConfig()` that Part 4 needs to construct all three domain caches from one `cache.<domain>.*` YAML schema.

**Architecture:** `VaultService` gains an optional `VaultCacheInterface` (mirroring the existing `SecretCacheFlusher` optional-dependency pattern already in that file) consulted in `getByName` and invalidated after every successful Update/Delete/Recover/Purge. `config.LoadCacheConfig()` mirrors the existing `LoadSoftDeleteConfig`/`LoadMonitoringConfig` IsSet-per-field override pattern, for five domains (secrets/keys/vaults/certificates/users).

**Tech Stack:** Go 1.25, `github.com/spf13/viper` (existing project config pattern).

**Spec:** `docs/superpowers/specs/2026-08-14-generic-cache-config-design.md`

## Sequence

This is **Part 3 of 4**. Requires **Part 1** (cachekit core) and **Part 2** (migrated keycache/secrets cache + new vaultcache) complete and merged — this part imports `internal/vaultcache` and `internal/cachekit`.

1. Part 1 — `internal/cachekit` core
2. Part 2 — migrate keycache + secrets cache, add vaultcache
3. **Part 3 (this file)** — wire vault caching into `VaultService`, add `config.CacheConfig`/`LoadCacheConfig` (Tasks 7–8)
4. Part 4 — rewire the DI container, update docs/config, final whole-repo verification (Tasks 9–10)

**Known intermediate state:** same caveat as Part 2 — `internal/container/service_container.go` is not updated until Part 4, so it still references pre-migration symbols removed in Part 2. `go build ./...` for the whole repository will still fail until Part 4 completes. Verify at the package level: `go build ./internal/services/vaults/... ./config/...` and run the tests each task specifies.

## Global Constraints

- `VaultCacheInterface` must be declared in the `vaults` package (not imported from `internal/vaultcache`) to stay import-cycle-free — mirrors the existing `SecretCacheFlusher`/`CascadeRepository` pattern already in `vault_service.go`.
- `getByName`'s cache population and every invalidation call must be guarded by `if s.vaultCache != nil` — unset means vault caching is disabled, and every pre-existing test in this package that never calls `SetVaultCache` must keep passing unchanged.
- `config.LoadCacheConfig()` validates all 5 domains regardless of `Enabled`, returning the first `Validate()` error found, in deterministic (not map-iteration) order.
- Go vet/gofmt must stay clean for every package this part touches after every task.

---

## File Structure (this part)

**New:**
- `internal/services/vaults/vault_cache_test.go`

**Modified:**
- `internal/services/vaults/vault_service.go` — `VaultCacheInterface`, `SetVaultCache`, cache-aware `getByName`, invalidation in Update/Delete/Recover/Purge
- `config/config.go` — `CacheConfig` struct + `LoadCacheConfig()`
- `config/config_test.go` — new tests

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


## Self-Review Notes (this part)

**Spec coverage:** covers the spec's `VaultService` wiring (cache-aware `getByName`, invalidation on every mutating path) and the unified `cache.<domain>.*` config schema in full.

**Type consistency:** `VaultCacheInterface` (Task 7) matches `*vaultcache.Cache`'s public method set from Part 2 exactly (`Get(string)(*model.Vault,bool)`, `Set(string,*model.Vault)`, `Invalidate(string)`) — Part 4 wires the real `*vaultcache.Cache` in through this same interface. `config.CacheConfig`'s five fields (Task 8) are all `cachekit.Config`, the exact type from Part 1, threaded unchanged into Part 4's container construction.

**No placeholders:** every step has complete, runnable code.

## Next step

Once this part's tasks are all committed and `go test ./internal/services/vaults/... ./config/... -v -race` is clean (whole-repo build is still expected to be broken — see "Known intermediate state" above), proceed to **Part 4**: `docs/superpowers/plans/2026-08-14-generic-cache-config-4-container-and-docs.md`.
