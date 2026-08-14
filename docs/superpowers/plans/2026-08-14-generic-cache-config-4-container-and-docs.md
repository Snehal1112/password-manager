# Generic Cache Config Implementation Plan — Part 4 of 4: container rewiring, docs, final verification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewire `internal/container/service_container.go` to construct all three domain caches through `config.LoadCacheConfig()`, remove the now-dead `cacheInv` nil-checks in the secrets rotation/versioning services, update `.rocketvault.yaml`/CLAUDE.md/release notes, and bring the whole repository back to a clean `go build ./... && go vet ./... && go test ./...`.

**Architecture:** `NewServiceContainer` loads `config.CacheConfig` once (aliased `rvconfig` to avoid shadowing its own `config Config` parameter name) and constructs `cache.NewSecretCache`, `keycache.NewCache`, `vaultcache.NewCache` unconditionally — each is always a real, non-nil object (real-or-no-op internally), removing every downstream nil-check this migration made obsolete.

**Tech Stack:** Go 1.25, existing DI container patterns in this repo.

**Spec:** `docs/superpowers/specs/2026-08-14-generic-cache-config-design.md`

## Sequence

This is **Part 4 of 4**, the final part. Requires **Parts 1–3** complete and merged.

1. Part 1 — `internal/cachekit` core
2. Part 2 — migrate keycache + secrets cache, add vaultcache
3. Part 3 — wire vault caching into `VaultService`, add `config.CacheConfig`/`LoadCacheConfig`
4. **Part 4 (this file)** — rewire the DI container, update docs/config, final whole-repo verification (Tasks 9–10)

This is the part where `go build ./...` for the whole repository becomes clean again — Parts 2–3 intentionally left `internal/container/service_container.go` referencing symbols that no longer exist; this part is where that gets fixed.

## Global Constraints

- Every getter that used to return `nil` when caching was disabled (`GetSecretCache`, `GetCachedSecretService`, `GetKeyCache`) now always returns a real (possibly no-op-internally) object — update `container_test.go`'s assertions to match; don't leave stale `assert.Nil` checks for the *disabled-but-constructed* case (the zero-value, never-constructed `ServiceContainer{}` case is unaffected and keeps its `assert.Nil` assertions).
- `internal/services/secrets/rotation_service.go`/`versioning_service.go`'s `if s.cacheInv == nil { return }` guards become dead code once the container always provides a real invalidator — remove them, and update any test that directly constructs these services with `cacheInv: nil` to pass a no-op fake instead.
- Full repository `go build ./... && go vet ./... && go test ./... -race` must be clean before this plan (and the whole 4-part effort) is considered done.
- `key_cache.*` is removed from `.rocketvault.yaml` with no back-compat alias, replaced by `cache.keys.*` alongside `cache.secrets.*`/`cache.vaults.*`/`cache.certificates.*`/`cache.users.*`.

---

## File Structure (this part)

**Modified:**
- `internal/container/service_container.go` — rewired construction, removed `cacheContext`/`cacheCancel`, always-non-nil caches, new `GetVaultCache()`
- `internal/container/container_test.go` — updated nil-vs-non-nil assertions, new vault-cache assertion
- `internal/services/secrets/rotation_service.go` — remove dead nil-check
- `internal/services/secrets/versioning_service.go` — remove dead nil-check
- `.rocketvault.yaml` — `key_cache:` → `cache:` (5 domains)
- `CLAUDE.md` — architecture tree + cache descriptions
- `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` — new breaking-change section

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


## Self-Review Notes (this part)

**Spec coverage:** covers the spec's container rewiring and docs/config-file sections in full — this is where every prior part's work gets connected end-to-end and verified.

**Type consistency:** `rvconfig.CacheConfig` (Part 3's `config.CacheConfig`, imported here under the `rvconfig` alias to avoid shadowing the `config Config` parameter name) flows unchanged into `cache.NewSecretCache(c.cacheConfig.Secrets, ...)`, `keycache.NewCache(c.cacheConfig.Keys)`, `vaultcache.NewCache(c.cacheConfig.Vaults)` — all three constructor signatures match exactly what Parts 2–3 produced.

**No placeholders:** every step has complete, runnable code.

## This is the final part

Once Task 10's Step 4 (`go build ./... && go vet ./... && go test ./... -race`) is clean, the full generic-cache-config effort (all 4 parts) is complete.
