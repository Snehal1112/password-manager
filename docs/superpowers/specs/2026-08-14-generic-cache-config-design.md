# Generic Cache Configuration — Unify Secret/Key Caching, Close the Vault Gap

**Date**: 2026-08-14
**Status**: Approved
**Scope**: `internal/cachekit` (new), `internal/cache`, `internal/keycache`, `internal/vaultcache` (new),
`internal/services/vaults`, `internal/container`, `config`, `.rocketvault.yaml`

---

## Problem

RocketVault has two independent in-memory caching layers with nearly identical config shapes but
different mechanics, plus one confirmed gap and two speculative future needs:

- `internal/cache` (secrets): `map[string]*CachedSecret` + `sync.RWMutex` + a `byID` reverse index,
  config hardcoded (`cache.CacheConfig`, never read from `.rocketvault.yaml` — confirmed via grep,
  no `cache.*` viper key exists anywhere).
- `internal/keycache` (keys): `sync.Map`-backed, driven by real `key_cache.*` YAML keys, has a
  formal `Cache` interface + `NopCache`, but a different key shape, no cloning, and no config
  validation.
- **Vaults have no cache at all.** `VaultResolutionMiddleware` calls `VaultService.GetVault(name)`
  on nearly every API request (confirmed: only health/liveness and the purge route skip it), and
  it's an uncached DB hit every time — the single most-frequently-repeated lookup in the codebase.
- Certificates and Users currently have no caching need (`CertificateService.GetCertificate` and
  `UserService.GetUser` are cheap, undecorated repo reads; JWT claims already serve as the
  de-facto per-request cache for auth/RBAC) — but a shared, generic cache should exist so adding
  either later is a small mechanical step, not a redesign.

Investigation (`.claude/secret-cache-cloning.md`, verified against current code) also surfaced a
correctness requirement, not just a config-unification opportunity: `VaultService.UpdateVault`
(`internal/services/vaults/vault_service.go:227-235`) fetches a vault and mutates the returned
pointer **in place** (`v.Enabled = *req.Enabled`, `v.Tags = *req.Tags`, ...) before persisting —
the exact same live-pointer-mutation pattern documented for secrets. If `VaultCache.Get` ever
returns a live pointer instead of a clone, this corrupts the cache on every vault update. (For
comparison: `KeyService.UpdateKey`/`CertificateService.UpdateCertificate`/`UserService.UpdateUser`
all shallow-copy-first — `updated := *current` — before mutating, so they are not currently
exposed to this bug, but the same clone-on-access guarantee is kept for all domains uniformly so
that invariant never has to be re-verified by hand again.)

---

## Goals

- One generic, reusable TTL+LRU cache implementation (`internal/cachekit`) that Secret and Key
  caching migrate onto, and that Vault caching (new) is built on directly.
- One shared YAML config schema (`cache.<domain>.*`) replacing the hardcoded `cache.CacheConfig`
  defaults and the separate `key_cache.*` keys, with a slot reserved for `certificates`/`users`.
- Close the vault-lookup gap: `VaultResolutionMiddleware` stops hitting the DB on every request.
- Every cached value is cloned on `Get`/`Set` (`Cloneable[T]` constraint) — a categorical
  guarantee, not a per-domain judgment call, closing the live-mutation bug for Vaults immediately
  and pre-empting it for any future domain.
- Real `MaxEntries` enforcement via LRU eviction (neither existing cache enforces it today —
  confirmed dead config field in both).
- Zero regression: existing Secret/Key cache behavior (scope isolation, `byID` reverse-index
  eviction, `Flush` vs `Clear` semantics) is preserved exactly, just re-implemented on the shared
  core.

## Non-goals

- No `CertificateCache`/`UserCache` Go types in this phase — no caller exists yet, and building
  unused wrapper types is dead code by this project's own standard (see the 2026-07-19 orphan-code
  cleanup). Only their YAML config slot is reserved.
- No distributed/Redis cache — in-process only, matching both existing caches.
- No change to what gets cached for Secrets/Keys (same data, same invalidation triggers) — this is
  a mechanics unification, not a caching-strategy change for the two domains that already cache.
- No backward-compatible alias for `key_cache.*` — this is a breaking rename to `cache.keys.*`,
  documented like the v4.0.0 Azure RBAC breaking changes.

---

## Architecture

```
internal/cachekit                          (new — generic core)
  Cloneable[T any] interface { Clone() T }
  Config{ Enabled, TTL, CleanupInterval, MaxEntries }  +Validate()
  Interface[K comparable, V Cloneable[V]] { Get/Set/Invalidate/InvalidateAll/Stats/Stop }
  Cache[K,V]     — sync.Map-backed, atomic LastAccess per entry, bounded LRU eviction on Set
  NopCache[K,V]  — no-op, used when Enabled=false

internal/cache        (secrets)   ─┐
internal/keycache      (keys)      ├─► each wraps cachekit.Cache[K,V], keeps domain-specific
internal/vaultcache    (vaults,new)┘   composition on top (scope keys, reverse index, etc.)

internal/container/service_container.go
  cacheCfg, err := config.LoadCacheConfig()
  c.secretCache = cache.NewSecretCache(cacheCfg.Secrets, logger)   // always non-nil now
  c.keyCache    = keycache.NewCache(cacheCfg.Keys)                  // always non-nil now
  c.vaultCache  = vaultcache.NewCache(cacheCfg.Vaults)               // wired into VaultService
```

### `internal/cachekit` (new package)

```go
type Cloneable[T any] interface { Clone() T }

// Zeroable is optional. If a cached value implements it, cachekit calls
// Zero() on the removed value after any internal removal (TTL sweep, LRU
// eviction, Invalidate, InvalidateAll) — before the value becomes
// unreachable, but after it is exclusively held (no other goroutine can
// still be reading it via the map at that point). Preserves keycache's
// existing "zero key material after removal" behavior; Secret/Vault don't
// implement it, so nothing changes for those domains.
type Zeroable interface { Zero() }

type Config struct {
    Enabled         bool
    TTL             time.Duration
    CleanupInterval time.Duration
    MaxEntries      int
}
func (c Config) Validate() error // TTL>0, 0<CleanupInterval<TTL, MaxEntries>=0

type Stats struct { TotalEntries, ExpiredEntries int }

type Interface[K comparable, V Cloneable[V]] interface {
    Get(key K) (V, bool)
    Set(key K, value V)
    Invalidate(key K)
    InvalidateAll()
    Stats() Stats
    Stop()
}

type Cache[K comparable, V Cloneable[V]] struct { /* sync.Map + atomic count + evictMu */ }
type NopCache[K comparable, V Cloneable[V]] struct{}
```

**Storage**: `sync.Map` (lock-free reads/writes), matching `keycache`'s existing performance-
sensitive design — not the mutex+map approach `SecretCache` uses today.

**LRU without a read-path lock**: each entry stores a `LastAccess int64` (unix nano) updated via
atomic store on `Get` — no lock. Eviction only runs inside `Set`, only when an approximate
`atomic.Int64` count exceeds `MaxEntries`: a `TryLock`-guarded sweep (at most one evictor at a
time; others proceed without waiting) scans entries (bounded by `MaxEntries`, so cheap — same
reasoning `keycache.Invalidate`'s existing O(n) comment already relies on) and evicts the
least-recently-touched ones. The cap can overshoot briefly under heavy concurrent writes — strictly
better than today's zero enforcement, not a new risk.

**Cloning**: `Get` and `Set` always call `value.Clone()` before storing/returning. Benchmarked cost
across all real value types in this codebase: 1–56ns (struct-copy scale — `model.Secret`,
`keycache.Entry` wrapping an immutable PEM string, and the new `model.Vault` are all plain data
structs, none holds a parsed crypto object with mutable internals). Negligible next to the DB
round-trip or AES-GCM decrypt the cache exists to avoid.

### Domain wrappers

- **`internal/cache` (secrets)** — `SecretCache` wraps `cachekit.Cache[string, *model.Secret]`,
  keeps its scope-compound-key builder (`scopeCacheKey`) and `byID map[uuid.UUID]map[string]struct{}`
  reverse index (for `DeleteByID`, evicting every scoped view of one secret in one call) as
  composition on top — this pattern is domain-specific, not part of `cachekit`. `model.Secret`
  gains `Clone() *model.Secret` (today's free function `cloneSecret` becomes this method, logic
  unchanged: shallow copy + explicit `Tags` slice copy + four `*time.Time` pointer copies).
  `Flush` (unconditional full clear) and `Clear` (prune-expired-only, the background-sweep
  primitive) stay two distinct methods, as today.

- **`internal/keycache` (keys)** — thin wrapper over `cachekit.Cache[keyCacheKey, *Entry]` where
  `keyCacheKey struct{ ID uuid.UUID; Version int }` replaces today's `"keyID:version"` string
  concatenation (a real comparable struct key — no string alloc/parse per lookup).
  `Entry.Clone() *Entry` is a shallow struct copy — `PrivateKey`/`PublicKey` hold either
  `keycache.PEMKey{PEM: string}` (immutable string, copy is free) or are nil; no marshal/unmarshal
  round-trip needed anywhere in this codebase's actual usage (verified against
  `crypto_service.go:216-237` — the cache stores decrypted PEM strings, not parsed key objects).
  `Entry` also implements `cachekit.Zeroable` (`Zero()` sets `PrivateKey`/`PublicKey` to nil),
  preserving today's `memory_cache.go` behavior of scrubbing key material immediately after an
  entry is removed (TTL expiry, LRU eviction, or explicit invalidation) rather than waiting for GC.
  `Invalidate(keyID)` still evicts every version via the same prefix-scan approach.

- **`internal/vaultcache` (new)** — `cachekit.Cache[string, *model.Vault]` keyed by vault name
  (matches `VaultService.getByName`'s lookup key exactly). `model.Vault` gains
  `Clone() *model.Vault`. Wired into `VaultService`:
  - `getByName`/`GetVault`: cache check → repo on miss → populate.
  - `UpdateVault`, `DeleteVault`, `RecoverVault`, `PurgeVault`: invalidate by name after a
    successful repo write. Vault names are immutable post-creation (`model.UpdateVaultRequest` has
    no `Name` field), so no rename/dual-key invalidation case exists.
  - `CreateVault`: no pre-population — the next `GetVault` populates on first miss, keeping create
    simple.

---

## Config schema

```yaml
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
  certificates:        # reserved — no consumer yet
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
  users:                # reserved — no consumer yet
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
```

`secrets`/`keys` defaults exactly match today's `DefaultCacheConfig()`/`DefaultKeyCacheConfig()` —
no behavior change for deployments that don't touch this section. `vaults` is a new default sized
for the read pattern (rarely-mutated records, hit on nearly every request). `certificates`/`users`
default `enabled: false` since there is no wrapper to turn on yet.

```go
// config/config.go
type CacheConfig struct {
    Secrets, Keys, Vaults, Certificates, Users cachekit.Config
}
func LoadCacheConfig() (CacheConfig, error) // IsSet-per-field override pattern, matches
                                              // LoadMonitoringConfig/LoadSoftDeleteConfig;
                                              // returns the first Validate() error found
```

`internal/cache/config.go`'s `CacheConfig`/`DefaultCacheConfig`/`DevelopmentCacheConfig`/
`ProductionCacheConfig` and `internal/keycache`'s `KeyCacheConfig`/`DefaultKeyCacheConfig` are
removed — `cachekit.Config` + `config.LoadCacheConfig()` supersede them. The env-preset functions
were never wired to any environment-switching mechanism (confirmed: `initConfig()` hardcodes
`.rocketvault.yaml`, no auto env switching exists in this codebase), so nothing depends on them.

**Breaking change**: `key_cache.*` is removed; `cache.keys.*` replaces it. No deprecated alias.
Documented in a new `docs/release-notes/` entry alongside the existing v4.0.0 Azure RBAC breaking
changes.

---

## Data flow (container wiring)

```
bootstrap.go / service_container.go
  cacheCfg, err := config.LoadCacheConfig()   // fails fast on invalid TTL/cleanup/max_entries
  c.secretCache = cache.NewSecretCache(cacheCfg.Secrets, logger)
  c.keyCache    = keycache.NewCache(cacheCfg.Keys)
  c.vaultCache  = vaultcache.NewCache(cacheCfg.Vaults)
  // certificates/users: cacheCfg.Certificates / cacheCfg.Users loaded, not constructed
```

`NewSecretCache`/`NewCache` (keys) always return a real, non-nil object — internally holding either
`*cachekit.Cache[K,V]` (enabled) or `cachekit.NopCache[K,V]` (disabled). This removes the nil-check
call sites that exist today: `service_container.go:315`, `rotation_service.go:129`,
`versioning_service.go:89`. `VaultCache` follows the same non-nil-always pattern from the start.

---

## Error handling

- `LoadCacheConfig()` validates all 5 domains' `cachekit.Config` regardless of `Enabled` — catches
  config typos early even in the currently-unused certificates/users slots. A validation failure
  fails bootstrap, same severity as any other startup config error.
- Cache misses are not errors (`(V, bool)` return, as today).
- `Set`/eviction never errors — best-effort, in-memory only; losing an entry is not a failure mode
  (the cache is a performance layer, never a source of truth).
- `Clone() T` has no error return — every value type here is a plain, infallible struct copy.

---

## Testing

- **`cachekit`** (tested once, used by all three wrappers): TTL expiry; LRU eviction at the cap
  using explicit `Get()` calls to establish deterministic access order (no wall-clock races);
  concurrent Get/Set/Invalidate under `-race`; `NopCache` no-op behavior; compile-time
  `Interface[K,V]` compliance for both `Cache` and `NopCache`.
- **Domain wrappers**: re-run/adapt the existing `SecretCache` suite (scope isolation, `byID`
  reverse-index eviction, `Flush` vs `Clear`) and `keycache` suite (`keyCacheKey` isolation,
  `Entry.Clone()`) against the new implementations — feature-parity proof, not just new coverage.
  New tests for `VaultCache`: hit/miss, invalidate-on-Update/Delete/Recover/Purge, TTL expiry.
- **Behavior change to call out explicitly**: `container_test.go` currently asserts
  `GetSecretCache()` is `nil` when caching is disabled. That assertion changes to "returns a
  `NopCache`" — an existing test's meaning changes, not just new tests added.
- **Integration test** for `VaultResolutionMiddleware`: first request populates the cache (observed
  via a call-counting fake repo), second identical request does not increment the repo call count.
  This is the only way to actually prove the vault gap is closed — it's an internal call-count
  fact, not something a live curl smoke test can observe.
- Standard bar before calling this done: `go build ./...`, `go vet ./...`, `gofmt -l` on changed
  files, full `go test ./...`, plus updates to `.rocketvault.yaml`, `CLAUDE.md`, and a new
  `docs/release-notes/` entry for the `key_cache.*` → `cache.keys.*` rename.

---

## Migration checklist

1. Add `internal/cachekit` (generic core) with its own test suite first — nothing else depends on
   it existing correctly.
2. Migrate `internal/keycache` onto `cachekit.Cache[keyCacheKey, *Entry]` — smaller blast radius
   (fewer call sites) than secrets, good second step to validate the wrapper pattern.
3. Migrate `internal/cache` (secrets) onto `cachekit.Cache[string, *model.Secret]`, preserving the
   scope-key + reverse-index composition.
4. Add `internal/vaultcache` and wire it into `VaultService` + `VaultResolutionMiddleware`.
5. Add `config.LoadCacheConfig()`, rewire `service_container.go`, remove `key_cache.*` /
   `cache.CacheConfig` / `KeyCacheConfig`, update `.rocketvault.yaml`.
6. Update `CLAUDE.md`, add the release-notes entry, remove now-nil-check-free branches in
   `rotation_service.go`/`versioning_service.go`.
