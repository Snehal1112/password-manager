# Key Crypto Latency — Decrypted Key Cache + Prometheus Metrics

**Date**: 2026-05-27
**Status**: Approved
**Scope**: `internal/services/keys`, `internal/keycache`, `internal/metrics`, `internal/container`

---

## Problem

Every key crypto operation (Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey) performs three
expensive steps before the actual crypto work:

1. `KeyRepository.Read` — DB round-trip
2. `common.DecryptSecret` — AES-GCM decrypt of stored PEM
3. PEM parse — `crypto.CryptoOperations` parses the PEM string on every call

Under concurrent load these steps dominate p99 latency for software keys. There is currently no
instrumentation to measure or validate improvement.

---

## Goals

- Eliminate steps 1–3 on cache hits for software keys.
- Add Prometheus histograms so p50/p95/p99 per operation and key type are observable.
- Zero regression: all existing tests pass unchanged; authorization and revocation semantics are preserved.
- Full DDD compliance: no new logic in `api/`, `cmd/`, or `repositories/`.

## Non-goals

- Worker pool / goroutine-level concurrency control (deferred to a future phase).
- HSM (PKCS#11) private-key caching — hardware enforces isolation; only the handle string is
  touched, which is already cheap.
- Redis or distributed cache — in-process only for this phase.

---

## Architecture

```
Request
  └─► CryptoService.Sign / Verify / Encrypt / Decrypt / WrapKey / UnwrapKey
        ├─► [access control: ownership, revoked, accessible checks — unchanged]
        ├─► metrics: start timer
        ├─► keycache.Get(keyID, version)
        │     hit  → skip DB + AES-GCM + PEM parse          (hot path)
        │     miss → KeyRepository.Read → resolveKeyHandle
        │             → crypto.Parse* → keycache.Set        (cold path)
        ├─► crypto op (RSA / ECDSA / AES via cryptoOps or keyProvider)
        └─► metrics: observe duration {op, key_type, cache_hit}
```

HSM keys (`pkcs11:` prefix): `resolveKeyHandle` returns `isPKCS11 = true`.
`keycache.Set` is never called. The PKCS#11 path is unchanged.

---

## New Packages

### `internal/keycache`

Infrastructure package. Mirrors the existing `internal/cache` pattern.

```
internal/keycache/
  cache.go        — Cache interface + Entry struct
  memory_cache.go — sync.Map-backed implementation with TTL sweeper
  config.go       — KeyCacheConfig with defaults
  nop_cache.go    — no-op implementation for tests
```

**`Entry`**:
```go
type Entry struct {
    PrivateKey crypto.PrivateKey // nil for public-only keys
    PublicKey  crypto.PublicKey
    KeyType    string            // "RSA", "EC", "oct"
    Version    int
    ExpiresAt  time.Time
}
```

**`Cache` interface**:
```go
type Cache interface {
    Get(keyID uuid.UUID, version int) (*Entry, bool)
    Set(keyID uuid.UUID, version int, entry *Entry)
    Invalidate(keyID uuid.UUID)  // evicts all versions for this key
    InvalidateAll()
    Stats() CacheStats
    Stop()                       // stops the background sweeper
}
```

**Configuration** (`KeyCacheConfig`):

| Field           | Default | Notes                          |
|-----------------|---------|--------------------------------|
| `Enabled`       | `true`  |                                |
| `TTL`           | `60s`   | Shorter than secret cache TTL  |
| `MaxEntries`    | `500`   | Configurable via yaml          |
| `CleanupInterval` | `30s` |                                |

Cache key: `fmt.Sprintf("%s:%d", keyID, version)` — rotation increments version
so old entries are naturally unreachable even before TTL expiry.

On eviction the `Entry` struct is zeroed (`entry.PrivateKey = nil`, `entry.PublicKey = nil`)
before the map entry is deleted, reducing the window of in-memory private key exposure.

### `internal/metrics`

Infrastructure package. No domain types.

```
internal/metrics/
  crypto_metrics.go  — CryptoMetrics interface + Prometheus implementation
  nop_metrics.go     — no-op implementation for tests
```

**`CryptoMetrics` interface**:
```go
type CryptoMetrics interface {
    RecordOp(op, keyType string, cacheHit bool, dur time.Duration)
}
```

**Prometheus implementation** registers one `HistogramVec` via `sync.Once` (safe for parallel
tests if the Prometheus implementation is used):

- Metric name: `rocketvault_crypto_op_duration_seconds`
- Labels: `op` (sign/verify/encrypt/decrypt/wrap_key/unwrap_key), `key_type` (RSA/EC/oct/pkcs11),
  `cache_hit` (true/false)
- Buckets (seconds): `0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500`

**`go.mod` addition**: `github.com/prometheus/client_golang v1.20.x` (latest stable).

---

## Modified Files

### `internal/services/keys/crypto_service.go`

`CryptoServiceConfig` gains two optional fields:

```go
type CryptoServiceConfig struct {
    KeyRepository repositories.KeyRepositoryInterface
    KeyProvider   crypto.KeyProvider
    Logger        *logging.Logger
    KeyCache      keycache.Cache        // nil → no-op cache used
    CryptoMetrics metrics.CryptoMetrics // nil → no-op metrics used
}
```

`cryptoService` struct gains the same two fields. `NewCryptoService` assigns no-op
implementations when either field is nil — no existing call site requires change.

Each of the six operations gains a shared preamble extracted into a private helper:

```go
// resolveKeyMaterial returns the parsed crypto key material for the given
// model.Key, using the in-memory cache on a hit or falling through to
// AES-GCM decrypt + PEM parse on a miss.
// For PKCS#11 keys it always returns (nil, nil, true, handle, false, nil) —
// the caller uses the handle string directly via keyProvider.
func (s *cryptoService) resolveKeyMaterial(key *model.Key) (
    privateKey crypto.PrivateKey,
    publicKey  crypto.PublicKey,
    isPKCS11   bool,
    handle     string, // populated only for PKCS#11 keys
    cacheHit   bool,
    err        error,
)
```

The access-control block (ownership, revoked, accessible checks) runs **before**
`resolveKeyMaterial` — the cache is only consulted after authorization passes.

### `internal/services/keys/key_service.go`

`KeyServiceConfig` gains one optional field:

```go
type KeyServiceConfig struct {
    KeyRepository repositories.KeyRepositoryInterface
    KeyProvider   crypto.KeyProvider
    Logger        *logging.Logger
    KeyCache      keycache.Cache // nil → invalidation calls are no-ops
}
```

Three methods call `s.keyCache.Invalidate(keyID)` after a successful DB write:

| Method      | When invalidated                        |
|-------------|-----------------------------------------|
| `DeleteKey` | After `keyRepo.SoftDelete` succeeds     |
| `RotateKey` | After `keyRepo.Update` succeeds         |
| `UpdateKey` | After `keyRepo.Update` succeeds (always — covers revoke, disable, expiry changes) |

### `internal/container/service_container.go`

New fields on `ServiceContainer`:
```go
keyCache      keycache.Cache
cryptoMetrics metrics.CryptoMetrics
```

`ServiceContainerInterface` gains:
```go
GetKeyCache() keycache.Cache
GetCryptoMetrics() metrics.CryptoMetrics
```

`initializeServices()` initialises `keyCache` and `cryptoMetrics` after repositories
and passes them into both `NewKeyService` and `NewCryptoService`.

`Close()` calls `c.keyCache.Stop()`.

Config-driven cache enable/disable via `key_cache.enabled` yaml key — mirrors
`cache.enabled` for secrets.

---

## Invalidation Map

| Trigger                          | Cache action             | Layer        |
|----------------------------------|--------------------------|--------------|
| `KeyService.DeleteKey`           | `Invalidate(keyID)`      | service      |
| `KeyService.RotateKey`           | `Invalidate(keyID)`      | service      |
| `KeyService.UpdateKey`           | `Invalidate(keyID)`      | service      |
| TTL expiry (60s)                 | Swept by background goroutine | keycache |
| `keycache.InvalidateAll`         | Available for future use | keycache     |

Note: `KeyService.RecoverKey` and `KeyService.PurgeKey` operate on soft-deleted
keys. Soft-deleted keys return an error from `keyRepo.Read` in `CryptoService`
before the cache is consulted, so no invalidation is needed there.

---

## Authorization Safety

The access-control block (UserID check, revoked flag, `IsAccessible()`) always
runs against a fresh `model.Key` record from `keyRepo.Read`, which happens
**before** `resolveKey` is called. The cache is consulted only after authorization
passes — it stores parsed key material, never the authorization result.

**Staleness window**: once a key passes the access-control check, the cache may
serve its parsed material for up to TTL (60s) without re-reading from the DB.
Within that window, a concurrent `UpdateKey(Revoked=true)` will:
1. Write `revoked=true` to the DB.
2. Call `keyCache.Invalidate(keyID)` — evicting the cache entry immediately.

So the effective staleness window for revocation is **the time between the DB
write and the cache invalidation**, which is sub-millisecond (same goroutine,
sequential calls). After invalidation, the next request hits the DB and is
rejected. The 60s TTL is the backstop only if the process crashes between the
two steps, which is acceptable for a self-hosted vault.

---

## Regression Safety

### Pre-existing test baseline

The only pre-existing failures are two HSM hardware tests
(`TestPKCS11Provider_SignVerify_RSA_PS256`, `TestPKCS11Provider_EncryptDecrypt_RSA_OAEP256`)
that fail with `CKR_ARGUMENTS_BAD` due to the local SoftHSM configuration. These
are unrelated to this change and must remain at the same baseline — not fixed, not
newly broken.

All other packages (`ok` in `go test ./...`) must remain green.

### Existing tests — no modification required

| File | Why unchanged |
|------|---------------|
| `crypto_service_revoked_test.go` | Constructs `CryptoService` without cache — nil → no-op, tests pass |
| `wrap_key_test.go` | Same — nil KeyCache, exercises HSM rejection and software wrap paths |
| `key_service_update_test.go` | No cache interaction; UpdateKey cache call is nil-safe |
| `key_soft_delete_test.go` | Same |
| `api/keys_crypto_test.go` | API-level, no container changes visible here |
| `api/keys_hsm_test.go` | Same |

### New tests added

| Test | What it verifies |
|------|------------------|
| `keycache`: Get/Set/Invalidate/TTL expiry | Core cache correctness |
| `keycache`: concurrent access under race detector | No data races |
| `keycache`: entry zeroing on eviction | Private key not accessible after eviction |
| `metrics`: no-op compiles and records nothing | Test isolation |
| `CryptoService`: cache hit skips `keyRepo.Read` | Mock asserts `Read` called once across two Sign calls |
| `CryptoService`: revoke invalidates cache | Sign succeeds → Invalidate → Read returns Revoked=true → Sign rejected |
| `CryptoService`: HSM path never calls `Set` | Mock cache asserts `Set` never called for pkcs11: key |
| `CryptoService`: nil cache/metrics are no-ops | `NewCryptoService` with zero-value config does not panic |

All new tests run with `-race` in CI.

---

## Configuration (`.rocketvault.yaml`)

```yaml
key_cache:
  enabled: true
  ttl: "60s"
  max_entries: 500
  cleanup_interval: "30s"
```

When `key_cache.enabled: false` the container injects `keycache.NopCache` — no
behaviour change, purely additive.

---

## Dependencies

| Package | Version | Reason |
|---------|---------|--------|
| `github.com/prometheus/client_golang` | `v1.20.0` | Histogram registration and exposition |

---

## Files Created / Modified Summary

| Action   | Path |
|----------|------|
| Create   | `internal/keycache/cache.go` |
| Create   | `internal/keycache/memory_cache.go` |
| Create   | `internal/keycache/config.go` |
| Create   | `internal/keycache/nop_cache.go` |
| Create   | `internal/keycache/memory_cache_test.go` |
| Create   | `internal/metrics/crypto_metrics.go` |
| Create   | `internal/metrics/nop_metrics.go` |
| Create   | `internal/metrics/crypto_metrics_test.go` |
| Modify   | `internal/services/keys/crypto_service.go` |
| Modify   | `internal/services/keys/key_service.go` |
| Create   | `internal/services/keys/crypto_service_cache_test.go` |
| Modify   | `internal/container/service_container.go` |
| Modify   | `go.mod` / `go.sum` |
