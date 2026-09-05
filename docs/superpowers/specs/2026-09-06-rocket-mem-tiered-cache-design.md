# Rocket-mem Tiered Cache — Design

## Context

RocketVault's four domain caches (`internal/cache` for secrets, `internal/keycache`
for keys, `internal/certcache` for certificates, `internal/vaultcache` for vault
metadata) are all built on `internal/cachekit`, a purely in-process
`sync.Map`-backed generic TTL+LRU cache. Each RocketVault instance's cache is
independent: horizontally scaled deployments get no cache coherency across
instances, and every instance starts cold.

Rocket-mem (`../rocket-mem`, a sibling project) is a from-scratch, RESP2/RESP3
-compatible key-value store written in Rust, actively developed by the same
author. Running it as a shared external cache would let multiple RocketVault
instances share one warm cache, observable with standard Redis tooling
(`redis-cli`, RedisInsight) for operational visibility.

This spec covers making that integration safe and adding it as a second cache
tier, without changing any existing cache's public contract.

## Problem statement

Two of the four domain caches store values that must never leave the
RocketVault process as plaintext:

| Cache | What's stored today | Safe for an external, network-observable store? |
|---|---|---|
| `internal/cache` (secrets) | plaintext, post-`DecryptSecret` | No |
| `internal/keycache` (keys) | plaintext PEM, post-`DecryptSecret` | No |
| `internal/certcache` (certs) | `PrivateKey` stays ciphertext, never decrypted | Yes |
| `internal/vaultcache` (vaults) | no secret material | Yes |

Rocket-mem itself persists to disk in plaintext (AOF + snapshot, both verified
against source — no encryption anywhere in the crate) and defaults to a fully
open ACL until at least one user is configured. So RocketVault must guarantee,
at the boundary where a value leaves its own process, that anything reaching
Rocket-mem is already ciphertext — this is not optional hardening, it is the
only thing that would stand between a secret and a plaintext file on disk in
Rocket-mem's own AOF.

## Rocket-mem capabilities (verified against source, 2026-09-06)

- RESP2 and RESP3 (negotiated via `HELLO`). Full GET/SET(NX/XX/EX/PX)/DEL/
  EXISTS/EXPIRE/PEXPIRE/TTL/PERSIST plus string/hash/list/set/sorted-set
  families. No transactions, pub/sub, Lua, or streams — not needed here.
- Real ACL (Argon2-hashed passwords, per-command and per-key-pattern rules),
  but **defaults fully open** with zero configured users (mirrors Redis's own
  `requirepass`-less default).
- Real TLS via rustls for the RESP port, config-enforced at startup.
- AOF + point-in-time snapshot persistence, both **plaintext on disk** —
  verified via source (`encode_frame`/`RespCodec` for AOF, plain `bincode` for
  snapshots; no encrypt/cipher/aes anywhere in the crate except a TLS doc
  comment).
- v0.1.3, ~9 days of development, 731 tests passing (verified by running
  them), self-labeled "not yet production-hardened": no failover, full-resync
  -only replication, unauthenticated `/metrics`.

## Architecture

### `TieredCache[K, V]`

`cachekit` itself has no external dependencies today (it's a generic,
dependency-free in-process cache core), and should stay that way — it must
not import `go-redis` or know anything about RESP. So `TieredCache[K, V]` is
a new generic type in `internal/cachekit`, implementing the package's
existing `Interface[K, V]`, but parameterized over a small `L2[K]` interface
rather than a concrete client:

```go
// in cachekit — no go-redis import. Not generic over K: every operation is
// already wire-string-keyed, so a type parameter would be unused.
type L2 interface {
    Get(wireKey string) ([]byte, bool)
    Set(wireKey string, payload []byte, ttl time.Duration)
    Invalidate(wireKey string)
    // Keys returns every live wire key matching prefix (e.g.
    // "rocketvault:secret:"). Used only by Range (see below), never on a
    // hot path. Errors (including "L2 unreachable") return an empty slice —
    // the same fail-open-to-miss posture as every other L2 method.
    Keys(prefix string) []string
}
```

**Why `Keys` is required, not optional:** `cachekit.Interface[K,V]` includes
`Range(fn func(key K, value V) bool)`, and the existing invalidation pattern
used by `SecretCache.DeleteByID`, `certcache`, and `keycache` all depend on
`Range` visiting **every live entry** — none of them know in advance which
scope-key(s) a given secret/key/cert ID was cached under, so they discover
it by scanning. If `TieredCache.Range` only visited L1, an entry evicted
from L1 (TTL/LRU) but still alive in L2 would be invisible to that scan —
silently reopening the exact "a secret rotated because it was compromised
keeps being served from cache" bug class this codebase has hit before,
except now from an external cache instead of a stale in-process one.

So `TieredCache.Range` scans **both** tiers: it ranges L1 as today, then
calls `L2.Keys(domainPrefix)`, decodes any wire key not already visited via
L1, and calls `fn` for those too (L1's copy wins on a key present in both,
since it's guaranteed at least as fresh). This makes `Range` more expensive
whenever the L2 tier is enabled, but `Range` is only ever used by bounded,
infrequent invalidation sweeps (a mutation event), never a hot read path, so
paying one `KEYS`-equivalent network round-trip there is an acceptable
trade for correctness. Rocket-mem's `KEYS` support was verified as "partial"
(missing character-class ranges and negation) — a literal prefix wildcard
like `rocketvault:secret:*` is the basic case that partial support should
still cover, but Plan B (below) must verify this against a live rocket-mem
instance before relying on it, since "partial" was not fully enumerated
during the initial audit.

The actual Rocket-mem/go-redis-backed implementation of `L2[K]` lives in a
new package, `internal/rocketmemcache`, which is the only place `go-redis`
gets imported. `TieredCache` depends on the interface, not the package.

Because Redis-family keys are wire strings, and not every domain's cache key
is already a plain `string` today (`internal/keycache` keys by a composite
`{uuid.UUID, int}` struct, not a string), `TieredCache[K, V]`'s constructor
takes an explicit key codec rather than constraining `K` itself — simpler
than adding a method to every domain's key type (`SecretCache`/`certcache`/
`vaultcache` key on a bare `string`, which can't grow a method without a
wrapper type):

```go
type KeyCodec[K comparable] struct {
    ToWire   func(K) string
    FromWire func(string) (K, bool) // ok=false for a malformed/foreign wire key
}
```

`FromWire` is needed, not just `ToWire`, because `Range` (below) discovers
keys that exist only in L2 via `L2.Keys(prefix)`, which returns wire strings
— it must turn each one back into a `K` to call `fn(k, v)`. For the three
string-keyed domains this pair is the identity (`ToWire` returns the string
unchanged, `FromWire` always succeeds). For keycache's composite key,
`ToWire` is `id.String() + ":" + strconv.Itoa(version)` and `FromWire` parses
it back via `uuid.Parse` + `strconv.Atoi`, returning `ok=false` (skipped,
never an error) for anything malformed.

`Interface[K, V]`, for reference:

```go
type Interface[K comparable, V Cloneable[V]] interface {
    Get(key K) (V, bool)
    Set(key K, value V)
    Invalidate(key K)
    InvalidateAll()
    Stats() Stats
    Stop()
}
```

`TieredCache` wraps an L1 (`cachekit.Cache[K,V]` — today's implementation,
unchanged) and an L2 (a new Rocket-mem-backed client, described below):

- `Get(key)`: L1 hit → return. L1 miss → ask L2. L2 hit → decode, populate L1,
  return. Both miss → `false`.
- `Set(key, value)`: write L1 immediately (preserves today's latency for the
  fast path), then push to L2.
- `Invalidate(key)` / `InvalidateAll()`: evict from L1 **and** issue the
  equivalent eviction to L2 for the same key(s).
- `Stats()` / `Stop()`: `Stats` reports L1 only (L2 has no equivalent local
  concept); `Stop` also closes the L2 connection.

Because `TieredCache` satisfies the same `Interface[K,V]`, every domain
package (`SecretCache`, `internal/keycache.Cache`, `internal/certcache.Cache`,
`internal/vaultcache.Cache`) changes only its constructor — swapping what its
`core` field is built from — with zero change to its own public API. This
matters because of a fan-out cost already documented in this codebase's
knowledge base: every method added to a *wrapped-service* interface
(`CachedSecretService`, the retry wrappers) must be replicated across every
wrapper and every test double. Slotting the new tier in underneath
`cachekit.Interface` instead of as a new service-layer decorator avoids that
fan-out entirely. It also means invalidation correctness is automatic: every
existing call site that already calls `DeleteByID`/`Invalidate`/`InvalidateAll`
(including the `SecretCacheInvalidator` hook that rotation/versioning use to
bypass `CachedSecretService`) reaches L2 the same way it reaches L1 today,
with no new invalidation path to forget.

### Codec — pluggable per domain

`TieredCache`'s L2 client needs bytes, not live Go structs, so a small codec
interface sits at the boundary:

```go
type Codec[V any] interface {
    Encode(V) ([]byte, error)
    Decode([]byte) (V, error)
}
```

Two implementations:

- **`EncryptedJSONCodec`** (secrets, keys): JSON-marshal, then AEAD-encrypt
  using the existing master-key `CryptographyService` — the same primitive
  already used for DB-at-rest encryption. No new key to provision, rotate, or
  back up. A master_key compromise would expose Rocket-mem's cached values
  too, but it already exposes the database, so this does not widen the blast
  radius.
- **`PlainJSONCodec`** (certs, vaults): JSON-marshal, no encryption — matches
  their existing "nothing decrypted enters this cache" status. Certs still
  cache `PrivateKey` as ciphertext (unchanged, `GetCertificate` never
  decrypts it); vaults carry no secret material at all.

Sharing the network/TTL/failure mechanics behind one generic type while
letting each domain supply its own codec avoids duplicating the L2 client
logic four times.

### Keys on the wire

Each domain's existing composite cache key (e.g. `"v|<vaultID>|<secretID>"`
for `ScopeVault`-keyed secrets) is reused as-is, prefixed with
`rocketvault:<domain>:` to namespace it, in case a Rocket-mem instance is ever
shared with another consumer.

### L2 client and failure handling (`internal/rocketmemcache`)

- Client library: `github.com/redis/go-redis/v9` — context-first (matches
  this codebase's `ctx`-threaded services throughout), works against any
  RESP2/3-compliant server (not Redis-specific), and is the actively
  maintained, idiomatic choice. No existing Redis-adjacent dependency exists
  in `go.mod` today; this is a new dependency, and it is confined entirely to
  this one new package — `cachekit` and the domain cache packages depend only
  on the `L2[K]` interface above.
- Constructed once at container startup, only when `cache.rocket_mem.enabled`.
- **Every** L2 call (`Get`/`Set`/`Invalidate`) is wrapped so any error —
  network timeout, connection refused, encode/decode failure — is treated as
  a plain miss on `Get` and a silently-logged (`Warn`, not `Error`) no-op on
  `Set`/`Invalidate`. This preserves `cachekit.Interface`'s existing
  zero-error contract: a Rocket-mem outage must never break a secret/key/cert
  read, only degrade it to "L1 miss → source-of-truth DB read," exactly the
  behavior an operator already sees today with caching disabled entirely.
- Short dial/read/write timeouts (~100–200ms default). An L2 cache's entire
  purpose is to be faster than the alternative; it must fail fast rather than
  add latency to the read path when Rocket-mem is slow or unreachable.
- Connection pooling via go-redis's built-in pool (small default pool size,
  configurable).

## Configuration

One shared section backs all four domains' L2 tier — a single Rocket-mem
instance serves all of them, distinguished by key namespace, not four
separate connection configs:

```yaml
cache:
  rocket_mem:
    enabled: false
    addr: "127.0.0.1:6379"
    tls: false
    username: ""
    password: ""
    dial_timeout: 100ms
    read_timeout: 100ms
    write_timeout: 100ms
    pool_size: 10
```

**Startup validation (fail closed):** if `cache.rocket_mem.enabled` is `true`,
startup refuses to proceed unless both `tls: true` and a non-empty
`username`/`password` are set. Rocket-mem defaults to a fully open ACL with
zero configured users, so allowing this cache to be enabled against an
unauthenticated, unencrypted-transport instance would hand a network-adjacent
attacker cache-poisoning and DoS capability (`DEL`, overwrite, or — if the
operator's Rocket-mem ACL user is over-scoped — `FLUSHALL`) even though the
*payload* is encrypted. This mirrors the existing pattern in this codebase of
validating configuration and aborting startup rather than degrading silently
(e.g. `master_key`, JWT signing key).

Deployment docs will additionally recommend scoping the Rocket-mem ACL user
RocketVault connects as to only the commands it needs
(`GET`/`SET`/`DEL`/`EXPIRE`-family) — not `FLUSHALL`, not `ACL`
administration — as defense in depth. This is an operational recommendation
in the deployment guide, not something RocketVault's own code can enforce
against an external service.

## Scope

All four domain caches (secrets, keys, certs, vaults) get the L2 tier, since
the cross-instance cache-coherency motivation applies equally to all of them.
Only secrets and keys use the encrypting codec; certs and vaults use the
plain codec, per the table in Problem Statement.

## Non-goals / deferred

- Rocket-mem clustering, replication, or failover — out of scope; RocketVault
  treats it as a single logical L2 endpoint regardless of how it's deployed
  behind that address.
- Cache warming / pre-population strategies — L2 fills lazily via normal
  `Get` traffic, same as L1 does today.
- Metrics/observability for L2 hit/miss rates — worth adding later
  (`rocketvault_cache_l2_*` Prometheus counters, mirroring the existing
  `rocketvault_vault_rate_limit_exceeded_total`-style per-domain metrics) but
  not required for correctness of this design; deferred to a follow-up.
- Migrating existing in-process-only deployments — enabling `cache.rocket_mem`
  is purely additive and optional; a deployment that never sets `enabled:
  true` is byte-for-byte unaffected by this work.

## Testing approach

- `TieredCache` unit tests using a fake/in-memory L2 double (not a real
  Rocket-mem connection) covering: L1-hit short-circuits L2 entirely, L1-miss
  -L2-hit populates L1, both-miss returns false, `Set` reaches both tiers,
  `Invalidate`/`InvalidateAll` evict both tiers, and every L2-error path
  (simulated timeout/connection-refused/decode-failure) degrades to
  miss-on-Get / silent-no-op-on-Set without returning an error to the caller.
- Codec unit tests: `EncryptedJSONCodec` round-trips and produces ciphertext
  indistinguishable from random bytes for a known plaintext (no plaintext
  substring leakage); `PlainJSONCodec` round-trips.
- A live-integration test suite (build-tagged, skipped by default like this
  project's other live-server suites) that runs against a real local
  rocket-mem instance for at least one full round-trip per domain, run
  manually / in a dedicated CI job rather than the default `go test ./...`
  path — mirrors how this project already handles tests needing a live
  external process.
- Startup-validation test: `cache.rocket_mem.enabled: true` without
  `tls`/credentials configured must fail startup with a clear error, not
  silently proceed.
