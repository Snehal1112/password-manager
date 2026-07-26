# Vault Scope Refactor and Azure Key Vault Authorization Parity — Design

**Date:** 2026-07-26
**Branch:** v-4.0.0
**Status:** Approved design, ready for implementation planning
**Covers:** Sub-projects P0 (safety net), P1 (`model.Scope` refactor), P2 (Azure RBAC authorization)
**Defers:** P3-P5 (see [Out of Scope](#out-of-scope))

---

## 1. Goal

Replace RocketVault's per-object ownership authorization with Azure Key Vault's vault-scoped RBAC model, and collapse the duplicated `*InVault` method pairs onto a single explicit scope value object that makes vault scoping structurally impossible to forget.

Three outcomes, in order:

1. **P0** pins current behavior with regression tests and fixes live defects, so the refactor is verifiable.
2. **P1** collapses 56 paired interface methods onto one `model.Scope` value. It is behavior-preserving except for four narrow, deliberate fixes called out in §5.3: the missing `vault_id` SELECT, scope enforcement on `RecoverSecret`/`PurgeSecret` (which have none today), the `listSecretVersionsHandler` 500→404 correction, and audit actor attribution.
3. **P2** changes behavior deliberately: ownership stops being an authorization input, per-vault Azure role assignments take over, and the policy middleware inverts to deny-by-default.

## 2. Decisions

These were settled during design and are not open for re-litigation during implementation.

| Decision | Choice | Consequence |
|---|---|---|
| Per-object ownership | **Removed as an authorization input.** `user_id` becomes provenance and audit metadata only. | Breaking change. A user who previously saw only their own secrets in the default vault will see every secret in it, subject to their vault role. |
| Authorization model | **Azure built-in data-plane role set**, assigned per vault, fail-closed. | Role names map 1:1 to Azure, so Azure documentation and scripts transfer. Existing `access_policies` table is retained only as an explicit-deny override. |
| Parity depth | **Full surface parity** is the program goal (P0-P5). This spec delivers P0-P2. | P3-P5 are separately specced. |
| Out-of-scope resource response | **404, not 403.** | Removes the existence oracle the legacy flat routes have today. Observable change for clients distinguishing the two. |
| B6 (crypto ops owner-gating) | **Temporary invariant.** Pinned by tests in P0, deliberately removed in P2. | Under Azure parity, crypto operations are gated by `Key Vault Crypto User` at vault scope. Ownership is not an input. |

## 3. Corrections to project documentation

Implementation must fix these; they are wrong today and will mislead.

- **`internal/domain/` does not exist.** `CLAUDE.md` describes it at length (`internal/domain/user.go`, `secret.go`, `key.go`, `certificate.go`) and the architecture diagram lists it. The actual domain package is `model/`, which holds `Secret`, `Key`, `Vault`, `DefaultVaultID`, and `RoleAdmin`, and depends only on stdlib plus `uuid`. All new domain types go in `model/`. Correct `CLAUDE.md` in the same release.
- **`.claude/multi-vault.md` asserts "no vault-scoped route silently ignores its vault."** False for `PUT /vaults/{n}/certificates/{id}`, `POST /vaults/{n}/keys/{id}/rotate`, and `GET /vaults/{n}/keys/{id}/versions`. Correct the claim; the routes themselves are fixed in P3.

## 4. Sub-project P0 — Safety net and live defects

P0 exists so that P1 is verifiable and cheaper. Nothing in P0 changes intended behavior except where a defect is being fixed.

### 4.1 Regression tests to land first

**B6 crypto-operation gating.** No test currently asserts it; the behavior is implied only by which service method each handler happens to call. Before any refactor, add tests asserting that a non-owner vault member receives 403 on `sign`, `verify`, `encrypt`, `decrypt`, `wrapkey`, `unwrapkey`, and key delete via `/vaults/{name}/keys/...`. These tests are deleted in P2 when the policy intentionally changes; their purpose is to make P1's mechanical edits safe.

**Cross-vault denial, end to end.** No existing test seeds a resource in vault B, requests it via `/vaults/A/...`, and asserts denial. Every HTTP-level vault test uses hand-written fakes whose `*InVault` methods unconditionally succeed, so they prove dispatch but not scoping. Add, per resource type (secrets, keys, certificates, certificate policy), a real-SQLite test doing exactly that. These are permanent.

### 4.2 Live defects to fix

| Defect | Location | Impact |
|---|---|---|
| `UpdateSecretInVault` passes the caller into `CreateVersion`, which gates on `secret.UserID != req.UserID` | `internal/services/secrets/secret_service.go:396-403`, `versioning_service.go:88-97` | A vault member updating a secret they do not own gets HTTP 500. The feature does not work for its intended case. |
| `CachedSecretService.UpdateSecretInVault` does not invalidate | `internal/cache/cache_integration.go:96-99` | After a vault-scoped update, `GET /api/v1/secrets/{id}` serves stale plaintext for up to the TTL (5 min default). |
| Cache hit path skips `IsAccessible()` | `internal/cache/cache_integration.go:36-45` | A secret that expires or is disabled while cached is served anyway. |
| `SecretCache.Clear` only prunes expired entries, but is called as a flush | `internal/cache/secret_cache.go:99-115`, called at `cache_integration.go:208` | `ImportSecrets`' "clear cache to ensure consistency" is a no-op for live entries. |
| CLI `keys wrap` / `unwrap` never set `VaultID` | `cmd/keys/wrap.go:85-90`, `unwrap.go:85-90` | `loadAndAuthorize`'s `key.VaultID != vaultID` check always fails against real keys. Both commands are broken today. |
| Audit actor is a vault UUID | `internal/repositories/secret_repository.go:730,736,740,744` | Writes a vault UUID into the `audit_logs.user_id` column, which is a queryable filter and feeds the hash chain. |
| `UpdateKeyInVault` emits contradictory audit rows | `internal/services/keys/key_service.go:620,628` plus `key_repository.go:303-317` | Service logs the actor; repository logs the key's owner. Two rows attribute the same action to different users. |
| `RotationService.GetSecretPolicies` and `AcknowledgeReminder` have no ownership check | `internal/services/secrets/rotation_service.go:339,497` | Unscoped. Not currently reachable over HTTP, but reachable from the CLI surface. |

### 4.3 Generated mocks

Five hand-written mock files re-implement 21-23 methods each (~115 hand-maintained methods) purely to satisfy interfaces. Adopt `mockery` for `SecretService`, `KeyService`, `CertificateService`, `VersioningServiceInterface`, and the three repository interfaces. This cuts the cost of adding an interface method from ~7 hand edits to ~3, and it must land before P1 Phase 2 to pay for itself.

Note: `go vet ./...` does **not** reliably catch missing mock methods here. `cmd/testutils.MockServiceContainer` stores services as `interface{}` and type-asserts at runtime, so a missing method surfaces only as a `go test` panic. Verification gates must run `go test ./...`, not `go vet` alone.

## 5. Sub-project P1 — The `model.Scope` refactor

### 5.1 The value object

`model/scope.go`. Placement rationale: `model/` is the real domain package, is dependency-free apart from `uuid`, and already holds `DefaultVaultID`, which scope construction needs. Creating `internal/domain/` would split one concept across two packages.

```go
// ScopeKind identifies how a resource operation is authorized. Its zero value
// is deliberately invalid so an uninitialised Scope fails closed.
type ScopeKind uint8

const (
	ScopeInvalid ScopeKind = iota // Zero value. Repositories reject it.
	ScopeVault                    // Any member of the vault may act.
	ScopeOwner                    // Restricted to the owner. P1 only; retired in P2.
	ScopeAdmin                    // No predicate. Trusted internal callers only.
)

// Scope is the authorization scope of a single resource operation. It replaces
// the *InVault and *ByOwner method pairs: the scope travels as a value instead
// of being encoded in the method name.
type Scope struct {
	kind    ScopeKind
	vaultID uuid.UUID // Set for ScopeVault; advisory for ScopeOwner.
	ownerID uuid.UUID // Set for ScopeOwner only.
	actorID uuid.UUID // The acting principal, for audit. Never an access predicate.
}

func NewVaultScope(vaultID, actorID uuid.UUID) Scope
func NewOwnerScope(vaultID, ownerID uuid.UUID) Scope
func NewAdminScope(actorID uuid.UUID) Scope

func (s Scope) Kind() ScopeKind
func (s Scope) VaultID() uuid.UUID
func (s Scope) ActorID() uuid.UUID
func (s Scope) OwnerID() (uuid.UUID, bool) // false when not owner-scoped
func (s Scope) ResolvedVaultID() uuid.UUID // falls back to DefaultVaultID
func (s Scope) Validate() error
func (s Scope) String() string             // for logs; never secret material
```

Two properties carry the design:

**Fail-closed zero value.** `ScopeInvalid = 0` means a struct literal, a forgotten field, or a zero-valued mock return can never be mistaken for admin. Every repository entry point calls `Validate()` before building a query. Without this, the refactor converts a compile error into a silent privilege escalation.

**No sentinel overloading.** `OwnerID()` returns `(uuid.UUID, bool)`. Compare today's `DeleteKeyInVault(ctx, keyID, vaultID, userID uuid.UUID)`, documented as "pass `uuid.Nil` to skip the check" — an accidentally-zero `userID` currently disables the ownership check entirely.

Composite literals of `model.Scope{}` are forbidden outside `model/scope_test.go`.

### 5.2 The predicate helper

`internal/repositories/scope_predicate.go`. A closed switch over the typed enum returning one of three compile-time constant SQL fragments plus bind arguments. No caller-supplied value is ever interpolated; every value travels as a `?` placeholder.

```go
var ErrInvalidScope = errors.New("invalid authorization scope")

func scopePredicate(scope model.Scope) (string, []any, error)
// ScopeVault -> "vault_id = ?"
// ScopeOwner -> "user_id = ?"
// ScopeAdmin -> "1 = 1", no args
// default / Validate failure -> ErrInvalidScope
```

Explicit branches rather than a query builder: there are three predicates and roughly six query shapes across three repositories. A builder introduces a stringly-typed surface and hides SQL that this codebase deliberately writes and reviews as literals.

`ScopeOwner` deliberately does **not** constrain `vault_id`. `ReadByOwner` and `ListByUser` have never filtered by vault, so tightening that here would be a behavioral change smuggled into a refactor. It is moot after P2, which retires `ScopeOwner` from the data plane.

Add `TestScopePredicateBindArity`, asserting every scope kind produces exactly as many `?` placeholders as bind arguments.

### 5.3 Layer changes

**Repository.** `SecretRepositoryInterface` collapses `Read`/`ReadByOwner`/`ReadInVault`, `Update`/`UpdateInVault`, and the four `List*` variants into three methods:

```go
Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error)
Update(ctx context.Context, secret *model.Secret, scope model.Scope) error
List(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error)

type SecretFilter struct {
	Tags           []string // Accepted for compatibility; tag filtering lives in TagService.
	IncludeDeleted bool
	OnlyDeleted    bool
}
```

Nine methods to three. `ListDeletedSecretsInVault`'s in-Go filtering loop becomes `List(ctx, scope, SecretFilter{OnlyDeleted: true})`, moving the filter into SQL instead of pulling every secret in the vault into memory to discard most of them. Key and certificate repositories follow the same shape with their own filter structs.

**Prerequisite bug fix.** `Read` and `ReadByOwner` do not select `vault_id` (`secret_repository.go:163,211`); only the `*InVault` variants backfill it from the query argument. A secret fetched via `UpdateSecret` therefore has `VaultID == uuid.Nil`. This is harmless only while `Update` scopes by `user_id`. Fix the SELECT list before any scope-aware write exists, and enforce architecturally: **the predicate is always built from the explicit `Scope` argument, never from the entity.**

**Service.** Request structs drop `UserID` + `VaultID` for a single `Scope` field. This erases comments like "Set only for vault-scoped updates; ignored by `UpdateSecret`" — a field whose meaning depends on which method you call. `SecretService` goes 23 methods to 15, `KeyService` 13 to 5.

The ~70 lines of field-merge logic duplicated between `UpdateSecret` and `UpdateSecretInVault` extract to a pure function:

```go
func applySecretUpdate(current *model.Secret, req UpdateSecretRequest,
	encrypt func(string) (string, error)) (*model.Secret, error)
```

It performs no I/O and no authorization, and is unit-testable without a database — neither original was. `applyKeyUpdate` mirrors it.

Authorization moves entirely into the scope: the scoped read *is* the check, and the write repeats the same predicate, so there is no TOCTOU window even if the row's vault changes between them. Today's pattern — unscoped `Read`, then an in-Go `currentSecret.UserID != req.UserID` comparison, then a differently-scoped `Update` — has three independent mechanisms that can disagree.

`RecoverSecret` and `PurgeSecret` gain a scope. They currently take a bare `secretID` with **no authorization check at all**; handlers gate them via a separate `IsSecretSoftDeleted*` pre-check, which is a TOCTOU window.

`ListKeysWithFilters(userID *uuid.UUID, ..., isAdmin bool)` disappears. Its `if !isAdmin && userID == nil` guard is a runtime re-derivation of what the caller already knew; `model.NewAdminScope(actor)` states it once at the call site where the RBAC decision was actually made.

**Handler.** `api/context.go` gains `scopeFromRequest(r)` and `ownerScopeFromRequest(r)`, replacing `isVaultScopedRoute` and its 8 call sites. A handler that neither builds nor uses a scope will not compile. `ownerScopeFromRequest` exists solely to mark the B6 handlers explicitly during P1; it is removed in P2.

A shared `writeSecretError(c, err)` replaces the identical three-way `errors.Is` chain repeated across `getSecret`, `updateSecret`, `deleteSecret`, and the three version handlers. This also fixes the inconsistency where `listSecretVersionsHandler` returns 500 for a wrong-vault lookup while its two siblings return 404.

**Decorators.** A generic `retried[T]` helper removes the repeated var/closure/return boilerplate; `retry_secret_service.go` goes from ~293 lines to ~90.

The cache needs real change, not a mechanical shrink. It is currently keyed by secret ID alone and admits a hit after checking only `cached.UserID == userID`. Once `GetSecret` is one method, it will cache vault-scoped reads too, and an ID-keyed cache would serve an owner-scoped caller a value admitted under a vault scope. Design:

- Compound key `scopeCacheKey(secretID, scope)` — `"v|{vaultID}|{secretID}"` or `"o|{ownerID}|{secretID}"`. `ScopeAdmin` reads are never cached.
- A `byID` reverse index so one mutation evicts every scoped view of a secret.
- `DeleteByID` becomes the invalidation primitive; `Flush` is added and distinguished from `Clear`.
- The hit path rechecks `IsAccessible()`.

Rejected alternative: keep the ID-only key and admit via a Go-side `Admits(scope, secret) bool`. That requires mirroring `scopePredicate`'s SQL in a second language forever; a divergence is a silent authorization bypass with no compiler or test to catch it. The compound key has no such twin.

`TestEveryMutatorInvalidates` — a table test over every mutating method, priming the cache under both a vault scope and an owner scope, invoking the mutator under one, and asserting both entries are gone. New mutators must be added to the table in the same commit.

### 5.4 Migration

The new API is added first as the canonical implementation; every old method becomes a three-line shim constructing a `Scope` and delegating. The existing test suite, untouched, is the equivalence proof through phases 1-4.

| Phase | Scope | Green? |
|---|---|---|
| 0 | `model/scope.go` + unit tests. Nothing consumes it. | Yes, additive |
| 1 | `scope_predicate.go`; scope-aware `Read`/`Update`/`List` as canonical bodies in the concrete repository structs; old methods become shims. Fix the `vault_id` SELECT. | Yes — no interface change, so no mocks move |
| 2 | Add the new methods to the repository interfaces. Update the retry wrapper and generated mocks. Old methods stay. | Yes, additive |
| 3 | Services, one resource per commit. Extract `applySecretUpdate`/`applyKeyUpdate`. Old methods become shims. **Caching stays disabled on the unified `GetSecret`.** | Yes |
| 4 | Handlers, then CLI. `scopeFromRequest`, `ownerScopeFromRequest`, `writeSecretError`. | Yes |
| 5 | Cache rework: compound key, `byID`, `DeleteByID`, `Flush`, `IsAccessible` recheck. Re-enable caching. | Yes |
| 6 | **Delete the shims.** Remove `*InVault`/`*ByOwner` from all interfaces. | Yes, irreversible |

Bottom-up is the only order where each phase's correctness is checked by the *existing* tests. Top-down would require rewriting handler tests before the layer beneath supports the new shape, so tests and code would change in the same commit with no independent check.

Phase 5 is deliberately isolated: the cache is where security regression risk concentrates, and it must bisect cleanly. Phase 3 passes `GetSecret` straight through to the service, accepting one phase of reduced cache hit rate to eliminate the window where a vault-scoped entry could be admitted to an owner-scoped caller.

**Point of no return:** the Phase 6 commit removing `ReadInVault`, `UpdateInVault`, `ListInVault`, `ListInVaultIncludeDeleted`, and `ReadByOwner` from the interfaces. Gate it in CI:

```bash
# Must return zero matches outside model/scope.go doc comments.
grep -rn "InVault\|ReadByOwner\|ListByUser(" --include="*.go" . | grep -v "_test.go"
```

## 6. Sub-project P2 — Azure RBAC authorization

### 6.1 What is broken today

Vault membership is never checked on any resource route. Traced and confirmed:

- `VaultResolutionMiddleware` (`internal/middleware/middleware.go:470-499`) checks only that the vault exists and is enabled. The principal is never consulted.
- `PolicyMiddleware` (`:402-462`) is deny-on-explicit-deny: zero matching policy rows yields `AccessFallback` and the request proceeds.
- `mapEndpointToPermission` (`internal/services/authorization/rbac_service.go:230-240`) **strips the `vaults/{name}/` prefix**, so a vault-scoped route maps to the same global permission as its flat equivalent. RBAC is vault-agnostic by construction.
- The only real vault gate, `requireVaultManage` (`api/role_assignments.go:45`), is used exclusively on vault-management and role-assignment routes. Zero resource routes use it.

Consequence: any principal holding a global permission can operate on any vault by name.

### 6.2 Target model

**Role vocabulary.** Azure's built-in data-plane roles as constants in `model/`:

| Role | Grants |
|---|---|
| Key Vault Administrator | All data-plane operations on all object types |
| Key Vault Reader | Metadata only; no secret values or key material |
| Key Vault Secrets User | Get and list secrets, including values |
| Key Vault Secrets Officer | Full secret control |
| Key Vault Crypto User | Use key material: encrypt, decrypt, sign, verify, wrap, unwrap |
| Key Vault Crypto Officer | Full key control including create, import, delete, rotation policy |
| Key Vault Certificates Officer | Full certificate control |

Assigned per vault via the existing `role_assignments` table, which already has `vault_id NOT NULL`.

**Middleware.** `PolicyMiddleware` inverts to deny-by-default for resource routes: no matching role assignment in the resolved vault yields 403. `mapEndpointToPermission` stops stripping the vault prefix and maps `(method, path)` to an Azure data action evaluated against the caller's role assignments in that specific vault. `access_policies` is retained only as an explicit-deny override, evaluated before the allow decision.

**Scope.** `ScopeOwner` retires from the data plane. Every resource route builds `ScopeVault`; flat routes resolve to the default vault and carry identical semantics. `ownerScopeFromRequest` and the B6 tests from P0 are deleted. `ScopeAdmin` remains for the vault cascade, backup/restore, and the rotation scheduler.

**Ownership.** `user_id` columns stay, populated as provenance for audit and display. Nothing reads them for an access decision.

### 6.3 The upgrade migration

Inverting to fail-closed locks out every existing deployment, because no role assignments exist yet. This is the highest-risk artifact in the spec and must be written test-first against a seeded database.

One-time migration, idempotent, running in `migrateSchema()`:

1. For each distinct `user_id` owning rows in `secrets` for a given `vault_id`, grant `Key Vault Secrets Officer` in that vault.
2. Same for `keys` → `Key Vault Crypto Officer`, and `certificates` → `Key Vault Certificates Officer`.
3. Every user with the existing global admin role gets `Key Vault Administrator` in every vault.
4. Log a summary line per vault: principals granted, roles granted, rows examined.

The migration must be verifiable before it runs destructively: ship a `rocketvault vaults preview-migration` command that prints the assignments it *would* create, so an operator can inspect before upgrading.

### 6.4 Release notes

Three breaking changes to document explicitly:

- Users see all objects in vaults they hold a role in, not just objects they created.
- Out-of-scope resources return 404 where some previously returned 403 with "access denied".
- Key crypto operations are gated by `Key Vault Crypto User` at vault scope rather than by key ownership.

## 7. Error handling

| Condition | Response |
|---|---|
| Resource not found, or outside the caller's scope | 404. Indistinguishable by design; no existence oracle. |
| Authenticated, but no role assignment granting the required data action in this vault | 403 |
| Vault does not exist | 404 |
| Vault exists but is disabled | 403 |
| Resource disabled or outside its validity window | 403, `ErrSecretLifecycleDenied` |
| Invalid or uninitialised scope reaching a repository | 500, `ErrInvalidScope`. This is a programming error, never reachable from a well-formed request. |

## 8. Testing

Beyond the existing suite, which must stay green through P1 Phases 1-4:

- **Cross-vault denial, real SQLite, per resource type.** Seed in vault B, request via `/vaults/A/...`, assert 404. Covers secrets, keys, certificates, certificate policy, and each of secrets' version endpoints.
- **`model.Scope{}` rejection, per repository method.** Assert `ErrInvalidScope`, not rows.
- **`TestScopePredicateBindArity`**, table-driven over all scope kinds.
- **`TestEveryMutatorInvalidates`**, over every mutating cache-decorator method, priming under two scopes.
- **P2 authorization matrix.** For each Azure role, assert the exact set of allowed and denied operations. Table-driven over (role, operation) pairs.
- **Upgrade migration.** Seed a database in the pre-migration shape with multiple users and vaults; run the migration; assert the exact role assignments produced and that re-running is a no-op.
- **B6 tests** land in P0 and are deleted in P2. Their deletion must be its own commit with the P2 policy change, never bundled into a refactor commit.

Verification gates run `go build ./... && go test ./...`. `go vet` alone is insufficient (see §4.3).

## 9. Risks

| Risk | Mitigation |
|---|---|
| Zero-value `Scope` failing open — the single highest-severity risk. A test helper or partially-migrated call site produces `Scope{}` and gains unrestricted access. | `ScopeInvalid = 0`; `scopePredicate` returns `ErrInvalidScope` on `default:` and `Validate()` failure; a rejection test per repository method; composite literals banned outside `model/scope_test.go`. |
| **Sequencing hazard: P0 widens exposure until P2 lands.** Fixing the `CreateVersion` ownership gate (§4.2) is what currently makes vault-scoped secret UPDATE fail with a 500 for non-owners. Repairing it restores the intended "any vault member may update" behavior — but until P2's fail-closed RBAC ships, "vault member" is still unenforced, so any principal with a global secrets permission can overwrite another user's secret in any vault by name. The same already-open exposure exists for vault-scoped key update, certificate policy, and bulk secret export. | P0, P1 and P2 must ship as **one release**, never incrementally to production. If that is not possible, land P2's fail-closed `PolicyMiddleware` inversion *before* the `CreateVersion` fix, accepting the 500 in the interim. Do not deploy P0 alone. |
| Cache serving a vault-scoped entry to an owner-scoped caller. | Caching disabled on the unified `GetSecret` through Phase 3; compound key lands in isolated Phase 5. |
| A new mutator forgets cache invalidation — this already happened once. The cache stores **decrypted** values, so the consequence is stale plaintext. | `TestEveryMutatorInvalidates` plus the rule that new mutators join the table in the same commit. |
| B6 widening during P1: a mechanical `GetKeyInVault` → `GetKey(scope)` edit in a crypto handler using `scopeFromRequest` instead of `ownerScopeFromRequest`. | P0's B6 tests land before any refactor commit. |
| Upgrade migration locking out a production deployment. | Test-first against a seeded database; `preview-migration` command; idempotent; per-vault summary logging. |
| Audit-log consumers keyed on the current empty or wrong actor values. | Enumerate consumers before P0's audit fixes; note in release notes. |
| Certificate `type`-column latent bug: `ListByUser`/`ListInVault` filter on a column that does not exist, reachable only with a non-empty `certType`. | Resolve (add the column or drop the filter) before P1 Phase 1 touches the certificate repository. |
| Large mechanical diffs inviting rubber-stamp review. | Generated mocks (§4.3) shrink the diff; one resource per commit in Phases 3-4. |

## 10. Out of scope

Deferred to later specs, with the gap list established during this design:

**P3 — Vault-blind routes and schema.** `PUT /vaults/{n}/certificates/{id}` (no `UpdateCertificateInVault` exists at all), `POST /vaults/{n}/keys/{id}/rotate`, `GET /vaults/{n}/keys/{id}/versions`. Add `vault_id` to `certificate_policies`, `secret_versions`, `key_versions`. Make the rotation subsystem vault-aware. Validate `VaultID` on backup restore, which currently re-inserts the blob's original vault unchecked. Register backup/restore on the vault-scoped router. Wire `--vault` through `cmd/keys/`, `cmd/certificates/`, and `cmd/secrets/{update,export,import}`.

**P4 — Azure object model.** Name plus version addressing (`/{type}/{name}/{version}`), names unique per vault; immutable versions where writes create versions rather than mutating; list never returns values; soft-delete blocking name reuse until purge or retention expiry; per-vault retention days and purge protection.

**P5 — Remaining Azure surfaces.** Certificate issuers, certificate contacts, merge and pending CSR flow, key rotation policies, per-object backup/restore, network ACLs, and the certificate-as-linked-key-plus-secret data model.

## 11. References

- Review findings and route inventory: this session's audit of commits `e0e56dc..e38bd11`
- Prior plan: `docs/superpowers/plans/2026-07-26-vault-scope-inconsistency-fixes.md`
- Azure RBAC guide: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- Azure access policy vs RBAC: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-access-policy
- Azure data actions: https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/security
- Azure object identifiers: https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates
- Azure soft-delete: https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview
