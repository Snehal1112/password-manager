# Flat-Route Vault Scope Fix — Design

**Date:** 2026-08-16
**Status:** Proposed
**Branch target:** `v-4.0.0`
**Source finding:** `.claude/pentest-report-2026-08-16.md` § H2 — "Cross-vault
authorization bypass on flat (non-vault-scoped) routes via retired owner
scope" (High, confirmed by live exploitation)

## Goal

Close a High-severity broken-access-control hole: on the legacy flat data-plane
routes (`/api/v1/secrets/{id}`, `/api/v1/keys/{id}`,
`/api/v1/certificates/{id}` and their sub-routes), the **authorization** check
runs against the default vault while the **data lookup** is vault-agnostic and
keyed only on `user_id == caller`. A principal who holds any data-plane grant on
the default vault can keep reading — and, with a set/create grant, writing —
resources they created in *any other* vault, including vaults where their role
assignment has been explicitly revoked.

The fix is one function: `scopeFromRequest` (`api/context.go:71`) returns
`model.NewVaultScope(vaultID, userID)` for every route shape, flat and
vault-scoped alike, instead of returning `model.NewOwnerScope` for flat routes.
This makes all 35 call sites consistent with `deleteSecret`
(`api/secrets.go:601-636`) and `deleteCertificate` (`api/certificates.go:354-390`),
which were already hardened against this exact bug by hand.

## Root cause

Three facts combine into the bypass.

**1. Flat routes are authorized against the default vault.**
`VaultResolutionMiddleware` (`internal/middleware/middleware.go:568-619`)
resolves `mux.Vars(r)["vault_name"]`, falling back to `model.DefaultVaultName`
when the route has no such variable, and stores the resolved vault's real ID in
`common.VaultIDKey`. `PolicyMiddleware` (`internal/middleware/middleware.go:479-490`)
reads that key — falling back to `model.DefaultVaultID` when it is absent — and
runs the explicit-deny check plus the deny-by-default `HasDataAction` check
against that vault. So on `GET /api/v1/secrets/{id}` the caller is authorized
**as a member of `default`**.

**2. The handler then throws that vault away.**
`scopeFromRequest` (`api/context.go:59-87`) branches on route shape:

```go
if mux.Vars(r)["vault_name"] != "" {
    return model.NewVaultScope(vaultID, userID), true
}
return model.NewOwnerScope(vaultID, userID), true
```

`vaultIDFromRequest` (`api/context.go:47-57`) resolved `vaultID` correctly — it
is the default vault's ID, exactly the vault `PolicyMiddleware` just checked —
but `NewOwnerScope` treats that vault ID as **advisory only** (`model/scope.go:43-49`:
"vaultID is advisory: owner-scoped queries never constrain vault_id").

**3. The repository predicate for an owner scope has no vault term.**
`scopePredicate` (`internal/repositories/scope_predicate.go:23-42`):

| Scope kind | SQL predicate |
|---|---|
| `ScopeVault` | `vault_id = ?` |
| `ScopeOwner` | `user_id = ?` |
| `ScopeAdmin` | `1 = 1` |

So the row is selected by ownership across **every** vault in the instance. The
authorization decision and the data access disagree about which vault the
request is for. `model/scope.go:17` has flagged `ScopeOwner` as "P1 only;
retired in P2" since the scope refactor; the request path never finished the
retirement.

**Live proof (from the pentest run):** a non-admin created a secret while
holding `Key Vault Secrets Officer` on a throwaway vault; the role assignment
was then revoked (`DELETE .../role-assignments/{id}` → 200). The vault-scoped
route returned 403 for that secret afterwards; the flat route
`GET /api/v1/secrets/{id}` still returned its plaintext value.

### Why keys were only partially exploitable

Three key-domain service methods already carry an in-Go "B6 conjunction" that
re-applies the vault term when the scope is owner-scoped:

- `keyService.DeleteKey` — `internal/services/keys/key_service.go:565`
- `keyService.RotateKey` — `internal/services/keys/key_service.go:680`
- `cryptoService.loadAndAuthorize` — `internal/services/keys/crypto_service.go:279`
  (covers all six crypto operations)

Each reads:

```go
if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && key.VaultID != scope.VaultID() {
```

`GetKey`, `ListKeys`, `UpdateKey` and `ListKeyVersions` have no such guard, and
neither the secret nor the certificate services have one anywhere. So the
exposure is: **secrets and certificates fully affected on every flat
read/write; keys affected on get/list/update/versions**, with delete, rotate and
crypto already defended by the conjunctions above. The fix removes the
conjunctions' last remaining reachable input, which is called out under "Not in
scope" below.

## Blast radius — every affected call site

`scopeFromRequest` has 35 callers. Because the fix is in the shared helper, all
35 change behavior at once. Grouped by behavior class:

| Class | Handlers | Files |
|---|---|---|
| Read / list | `getSecret`, `listSecrets`, `listSecretVersionsHandler`, `getSecretVersionHandler`, `getLatestSecretVersionHandler`, `getKey`, `listKeys`, `listKeyVersions`, `getCertificate`, `listCertificates`, `getCertificatePolicy`, `getKeyRotationPolicy` | `api/secrets.go:95,123,150,395,442`; `api/keys.go:392,429,604`; `api/certificates.go:246,279`; `api/certificate_policy.go:23`; `api/key_rotation_policy.go:23` |
| Write | `updateSecret`, `exportSecrets`, `importSecrets`, `updateKey`, `deleteKey`, `rotateKey`, `updateCertificate`, `upsert/deleteCertificatePolicy`, `upsert/deleteKeyRotationPolicy` | `api/secrets.go:185,260,514`; `api/keys.go:476,522,567`; `api/certificates.go:318`; `api/certificate_policy.go:61,94`; `api/key_rotation_policy.go:61,94` |
| Crypto | `wrapKey`, `unwrapKey`, `signKey`, `verifyKey`, `encryptKey`, `decryptKey` | `api/keys.go:635,703,771,840,912,986` |
| Soft-delete | `listDeletedSecrets` variants, `recover*`, `purge*` | `api/soft_delete.go:73,100,226,253,324,351` |

Plus one direct owner-scope construction outside the helper:
`createKey`'s response read-back, `api/keys.go:372`
(`keyService.GetKey(..., model.NewOwnerScope(vaultID, userID))`). It reads back
a key this same request just created in `vaultID`, so a vault scope is
equivalent, and leaving it would keep an owner scope alive on the request path.
It changes with the helper.

After this fix, `grep -rn "NewOwnerScope" api/` returns nothing.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Where to fix | The shared helper `scopeFromRequest`, not the 35 call sites | The bug is one branch on route shape. Fixing call sites individually would leave the trap armed for the next handler that calls the helper — exactly how the get/update/version/crypto handlers were left behind when `deleteSecret`/`deleteCertificate` were hardened. |
| Which vault a flat route targets | The one already in `common.VaultIDKey`, i.e. `default` | Verified, not assumed: `VaultResolutionMiddleware` resolves `model.DefaultVaultName` for any route without a `vault_name` var (`middleware.go:580-583`) and `vaultIDFromRequest` falls back to `model.DefaultVaultID` when the middleware is bypassed (unit tests, direct handler calls). This is the same vault `PolicyMiddleware` authorized against, so authorization and data access finally agree. |
| Keep `vaultIDFromRequest` unchanged | Yes | It already resolves the correct vault for both route shapes; the defect was never in vault resolution, only in which scope kind was built from it. |
| Simplify `deleteSecret` / `deleteCertificate` to call the now-fixed helper | **No** — leave as-is, refresh their comments only | Not a one-line change: `deleteSecret` uses the locally bound `userID` in its trailing audit log (`api/secrets.go:635`) and both handlers would need their `vaultIDFromRequest`/`userIDFromClaims` blocks collapsed and the log rewritten to `scope.ActorID()`. Zero behavioral difference either way, so the churn buys nothing, and an explicit local construction is cheap defense-in-depth if route-shape branching is ever reintroduced. Their comments do become wrong ("so a flat-route caller cannot get an owner scope here" implies the helper still yields one) and are corrected in place. Recorded as an optional follow-up. |
| `createKey`'s read-back (`api/keys.go:372`) | Change to `NewVaultScope` in the same commit | It is the only other owner-scope construction on the request path, and its existing tests share the `keyLegacyOwnerScope()` fixture with the helper's tests — splitting it into a separate commit would leave the package red. |
| Retire `ScopeOwner` from `model/scope.go` | **No** — out of scope, see below | Bounded fix. |
| Error semantics for a now-denied request | Unchanged: the scoped read misses, the service maps it to its not-found sentinel, the handler returns 404 | Matches the vault-scoped route's existing behavior for the identical request, and `SecretRepository.Read` already documents "a row outside the scope is indistinguishable from a row that does not exist" (`internal/repositories/secret_repository.go:181-183`). No new 403 path is introduced at the data layer. |

## The change

`api/context.go` — replace the route-shape branch and rewrite the doc comment:

```go
// scopeFromRequest builds the authorization scope for a resource operation. It
// is the only scope constructor on the data plane: ownership is provenance and
// audit metadata, never an access predicate.
//
// Every route shape yields a vault scope. Vault-scoped routes
// (/api/v1/vaults/{vault_name}/...) carry the vault resolved from the path;
// legacy flat routes carry the default vault — the same vault PolicyMiddleware
// authorized the request against, because VaultResolutionMiddleware resolves
// model.DefaultVaultName for any route with no vault_name variable.
//
// Flat routes used to yield an owner scope, whose SQL predicate is "user_id = ?"
// with no vault term (internal/repositories/scope_predicate.go). That let a
// caller authorized against the default vault read and write their own
// resources in any OTHER vault, surviving revocation of their role assignment
// there. See docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md.
//
// It sets c.Err and returns false when the caller's identity cannot be
// determined, so a handler can never proceed with an invalid scope.
func scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return model.Scope{}, false
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return model.Scope{}, false
	}

	return model.NewVaultScope(vaultID, userID), true
}
```

`github.com/gorilla/mux` becomes an unused import in `api/context.go` after
this edit (line 83 was its only use in the file) and must be removed, or the
package will not compile.

`api/keys.go:372` — the `createKey` read-back:

```go
	// Fetch the full key record so buildKeyResponse can inspect the stored value.
	key, err := keyService.GetKey(r.Context(), result.KeyID, model.NewVaultScope(vaultID, userID))
```

## Behavior changes

1. **Cross-vault access on flat routes is denied (the fix).** A flat-route
   request can only reach a resource whose `vault_id` is the default vault.
   Anything else 404s. Callers who legitimately need another vault must use
   `/api/v1/vaults/{vault_name}/...` — which `internal/vaultclient` already
   supports via its `Vault` config field (`internal/vaultclient/client.go:43-44,272-274`).

2. **Flat-route listing widens within the default vault.** `listSecrets`,
   `listKeys`, `listCertificates`, `exportSecrets` and the deleted-item lists
   previously returned only the caller's own rows regardless of vault; they now
   return every row in the default vault. That is the documented Azure-parity
   semantic ("vault members see all"), already in force on the vault-scoped
   routes for the same vault, and every such caller must already hold the
   corresponding data action on `default` to get past `PolicyMiddleware`. It is
   still a visibility widening and belongs in the release notes.

3. **Cache keys change shape for flat routes.** `SecretCache.scopeCacheKey`
   (`internal/cache/secret_cache.go:41-57`) keys owner scopes as
   `o|<owner>|<id>` and vault scopes as `v|<vault>|<id>`. Flat-route reads now
   populate and hit the `v|` namespace, sharing entries with the vault-scoped
   route for the same vault. Pre-existing `o|` entries simply age out; nothing
   reads them and `DeleteByID`'s reverse index still evicts every scoped view.
   No migration or flush is required.

4. **Audit attribution is unchanged.** `NewVaultScope(vaultID, userID)` sets
   `actorID = userID`, and every service reads the actor via `scope.ActorID()`
   (for example `internal/services/secrets/secret_service.go:262,328,361,398`),
   so audit rows still name the acting principal. `ImportSecrets` likewise keeps
   writing `UserID: req.Scope.ActorID()` and
   `VaultID: req.Scope.ResolvedVaultID()` (`secret_service.go:722-723`).

## Not in scope

**Full retirement of `ScopeOwner`.** `model/scope.go` still defines
`ScopeOwner`, `NewOwnerScope` and the `user_id = ?` predicate, and this fix
leaves all of them in place. Three reasons. First, the bounded-fix principle:
this is a live access-control hole and the smallest change that closes it — one
branch in one function — is the one that can be reviewed and shipped fastest,
with the least chance of collateral regression. Second, the remaining owner-scope
constructions are in genuinely different contexts that each need their own
analysis: `cmd/version.go:133,169,194` builds `NewOwnerScope(uuid.Nil, userID)`
on the **CLI** path (which has no `VaultIDKey` and would need
`vaultcli.ResolveVaultID` plus `RequireDataAction` — a CLI-authorization change,
not an HTTP one), while `internal/services/secrets/versioning_service.go:353`
and `rotation_service.go:429` build the scope from the entity's own
`secret.UserID`/`secret.VaultID` as trusted internal callers, where it is not an
externally influenced predicate at all. Third, `model/scope.go` and the
repositories sit behind the `scope-gate` CI job (`.github/workflows/go.yml:120-160`),
which bans hand-built `model.Scope{}` literals outside `api/context.go` and
bans the retired `InVault`/`ByOwner` method names; widening this change into
that area invites a gate failure on work that is unrelated to the security fix
and deserves its own review. Track the retirement separately.

**The now-unreachable B6 conjunctions.** After this fix nothing on the HTTP path
passes an owner scope to the key services, so the three `ownerScoped &&
scope.VaultID() != uuid.Nil && ...` guards (`key_service.go:565,680`,
`crypto_service.go:279`) become unreachable belt-and-braces. Leave them: they are
correct, cheap, and their removal belongs with the `ScopeOwner` retirement above.
Their comments claiming flat routes still reach them do go stale — noted as a
follow-up, not fixed here, because touching key/crypto service code for a
comment would widen the diff of a security fix.

**CLI `rocketvault version` commands** (`cmd/version.go`) — same bug class,
different enforcement point, separate fix.

**Vault-management routes** (`/vaults/{name}`) — already fixed by
`docs/superpowers/specs/2026-07-19-vault-management-authz-fix-design.md`.

## Testing

Existing coverage pins the *old* behavior in roughly 60 places across the `api`
package (mock expectations built from `keyLegacyOwnerScope()` /
`certLegacyOwnerScope()`, plus `assert.Equal(t, model.ScopeOwner, ...)` scope-shape
assertions in `scope_helpers_test.go`, `secrets_scope_test.go`,
`keys_scope_test.go`, `certificates_scope_test.go`, `soft_delete_scope_test.go`,
`soft_delete_extended_test.go`, `vault_scoped_routes_test.go`,
`vault_scoped_keys_certs_test.go`). All of it must flip in the same commit as
the production change, or the package is red. This is mechanical: the two
fixture helpers are shared by most of the mock expectations, so changing their
bodies fixes ~30 call sites at once.

New regression coverage (new file, `api/flat_route_vault_scope_test.go`) must
assert the property the pentest exercised, not merely the scope's shape: a
flat-route request **cannot reach a resource whose `vault_id` differs from the
route's resolved vault**. The stubs mirror
`internal/repositories.scopePredicate` exactly — a vault scope selects on
`vault_id`, an owner scope selects on `user_id` with no vault term — so the test
fails if the handler ever reverts to an owner scope, and passes only when the
foreign-vault row is unreachable. Required cases:

- **Secrets**: `getSecret`, `updateSecret`, `listSecretVersionsHandler` against
  a secret owned by the caller but stored in a different vault → 404.
- **Certificates**: `getCertificate`, same setup → 404.
- **Keys (crypto)**: `signKey` against a key owned by the caller in a different
  vault → the scope handed to `CryptoService.Sign` carries the route's resolved
  vault and no owner predicate.
- **Positive control**: the same resource in the *resolved* vault still
  resolves 200 on the flat route, so the tests prove denial, not breakage.

Each new test must be shown to fail against the pre-fix code (temporarily
restoring the `NewOwnerScope` branch) before it is trusted.

## Verification gate

```
go build ./...
go vet ./...
go test ./api/... ./internal/services/... ./internal/repositories/... ./internal/cache/... ./model/...
```

Plus the `scope-gate` job's own greps, which this change must not trip:

```
grep -rn "model\.Scope{" --include="*.go" . | grep -v "^./api/context.go"   # must be empty
grep -rn "NewOwnerScope" --include="*.go" api/                              # must be empty after the fix
```

All must pass before claiming completion.

## Risks

- **Visibility widening on flat list routes** (behavior change 2 above) is the
  one change an operator could experience as a regression. It is intended
  Azure-parity behavior and is gated by the same data action as before, but it
  must be in the release notes rather than discovered in production.
- **Callers relying on the bug** — any integration that reads a non-default-vault
  secret through the flat path will start getting 404. That is the fix working;
  the migration is to set `vaultclient.Config.Vault` (or use the vault-scoped
  URL directly). Release-note item.
- **Large test diff.** ~60 expectation updates in one commit make review noisy.
  Mitigated by concentrating the change in the two shared fixture helpers and by
  landing the new behavioral regression tests as a separate, readable commit.

## Documentation to update

- `.claude/known-bugs.md` — new entry **B11** with root cause and fix (open with
  the root cause; fill in the fix commit when implemented).
- `.claude/multi-vault.md:70-90` — the "B6 resolved" paragraph states flat
  routes yield `ScopeOwner` and that the conjunction code paths are "only
  reachable via `ScopeOwner`, i.e. the flat routes". Both clauses become false.
- `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` — breaking-change
  note covering the two behavior changes above.
- `.claude/e2e-manual-testing-guide.md:1240` — the certificates-area finding
  "`PUT`/`DELETE` authorization asymmetry on certificates" is resolved by this
  fix; annotate it rather than deleting the history.
