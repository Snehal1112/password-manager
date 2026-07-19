# Vault Management Authorization Bypass — Design

**Date:** 2026-07-19
**Status:** Proposed
**Branch target:** `v-4.0.0`

## Goal

Close a critical authorization bypass: `GET/PATCH/DELETE /vaults/{name}` perform
**zero** explicit access check against the target vault named in the path. A
principal whose `vaults:manage` grant is scoped to the default vault only can
still read, modify, or soft-delete any *other* vault by name.

Fix `getVault`, `updateVault`, and `deleteVault` in `api/vault.go` to resolve the
target vault and call the existing `requireVaultManage` check (already used by
`api/role_assignments.go`) before doing anything else observable to the caller.

`createVault` and `listVaults` are explicitly **out of scope** — they don't
target an existing named vault, so this vulnerability class doesn't apply to
them the same way. List-filtering-by-access is a separate, larger design
question.

## Root cause

`VaultResolutionMiddleware` deliberately does not resolve `{name}` into vault
context for these three routes — see the comment on `InitVault` in
`api/vault.go:14-17` and the routing comment in `api/api.go:78-81`: management
routes use `{name}`, not `{vault_name}`, precisely so a disabled or
soft-deleted vault can still be managed (VaultResolutionMiddleware would
otherwise 403/404 before the handler ever runs).

But `PolicyMiddleware` (`internal/middleware/middleware.go:408-469`) still runs
ambiently on every `/vaults` path. `resolvePolicy` (`internal/middleware/middleware.go:367-370`)
maps any path containing `/vaults` to `(PolicyResourceVaults, OpManage)`
unconditionally. Because no vault was resolved into
`r.Context().Value(common.VaultIDKey)`, `PolicyMiddleware` reads `vaultID =
uuid.Nil` (`middleware.go:434-435`) and checks access against the **default**
vault (nil-vault-ID matches only global policies plus, per the access-policy
service, the default vault). The handlers then call the service directly
(`api/vault.go:121`, `156`, `184`) with no further check. Net effect: the
`/vaults/{name}` path segment is never checked against the policy engine at
all — only the caller's *default*-vault access is checked, then the handler
acts on whatever vault name is actually in the path.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Which handlers to fix | `getVault`, `updateVault`, `deleteVault` — all three | All three call the service with a caller-supplied `name` and currently have no per-vault check. |
| Check to reuse | `requireVaultManage(c, r, vaultID)` from `api/role_assignments.go:26-42` | Already solves this exact problem for role-assignment routes: admin short-circuit, else `AccessPolicyService.CheckAccess(..., PolicyResourceVaults, OpManage, vaultID)`. No new authz primitive needed. |
| Read vs. manage granularity | Gate `getVault` behind `OpManage` too, not a separate read op | `model.PolicyOperation` has no `OpRead`/`OpGet` defined for `PolicyResourceVaults` (only `OpManage` — `model/access_policy.go:53`, `internal/services/authorization/roles.go:58`). `OpManage` is the *only* permission granularity the model currently supports for vaults, so it is also the conservative, safe default for the read path. **Documented trade-off**, not an oversight. |
| Existence vs. authorization ordering | Check existence first (404), then authorization (403) | Matches Azure Key Vault's behavior (a vault that doesn't exist 404s regardless of caller permissions) and avoids conflating two distinct failure modes behind one status code. **Alternative considered:** 403-first, to prevent an authenticated-but-unauthorized caller from using response-code differences to enumerate vault names. **Recommendation: 404-first.** Vault names are not treated as secret material elsewhere in the system (`listVaults` already returns names to anyone with `vaults:manage` on the default vault; vault names appear in URLs, logs, and CLI output throughout), so the enumeration risk is low, and consistent, unambiguous error semantics for operators/CLI users outweighs it. Revisit if vault-name confidentiality ever becomes a requirement. |
| Where to resolve the vault ID | Reuse `svc.GetVault(ctx, name)` (already called by `getVault`; not currently called by `updateVault`/`deleteVault` before mutating) | No lighter-weight "ID by name" lookup exists on `VaultService` (`internal/services/vaults/vault_service.go:35-44`); `GetVault` → `getByName` → `repo.ReadByName` is the only path. Reusing it for `updateVault`/`deleteVault` costs one extra read per request, which is negligible next to the security gain and matches the pattern `DeleteVault`/`UpdateVault` already use internally (`vault_service.go:130`, `166`). |
| Check timing relative to mutation | Resolve → authorize → *then* call `UpdateVault`/`DeleteVault` | An unauthorized caller must not receive any side effect, and no response should leak more than "not found" or "forbidden" — `SetNotFound`/`SetPermissionError` only (`api/context.go:68-79`). |

**Out of scope for this fix (future consideration):** a future `OpRead` for
`PolicyResourceVaults` would let a policy grant read-only access to a vault
without granting full manage. That is a model/schema change (new enum value,
role-definition updates in `internal/services/authorization/roles.go`,
possibly a new built-in role) and is not part of this critical fix.

## Components and changes

### 1. `api/vault.go` — `getVault`

Resolve the vault first (existence check), then authorize, then respond:

```go
func getVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.GetVault(r.Context(), name)
	if err != nil {
		c.SetNotFound("vault")
		return
	}

	if !requireVaultManage(c, r, vault.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}
```

### 2. `api/vault.go` — `updateVault`

Resolve the target vault by name *before* calling `UpdateVault`, so the
authorization check happens before any write:

```go
func updateVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	req, err := model.UpdateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		c.SetNotFound("vault")
		return
	}
	if !requireVaultManage(c, r, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	// ... existing updatedBy claim extraction and svc.UpdateVault(...) call ...
}
```

Note `svc.UpdateVault` internally re-resolves by name via `getByName`
(`vault_service.go:130`) — a second read. Acceptable; not worth threading the
already-fetched `*model.Vault` through the service signature for this fix.

### 3. `api/vault.go` — `deleteVault`

Same pattern: resolve, authorize, then delete.

```go
func deleteVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		c.SetNotFound("vault")
		return
	}
	if !requireVaultManage(c, r, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	if err := svc.DeleteVault(r.Context(), name); err != nil {
		// ... unchanged ...
	}
	// ... unchanged ...
}
```

### 4. `requireVaultManage` — no change, relocate consideration

The function already lives in `api/role_assignments.go:26-42` and is
unexported (package-private to `api`), so `api/vault.go` can call it directly
with no import changes. Not moving it to a shared helper file in this fix —
churn isn't justified for a one-line call-site addition to a new file, but
flag as a candidate for a small follow-up cleanup (e.g. `api/authz_helpers.go`)
if a third call site appears.

### 5. `InitVault` comment

Update the existing comment block (`api/vault.go:14-17`) to note that,
although `VaultResolutionMiddleware` intentionally skips these routes, the
handlers now perform their own `requireVaultManage` check against the
path-resolved vault — so the security property removed from the middleware
layer is restored at the handler layer instead.

## Testing

The existing `api/vault_test.go` calls handlers directly, bypassing
`AuthenticationMiddleware` → `VaultResolutionMiddleware` → `PolicyMiddleware`
→ `AuthorizationMiddleware` entirely (wired in `api/api.go:67-74`). That is
exactly why this bug shipped without a failing test — handler-only tests
cannot observe a bug that lives in the interaction between "middleware skips
this route" and "handler doesn't check either." Unit tests on the handler in
isolation are insufficient for this fix; they stay as regression coverage for
the new in-handler check but do not fulfil the requirement below.

- **New full-chain test** (new file, e.g. `api/vault_authz_integration_test.go`
  or an addition to `internal/middleware/middleware_test.go` if it already
  builds a real router): spin up the actual middleware chain in front of the
  real `InitVault` routes — `CORS → RateLimit → Authentication →
  VaultResolution → Policy → Authorization → handler` — against a real or
  fully-faked `ServiceContainer` (`AccessPolicyService`, `VaultService`).
  - Seed vault A and vault B.
  - Seed a non-admin principal with an access policy: `vaults:manage`,
    effect allow, scoped to vault A's ID.
  - `GET /vaults/B`, `PATCH /vaults/B`, `DELETE /vaults/B` as that principal
    → assert **403** on all three, and that no mutation occurred (re-read
    vault B and confirm it is unchanged/not deleted).
  - Same principal against `GET/PATCH/DELETE /vaults/A` → assert allowed
    (200/200/204).
  - Admin role → assert allowed on both vaults regardless of policy scope
    (existing `common.HasRequiredRole` short-circuit).
- **Handler-level unit tests** (extend `api/vault_test.go`): a caller with no
  `vaults:manage` grant at all gets 403 from `requireVaultManage` directly;
  a nonexistent vault name gets 404 *before* any authz call is made (verify
  via a spy/mock that `CheckAccess` is not invoked in that path, confirming
  the existence-first ordering).

## Verification gate

```
go build ./...
go vet ./...
go test ./api/... ./internal/middleware/... ./internal/services/vaults/... ./internal/services/authorization/...
```

All must pass before claiming completion (no success claims without fresh
evidence).

## Risks

- **Extra DB read per request** on `updateVault`/`deleteVault` (resolve-by-name
  before the service's own resolve-by-name). Negligible; vault management
  operations are low-frequency and not on a hot path.
- **Behavior change for existing default-vault-scoped admins**: any principal
  currently relying on the ambient default-vault `OpManage` check to manage
  *other* vaults (i.e., relying on the bug) will start getting 403s. This is
  the intended fix, but worth calling out in the changelog/release notes as a
  breaking authorization tightening, not a regression.
- **404-vs-403 ordering** is a judgment call (see Design decisions); if vault
  name confidentiality later becomes a requirement, this needs revisiting
  everywhere `SetNotFound("vault")` precedes an authz check.

## Related Work / Follow-Up

This spec covers only the **Critical**-severity finding from a broader
multi-vault code-quality review conducted 2026-07-19. Separate specs/plans
will follow for the **High** and **Medium** findings from that same review,
in this recommended order:

1. *(this doc)* **Critical** — vault-management authorization bypass. Fix
   first; it's a live access-control hole.
2. **High** — introduce a `repositories.ErrNotFound` sentinel and fix the
   error-taxonomy end-to-end (repository → service → API) so a DB outage
   doesn't present as a mass "vault not found" 404 storm. Root cause is in
   `vault_service.go`'s `getByName` (`internal/services/vaults/vault_service.go:98-105`),
   which collapses *any* `repo.ReadByName` error — including connection
   failures — into `ErrVaultNotFound`. Confirmed independently by three
   reviewers.
3. **High** — wrap the `DeleteVault`/`RecoverVault` cascade fan-out
   (`internal/services/vaults/cascade_adapter.go`) in
   `internal/db/txhelper.go`'s `WithTx`, so a partial cascade failure can't
   orphan active secrets/keys/certs under a soft-deleted vault.
4. **Medium** (before shipping Postgres HA) — add a `pg_advisory_lock` around
   `SetupSchema`/`finalizeVaultIndexes` to prevent a multi-instance startup
   race, and consolidate the two divergent migration systems
   (`cmd/migrate.go`'s `MigrationRunner` vs. `internal/db/db.go`'s
   `migrateSchema()`).
