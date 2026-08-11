# Azure Key Vault Role Parity + Vault-Management Authorization Fix — Design

**Date:** 2026-08-11
**Status:** Proposed
**Branch target:** `v-4.0.0`
**Supersedes-in-part:** `docs/superpowers/specs/2026-07-19-vault-management-authz-fix-design.md` (see
"Relationship to the 2026-07-19 fix" below — that fix is correct but incomplete
in production; this design completes it as a side effect of unrelated work.)

## Goal

RocketVault's vault-scoped RBAC currently grants 7 of Azure Key Vault's ~11
built-in data-plane/management roles (`model/azure_roles.go`). Add the 5
missing roles:

| Role | Grants (this design) |
|---|---|
| `Key Vault Purge Operator` | Purge a soft-deleted vault |
| `Key Vault Certificate User` | Read certificates (parity placeholder — see below) |
| `Key Vault Crypto Service Encryption User` | Read key metadata + wrap/unwrap only |
| `Key Vault Data Access Administrator` | Grant/revoke role assignments in one vault |
| `Key Vault Crypto Service Release User` | **Not implemented** — see "Explicitly out of scope" |

`Data Access Administrator` was chosen to close a documented known limitation
(`docs/release-notes/v4.0.0-azure-rbac.md`, "Known limitations": role-assignment
management is currently global-admin-only even though the handler's own check
is written to accept more). Scoping that role's fix turned up a root cause that
is bigger than role-assignments alone.

## Root cause: `mapEndpointToPermission` blocks every `/vaults/...` route at the
## global layer, making every per-vault handler check unreachable for non-admins

`api/api.go:68-75` wires the middleware chain in this order:

```
CORS → RateLimit → Authentication → VaultResolution → Policy → Authorization → handler
```

`AuthorizationMiddleware` (`internal/middleware/middleware.go:307-346`) runs
**last**, immediately before the handler, and calls
`RBACService.ValidateEndpointAccess(role, method, path)`
(`internal/services/authorization/rbac_service.go:189-218`), which in turn
calls `mapEndpointToPermission`:

```go
// internal/services/authorization/rbac_service.go:234-247
func (s *rbacService) mapEndpointToPermission(method, path string) Permission {
    if _, kind := MapRouteToDataAction(method, path); kind == RouteVaultData {
        return ""
    }
    path = strings.TrimPrefix(path, DataPlaneBasePath)
    path = strings.TrimPrefix(path, "/")
    if strings.HasPrefix(path, "vaults") {
        return PermissionManageVaults   // only `admin` has this (rbac_service.go:90-98)
    }
    ...
}
```

`MapRouteToDataAction` (`internal/services/authorization/data_actions.go:44-73`)
classifies a bare `/vaults/{name}` path (no further segment) as `RouteUnmanaged`
— there is no case for it. So every vault-management route
(`GET/PATCH/DELETE /vaults/{name}`, `POST/GET /vaults`, and the
`/vaults/{name}/role-assignments/...` family) falls into the
`strings.HasPrefix(path, "vaults")` branch and requires `PermissionManageVaults`,
which only the global `admin` role holds. **This check runs and can deny the
request before the handler executes.**

The handlers were already written expecting a second, finer check to matter:
`getVault`, `updateVault`, `deleteVault` (`api/vault.go`) and
`createRoleAssignment`/`deleteRoleAssignment` (`api/role_assignments.go`) all
call `requireVaultManage(c, r, vaultID)`, which accepts `admin` **or** an
access-policy `allow` on `(vaults, manage)` scoped to that vault. In production,
a non-admin caller never reaches that check: `AuthorizationMiddleware` already
returned 403. `requireVaultManage`'s access-policy branch is unreachable dead
code today, for every vault-management route, not just role-assignments.

**`createVault` and `listVaults` have no handler-level check at all** — they
rely entirely on the global gate, so today they are (correctly, but only by
accident of the same bug) admin-only.

### This was never caught by tests — confirmed, not inferred

- `api/vault_test.go:476-491` (`newVaultTestAPIWithContainer`) wires **zero**
  middleware — `AuthenticationMiddleware` and `AuthorizationMiddleware` are
  never in the chain; role/user ID are injected straight into `context`,
  bypassing every gate this design touches.
- `api/vault_authz_test.go:130-162` (`buildChainedVaultAPI`), the test
  explicitly named to cover "Full middleware chain regression" and whose
  comment claims it wires the chain "exactly as api.go does," in fact wires
  only `mw.VaultResolutionMiddleware, mw.PolicyMiddleware` — `Authentication`
  and `Authorization` are both absent. Its `permissiveRBAC{}` container field
  (`api/vault_test.go:459-471`, `ValidateEndpointAccess` unconditionally
  returns `nil`) is configured but never exercised, because the one middleware
  that reads it is never wired in.
- Net effect: every existing vault-authz test is green because it runs against
  a request chain that omits the exact middleware causing the production bug.
  The tests prove `requireVaultManage` works in isolation; they cannot and do
  not prove it is reachable.

This means the 2026-07-19 fix (see "Relationship" below) shipped a correct
handler-level check that has not actually protected anything beyond
admin-vs-admin scenarios in production, and its own prescribed regression test
does not catch this. Part of this design's testing section closes that gap.

## Design decisions

### 1. Shared, parameterized vault-authorization functions

Extract and generalize `requireVaultManage` into
`internal/services/authorization/vault_authz.go`, callable from both `api/`
handlers and `cmd/vaults/`, `cmd/vault-access/` CLI commands — the two places
that currently duplicate or skip this check entirely (see CLI section below):

```go
// CanManageVault reports whether principalID may perform vault-management
// operations (create/get/update/delete/list) on vaultID: admin role, or an
// access-policy allow on (vaults, manage) scoped to vaultID.
func CanManageVault(ctx context.Context, accountRole string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool

// CanPurgeVault reports whether principalID may purge vaultID: admin role, or
// a Key Vault Purge Operator role assignment in vaultID.
func CanPurgeVault(ctx context.Context, accountRole string, roles RoleAssignmentService, principalID, vaultID uuid.UUID) bool

// CanManageRoleAssignments reports whether principalID may create (write=true)
// or revoke (write=false) role assignments in vaultID: admin role, an
// access-policy allow on (vaults, manage) scoped to vaultID (preserves today's
// documented behavior), or a Key Vault Data Access Administrator role
// assignment in vaultID.
func CanManageRoleAssignments(ctx context.Context, accountRole string, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, write bool) bool
```

Each: `admin` short-circuits true (existing behavior preserved exactly). Chosen
over alternatives considered:

- *Keep `requireVaultManage` `api`-package-private and duplicate it in `cmd`* —
  rejected; duplicating a security check is how this class of bug happens
  again.
- *Pass `*Context`/`*http.Request` types into the shared function* — rejected;
  those are `api`-package types, `cmd` has no equivalent, and the function has
  no real need for the whole request, only `(accountRole, principalID,
  vaultID)`.

### 2. `mapEndpointToPermission`: exempt all `/vaults/...` paths, not just
### data-plane ones

Add a `RouteVaultManagement` classification (or reuse `RouteUnmanaged` with an
explicit early-return in `mapEndpointToPermission` — implementation detail for
the plan) so that **every** path under `/vaults` returns `""` from
`mapEndpointToPermission`, deferring entirely to the handler's own
`CanManageVault`/`CanPurgeVault`/`CanManageRoleAssignments` call. This is the
same pattern already established for `RouteVaultData` (vault data-plane
routes) — extending it to vault-management routes is consistency, not a new
pattern.

**Consequence requiring explicit handler changes:** `createVault` and
`listVaults` currently have no handler-level check and were implicitly
admin-only via the global gate. Once that gate is removed for `/vaults`, they
must gain an explicit `CanManageVault` call or they become reachable by any
authenticated user. This is a real gap this design closes, not a preserved
behavior — call out prominently in the plan and PR description as a
CLI/API-parity fix, matching the CLI section below where the equivalent gap
already exists today.

`listVaults` is scoped globally (not to one vault); `CanManageVault` is called
with a synthetic check against... **open question deferred to planning**:
either (a) require `admin` OR any `vaults:manage` grant on any vault (loosest,
matches "can manage vaults" as a coarse capability), or (b) filter the returned
list to vaults the caller can manage (finer, more work, mirrors Azure's
per-scope visibility). Recommend (a) for this pass — `listVaults` already
returns full vault metadata with no per-item secret material, and (b) is a
larger, separable "list filtering by access" question the 2026-07-19 spec
explicitly deferred for the same reason. Flag as a named follow-up, not silently
picked.

### 3. New endpoint: vault purge over HTTP

`DELETE /api/v1/vaults/{vault_name}/purge`, registered on `VaultScoped`
(vault-scoped path, unlike the other four management routes which use bare
`{name}` — purge already only makes sense against an existing, resolvable
vault ID the same way data-plane routes do). Maps in `MapRouteToDataAction` to
`ActionVaultPurge` / `RouteVaultData`, so it is authorized by the existing
deny-by-default `PolicyMiddleware` step 2 (`HasDataAction`) — no new plumbing
needed at the middleware layer, only the route-to-action mapping entry and the
handler. CLI `vaults purge` calls the same `VaultService.PurgeVault`, gated by
the new `CanPurgeVault` check before it (see CLI section).

### 4. Data model (`model/azure_roles.go`)

New `DataAction` constants:

```go
ActionVaultPurge           DataAction = "Microsoft.KeyVault/vaults/purge/action"
ActionRoleAssignmentsWrite DataAction = "Microsoft.Authorization/roleAssignments/write"
ActionRoleAssignmentsDelete DataAction = "Microsoft.Authorization/roleAssignments/delete"
```

(The `Microsoft.Authorization/...` strings match Azure's real data actions for
`Key Vault Data Access Administrator`, confirmed against Microsoft Learn's
Key Vault RBAC guide, 2026-07-17 revision.)

New role constants + `azureRoleDataActions` bundles:

```go
RoleKeyVaultPurgeOperator                  = "Key Vault Purge Operator"
RoleKeyVaultCertificateUser                = "Key Vault Certificate User"
RoleKeyVaultCryptoServiceEncryptionUser    = "Key Vault Crypto Service Encryption User"
RoleKeyVaultDataAccessAdministrator        = "Key Vault Data Access Administrator"
```

```go
RoleKeyVaultPurgeOperator:               {ActionVaultPurge},
RoleKeyVaultCertificateUser:             {ActionCertificatesRead},
RoleKeyVaultCryptoServiceEncryptionUser: {ActionKeysRead, ActionKeysWrap, ActionKeysUnwrap},
RoleKeyVaultDataAccessAdministrator:     {ActionRoleAssignmentsWrite, ActionRoleAssignmentsDelete},
```

`AzureRoleNames()`, `IsAzureRole()`, `AzureRoleDataActions()`,
`RoleGrantsDataAction()` all work unchanged — they iterate the map, no
per-role special-casing exists to update.

### 5. `Key Vault Certificate User` — documented parity gap, not a full
### implementation

Azure's real Certificate User reads the private-key portion of a certificate
(Azure Key Vault certs are a combined cert+key+secret object). RocketVault
does not link a certificate to its key/secret material yet (`.claude/azure-keyvault-parity.md`
§6: "RocketVault does not yet model a certificate as a linked key plus secret
... deferred to P5"). This design adds the role now, granting
`ActionCertificatesRead` — functionally identical to what `Key Vault Reader`
already grants for certificates. The role exists and is assignable today
(useful for forward-compatible automation/tooling that names roles by their
Azure identity) but grants nothing `Reader` doesn't already grant until P5
lands. Document this explicitly in the parity doc and admin manual — do not
let it read as full parity.

### 6. Explicitly out of scope: `Key Vault Crypto Service Release User`

RocketVault has no confidential-computing/TEE attestation flow
(`.claude/azure-keyvault-parity.md` §2: "Release (confidential compute) ❌ no
TEE attestation flow"). Unlike Certificate User, there is no existing action
this role could usefully bundle — granting it would mean a role name that
grants literally nothing, which is the exact anti-pattern
`internal/services/authorization/roles.go`'s `IsLegacyRole` mechanism already
exists to prevent for the old vault-scoped role vocabulary. **Not added to
`azureRoleDataActions`.** Documented in the parity doc as blocked on the
missing TEE feature, with a pointer back to this design so a future spec
implementing confidential-compute release can pick the role up without
rediscovering the gap.

### 7. CLI layer: close a pre-existing, broader authorization gap

`cmd/vaults/{create,update,delete,recover,purge}.go` currently call the
service layer directly with **no** authorization check of any kind.
`cmd/root.go`'s `persistentPreRun` (lines 137-239) only authenticates
(validates username/password/TOTP) and stores claims in context — it never
checks the resulting role before a command runs. `VaultService.PurgeVault`/
`DeleteVault` (`internal/services/vaults/vault_service.go`) have no
authorization check either. **Today, any successfully authenticated user of
any role can delete or purge any vault via the CLI.** This predates and is
independent of the role-assignment work; it surfaced because implementing
`Purge Operator` meaningfully requires a real gate to plug into, and the
user directed fixing all five commands together rather than leaving four
open after fixing one.

Fix: each of the five commands resolves the target vault ID, then calls the
matching shared function from §1 (`CanManageVault` for
create/update/delete/recover; `CanPurgeVault` for purge) via the service
container's `AccessPolicyService`/`RoleAssignmentService`, using the
already-authenticated claims from `persistentPreRun`. A denial returns a
plain error (Cobra `RunE` returns `error`; no HTTP status codes in play) —
match the CLI's existing error-message style (see `cmd/vault-access/grant.go`
for precedent: `fmt.Errorf("grant failed: %w", err)`).

`create` has no existing target vault (it's being created), so `CanManageVault`
is checked the same way `listVaults` is (§2, open question (a)): `admin` or
any `vaults:manage` grant — creating a vault is not scoped to a vault that
doesn't exist yet, matching Azure's real model where vault creation is a
resource-group-scoped, not vault-scoped, operation.

## Components and changes (implementation plan will detail exact diffs)

1. `model/azure_roles.go` — new `DataAction` consts, new role consts, new
   `azureRoleDataActions` entries (§4).
2. `internal/services/authorization/vault_authz.go` (new file) —
   `CanManageVault`, `CanPurgeVault`, `CanManageRoleAssignments` (§1).
3. `internal/services/authorization/data_actions.go` — `MapRouteToDataAction`
   gains a case for `/vaults/{name}/purge` → `ActionVaultPurge`,
   `RouteVaultData` (§3).
4. `internal/services/authorization/rbac_service.go` — `mapEndpointToPermission`
   exempts all `/vaults/...` paths (§2).
5. `api/vault.go` — `createVault`, `listVaults` gain `CanManageVault` calls;
   `getVault`/`updateVault`/`deleteVault` swap `requireVaultManage` for
   `CanManageVault`; new `purgeVault` handler + route registration.
6. `api/role_assignments.go` — `requireVaultManage` replaced by
   `CanManageRoleAssignments` (write=true for create, false for delete);
   remove the now-dead local `requireVaultManage` function once both call
   sites are migrated.
7. `cmd/vaults/{create,update,delete,recover,purge}.go` — add the matching
   authorization call before the service-layer call (§7).
8. `cmd/vault-access/roles.go` — no logic change; new roles automatically
   appear via `BuiltInRoleNames()`/`AzureRoleDataActions()`, already iterating
   the map.
9. Docs: `.claude/azure-keyvault-parity.md` (§6 table — 11 grantable roles + 1
   documented-blocked), `docs/admin-manual.html` `#vault-rbac` (roles table,
   replace the "global-admin-only" callout with the real Data Access
   Administrator grant path, document the new purge endpoint + CLI parity
   fix), `docs/release-notes/` addendum noting the CLI authorization-gap fix
   as security-relevant for anyone running a pre-fix binary.

## Testing

Per the confirmed test-harness gap above, unit tests against handler-only or
partial-chain harnesses are **not sufficient evidence** that a fix works in
production for this area of the code. Required:

- **Fix the full-chain test harness first, or alongside**: `buildChainedVaultAPI`
  (`api/vault_authz_test.go`) must wire the *actual* middleware stack —
  `AuthenticationMiddleware` and `AuthorizationMiddleware` included, using the
  real `RBACService` (`authorization.NewRBACService`), not `permissiveRBAC{}`
  — or a new test file must do so. Without this, green tests for this design's
  changes carry the same false confidence as the 2026-07-19 fix's tests did.
- **Regression proving the bug is closed**: non-admin with no vault-scoped
  grant → `POST/GET /api/v1/vaults`, `GET/PATCH/DELETE /api/v1/vaults/{name}`
  → 403 through the *real* chain (not the partial one). Non-admin with a
  matching `vaults:manage` access-policy grant → 200/204 through the real
  chain. This specific case must be new — it does not exist today.
- **Per new role**: a principal holding only `Key Vault Purge Operator` in
  vault A can `DELETE /vaults/A/purge` but not `DELETE /vaults/B/purge`, and
  cannot perform any other vault-management or data-plane operation. Same
  pattern for `Data Access Administrator` (can `POST`/`DELETE`
  role-assignments in its vault, cannot read secrets there), `Crypto Service
  Encryption User` (can wrap/unwrap and read key metadata, cannot
  encrypt/decrypt/sign/verify — reuse the existing `HasDataAction` test
  pattern from the P2 role-assignment tests).
- **CLI**: table-driven test per command (`create/update/delete/recover/purge`)
  — authenticated-but-unauthorized → error, no service-layer call made
  (assert via a spy/mock, matching the "existence-first" ordering precedent
  from the 2026-07-19 spec); authorized (admin, and separately, a scoped
  grant) → success.
- **`Key Vault Certificate User`**: grants exactly `ActionCertificatesRead`,
  nothing else — table-driven `RoleGrantsDataAction` test alongside the
  existing role-bundle tests.
- **Negative control for Release User**: `IsAzureRole("Key Vault Crypto
  Service Release User")` is `false`; `vault-access grant` rejects it the same
  way it rejects a legacy role name (reuse `IsLegacyRole`'s test pattern,
  new assertion, not a change to that function — Release User is "not yet
  implemented," a different reason than "deprecated").

## Verification gate

```
go build ./...
go vet ./...
go test ./api/... ./cmd/... ./internal/services/authorization/... ./internal/services/vaults/... ./internal/middleware/... ./model/...
```

All must pass before claiming completion (no success claims without fresh
evidence, per project convention).

## Risks

- **Behavior change for non-admin vault managers**: `createVault`/`listVaults`
  go from "reachable only by admin (as a side effect of a bug)" to "reachable
  by admin or a vaults:manage grant" — intended, but call out in release notes
  as a deliberate capability expansion, not silently.
- **CLI behavior change**: any non-admin currently relying on the CLI gap to
  delete/purge/recover/update/create vaults loses that ability. This is the
  intended fix (closing a real authorization hole), but is a breaking change
  for anyone who was — knowingly or not — depending on it. Flag prominently in
  release notes, same treatment as the v4.0.0 RBAC inversion itself.
- **`listVaults`/`createVault` coarse-grained check (§2 option (a))**: any
  `vaults:manage` grant on *any* vault permits listing/creating, not scoped
  per-item. Documented trade-off, matches the 2026-07-19 spec's own precedent
  of deferring "list filtering by access" as a separate, larger question.
- **Test harness fix is a prerequisite, not a nice-to-have**: if the plan
  sequences new-role tests before fixing `buildChainedVaultAPI`, they will
  pass against the same blind spot as every existing vault-authz test and
  provide no real assurance.

## Relationship to the 2026-07-19 fix

That spec correctly identified and fixed "the handler checks the wrong vault
ID" (ambient default-vault check instead of the path-resolved target vault).
It did not identify — and its own prescribed regression test does not catch —
that `AuthorizationMiddleware`'s global gate makes the corrected handler check
unreachable for non-admins in production regardless. This design does not
revert or contradict that fix; `requireVaultManage`'s vault-ID logic is
correct and is preserved (renamed/relocated into `CanManageVault`). This
design is what makes it reachable for the first time.

## Follow-ups explicitly named, not folded in

- `listVaults` filtering by per-vault access (rather than a coarse
  any-vault-grant check) — separable, larger design question, deferred twice
  now (2026-07-19 spec, and again here).
- `Key Vault Crypto Service Release User` — blocked on confidential-compute/TEE
  attestation support existing at all.
- Full certificate/key/secret linkage (P5) — would give `Key Vault Certificate
  User` its real Azure semantics instead of the Reader-equivalent placeholder.
