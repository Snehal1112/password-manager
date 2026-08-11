# Vault CLI Extension — Design

**Goal:** Extend `--vault` support to `keys` and `certificates` CLI commands (today only `secrets` commands honor it), fix certificate `update`/`renew` to be genuinely vault-scoped instead of hardcoded owner-only, and — the piece that changed this design's shape — add a real per-vault authorization check to the CLI, which currently has none, for `secrets`, `keys`, and `certificates` alike.

**Context:** Roadmap item (`README.md`): *"Extend `--vault` CLI support to `keys` and `certificates` commands... Make certificate update and renew genuinely vault-scoped... before extending `--vault` to them."* Investigation (this session, 4 parallel subagents) confirmed the HTTP API is already vault-scoped for every keys operation and for certificates list/get/delete, but certificate `update` is hardcoded owner-only at the API handler and `renew` ignores any scope internally — those two need backend work, not just a CLI flag.

## The authorization gap (why this grew beyond CLI wiring)

While designing the CLI wiring, we found `cmd/secrets/get.go` and `delete.go` (the only commands that already support `--vault`) have **no per-vault role check at all** — only a `vault_id = ?` repository filter (`model.NewVaultScope`). `persistentPreRun` (`cmd/root.go:137`) only authenticates; no CLI command calls `RoleAssignmentService.HasDataAction` today except `cmd/vault-access/*.go` (the role-assignment management commands themselves). The HTTP API enforces this via `PolicyMiddleware` → `HasDataAction` for every vault-scoped route; the CLI has no equivalent. Today, any authenticated user — any role — can read/write any secret in any vault via the CLI, regardless of role assignment.

Extending `--vault` to keys/certificates without fixing this would propagate the same gap into wrap/unwrap/sign-adjacent key operations and certificate lifecycle operations. This design closes it instead, for secrets/keys/certificates together.

### Azure parity — what "parity" means here

Real Azure Key Vault enforces authorization in exactly one place: server-side, at the vault's own data-plane endpoint (`<vault>.vault.azure.net`). `az cli`, PowerShell, the Portal, and SDKs are all thin clients — none of them contain authorization logic; they authenticate and forward the request, and the vault service returns 200 or 403. ([Microsoft Learn: Grant permission to applications using Azure RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide))

RocketVault's CLI is not shaped like `az cli` — it builds its own service container per-invocation and talks to the database directly, bypassing the HTTP layer (`PolicyMiddleware`) entirely. That's the structural root of the gap: RocketVault has two entry points into the same backend where Azure has one. True structural parity (CLI as a genuine HTTP client of `rocketvault serve`) would eliminate the need for a separate CLI-side check, but it touches every CLI command and the bootstrap flow (`rocketvault users admin --bootstrap-token` currently works with no server running) — **explicitly out of scope for this design**, and would need its own brainstorming cycle if pursued later.

This design instead targets **guarantee-level parity**: the same authorization outcome as Azure (no action without a role assignment granting it, regardless of entry point), achieved by having the CLI call the same `HasDataAction` decision the HTTP layer already calls, rather than duplicating or reinventing the logic.

## Scope

**In scope:**
- `cmd/keys`: `create`, `get`, `list`, `update`, `delete`, `rotate`, `wrap`, `unwrap` — add `--vault` wiring + authorization check.
- `cmd/certificates`: `list`, `get`, `delete` — same, pure wiring (backend already vault-scoped).
- `cmd/certificates`: `update` — fix `api/certificates.go`'s hardcoded owner-scope handler, then wire `--vault` + authz.
- `cmd/certificates`: `renew` — change `RenewCertificate`'s signature to accept `model.Scope`, then wire `--vault` + authz.
- `cmd/secrets`: retrofit the new authorization check onto its 7 existing vault-aware commands (`create`, `list`, `get`, `delete`, `update`, `export`, `import`) — closes the gap where it originated.
- New shared `cmd/vaultcli` package (`ResolveVaultID` + thin authorization adapter), replacing `cmd/secrets/vault.go`.
- New `internal/services/authorization/data_action_authz.go` (`RequireDataAction`).
- One-line correctness fix: `cmd/secrets/get.go:72` passes `uuid.Nil` as the scope's actor ID instead of `claims.UserID` — an audit-attribution gap, found while reading this code for the authz retrofit, unrelated to the design itself but touched in the same file.

**Explicitly out of scope:**
- `sign`/`verify`/`encrypt`/`decrypt` CLI commands — these don't exist yet (only the HTTP API has them); adding them is a separate feature, not part of extending existing commands.
- CLI-as-HTTP-client structural redesign (see Azure parity discussion above) — separate future spec if wanted.
- A build-time/CI guardrail (e.g. an AST check) preventing a *future* command from forgetting to call `ResolveVaultID`/`RequireDataAction` — considered and declined; relying on code review, same as today.
- Vault management commands (`cmd/vaults/*`, `cmd/vault-access/*`) — already covered by the sibling `2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` effort.

## Architecture

### `cmd/vaultcli` (new package)

Promoted from `cmd/secrets/vault.go`'s private `resolveVaultID`, plus a new authorization adapter. Lives under `cmd/` (not `common/`) because `common/` currently has zero dependency on `internal/container` or any `internal/services/*` package — it's imported by nearly all of `api/`, which never touches `cobra.Command` and would gain a dependency it can't use if this moved there instead.

```go
package vaultcli

func ResolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error)

// RequireDataAction resolves the vault, then checks the caller holds a role
// assignment in it granting action. Returns the resolved vaultID on success
// so callers don't have to resolve twice.
func RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction) (vaultID uuid.UUID, err error)
```

`RequireDataAction` (the package function) is a thin wrapper: resolve vault → call `authorization.RequireDataAction(ctx, sc.GetRoleAssignmentService(), principalID, vaultID, action)` → return the vault ID or the error. This is the only function each CLI command needs to call.

### `internal/services/authorization/data_action_authz.go` (new file)

```go
// RequireDataAction returns nil if principalID holds a role assignment in
// vaultID granting action, and an error otherwise. It is the CLI-callable
// equivalent of PolicyMiddleware's HasDataAction check and must stay
// behaviorally identical to it: no admin short-circuit. Data-plane access
// has none today, even over HTTP (unlike vault-management's CanManageVault/
// CanPurgeVault, which do short-circuit for the global admin role) — copying
// that idiom here would grant the CLI a bypass the HTTP API doesn't have.
func RequireDataAction(ctx context.Context, roles RoleAssignmentService, principalID, vaultID uuid.UUID, action model.DataAction) error {
	ok, err := roles.HasDataAction(ctx, principalID, vaultID, action)
	if err != nil {
		return fmt.Errorf("checking vault authorization: %w", err)
	}
	if !ok {
		return fmt.Errorf("forbidden: no role grants %s in this vault", action)
	}
	return nil
}
```

### `model.DataAction` per command (verified against `internal/services/authorization/data_actions.go`, the existing HTTP route→action table — reused as the source of truth, not re-derived)

| Package | Command | Action |
|---|---|---|
| keys | create | `ActionKeysCreate` |
| keys | get | `ActionKeysRead` |
| keys | list | `ActionKeysRead` |
| keys | update | `ActionKeysUpdate` |
| keys | delete | `ActionKeysDelete` |
| keys | rotate | `ActionKeysRotate` |
| keys | wrap | `ActionKeysWrap` |
| keys | unwrap | `ActionKeysUnwrap` |
| certificates | list | `ActionCertificatesRead` |
| certificates | get | `ActionCertificatesRead` |
| certificates | delete | `ActionCertificatesDelete` |
| certificates | update | `ActionCertificatesUpdate` |
| certificates | renew | `ActionCertificatesCreate` (matches `data_actions.go`'s own `mapCertificateAction`, which already maps a hypothetical `POST .../renew` route this way, even though no HTTP route is registered for it) |
| secrets | create | `ActionSecretsSet` |
| secrets | list | `ActionSecretsReadMetadata` |
| secrets | get | `ActionSecretsGet` |
| secrets | update | `ActionSecretsSet` |
| secrets | delete | `ActionSecretsDelete` |
| secrets | export | `ActionSecretsGet` |
| secrets | import | `ActionSecretsSet` |

Each command hardcodes its own constant directly (`vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionKeysWrap)`) rather than deriving it from a synthetic HTTP path via `MapRouteToDataAction` — that function exists to solve generic route dispatch for middleware that must handle every route uniformly; a CLI command already knows its own action at compile time, and routing through a fake path string would be fragile, unenforced drift risk for no benefit.

### Certificate `update` fix (`api/certificates.go`)

Replace the hardcoded:
```go
scope := model.NewOwnerScope(uuid.Nil, userID)
```
with:
```go
scope, ok := scopeFromRequest(c, r)
if !ok {
	return
}
```
— identical, already-proven pattern from the `updateKey` handler (`api/keys.go`, fixed 2026-07-26). `UpdateCertificateRequest` already has a `Scope` field; no service-layer signature change needed for this one.

### `RenewCertificate` signature change (`internal/services/certificates/certificate_service.go`)

```go
// Before:
RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*CreateCertificateResult, error)
// After:
RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)
```
Internal `scope := model.NewOwnerScope(uuid.Nil, userID)` is deleted; the passed-in `scope` is used instead. Three call sites, all in this repo (confirmed by grep, no external consumers):
- `cmd/certificates/renew.go` — resolves `--vault`, checks `RequireDataAction(..., model.ActionCertificatesCreate)`, passes `model.NewVaultScope(vaultID, claims.UserID)`.
- `internal/services/certificates/renewal_service.go:85` (automatic background scheduler) — passes `model.NewAdminScope(cert.UserID)`. The scheduler already found the exact cert row via its own query and has no caller identity to check against; this matches the documented `ScopeAdmin` pattern ("no predicate, trusted internal callers").
- `internal/services/certificates/mocks/mock_CertificateService.go` — regenerated/hand-updated to match.

## Data flow (representative: `keys wrap`)

1. Cobra parses flags (`--vault` is already a persistent root flag; nothing new to register).
2. `RunE` reads `claims` from context (unchanged authentication).
3. `vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionKeysWrap)` — resolves the vault by name and checks the role assignment in one call; returns before any service/repository call if either fails.
4. Build `model.NewVaultScope(vaultID, claims.UserID)`, call `cryptoService.WrapKey(...)` as today.
5. Format/print output (unchanged).

## Error handling

- Unknown `--vault` name → `vault %q not found`, non-zero exit, nothing touched.
- No role assignment grants the action → `forbidden: no role grants %s in this vault`, non-zero exit, before any service call — no partial reads or side effects ahead of the deny.
- A real error from `HasDataAction` (e.g. DB failure) propagates distinctly from a plain deny (`checking vault authorization: %w`), matching `HasDataAction`'s own contract that a lookup failure is an error, never a silent false.

## Testing

- `internal/services/authorization/data_action_authz_test.go` (new): no admin shortcut; fails closed on `HasDataAction` returning `(false, nil)` and on `(false, err)`.
- `cmd/vaultcli` tests (new): port existing `cmd/secrets/vault_test.go` coverage for `ResolveVaultID`, add `RequireDataAction` success/deny/error cases.
- Every touched command's test file gets two new cases per command: role-assignment mock returns `true` → command succeeds with the expected `VaultScope`; returns `false` → command fails **and the underlying service method is never called** (`mock.AssertNotCalled`, not just "returned an error" — a helper that returns the right bool but where the calling command ignores it would still pass a weaker test).
- `api/certificates_test.go`: new case mirroring the existing `updateKey` vault-scope test, for the `updateCertificate` fix.
- `renewal_service_test.go`, `cmd/certificates/renew_test.go`, and the certificate service mock: updated for `RenewCertificate`'s new signature.
- `go build ./...` and `go vet ./...` must pass throughout.

## Key decisions and rejected alternatives

- **CLI wiring style: explicit per-command calls, not a `PersistentPreRunE` hook.** Cobra (v1.9.1, this repo) only runs the nearest `PersistentPreRunE` up the command tree by default (`EnableTraverseRunHooks` is not set anywhere in this codebase) — and `cmd/vaults/preview_migration.go` already overrides root's `PersistentPreRunE` for legitimate reasons, proving this isn't theoretical. A future vault-resolution hook at a command-group level is one accidental override away from silently not running. Explicit per-command calls, matching the existing `cmd/secrets` precedent, carry no such risk. Accepted trade-off: nothing stops a *future* command from forgetting to call `vaultcli.RequireDataAction` — no guardrail test was added for this (see Scope).
- **`ResolveVaultID`/`RequireDataAction` live in a new `cmd/vaultcli` package, not `common/`.** `common/` has zero dependency on `internal/container` or `internal/services/*` today and is imported by nearly all of `api/`, which has no use for `cobra.Command`-typed functions.
- **The authorization decision itself lives in `internal/services/authorization`, not inline in `cmd/`.** Keeps the actual security logic in one tested place (mirrors how `PolicyMiddleware` is a thin caller of `HasDataAction`), consistent with this codebase's service-layer pattern.
- **No admin short-circuit in `RequireDataAction`**, unlike the sibling `CanManageVault`/`CanPurgeVault`/`CanManageRoleAssignments` functions (`internal/services/authorization/vault_authz.go`, `cmd/vaults/authz.go`, `cmd/vault-access/authz.go`) — those three do short-circuit for `admin`, matching `PolicyMiddleware`'s vault-*management* behavior, but data-plane access has no such bypass today, confirmed by reading `PolicyMiddleware`'s vault-data-plane branch directly.
- **Hardcoded `model.DataAction` per command, not derived via `MapRouteToDataAction` + a synthetic path** — see table above.
- **Certificates `renew` uses `ActionCertificatesCreate`**, not a new action — matches `data_actions.go`'s own existing (currently dead, since no HTTP route reaches it) mapping for a hypothetical renew route, rather than inventing a new constant.
- **Azure parity target is guarantee-level (same outcome), not mechanism-level (one physical enforcement point)** — see the dedicated section above. Mechanism-level parity is a separate, much larger CLI transport redesign, deliberately deferred.

## Re-verification against a later merge (2026-08-11)

After this spec and Plans 01–05 were written, a separate branch (`worktree-azure-role-parity-vault-authz`, commit `8aba6d9`) merged — the sibling vault-*management* authorization fix referenced above (previously a plan; now live code), plus four new Azure roles and three new `DataAction` constants (`docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`). Re-verified against `HEAD` at that point:

- `HasDataAction` and `PolicyMiddleware`'s vault-data-plane branch: unchanged, still no admin short-circuit — this design's central constraint stays valid.
- No new `CertificateService`/`RoleAssignmentService` methods; `RenewCertificate`'s signature is still the pre-fix bare-`userID` form Plan 04 expects. The merge *did* rewrite `RenewCertificate`'s body (fixing an unrelated `UNIQUE(vault_id, name)` collision bug), but landed it in exactly the shape Plan 04's Task 2 already treats as its starting point — safe to execute as written.
- All pre-existing `model.DataAction` constants this design's table references are unchanged; the new roles/actions are additive.
- `cmd/testutils/test_utils.go`: `MockServiceContainer.RoleAssignmentService` field and `GetRoleAssignmentService()` were already added by an earlier, unrelated commit — Plan 01 Task 2 was adjusted to not re-add them, keeping only the parts that hadn't landed (`MockRoleAssignmentService` test double, default-allow wiring).
- No functional overlap between the newly-merged `CanManageVault`/`CanPurgeVault`/`CanManageRoleAssignments` (vault-management) and this design's `RequireDataAction` (vault data-plane) — confirmed distinct concerns, no rework needed.
