# CLI Audit-Command Authorization Bypass — Design

**Date:** 2026-08-16
**Status:** Proposed
**Branch target:** `v-4.0.0`

## Goal

Close a High-severity authorization bypass confirmed by a live pentest run
today: `rocketvault audit logs`, `rocketvault audit report`, and
`rocketvault audit config` perform **zero** role check before calling into
`ComplianceReportService`. A logged-in principal with the plain `user` role —
no admin grant, no audit-related grant of any kind — can run any of the three
and get the full result: the complete cross-vault audit trail, a full SOC 2
report covering every user including the admin, a GDPR report for any
`subject_id`, and both read and write access to the global audit retention
policy.

Fix `cmd/audit/logs.go`, `cmd/audit/report.go`, and `cmd/audit/config.go` so
each `RunE` rejects a non-admin caller before touching
`ComplianceReportService`, mirroring the identical `claims.Role !=
model.RoleAdmin` restriction `api/audit.go`'s five HTTP handlers already
enforce.

## Root cause

CLI commands bypass the HTTP middleware chain entirely and call into the
service layer directly — this is documented, load-bearing behavior in this
codebase's CLI architecture (see `CLAUDE.md` § "CLI Authorization"): every
resource command is individually responsible for reproducing whatever check
its HTTP equivalent gets for free from middleware. `api/audit.go`'s five
handlers each open with the same three lines:

```go
role := c.Claims.Role
if role != string(model.RoleAdmin) {
	c.SetPermissionError("admin role required")
	return
}
```

(`getAuditLogs` at `api/audit.go:66-71`, `getSOC2Report` at `98-103`,
`getGDPRReport` at `142-147`, `getAuditConfig` at `190-195`,
`patchAuditConfig` at `214-219`.)

The three CLI commands under `cmd/audit/` never reproduced this. Each
`RunE` does exactly one check — that a `container.ServiceContainerInterface`
is present in the command context — and then calls straight into
`sc.GetComplianceReportService()`:

- `cmd/audit/logs.go:33-111` (`logsCmd.RunE`) → `svc.QueryLogs(...)`
- `cmd/audit/report.go:36-129` (`reportCmd.RunE`) → `svc.GenerateSOC2Report`/
  `GenerateSOC2CSV`/`GenerateGDPRReport`/`GenerateGDPRCSV`
- `cmd/audit/config.go:25-51` (`configCmd.RunE`) → `svc.GetRetentionDays`/
  `SetRetentionDays`

None of the three reads `common.ClaimsKey` from the command context at all.
This is a plain omission, not a design tradeoff — the claims are already
populated on every authenticated CLI invocation by `persistentPreRun` in
`cmd/root.go:316` (`ctx = context.WithValue(ctx, common.ClaimsKey, claims)`),
the same mechanism every other admin-gated CLI command already reads from.

**Live proof (2026-08-16):** logged in as a freshly created `role=user`
account with no admin or audit-related grant anywhere, `rocketvault audit
logs` and `rocketvault audit report --type soc2 ...` both succeeded,
returning the full cross-vault audit trail and a complete SOC2 report.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Check to reproduce | `claims.Role != model.RoleAdmin` — a flat global-admin gate | Matches `api/audit.go` exactly. Audit logs and compliance reports span every vault; there is nothing to scope the check to, so this is categorically the same shape of check as `cmd/backup.go`'s admin gate, not the per-vault `vaultcli.RequireDataAction` pattern `secrets`/`keys`/`certificates` commands use, and not the vault-management `CanManageVault`/`CanPurgeVault` pattern `cmd/vaults`/`cmd/vault-access` use. |
| Where the check lives | A small package-local helper, `requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error)`, in a new file `cmd/audit/authz.go` | This codebase already has direct, exact precedent for this shape of problem: `cmd/backup.go`'s `requireBackupAdmin` is the *same* pattern — cross-vault CLI operation, no per-vault scope, gated on `claims.Role != model.RoleAdmin` alone, doc-commented as "same category as users/vaults/migrate commands." Three call sites (`logs`, `report`, `config`) in one package is exactly the shape `requireBackupAdmin` already solves for `backup create`/`list`/`restore`. Following that precedent — rather than either inlining the same three lines three times, or reaching for `vaultcli`/`cmd/vaults/authz.go` machinery that doesn't apply here — is the smallest change consistent with the codebase's own prior art. Not creating a shared cross-package helper (e.g. promoting `requireBackupAdmin` out of `cmd/backup.go`): `backup.go` lives in package `cmd` (root), `audit` is its own package, and two independent one-line-bodied helpers in their natural packages is simpler than introducing a new shared `cmd/cliauthz` package for two call sites total across the whole CLI. Revisit if a third such package appears. |
| Claims-missing vs. wrong-role | Two distinct error messages, matching `requireBackupAdmin` and `cmd/users/list.go`: `"unauthorized: missing authentication claims"` when `common.ClaimsKey` isn't set at all, `"forbidden: requires admin role"` when it's set but the role isn't admin | Established convention in this codebase (`cmd/backup.go:47-57`, `cmd/users/list.go:48-61`) — distinguishing "not authenticated" from "authenticated but not permitted" gives a CLI operator a more actionable error than one flat message. |
| Check placement within each `RunE` | Immediately after the existing `sc, ok := ctx.Value(common.ServiceContainerKey)...` guard, before any flag parsing or service call | Preserves the existing, already-tested "service container not available" error path unchanged (see Testing below) while still gating every code path that would otherwise reach `ComplianceReportService`. Ordering relative to the *service-container* check is not security-relevant (both are fail-closed); ordering relative to the *service call* is — the admin check must run before `QueryLogs`/`GenerateSOC2Report`/etc. is ever invoked, which this placement guarantees. |
| Route-level parity beyond role | Scope to the role check only; do not add scoping like the vault-management CSRF/rate-limit/etc. HTTP middleware layers | Those are HTTP-transport concerns (CORS, rate limiting) with no CLI analogue — out of scope, matching how every other CLI command in this codebase treats them. |

**Out of scope for this fix:** the underlying `ComplianceReportService`
methods (`QueryLogs`, `GenerateSOC2Report`, etc.) remain unauthenticated at
the service layer — this is consistent with this codebase's layering, where
authorization is a caller's-edge concern (HTTP middleware or CLI command),
not a service-layer concern, throughout the codebase. Not changing that
boundary here.

## Components and changes

### 1. `cmd/audit/authz.go` (new file)

```go
// Package audit — authz.go provides the authorization check shared by every
// audit CLI command. Audit logs and compliance reports span every vault, so
// (like cmd/backup.go's requireBackupAdmin) there is no vault to scope this
// to — the global admin role is the only applicable gate, mirroring the
// identical claims.Role != model.RoleAdmin restriction api/audit.go enforces
// on every audit HTTP route (getAuditLogs, getSOC2Report, getGDPRReport,
// getAuditConfig, patchAuditConfig).
package audit

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/model"
)

// requireAuditAdmin returns the caller's claims if they are logged in as
// admin, and an error otherwise. CLI commands bypass the HTTP middleware
// chain entirely (see CLAUDE.md's "CLI Authorization" section), so each
// audit command must reproduce this check itself.
func requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error) {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("unauthorized: missing authentication claims")
	}
	if claims.Role != model.RoleAdmin {
		return nil, fmt.Errorf("forbidden: requires admin role")
	}
	return claims, nil
}
```

### 2. `cmd/audit/logs.go` — `logsCmd.RunE`

Insert the gate immediately after the existing service-container guard
(currently `cmd/audit/logs.go:36-39`), before any flag parsing:

```go
sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
if !ok || sc == nil {
	return fmt.Errorf("service container not available in context")
}

if _, err := requireAuditAdmin(cmd); err != nil {
	return err
}

// Parse time range flags.
// ... unchanged ...
```

### 3. `cmd/audit/report.go` — `reportCmd.RunE`

Same insertion point, immediately after the existing service-container guard
(currently `cmd/audit/report.go:39-42`):

```go
sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
if !ok || sc == nil {
	return fmt.Errorf("service container not available in context")
}

if _, err := requireAuditAdmin(cmd); err != nil {
	return err
}

reportType, _ := cmd.Flags().GetString("type")
// ... unchanged ...
```

### 4. `cmd/audit/config.go` — `configCmd.RunE`

Same insertion point, immediately after the existing service-container guard
(currently `cmd/audit/config.go:28-31`):

```go
sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
if !ok || sc == nil {
	return fmt.Errorf("service container not available in context")
}

if _, err := requireAuditAdmin(cmd); err != nil {
	return err
}

retentionDays, _ := cmd.Flags().GetInt("retention-days")
// ... unchanged ...
```

No changes to `cmd/audit/audit.go` (top-level command registration) or to
`api/audit.go` (already correct — this fix only closes the CLI-side gap).

## Testing

`cmd/testutils.NewTestContext(t)` already seeds `tc.Ctx` with admin claims
(`testClaims := &model.Claims{..., Role: model.RoleAdmin}`,
`cmd/testutils/test_utils.go:105-115`) precisely so pre-existing CLI tests —
none of which currently exercise a role check, because none currently exists
— continue to pass unmodified once the gate is added: they already run as
admin. This means every existing `TestLogsCmd_*`, `TestReportCmd_*`, and
`TestConfigCmd_*` test in `cmd/audit/audit_cmds_test.go` (and the earlier
inline-command tests in `cmd/audit/audit_test.go`) is expected to keep
passing with no changes.

New tests, one pair per command (non-admin rejected, admin still succeeds),
following the existing per-package pattern of overriding `common.ClaimsKey`
on top of `tc.Ctx` for a non-default role (see `cmd/users/list_test.go:241-243`,
`cmd/users/update_test.go:25`):

- `TestLogsCmd_NonAdmin_Forbidden` / `TestLogsCmd_Admin_Allowed`
- `TestReportCmd_NonAdmin_Forbidden` / `TestReportCmd_Admin_Allowed`
- `TestConfigCmd_NonAdmin_Forbidden` / `TestConfigCmd_Admin_Allowed`

Each "forbidden" test asserts both the error text (`"forbidden: requires
admin role"`) and, via `mockSvc.AssertNotCalled(t, "QueryLogs", ...)` (or the
equivalent method for report/config), that `ComplianceReportService` was
never invoked — proving the gate runs *before* the service call, not just
that the command happens to return an error some other way.

A `TestRequireAuditAdmin_*` table in `cmd/audit/authz_test.go` covers the
helper directly: missing claims, non-admin role, admin role — matching the
style of `cmd/vault-access/authz_test.go` and `cmd/vaults/authz_test.go`.

## Verification gate

```
go build ./...
go vet ./...
go test ./cmd/audit/... ./cmd/... ./api/...
```

All must pass before claiming completion (no success claims without fresh
evidence).

## Risks

- **None functionally new.** This closes a bypass; it does not change the
  HTTP API, the service layer, or any other CLI command's behavior.
- **Breaking-change note:** any non-admin operator currently (mis)using
  `audit logs`/`audit report`/`audit config` will start getting a `forbidden`
  error. This is the intended fix, not a regression, but worth a one-line
  mention in the next release notes given it's a hardening of previously
  (incorrectly) permissive CLI behavior.

## Related Work / Follow-Up

This is a narrow, single-purpose fix — no follow-up work is being deferred
out of it. The `.claude/known-bugs.md` entry this plan adds (see the
implementation plan's final task) documents it for posterity once fixed.
