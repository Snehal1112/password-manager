# CLI Audit-Command Authorization Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close a High-severity broken-access-control hole confirmed live on 2026-08-16: `rocketvault audit logs`, `rocketvault audit report`, and `rocketvault audit config` call straight into `ComplianceReportService` with **no** role check, while their HTTP equivalents in `api/audit.go` all correctly restrict to `claims.Role == model.RoleAdmin`. A plain `role=user` account with no admin or audit grant can currently read the entire cross-vault audit trail, generate full SOC2/GDPR compliance reports for any user, and read/write the global audit retention policy. The fix adds a `requireAuditAdmin` gate — reproducing the identical `claims.Role != model.RoleAdmin` check `api/audit.go` already enforces — to the top of all three commands' `RunE` closures.

**Architecture:** CLI commands bypass the HTTP middleware chain entirely and call the service layer directly (`CLAUDE.md` § "CLI Authorization"), so each command must reproduce its HTTP equivalent's check itself. Audit logs and compliance reports span every vault — there is no vault to scope this to — so this is the same category of check as `cmd/backup.go`'s `requireBackupAdmin` (a flat global-admin gate), not the per-vault `vaultcli.RequireDataAction` pattern or the vault-management `CanManageVault`/`CanPurgeVault` pattern. Following `requireBackupAdmin`'s exact precedent, a new package-local helper `requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error)` is added to a new file `cmd/audit/authz.go`, and called from the top of each of the three `RunE` closures, immediately after their existing service-container guard and before any flag parsing or service call.

**Tech Stack:** Go 1.24.2, `github.com/spf13/cobra`, `rocketvault/common` (`ClaimsKey`), `rocketvault/model` (`Claims`, `RoleAdmin`), `rocketvault/internal/container` (`ServiceContainerInterface`), testify (`assert`/`mock`), `rocketvault/cmd/testutils` (`NewTestContext`).

**Spec:** `docs/superpowers/specs/2026-08-16-cli-audit-authz-fix-design.md` — §"Root cause", §"Design decisions" (check shape, helper placement, claims-missing vs. wrong-role, check placement within `RunE`), §"Components and changes", §"Testing".

## Global Constraints

- The check must be **exactly** `claims.Role != model.RoleAdmin`, matching `api/audit.go`'s five handlers verbatim — no `common.HasRequiredRole` multi-role variant, no vault scoping.
- The gate must run **before** any call into `ComplianceReportService` on every code path — no flag-parsing branch may reach the service first.
- Missing claims and wrong-role are two distinct errors: `"unauthorized: missing authentication claims"` vs. `"forbidden: requires admin role"` (matches `cmd/backup.go:47-57`, `cmd/users/list.go:48-61`).
- No changes to `api/audit.go` (already correct) or to `ComplianceReportService`/its interface.
- Existing tests in `cmd/audit/audit_test.go` and the pre-existing tests in `cmd/audit/audit_cmds_test.go` must keep passing unmodified — `cmd/testutils.NewTestContext(t)` already seeds admin claims, so they exercise the admin-success path implicitly.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `cmd/audit/authz.go` | Create | `requireAuditAdmin` helper, mirrors `cmd/backup.go`'s `requireBackupAdmin` |
| `cmd/audit/authz_test.go` | Create | Unit tests for the helper in isolation |
| `cmd/audit/logs.go` | Modify | Add the gate to `logsCmd.RunE` |
| `cmd/audit/report.go` | Modify | Add the gate to `reportCmd.RunE` |
| `cmd/audit/config.go` | Modify | Add the gate to `configCmd.RunE` |
| `cmd/audit/audit_cmds_test.go` | Modify | Add non-admin/admin test pairs for all three commands |
| `.claude/known-bugs.md` | Modify | Record the finding and fix as a new `### B<N>` entry |

No other production files change. `common.ClaimsKey`, `model.Claims`, and `model.RoleAdmin` already exist and are unchanged (`common/context.go:20`, `model/user.go:29-38`).

---

## Task 1: `requireAuditAdmin` helper

**Files:**
- Create: `cmd/audit/authz.go`
- Create: `cmd/audit/authz_test.go`

**Interfaces:**
- Produces: `requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error)` — every later task calls this exact signature.

### Step 1: Write the failing tests

Create `cmd/audit/authz_test.go`:

```go
package audit

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"rocketvault/common"
	"rocketvault/model"
)

// TestRequireAuditAdmin_MissingClaims proves a context with no ClaimsKey at
// all is rejected with the "unauthorized" message, not the "forbidden" one.
func TestRequireAuditAdmin_MissingClaims(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	claims, err := requireAuditAdmin(cmd)
	assert.Nil(t, claims)
	assert.ErrorContains(t, err, "unauthorized: missing authentication claims")
}

// TestRequireAuditAdmin_NonAdminRole proves an authenticated non-admin caller
// is rejected with the "forbidden" message.
func TestRequireAuditAdmin_NonAdminRole(t *testing.T) {
	cmd := &cobra.Command{}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{Role: model.RoleUser})
	cmd.SetContext(ctx)

	claims, err := requireAuditAdmin(cmd)
	assert.Nil(t, claims)
	assert.ErrorContains(t, err, "forbidden: requires admin role")
}

// TestRequireAuditAdmin_AdminRole proves an admin caller passes and gets
// their claims back.
func TestRequireAuditAdmin_AdminRole(t *testing.T) {
	cmd := &cobra.Command{}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{Role: model.RoleAdmin, Username: "admin"})
	cmd.SetContext(ctx)

	claims, err := requireAuditAdmin(cmd)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, model.RoleAdmin, claims.Role)
}
```

### Step 2: Run to confirm the tests fail to compile

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -run TestRequireAuditAdmin -v 2>&1 | tail -20
```

Expected: build failure — `requireAuditAdmin` undefined.

### Step 3: Implement the helper

Create `cmd/audit/authz.go`:

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

### Step 4: Build and run the tests

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -run TestRequireAuditAdmin -v 2>&1 | tail -20
```

Expected: all three PASS.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add cmd/audit/authz.go cmd/audit/authz_test.go && git commit -S -m "feat(audit): add requireAuditAdmin CLI authorization helper"
```

---

## Task 2: Gate `logsCmd`

**Files:**
- Modify: `cmd/audit/logs.go:33-111` (`logsCmd.RunE`)
- Modify: `cmd/audit/audit_cmds_test.go`

**Interfaces:**
- Consumes: `requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error)` from Task 1.

### Step 1: Write the failing tests

Append to `cmd/audit/audit_cmds_test.go` (same package, existing imports — `context`, `common`, `model` via `mock`/`testutils` already present; add `"rocketvault/model"` to the import block if not already there):

```go
// TestLogsCmd_NonAdmin_Forbidden proves a non-admin caller is rejected before
// QueryLogs is ever called.
func TestLogsCmd_NonAdmin_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc).Maybe()

	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{Role: model.RoleUser})

	cmd, _ := newLogsCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()

	assert.ErrorContains(t, err, "forbidden: requires admin role")
	mockSvc.AssertNotCalled(t, "QueryLogs", mock.Anything, mock.Anything)
}

// TestLogsCmd_Admin_Allowed proves an admin caller still reaches QueryLogs
// after the gate is added (regression guard for the fix in this task).
func TestLogsCmd_Admin_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return([]repositories.AuditLog{}, int64(0), true, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Total matching: 0")
	mockSvc.AssertExpectations(t)
}
```

### Step 2: Run to confirm `TestLogsCmd_NonAdmin_Forbidden` fails

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -run "TestLogsCmd_NonAdmin_Forbidden|TestLogsCmd_Admin_Allowed" -v 2>&1 | tail -25
```

Expected: `TestLogsCmd_NonAdmin_Forbidden` **FAILs** — no error is returned today, so `assert.ErrorContains` fails. `TestLogsCmd_Admin_Allowed` already passes (admin claims, no gate yet).

### Step 3: Add the gate to `logsCmd.RunE`

In `cmd/audit/logs.go`, insert immediately after the existing service-container guard (currently lines 36-39):

```go
		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		if _, err := requireAuditAdmin(cmd); err != nil {
			return err
		}

		// Parse time range flags.
		fromStr, _ := cmd.Flags().GetString("from")
```

(everything from `fromStr, _ := ...` onward is unchanged.)

### Step 4: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -v 2>&1 | tail -60
```

Expected: all tests in `cmd/audit` PASS, including every pre-existing `TestLogsCmd_*`/`TestAuditLogs*` test (they run as admin via `tc.Ctx`/inline claims already, so they're unaffected) and the two new tests.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add cmd/audit/logs.go cmd/audit/audit_cmds_test.go && git commit -S -m "fix(audit): require admin role for CLI audit logs command"
```

---

## Task 3: Gate `reportCmd`

**Files:**
- Modify: `cmd/audit/report.go:36-129` (`reportCmd.RunE`)
- Modify: `cmd/audit/audit_cmds_test.go`

**Interfaces:**
- Consumes: `requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error)` from Task 1.

### Step 1: Write the failing tests

Append to `cmd/audit/audit_cmds_test.go`:

```go
// TestReportCmd_NonAdmin_Forbidden proves a non-admin caller is rejected
// before any report-generation method is called.
func TestReportCmd_NonAdmin_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc).Maybe()

	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{Role: model.RoleUser})

	cmd, _ := newReportCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()

	assert.ErrorContains(t, err, "forbidden: requires admin role")
	mockSvc.AssertNotCalled(t, "GenerateSOC2Report", mock.Anything, mock.Anything, mock.Anything)
}

// TestReportCmd_Admin_Allowed proves an admin caller still reaches
// GenerateSOC2Report after the gate is added.
func TestReportCmd_Admin_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	mockSvc.On("GenerateSOC2Report", mock.Anything, from, to).
		Return(&auditServices.SOC2Report{From: from, To: to, TotalEvents: 1}, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "SOC 2 Report")
	mockSvc.AssertExpectations(t)
}
```

### Step 2: Run to confirm `TestReportCmd_NonAdmin_Forbidden` fails

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -run "TestReportCmd_NonAdmin_Forbidden|TestReportCmd_Admin_Allowed" -v 2>&1 | tail -25
```

Expected: `TestReportCmd_NonAdmin_Forbidden` **FAILs** — no error returned today. `TestReportCmd_Admin_Allowed` already passes.

### Step 3: Add the gate to `reportCmd.RunE`

In `cmd/audit/report.go`, insert immediately after the existing service-container guard (currently lines 39-42):

```go
		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		if _, err := requireAuditAdmin(cmd); err != nil {
			return err
		}

		reportType, _ := cmd.Flags().GetString("type")
```

(everything from `reportType, _ := ...` onward is unchanged.)

### Step 4: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -v 2>&1 | tail -80
```

Expected: all tests in `cmd/audit` PASS, including every pre-existing `TestReportCmd_*`/`TestAuditReport*` test and the two new ones.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add cmd/audit/report.go cmd/audit/audit_cmds_test.go && git commit -S -m "fix(audit): require admin role for CLI audit report command"
```

---

## Task 4: Gate `configCmd`

**Files:**
- Modify: `cmd/audit/config.go:25-51` (`configCmd.RunE`)
- Modify: `cmd/audit/audit_cmds_test.go`

**Interfaces:**
- Consumes: `requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error)` from Task 1.

### Step 1: Write the failing tests

Append to `cmd/audit/audit_cmds_test.go`:

```go
// TestConfigCmd_NonAdmin_Forbidden proves a non-admin caller is rejected
// before GetRetentionDays/SetRetentionDays is ever called.
func TestConfigCmd_NonAdmin_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc).Maybe()

	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{Role: model.RoleUser})

	cmd, _ := newConfigCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()

	assert.ErrorContains(t, err, "forbidden: requires admin role")
	mockSvc.AssertNotCalled(t, "GetRetentionDays", mock.Anything)
	mockSvc.AssertNotCalled(t, "SetRetentionDays", mock.Anything, mock.Anything)
}

// TestConfigCmd_Admin_Allowed proves an admin caller still reaches
// GetRetentionDays after the gate is added.
func TestConfigCmd_Admin_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GetRetentionDays", mock.Anything).Return(90, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "90 days")
	mockSvc.AssertExpectations(t)
}
```

### Step 2: Run to confirm `TestConfigCmd_NonAdmin_Forbidden` fails

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -run "TestConfigCmd_NonAdmin_Forbidden|TestConfigCmd_Admin_Allowed" -v 2>&1 | tail -25
```

Expected: `TestConfigCmd_NonAdmin_Forbidden` **FAILs** — no error returned today. `TestConfigCmd_Admin_Allowed` already passes.

### Step 3: Add the gate to `configCmd.RunE`

In `cmd/audit/config.go`, insert immediately after the existing service-container guard (currently lines 28-31):

```go
		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		if _, err := requireAuditAdmin(cmd); err != nil {
			return err
		}

		retentionDays, _ := cmd.Flags().GetInt("retention-days")
```

(everything from `retentionDays, _ := ...` onward is unchanged.)

### Step 4: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... -v 2>&1 | tail -100
```

Expected: all tests in `cmd/audit` PASS, including every pre-existing `TestConfigCmd_*`/`TestAuditConfig*` test and the two new ones.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add cmd/audit/config.go cmd/audit/audit_cmds_test.go && git commit -S -m "fix(audit): require admin role for CLI audit config command"
```

---

## Task 5: Full regression sweep and bug-tracking documentation

**Files:**
- Modify: `.claude/known-bugs.md`
- No further code changes — this task is verification and documentation only.

**Interfaces:** None — this task consumes nothing new and produces nothing new in code.

### Step 1: Full build, vet, and test sweep

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go vet ./... 2>&1
```

Expected: clean build, no vet warnings.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/audit/... ./cmd/... ./api/... 2>&1 | grep -E "FAIL|^ok"
```

Expected: every package `ok`, no `FAIL`.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|^ok" | tail -60
```

Expected: every package `ok`, no `FAIL` anywhere in the repo (this fix touches only `cmd/audit`, but a full sweep confirms no accidental blast radius).

### Step 2: Confirm the blast radius matches this plan

```bash
cd /home/numericlabs/data/rocket/rocketvault && git diff --stat HEAD~4
```

Expected: only `cmd/audit/authz.go`, `cmd/audit/authz_test.go`, `cmd/audit/logs.go`, `cmd/audit/report.go`, `cmd/audit/config.go`, `cmd/audit/audit_cmds_test.go` appear.

### Step 3: Record the fix in `.claude/known-bugs.md`

Get the four fix commit hashes from Tasks 1-4:

```bash
cd /home/numericlabs/data/rocket/rocketvault && git log --oneline -4
```

Read `.claude/known-bugs.md`'s existing `## Open Bugs` section structure first — it uses `### B<N> — title` headers with `**Status**`/`**Severity**`/`**File**` fields (e.g. `B7`, `B8`). Check the highest existing number:

```bash
cd /home/numericlabs/data/rocket/rocketvault && grep -n '^### ' .claude/known-bugs.md
```

As of this plan's writing the highest is `B8`, so the new entry is `B13`. Add it directly above the `---` that precedes the next section (after B8's closing content), substituting the real commit hashes from Step 1's `git log` output for `<hash1>`-`<hash4>`:

```markdown
### B13 — CLI `audit logs`/`audit report`/`audit config` bypassed the admin-only restriction enforced by their HTTP equivalents

**Status**: Fixed in commits `<hash1>` (helper), `<hash2>` (logs), `<hash3>`
(report), `<hash4>` (config)
**Severity**: High — confirmed by a live pentest run 2026-08-16
**File**: `cmd/audit/authz.go`, `cmd/audit/logs.go`, `cmd/audit/report.go`,
`cmd/audit/config.go`

**Root cause**: `api/audit.go`'s five HTTP handlers (`getAuditLogs`,
`getSOC2Report`, `getGDPRReport`, `getAuditConfig`, `patchAuditConfig`) each
correctly gate on `claims.Role != model.RoleAdmin` before touching
`ComplianceReportService`. CLI commands bypass the HTTP middleware chain
entirely and are individually responsible for reproducing the equivalent
check (`CLAUDE.md` § "CLI Authorization") — the three CLI equivalents under
`cmd/audit/` never did. Each `RunE` only checked that a service container was
present in context, then called straight into `sc.GetComplianceReportService()`.
A plain `role=user` account with no admin or audit grant could run `rocketvault
audit logs` or `rocketvault audit report --type soc2 ...` and get the full
cross-vault audit trail and a complete SOC2 report covering every user
including the admin — confirmed live before the fix.

**What was fixed**: Added `requireAuditAdmin(cmd *cobra.Command)
(*model.Claims, error)` (`cmd/audit/authz.go`), modeled directly on
`cmd/backup.go`'s pre-existing `requireBackupAdmin` — same category of check
(global admin gate, no vault to scope to). Called from the top of
`logsCmd.RunE`, `reportCmd.RunE`, and `configCmd.RunE`, immediately after
each command's existing service-container guard and before any flag parsing
or service call. `TestLogsCmd_NonAdmin_Forbidden`,
`TestReportCmd_NonAdmin_Forbidden`, and `TestConfigCmd_NonAdmin_Forbidden`
(`cmd/audit/audit_cmds_test.go`) each assert both the `forbidden` error and,
via `AssertNotCalled`, that the underlying `ComplianceReportService` method
was never invoked.

**Spec/plan**: `docs/superpowers/specs/2026-08-16-cli-audit-authz-fix-design.md`,
`docs/superpowers/plans/2026-08-16-cli-audit-authz-fix.md`.
```

### Step 4: Commit the documentation update

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add .claude/known-bugs.md && git commit -S -m "docs(known-bugs): record the CLI audit authorization bypass fix"
```

---

## Self-Review

**Spec coverage:**
- "logs/report/config bypass the admin-only restriction" → `requireAuditAdmin` added to all three `RunE` closures, called before any `ComplianceReportService` method. ✅
- Design decision "check shape" (`claims.Role != model.RoleAdmin`, no vault scoping) → `requireAuditAdmin` uses exactly that comparison against `model.RoleAdmin`; no vault ID anywhere in the helper. ✅
- Design decision "where the check lives" (package-local helper, modeled on `requireBackupAdmin`, not a new shared cross-package helper) → `cmd/audit/authz.go`, doc comment explicitly cross-references `cmd/backup.go`. ✅
- Design decision "claims-missing vs. wrong-role" (two distinct error strings) → `"unauthorized: missing authentication claims"` vs. `"forbidden: requires admin role"`, both covered by `TestRequireAuditAdmin_MissingClaims`/`TestRequireAuditAdmin_NonAdminRole`. ✅
- Design decision "check placement" (immediately after the service-container guard, before flag parsing/service calls) → all three Task 2-4 insertions follow this exact placement; verified by the `AssertNotCalled` tests, which prove the gate runs before the service method regardless of which flags are set. ✅
- Testing requirement (non-admin rejected + admin still succeeds, per command group) → `TestLogsCmd_NonAdmin_Forbidden`/`TestLogsCmd_Admin_Allowed`, `TestReportCmd_NonAdmin_Forbidden`/`TestReportCmd_Admin_Allowed`, `TestConfigCmd_NonAdmin_Forbidden`/`TestConfigCmd_Admin_Allowed`. ✅
- Testing requirement (existing tests keep passing unmodified) → no existing test in `cmd/audit/audit_test.go` or the pre-existing tests in `cmd/audit/audit_cmds_test.go` is edited by this plan; each task's Step 4 re-runs the full `cmd/audit` suite to confirm. ✅
- known-bugs.md task → Task 5 Step 3 adds a full `### B13` entry in the file's established format, with real content (not a placeholder), substituting the actual commit hashes captured in Step 3. ✅

**Placeholder scan:** No `TODO`, `TBD`, or "add appropriate error handling." The `<hash1>`-`<hash4>` tokens in Task 5 Step 3 are not placeholders in the "No Placeholders" sense — they are values the executor captures from `git log` output produced by that same task's own prior steps and substitutes before committing, the same pattern used by `docs/superpowers/plans/2026-08-15-retry-oidc-hardening.md` Task 6. ✅

**Type consistency (verified by reading the code):**
- `requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error)` — defined once in Task 1, called identically (`if _, err := requireAuditAdmin(cmd); err != nil { return err }`) in Tasks 2, 3, 4. ✅
- `common.ClaimsKey` — `common/context.go:20`, already imported in `logs.go`/`report.go`/`config.go` via the existing `"rocketvault/common"` import (used for `common.ServiceContainerKey`); no new import needed in those three files since `requireAuditAdmin` lives in `authz.go` and callers only use its return values via `_`. ✅
- `model.Claims{Role string, ...}` and `model.RoleAdmin`/`model.RoleUser` string constants — `model/user.go:29-38`; matches every `&model.Claims{Role: model.RoleUser}` / `Role: model.RoleAdmin` literal used across all new tests. ✅
- `container.ServiceContainerInterface` — unchanged; `sc` variable type and guard clause in all three commands are untouched by this plan, only new lines are inserted after them. ✅
- `MockComplianceReportService` — already defined in `cmd/audit/audit_test.go` (`QueryLogs`, `GenerateSOC2Report`, `GenerateSOC2CSV`, `GenerateGDPRReport`, `GenerateGDPRCSV`, `GetRetentionDays`, `SetRetentionDays`), reused as-is by every new test; argument counts in `AssertNotCalled` calls match each method's real signature (`QueryLogs`: ctx+filter=2, `GenerateSOC2Report`: ctx+from+to=3, `GetRetentionDays`: ctx=1, `SetRetentionDays`: ctx+days=2) so `testify`'s length-sensitive `Diff` comparison is meaningful rather than vacuously true. ✅
- `testutils.NewTestContext(t)` seeds `tc.Ctx` with `model.RoleAdmin` claims (`cmd/testutils/test_utils.go:105-115`) — every "Admin_Allowed" test either uses `tc.Ctx` directly or `buildAuditCtx(tc)` (which wraps `tc.Ctx`), so the admin claims flow through unchanged; every "NonAdmin_Forbidden" test explicitly overrides `common.ClaimsKey` on top of `tc.Ctx` with `model.RoleUser`. ✅

---

## Follow-Up

None. This is a narrow, self-contained fix — no work is deferred out of it.
