# Remove Unreachable Branch in `vault-access roles` CLI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the one genuinely unreachable code path found while auditing RocketVault's legacy (pre-Azure-RBAC) role vocabulary for dead code: the final `else` branch in `cmd/vault-access/roles.go`'s `roles` command loop, which calls `authzServices.RolePermissions(name)` for a role name that is neither legacy nor an Azure built-in role — a case that can never occur, since `authz.BuiltInRoleNames()` (the loop's only source of names) returns exactly the union of the seven legacy names and the eleven Azure names.

**Architecture:** Replace the unreachable `else` branch with an explicit internal-invariant error, matching this codebase's existing fail-closed style ("an unrecognised assignment grants nothing rather than defaulting open" — `model/azure_roles.go:225-226`) instead of silently doing nothing if the invariant is ever violated by a future change to `BuiltInRoleNames`.

**Tech Stack:** Go, `github.com/spf13/cobra`.

## Global Constraints

- `go build ./...` and `go vet ./...` must pass after the task.
- Scope note: this plan intentionally does **not** touch `internal/services/authorization/roles.go`'s `builtInRoles`, `bundle()`, `ExpandRole`, or `RolePermissions()`. Those looked like dead legacy-RBAC code at first glance, but are not: `RolePermissions()` is called live from `api/role_assignments.go:37` to display existing (possibly not-yet-upgrade-migrated) `role_assignments` rows that may still carry a legacy role name, and `ExpandRole`/`bundle()` are directly exercised by `TestExpandRole_SecretsUser`, `TestExpandRole_VaultAdminIncludesManage`, and `TestExpandRole_Unknown` in `internal/services/authorization/roles_test.go`, which validate legacy-role expansion as intended, documented behavior (see `roles.go:92-101,110-115` for the code's own rationale). Removing them would delete tested, load-bearing functionality under a false "dead code" label — do not do this without a separate, explicit decision to drop support for displaying/expanding not-yet-migrated legacy role assignments.

---

### Task 1: Remove the unreachable branch and add a fail-closed invariant check

**Files:**
- Modify: `cmd/vault-access/roles.go:19-49` (`InitVaultAccessRoles`'s `RunE` closure)
- Test: `cmd/vault-access/roles_test.go` (existing `TestRolesCommand_ListsBuiltInRoles` stays as regression coverage; add one new test)

**Interfaces:**
- Consumes: `authz.BuiltInRoleNames() []string`, `authz.IsLegacyRole(name string) bool`, `model.IsAzureRole(name string) bool`, `model.AzureRoleDataActions(name string) []model.DataAction` — all unchanged, already imported in this file.
- Produces: no change to the command's observable output for any name `BuiltInRoleNames()` actually returns today (this is a pure refactor of unreachable code) — `RunE`'s error return type is unchanged (`error`), so callers of the cobra command are unaffected.

- [ ] **Step 1: Write the failing test**

Add to `cmd/vault-access/roles_test.go`:

```go
// TestRolesCommand_EveryNameIsLegacyOrAzure locks in the invariant the roles
// command's RunE relies on: authz.BuiltInRoleNames() only ever yields names
// that are either legacy or an Azure built-in role. If this ever stops being
// true, RunE now returns an explicit internal error instead of silently
// dropping the unrecognized name from the output.
func TestRolesCommand_EveryNameIsLegacyOrAzure(t *testing.T) {
	for _, name := range authz.BuiltInRoleNames() {
		if !authz.IsLegacyRole(name) && !model.IsAzureRole(name) {
			t.Fatalf("BuiltInRoleNames() returned %q, which is neither legacy nor an Azure role", name)
		}
	}
}
```

This requires adding `authz "rocketvault/internal/services/authorization"` and `"rocketvault/model"` to this test file's imports.

- [ ] **Step 2: Run the test to verify it passes today**

Run: `go test ./cmd/vault-access/... -run TestRolesCommand_EveryNameIsLegacyOrAzure -v`

Expected: PASS. This confirms the invariant is currently true — the refactor in Step 3 is safe. (This is a proof-of-invariant test rather than a red/green TDD test, since the change in Step 3 is a pure refactor of code this test proves is already unreachable — there is no new observable behavior to drive out with a failing test first.)

- [ ] **Step 3: Replace the unreachable branch**

In `cmd/vault-access/roles.go`, change:

```go
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for _, name := range authz.BuiltInRoleNames() {
				// Legacy names remain in BuiltInRoleNames (IsValidRole still
				// recognizes them for display and upgrade translation), but
				// AssignRole now refuses to grant them: a legacy-named
				// role_assignments row grants zero data-plane access.
				// Printing them with a permission list here would repeat that
				// lie back to the operator.
				if authz.IsLegacyRole(name) {
					fmt.Fprintf(out, "%s (deprecated: no longer grantable, grants no access — use an Azure role instead)\n", name) //nolint:errcheck
					continue
				}
				if model.IsAzureRole(name) {
					fmt.Fprintf(out, "%s\n", name) //nolint:errcheck
					for _, action := range model.AzureRoleDataActions(name) {
						fmt.Fprintf(out, "  %s\n", action) //nolint:errcheck
					}
					continue
				}
				perms, err := authz.RolePermissions(name)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%s\n", name) //nolint:errcheck
				for _, p := range perms {
					fmt.Fprintf(out, "  %s/%s\n", p[0], p[1]) //nolint:errcheck
				}
			}
			return nil
		},
```

to:

```go
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for _, name := range authz.BuiltInRoleNames() {
				// Legacy names remain in BuiltInRoleNames (IsValidRole still
				// recognizes them for display and upgrade translation), but
				// AssignRole now refuses to grant them: a legacy-named
				// role_assignments row grants zero data-plane access.
				// Printing them with a permission list here would repeat that
				// lie back to the operator.
				if authz.IsLegacyRole(name) {
					fmt.Fprintf(out, "%s (deprecated: no longer grantable, grants no access — use an Azure role instead)\n", name) //nolint:errcheck
					continue
				}
				if !model.IsAzureRole(name) {
					// Every name BuiltInRoleNames returns is either legacy or
					// an Azure role — see TestRolesCommand_EveryNameIsLegacyOrAzure.
					// Fail closed rather than silently dropping the name from
					// the output if that invariant is ever violated.
					return fmt.Errorf("internal error: role %q is neither a legacy nor an Azure built-in role", name)
				}
				fmt.Fprintf(out, "%s\n", name) //nolint:errcheck
				for _, action := range model.AzureRoleDataActions(name) {
					fmt.Fprintf(out, "  %s\n", action) //nolint:errcheck
				}
			}
			return nil
		},
```

Remove the now-unused `authz.RolePermissions` reference from this file only (it stays defined and used elsewhere — see Global Constraints). Check `goimports`/`go vet` don't flag any now-unused import in this file (none expected: `authz` and `model` both remain used).

- [ ] **Step 4: Run tests to verify everything still passes**

Run: `go build ./... && go vet ./... && go test ./cmd/vault-access/... -v`

Expected: PASS, including the pre-existing `TestRolesCommand_ListsBuiltInRoles` (output for every real role name is unchanged) and the new `TestRolesCommand_EveryNameIsLegacyOrAzure`.

- [ ] **Step 5: Commit**

```bash
git add cmd/vault-access/roles.go cmd/vault-access/roles_test.go
git commit -m "refactor(cmd/vault-access): remove unreachable branch in roles command"
```
