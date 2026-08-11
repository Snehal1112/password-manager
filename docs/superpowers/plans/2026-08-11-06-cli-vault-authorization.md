# CLI Vault Authorization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the pre-existing CLI authorization gap — `rocketvault vaults {create,update,delete,recover,purge}` currently call the service layer directly with zero authorization check, so any authenticated user of any role can delete or purge any vault today.

**Architecture:** A new `cmd/vaults/authz.go` provides `callerIdentity` (reads the CLI's already-authenticated claims), `resolveTargetVaultID` (finds a vault's ID by name, active or soft-deleted, via `VaultService.ListVaults`), and three thin wrappers around Plan 2's shared functions: `requireCanCreateVault`, `requireCanManageVault`, `requireCanPurgeVault`. Each of the five commands calls the matching wrapper before touching the service layer.

**Tech Stack:** Go, Cobra, `github.com/stretchr/testify/mock`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` — read §7 before starting.
- Depends on: Plan `2026-08-11-01` (data model), Plan `2026-08-11-02` (`CanManageVault`, `CanPurgeVault`). Independent of Plans 3-5.
- `cmd/vaults/get.go` and `cmd/vaults/list.go` are **not** touched by this plan — the design scoped the CLI fix to the five mutating commands only (create/update/delete/recover/purge), matching what the HTTP layer gates.
- `resolveTargetVaultID` uses `VaultService.ListVaults(ctx, true)` (the only existing method that can find a vault by name whether active or soft-deleted) — do not add a new `VaultService` method; that would be outside this design's approved component list.
- Every CLI command in this plan calls `sc.GetAccessPolicyService()` and/or `sc.GetRoleAssignmentService()` unconditionally, as arguments to the shared `Can*` functions, even when the caller turns out to be admin (Go evaluates arguments before the call) — the `cmd/testutils.MockServiceContainer`'s existing `GetAccessPolicyService`/`GetRoleAssignmentService` implementations return `nil` unconditionally, which is safe only because `Can*` fails closed on a `nil` dependency for non-admins and short-circuits before touching it for admins. Task 1 below makes both configurable (mirroring the existing `VaultService` field) so non-admin-grant tests are possible at all.
- `go build ./...` and `go vet ./...` must pass after every task.

---

### Task 1: Shared `cmd/vaults/authz.go`; wire `create` and `update`

**Files:**
- Create: `cmd/vaults/authz.go`
- Modify: `cmd/vaults/create.go` (add check)
- Modify: `cmd/vaults/update.go` (add check; fix the stale `uuid.Nil` `updatedBy`)
- Modify: `cmd/testutils/test_utils.go:116-198` (make `GetAccessPolicyService`/`GetRoleAssignmentService` configurable)
- Modify: `cmd/vaults/vaults_test.go` (update `TestVaultsUpdate`; append new tests)
- Modify: `cmd/vaults/vaults_more_test.go` (update `TestVaultsUpdate_ServiceError`, `TestVaultsUpdate_NoFormatter`, `TestVaultsUpdate_WithPurgeAndRetention`)

**Interfaces:**
- Consumes: `authorization.CanManageVault` (Plan 2, Task 1); `common.ClaimsKey` (existing, `common/context.go:20`); `model.Claims{UserID uuid.UUID, Role string}` (existing, `model/user.go:23-28`); `vaultServices.VaultService.ListVaults(ctx, includeDeleted bool) ([]model.Vault, error)` (existing); `vaultServices.ErrVaultNotFound` (existing).
- Produces: `func callerIdentity(ctx context.Context) (role string, principalID uuid.UUID, err error)`, `func resolveTargetVaultID(ctx context.Context, svc vaultServices.VaultService, name string) (uuid.UUID, error)`, `func requireCanCreateVault(ctx context.Context, sc container.ServiceContainerInterface) error`, `func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) error` — all in `cmd/vaults` package, reused by every task in this plan.

- [ ] **Step 1: Make the test container's policy/role-assignment services configurable**

In `cmd/testutils/test_utils.go`, add two fields to `MockServiceContainer` (currently lines 116-121):

```go
// Mock Service Container implements ServiceContainerInterface for testing
type MockServiceContainer struct {
	mock.Mock
	// VaultService is returned by GetVaultService. It defaults to a MockVaultService
	// that resolves the "default" vault so vault-aware resource commands work in tests.
	VaultService vaultServices.VaultService
	// AccessPolicyService is returned by GetAccessPolicyService, nil by default.
	AccessPolicyService authzServices.AccessPolicyService
	// RoleAssignmentService is returned by GetRoleAssignmentService, nil by default.
	RoleAssignmentService authzServices.RoleAssignmentService
}
```

Then replace (currently lines 192-198):

```go
func (m *MockServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return nil
}

func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
```

with:

```go
func (m *MockServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return m.AccessPolicyService
}

func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return m.RoleAssignmentService
}
```

This is backward compatible: every existing test that never sets these fields continues to get `nil`, exactly as before.

- [ ] **Step 2: Write the failing tests**

Append to `cmd/vaults/vaults_test.go`:

```go
// TestVaultsCreate_ForbiddenWithoutGlobalGrant proves a non-admin with no
// global vaults:manage policy cannot create a vault via the CLI.
func TestVaultsCreate_ForbiddenWithoutGlobalGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser})

	policySvc := &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockContainer.AccessPolicyService = policySvc

	cmd := &cobra.Command{Use: "create", Args: createCmd.Args, RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))
	cmd.SetArgs([]string{"newvault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "CreateVault", mock.Anything, mock.Anything, mock.Anything)
}
```

This requires a small local test double, `mockAccessPolicyService`, since `cmd/vaults` package tests have no existing one (unlike `api`, which has `mockAccessPolicyService` in `api/access_policies_test.go` — a different package, not importable here). Add it to `cmd/vaults/vaults_test.go`:

```go
// mockAccessPolicyService is a minimal test double for authzServices.AccessPolicyService.
type mockAccessPolicyService struct {
	decision authzServices.AccessDecision
}

func (m *mockAccessPolicyService) CheckAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (authzServices.AccessDecision, error) {
	return m.decision, nil
}
func (m *mockAccessPolicyService) CreatePolicy(context.Context, *model.AccessPolicy) error { return nil }
func (m *mockAccessPolicyService) GetPolicy(context.Context, uuid.UUID) (*model.AccessPolicy, error) {
	return nil, nil
}
func (m *mockAccessPolicyService) ListPolicies(context.Context) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (m *mockAccessPolicyService) ListByPrincipal(context.Context, uuid.UUID) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (m *mockAccessPolicyService) UpdatePolicy(context.Context, *model.AccessPolicy) error { return nil }
func (m *mockAccessPolicyService) DeletePolicy(context.Context, uuid.UUID) error           { return nil }
```

Add `authzServices "rocketvault/internal/services/authorization"` to `cmd/vaults/vaults_test.go`'s import block.

Also update `TestVaultsUpdate` (currently lines 141-165) to account for the new `ListVaults` resolution call and the real `updatedBy`. Replace:

```go
func TestVaultsUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)

	updated := &model.Vault{ID: uuid.New(), Name: "my-vault", Enabled: false, RetentionDays: 90}
	tc.MockVaultService.On("UpdateVault", mock.Anything, "my-vault", mock.MatchedBy(func(r model.UpdateVaultRequest) bool {
		return r.Enabled != nil && !*r.Enabled
	}), uuid.Nil).Return(updated, nil)
```

with:

```go
func TestVaultsUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	updated := &model.Vault{ID: uuid.New(), Name: "my-vault", Enabled: false, RetentionDays: 90}
	tc.MockVaultService.On("UpdateVault", mock.Anything, "my-vault", mock.MatchedBy(func(r model.UpdateVaultRequest) bool {
		return r.Enabled != nil && !*r.Enabled
	}), tc.TestUserID).Return(updated, nil)
```

(The rest of `TestVaultsUpdate` is unchanged — `testClaims.Role` defaults to `model.RoleAdmin`, so `requireCanManageVault` short-circuits and this test's admin behavior is otherwise identical.)

In `cmd/vaults/vaults_more_test.go`, apply the equivalent two changes to each of the three remaining update tests:

`TestVaultsUpdate_ServiceError` (currently lines 315-330): add before the existing `UpdateVault` mock —

```go
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "error-vault"}}, nil)
```

and change `uuid.Nil` to `tc.TestUserID` in the existing `UpdateVault` `.On(...)` call.

`TestVaultsUpdate_NoFormatter` (currently lines 332-349): same two changes, vault name `"nofmt-vault"`.

`TestVaultsUpdate_WithPurgeAndRetention` (currently lines 351-381): same two changes, vault name `"full-update-vault"`.

- [ ] **Step 3: Run tests to verify the new one fails and the modified ones fail too (before implementation)**

Run: `go test ./cmd/vaults/... -run 'TestVaultsCreate_ForbiddenWithoutGlobalGrant|TestVaultsUpdate' -v`
Expected: `TestVaultsCreate_ForbiddenWithoutGlobalGrant` FAILs (create currently has no check, so it succeeds — got nil error, want a permission-denied error). The `TestVaultsUpdate*` tests FAIL with a testify panic ("mock: I don't know what to return because the method call was unexpected: ListVaults") — this is expected: the tests were changed to expect a call that doesn't exist in production code yet.

- [ ] **Step 4: Write `cmd/vaults/authz.go`**

Create `cmd/vaults/authz.go`:

```go
// Package vaults — authz.go provides shared authorization checks for the CLI
// vault-management commands (create/update/delete/recover/purge), closing a
// pre-existing gap: these commands previously called the service layer
// directly with no authorization check at all. See
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md
// §7.
package vaults

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// callerIdentity extracts the acting principal's account role and user ID
// from the CLI's authenticated context, populated by persistentPreRun in
// cmd/root.go. Returns an error if claims are missing — a command reaching
// this far without prior authentication indicates a wiring bug, not a
// permission denial.
func callerIdentity(ctx context.Context) (role string, principalID uuid.UUID, err error) {
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return "", uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	return claims.Role, claims.UserID, nil
}

// resolveTargetVaultID finds the ID of the vault named name, whether active
// or soft-deleted. VaultService.GetVault only returns active vaults, and
// recover/purge commonly target a soft-deleted one, so ListVaults(true) is
// used uniformly by every command in this file.
func resolveTargetVaultID(ctx context.Context, svc vaultServices.VaultService, name string) (uuid.UUID, error) {
	vaults, err := svc.ListVaults(ctx, true)
	if err != nil {
		return uuid.Nil, err
	}
	for _, v := range vaults {
		if v.Name == name {
			return v.ID, nil
		}
	}
	return uuid.Nil, vaultServices.ErrVaultNotFound
}

// requireCanCreateVault checks CanManageVault against a global (not
// vault-specific) grant, since there is no target vault to resolve yet when
// creating one — mirrors the HTTP createVault handler's use of uuid.Nil.
func requireCanCreateVault(ctx context.Context, sc container.ServiceContainerInterface) error {
	role, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageVault(ctx, role, sc.GetAccessPolicyService(), principalID, uuid.Nil) {
		return fmt.Errorf("permission denied: admin or a global vaults/manage grant required to create a vault")
	}
	return nil
}

// requireCanManageVault resolves vaultName to an ID and checks CanManageVault
// against it.
func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) error {
	role, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanManageVault(ctx, role, sc.GetAccessPolicyService(), principalID, vaultID) {
		return fmt.Errorf("permission denied: admin or vaults/manage required for vault %q", vaultName)
	}
	return nil
}

// requireCanPurgeVault resolves vaultName to an ID and checks CanPurgeVault
// against it.
func requireCanPurgeVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) error {
	role, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanPurgeVault(ctx, role, sc.GetRoleAssignmentService(), principalID, vaultID) {
		return fmt.Errorf("permission denied: admin or Key Vault Purge Operator required for vault %q", vaultName)
	}
	return nil
}
```

- [ ] **Step 5: Wire `create.go`**

In `cmd/vaults/create.go`, insert the check immediately after `serviceContainer` is resolved (currently lines 43-47):

```go
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		vaultService := serviceContainer.GetVaultService()
```

becomes:

```go
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if err := requireCanCreateVault(ctx, serviceContainer); err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()
```

- [ ] **Step 6: Wire `update.go`, fix the stale `updatedBy`**

In `cmd/vaults/update.go`, replace (currently lines 33-55):

```go
		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		vaultService := serviceContainer.GetVaultService()

		var req model.UpdateVaultRequest
		if cmd.Flags().Changed("enabled") {
			en, _ := cmd.Flags().GetBool("enabled")
			req.Enabled = &en
		}
		if cmd.Flags().Changed("purge-protection") {
			pp, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &pp
		}
		if cmd.Flags().Changed("retention-days") {
			rd, _ := cmd.Flags().GetInt("retention-days")
			req.RetentionDays = &rd
		}

		// The CLI has no authenticated user context, so updated_by is left unset.
		vault, err := vaultService.UpdateVault(ctx, name, req, uuid.Nil)
```

with:

```go
		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if err := requireCanManageVault(ctx, serviceContainer, name); err != nil {
			return err
		}
		_, callerID, err := callerIdentity(ctx)
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		var req model.UpdateVaultRequest
		if cmd.Flags().Changed("enabled") {
			en, _ := cmd.Flags().GetBool("enabled")
			req.Enabled = &en
		}
		if cmd.Flags().Changed("purge-protection") {
			pp, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &pp
		}
		if cmd.Flags().Changed("retention-days") {
			rd, _ := cmd.Flags().GetInt("retention-days")
			req.RetentionDays = &rd
		}

		vault, err := vaultService.UpdateVault(ctx, name, req, callerID)
```

The `"github.com/google/uuid"` import in `cmd/vaults/update.go` becomes unused after this change (it was only used for `uuid.Nil`) — remove it from the import block. Confirm with `go build ./cmd/vaults/...` after this step; it will fail with "imported and not used" if left in.

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./cmd/vaults/... -v`
Expected: PASS across the entire package. In particular: `TestVaultsCreate_ForbiddenWithoutGlobalGrant` (new), `TestVaultsCreate`/`TestVaultsCreateRequiresName` (unaffected — admin role), `TestVaultsUpdate`, `TestVaultsUpdate_ServiceError`, `TestVaultsUpdate_NoFormatter`, `TestVaultsUpdate_WithPurgeAndRetention` (all updated), `TestVaultsGet`/`TestVaultsList` (untouched, not in scope).

- [ ] **Step 8: Commit**

```bash
git add cmd/vaults/authz.go cmd/vaults/create.go cmd/vaults/update.go cmd/testutils/test_utils.go cmd/vaults/vaults_test.go cmd/vaults/vaults_more_test.go
git commit -m "fix(cmd): require authorization checks on vaults create and update"
```

---

### Task 2: Wire `delete` and `recover`

**Files:**
- Modify: `cmd/vaults/delete.go`, `cmd/vaults/recover.go`
- Modify: `cmd/vaults/vaults_test.go` (update `TestVaultsDelete`)
- Modify: `cmd/vaults/vaults_more_test.go` (update `TestVaultsDelete_ServiceError`, `TestRecoverCmd_Success`, `TestRecoverCmd_ServiceError`; append new denial tests)

**Interfaces:**
- Consumes: `requireCanManageVault` (Task 1).

- [ ] **Step 1: Write the failing tests**

Append to `cmd/vaults/vaults_more_test.go`:

```go

// TestVaultsDelete_ForbiddenWithoutGrant proves a non-admin with no
// vaults:manage policy on the target vault cannot delete it via the CLI.
func TestVaultsDelete_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(nonAdminCtx)
	cmd.SetArgs([]string{"guarded-vault"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "DeleteVault", mock.Anything, mock.Anything)
}

// TestVaultsRecover_ForbiddenWithoutGrant mirrors the delete case for recover.
func TestVaultsRecover_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd := &cobra.Command{Use: "recover", Args: cobra.ExactArgs(1), RunE: recoverCmd.RunE}
	cmd.SetContext(nonAdminCtx)
	cmd.SetArgs([]string{"guarded-vault"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "RecoverVault", mock.Anything, mock.Anything)
}
```

`"context"` and `"rocketvault/common"` must be added to `cmd/vaults/vaults_more_test.go`'s import block if not already present (it currently imports `"bytes"`, `"fmt"`, `"os"`, `"testing"`, uuid, cobra, assert, mock, require, `"rocketvault/cmd/testutils"`, `"rocketvault/model"` — add `"context"` and `"rocketvault/common"`, and `authzServices "rocketvault/internal/services/authorization"`).

Also update the three existing tests that will now break once `resolveTargetVaultID` is wired in. In `cmd/vaults/vaults_test.go`, `TestVaultsDelete` (currently lines 122-139), insert before the existing `DeleteVault` mock:

```go
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
```

In `cmd/vaults/vaults_more_test.go`, `TestVaultsDelete_ServiceError` (currently lines 299-311): insert before the existing `DeleteVault` mock:

```go
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "locked-vault"}}, nil)
```

`TestRecoverCmd_Success` (currently lines 76-88): insert before the existing `RecoverVault` mock:

```go
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
```

`TestRecoverCmd_ServiceError` (currently lines 90-101): insert before the existing `RecoverVault` mock:

```go
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "broken-vault"}}, nil)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/vaults/... -v`
Expected: the two new `*_ForbiddenWithoutGrant` tests FAIL (no check exists yet — commands succeed instead of erroring); the four modified existing tests FAIL with a testify panic (unexpected `ListVaults` call registered but not yet made by production code — actually the reverse: since production code doesn't call `ListVaults` yet, the registered `.On(...)` simply goes unused, which does NOT panic by itself; the tests should still PASS at this point for the modified-but-not-yet-wired commands). Confirm this nuance by running before Step 3: the delete/recover tests pass (mock addition is inert until the command calls it), only the two brand-new denial tests fail.

- [ ] **Step 3: Wire `delete.go` and `recover.go`**

In `cmd/vaults/delete.go`, replace (currently lines 20-33):

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.DeleteVault(ctx, name); err != nil {
```

with:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if err := requireCanManageVault(ctx, serviceContainer, name); err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.DeleteVault(ctx, name); err != nil {
```

In `cmd/vaults/recover.go`, replace (currently lines 20-31):

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.RecoverVault(ctx, name); err != nil {
```

with:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if err := requireCanManageVault(ctx, serviceContainer, name); err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.RecoverVault(ctx, name); err != nil {
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/vaults/... -v`
Expected: PASS across the entire package.

- [ ] **Step 5: Commit**

```bash
git add cmd/vaults/delete.go cmd/vaults/recover.go cmd/vaults/vaults_test.go cmd/vaults/vaults_more_test.go
git commit -m "fix(cmd): require authorization checks on vaults delete and recover"
```

---

### Task 3: Wire `purge`

**Files:**
- Modify: `cmd/vaults/purge.go`
- Modify: `cmd/vaults/vaults_more_test.go` (update `TestPurgeCmd_Success`, `TestPurgeCmd_ServiceError`; append new tests)

**Interfaces:**
- Consumes: `requireCanPurgeVault` (Task 1); `authorization.RoleAssignmentService` (existing interface) for the positive-grant test.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/vaults/vaults_more_test.go`:

```go

// stubRoleAssignmentService is a minimal RoleAssignmentService test double
// whose HasDataAction result is fixed at construction — enough to prove
// CanPurgeVault's positive path from the CLI without a full mock.
type stubRoleAssignmentService struct {
	allowed bool
}

func (s *stubRoleAssignmentService) AssignRole(context.Context, authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	return nil, fmt.Errorf("not implemented in stub")
}
func (s *stubRoleAssignmentService) RevokeAssignment(context.Context, uuid.UUID, uuid.UUID) error {
	return fmt.Errorf("not implemented in stub")
}
func (s *stubRoleAssignmentService) ListAssignments(context.Context, uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, fmt.Errorf("not implemented in stub")
}
func (s *stubRoleAssignmentService) HasDataAction(context.Context, uuid.UUID, uuid.UUID, model.DataAction) (bool, error) {
	return s.allowed, nil
}

// TestVaultsPurge_ForbiddenWithoutGrant proves a non-admin with no Purge
// Operator role assignment cannot purge a vault via the CLI. This is the
// concrete regression for the pre-existing gap: before this task, purge had
// no authorization check of any kind.
func TestVaultsPurge_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser})
	tc.MockContainer.RoleAssignmentService = &stubRoleAssignmentService{allowed: false}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd, _ := newVltCmd(purgeCmd.RunE, []string{"guarded-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(nonAdminCtx)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "PurgeVault", mock.Anything, mock.Anything)
}

// TestVaultsPurge_AllowedWithPurgeOperatorGrant proves a non-admin holding
// Key Vault Purge Operator in the target vault CAN purge it via the CLI.
func TestVaultsPurge_AllowedWithPurgeOperatorGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser})
	tc.MockContainer.RoleAssignmentService = &stubRoleAssignmentService{allowed: true}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	tc.MockVaultService.On("PurgeVault", mock.Anything, "my-vault").Return(nil)

	cmd, buf := newVltCmd(purgeCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(nonAdminCtx)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "purged successfully")
	tc.MockVaultService.AssertExpectations(t)
}
```

Also update the two existing purge tests to account for the new `ListVaults` resolution call. `TestPurgeCmd_Success` (currently lines 46-58): insert before the existing `PurgeVault` mock:

```go
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
```

`TestPurgeCmd_ServiceError` (currently lines 60-72): insert before the existing `PurgeVault` mock:

```go
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/vaults/... -run 'TestVaultsPurge|TestPurgeCmd' -v`
Expected: `TestVaultsPurge_ForbiddenWithoutGrant` and `TestVaultsPurge_AllowedWithPurgeOperatorGrant` FAIL (`purgeCmd` has no check yet — the forbidden case succeeds when it should error, and the allowed case never calls `ListVaults`/the check path at all, though it may coincidentally pass since `PurgeVault` is still called directly). `TestPurgeCmd_Success`/`TestPurgeCmd_ServiceError` continue to PASS (same reasoning as Task 2 Step 2 — an unused mock registration is inert).

- [ ] **Step 3: Wire `purge.go`**

In `cmd/vaults/purge.go`, replace (currently lines 20-33):

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.PurgeVault(ctx, name); err != nil {
```

with:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if err := requireCanPurgeVault(ctx, serviceContainer, name); err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.PurgeVault(ctx, name); err != nil {
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/vaults/... -v`
Expected: PASS across the entire package — every test in `cmd/vaults`, old and new.

- [ ] **Step 5: Commit**

```bash
git add cmd/vaults/purge.go cmd/vaults/vaults_more_test.go
git commit -m "fix(cmd): require Key Vault Purge Operator or admin on vaults purge"
```

---

## Verification Gate (run before considering this plan complete)

```bash
go build ./...
go vet ./...
go test ./cmd/... -v
```

All must pass. Manually verify against a running server (bootstrap an admin, create a non-admin user, attempt each of the five commands without and then with the right grant):

```bash
go run main.go vaults create tmp --username admin --password admin123 --totp-code <code>
go run main.go vaults purge tmp --username alice --password ... --totp-code <code>
# Expected: "permission denied: admin or Key Vault Purge Operator required for vault \"tmp\""
```
