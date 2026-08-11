# Role Assignments — Data Access Administrator Wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the documented known limitation — role-assignment management is currently global-admin-only even though the handler was written to accept more — by migrating `createRoleAssignment`/`deleteRoleAssignment` to `CanManageRoleAssignments`, which additionally accepts a `Key Vault Data Access Administrator` role assignment scoped to the target vault.

**Architecture:** `api/role_assignments.go`'s two mutating handlers swap their `requireVaultManage(c, r, vaultID)` calls for `authorization.CanManageRoleAssignments(...)` (Plan 2, Task 3), passing `write=true` for create and `write=false` for delete. The old `requireVaultManage` function is deleted once both its call sites are migrated — this was its only use.

**Tech Stack:** Go, `net/http/httptest`, `github.com/stretchr/testify/mock`, `github.com/golang-jwt/jwt/v5`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` — read §1 and the "Known limitation" cross-reference in `docs/release-notes/v4.0.0-azure-rbac.md` before starting.
- Depends on: Plan `2026-08-11-01` (data model — `RoleKeyVaultDataAccessAdministrator`, `ActionRoleAssignmentsWrite`/`Delete`), Plan `2026-08-11-02` (`CanManageRoleAssignments`). Independent of Plans 3 and 4 — `/vaults/{name}/role-assignments/...` routes were already exempted from the global gate before this design (they are `RouteUnmanaged`, matched by the pre-existing `MapRouteToDataAction`-based exemption in `mapEndpointToPermission`, not the `/vaults` prefix branch Plan 3 changes), so this plan can be implemented and tested independently of Plan 3 landing.
- `go build ./...` and `go vet ./...` must pass after every task.

---

### Task 1: Migrate `createRoleAssignment`

**Files:**
- Modify: `api/role_assignments.go:63-119` (`createRoleAssignment`)
- Test: `api/role_assignments_test.go` (modify existing test, append new one)

**Interfaces:**
- Consumes: `callerIdentity(c *Context) (role string, principalID uuid.UUID, ok bool)` (defined in `api/vault.go` by Plan `2026-08-11-04`, Task 1 — same package, no import needed). **If Plan `2026-08-11-04` has not landed yet when this task runs, define `callerIdentity` locally in this file instead** (identical body, see Plan 4 Task 1 Step 3) and delete the duplicate once both plans have merged — do not block this plan on that one.
- Consumes: `authorization.CanManageRoleAssignments(ctx, accountRole string, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, write bool) bool` (Plan 2, Task 3).
- Produces: no change to `createRoleAssignment`'s external behavior for admins or existing access-policy grants — only adds the new Data Access Administrator path and removes the dead `requireVaultManage` indirection.

- [ ] **Step 1: Fix `mockRoleAssignmentService.HasDataAction` to be configurable**

In `api/role_assignments_test.go`, the existing mock (lines 49-51) hardcodes a return value and is not currently exercised by any test (`requireVaultManage` never calls `HasDataAction`). Replace:

```go
func (m *mockRoleAssignmentService) HasDataAction(_ context.Context, _, _ uuid.UUID, _ model.DataAction) (bool, error) {
	return false, nil
}
```

with:

```go
func (m *mockRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	args := m.Called(ctx, principalID, vaultID, action)
	return args.Bool(0), args.Error(1)
}
```

This is safe: no existing test calls `HasDataAction` on this mock without now registering an `.On(...)` expectation first (none did before either — the old body was dead code for every test that used this mock).

- [ ] **Step 2: Write the failing test**

Append to `api/role_assignments_test.go`:

```go
// TestRoleAssignments_GrantAllowedForDataAccessAdministrator proves a
// non-admin holding Key Vault Data Access Administrator in the target vault
// can create a role assignment there — the fix for the documented known
// limitation (role-assignment management was global-admin-only).
func TestRoleAssignments_GrantAllowedForDataAccessAdministrator(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsWrite).
		Return(true, nil)
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).
		Return(&model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: "Key Vault Secrets User"}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: jwt.MapClaims{"user_id": callerID.String(), "role": "user"},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
	body := []byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	w := httptest.NewRecorder()

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestRoleAssignments_GrantDeniedForDataAccessAdministratorInWrongVault
// proves the grant is scoped: holding Key Vault Data Access Administrator in
// vault A does not authorize creating a role assignment in vault B.
func TestRoleAssignments_GrantDeniedForDataAccessAdministratorInWrongVault(t *testing.T) {
	grantedVault := uuid.New()
	targetVault := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, targetVault, model.ActionRoleAssignmentsWrite).
		Return(false, nil)
	_ = grantedVault // the grant (not registered on roleSvc at all) is scoped elsewhere; omitted here since HasDataAction is queried only against targetVault

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: jwt.MapClaims{"user_id": callerID.String(), "role": "user"},
		Params: &ApiParams{VaultName: "other", PerPage: 60},
	}
	body := []byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/other/role-assignments", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, targetVault.String()))
	w := httptest.NewRecorder()

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}
```

Add `"rocketvault/common"` to the import block of `api/role_assignments_test.go` (currently: `"bytes"`, `"context"`, `"encoding/json"`, `"net/http"`, `"net/http/httptest"`, `"testing"`, jwt, uuid, assert, mock, `"rocketvault/app"`, authzServices, `"rocketvault/internal/testutils"`, `"rocketvault/model"`).

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./api/... -run TestRoleAssignments_GrantAllowedForDataAccessAdministrator -v`
Expected: FAIL — `createRoleAssignment` still calls the old `requireVaultManage`, which never consults `RoleAssignmentService.HasDataAction` at all, so a `user`-role caller with only the access-policy fallback (`AccessFallback`) is denied regardless of the `HasDataAction` mock (got 403, want 201).

- [ ] **Step 4: Migrate `createRoleAssignment`**

In `api/role_assignments.go`, replace (currently lines 65-119):

```go
// createRoleAssignment grants a built-in role to a principal within a vault.
// POST /vaults/{vault_name}/role-assignments
func createRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	if !requireVaultManage(c, r, vaultID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	req, err := model.AssignRoleRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Principal == "" || req.Role == "" {
		c.SetInvalidParam("principal and role are required")
		return
	}
	pType := model.PrincipalType(req.PrincipalType)
	if pType == "" {
		pType = model.PrincipalTypeUser
	}

	callerIDStr, _ := c.Claims["user_id"].(string)
	callerID, _ := uuid.Parse(callerIDStr)

	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	ra, err := svc.AssignRole(r.Context(), authzServices.AssignRoleInput{
		Principal:     req.Principal,
		PrincipalType: pType,
		Role:          req.Role,
		VaultID:       vaultID,
		CreatedBy:     callerID,
	})
```

with:

```go
// createRoleAssignment grants a built-in role to a principal within a vault.
// POST /vaults/{vault_name}/role-assignments
func createRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	role, callerID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageRoleAssignments(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(),
		c.App.ServiceContainer.GetRoleAssignmentService(), callerID, vaultID, true) {
		c.SetPermissionError("admin, vaults/manage, or Key Vault Data Access Administrator required")
		return
	}

	req, err := model.AssignRoleRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Principal == "" || req.Role == "" {
		c.SetInvalidParam("principal and role are required")
		return
	}
	pType := model.PrincipalType(req.PrincipalType)
	if pType == "" {
		pType = model.PrincipalTypeUser
	}

	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	ra, err := svc.AssignRole(r.Context(), authzServices.AssignRoleInput{
		Principal:     req.Principal,
		PrincipalType: pType,
		Role:          req.Role,
		VaultID:       vaultID,
		CreatedBy:     callerID,
	})
```

Note `requireVaultManage` is not deleted yet — `deleteRoleAssignment` still calls it (Task 2 migrates that one).

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./api/... -run 'TestRoleAssignments' -v`
Expected: PASS, including the pre-existing `TestRoleAssignments_GrantRequiresAdmin` (still denied — `policyContainer.GetRoleAssignmentService()` returns `nil`, and `CanManageRoleAssignments` fails closed on a nil `roles` argument) and `TestListRoleAssignments_ReturnsEnrichedResponse` (untouched — `listRoleAssignments` has no authorization gate to begin with).

- [ ] **Step 6: Commit**

```bash
git add api/role_assignments.go api/role_assignments_test.go
git commit -m "feat(api): allow Key Vault Data Access Administrator to grant role assignments"
```

---

### Task 2: Migrate `deleteRoleAssignment`, remove `requireVaultManage`

**Files:**
- Modify: `api/role_assignments.go:44-61` (delete `requireVaultManage`), `:180-211` (`deleteRoleAssignment`), imports
- Test: `api/role_assignments_test.go` (append)

**Interfaces:**
- Consumes: same as Task 1.
- Produces: `requireVaultManage` no longer exists anywhere in the codebase.

- [ ] **Step 1: Write the failing test**

Append to `api/role_assignments_test.go`:

```go
// TestRoleAssignments_RevokeAllowedForDataAccessAdministrator mirrors the
// grant test for the delete path, and proves write/delete are checked as
// distinct actions (a principal could in principle hold write without
// delete, or vice versa, though the built-in role grants both).
func TestRoleAssignments_RevokeAllowedForDataAccessAdministrator(t *testing.T) {
	vaultID := uuid.New()
	assignmentID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).
		Return(true, nil)
	roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID).Return(nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: jwt.MapClaims{"user_id": callerID.String(), "role": "user"},
		Params: &ApiParams{VaultName: "prod", AssignmentID: assignmentID.String(), PerPage: 60},
	}
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/role-assignments/"+assignmentID.String(), nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	w := httptest.NewRecorder()

	deleteRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}
```

`ApiParams` must have an `AssignmentID` field — confirm via `grep -n "AssignmentID" api/context.go api/params*.go` before writing this; it is already read by `getRoleAssignment`/`deleteRoleAssignment` today (`c.Params.AssignmentID`, `api/role_assignments.go:159`, `:196`), so the field exists.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestRoleAssignments_RevokeAllowedForDataAccessAdministrator -v`
Expected: FAIL — same reason as Task 1's test (old `requireVaultManage` doesn't check `HasDataAction`).

- [ ] **Step 3: Migrate `deleteRoleAssignment` and delete `requireVaultManage`**

In `api/role_assignments.go`, replace (currently lines 180-211):

```go
// deleteRoleAssignment revokes a role assignment within a vault.
// DELETE /vaults/{vault_name}/role-assignments/{assignment_id}
func deleteRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	if !requireVaultManage(c, r, vaultID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
	id, err := uuid.Parse(c.Params.AssignmentID)
```

with:

```go
// deleteRoleAssignment revokes a role assignment within a vault.
// DELETE /vaults/{vault_name}/role-assignments/{assignment_id}
func deleteRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	role, callerID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageRoleAssignments(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(),
		c.App.ServiceContainer.GetRoleAssignmentService(), callerID, vaultID, false) {
		c.SetPermissionError("admin, vaults/manage, or Key Vault Data Access Administrator required")
		return
	}
	id, err := uuid.Parse(c.Params.AssignmentID)
```

Then delete the now-unused `requireVaultManage` function entirely (currently lines 44-61):

```go
// requireVaultManage gates assignment management to global admins or vault managers.
func requireVaultManage(c *Context, r *http.Request, vaultID uuid.UUID) bool {
	role, _ := c.Claims["role"].(string)
	if common.HasRequiredRole(role, string(model.RoleAdmin)) {
		return true
	}
	userIDStr, _ := c.Claims["user_id"].(string)
	pid, err := uuid.Parse(userIDStr)
	if err != nil {
		return false
	}
	dec, err := c.App.ServiceContainer.GetAccessPolicyService().
		CheckAccess(r.Context(), pid, model.PolicyResourceVaults, model.OpManage, vaultID)
	if err != nil {
		return false
	}
	return dec == authzServices.AccessAllowed
}

```

Remove this block entirely. Then remove `"rocketvault/common"` from `api/role_assignments.go`'s import block — it was only used inside `requireVaultManage`, and nothing else in the file calls `common.*`. Confirm with:

```bash
grep -n "common\." api/role_assignments.go
```

Expected: no output after the deletion (if there is output, do not remove the import — something else still needs it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./api/... -v`
Expected: PASS across the entire package, zero regressions.

Run: `grep -rn "requireVaultManage" --include="*.go" .`
Expected: no output — confirms the function is fully removed, not just unused.

- [ ] **Step 5: Commit**

```bash
git add api/role_assignments.go api/role_assignments_test.go
git commit -m "feat(api): allow Key Vault Data Access Administrator to revoke role assignments; remove requireVaultManage"
```

---

### Task 3: End-to-end regression — Data Access Administrator is vault-scoped

**Files:**
- Test: `api/role_assignments_test.go` (append)

**Interfaces:**
- Consumes: everything from Tasks 1-2. No production code changes in this task — pure regression coverage proving Tasks 1-2 compose correctly across both handlers and across vaults in one place.

- [ ] **Step 1: Write the test**

Append to `api/role_assignments_test.go`:

```go
// TestRoleAssignments_DataAccessAdministrator_GrantAndRevokeComposeAcrossVaults
// is the closing regression for the known limitation this plan fixes: a
// single principal holding Key Vault Data Access Administrator in vault A
// can both grant AND revoke assignments in vault A, using the same mocked
// grant, and is denied both operations in vault B.
func TestRoleAssignments_DataAccessAdministrator_GrantAndRevokeComposeAcrossVaults(t *testing.T) {
	vaultA := uuid.New()
	vaultB := uuid.New()
	assignmentID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultA, model.ActionRoleAssignmentsWrite).Return(true, nil)
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultA, model.ActionRoleAssignmentsDelete).Return(true, nil)
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultB, model.ActionRoleAssignmentsWrite).Return(false, nil)
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultB, model.ActionRoleAssignmentsDelete).Return(false, nil)
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).
		Return(&model.RoleAssignment{ID: uuid.New(), VaultID: vaultA, Role: "Key Vault Secrets User"}, nil)
	roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultA).Return(nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	newCtx := func(vaultName string) *Context {
		return &Context{
			App:    &app.App{ServiceContainer: mc},
			Claims: jwt.MapClaims{"user_id": callerID.String(), "role": "user"},
			Params: &ApiParams{VaultName: vaultName, AssignmentID: assignmentID.String(), PerPage: 60},
		}
	}

	// Grant in A: allowed.
	cGrantA := newCtx("a")
	rGrantA := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/a/role-assignments", bytes.NewReader([]byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)))
	rGrantA = rGrantA.WithContext(context.WithValue(rGrantA.Context(), common.VaultIDKey, vaultA.String()))
	wGrantA := httptest.NewRecorder()
	createRoleAssignment(cGrantA, wGrantA, rGrantA)
	if cGrantA.Err != nil {
		writeError(wGrantA, cGrantA)
	}
	assert.Equal(t, http.StatusCreated, wGrantA.Code, "grant in own vault must succeed")

	// Revoke in A: allowed.
	cRevokeA := newCtx("a")
	rRevokeA := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/a/role-assignments/"+assignmentID.String(), nil)
	rRevokeA = rRevokeA.WithContext(context.WithValue(rRevokeA.Context(), common.VaultIDKey, vaultA.String()))
	wRevokeA := httptest.NewRecorder()
	deleteRoleAssignment(cRevokeA, wRevokeA, rRevokeA)
	if cRevokeA.Err != nil {
		writeError(wRevokeA, cRevokeA)
	}
	assert.Equal(t, http.StatusOK, wRevokeA.Code, "revoke in own vault must succeed")

	// Grant in B: denied.
	cGrantB := newCtx("b")
	rGrantB := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/b/role-assignments", bytes.NewReader([]byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)))
	rGrantB = rGrantB.WithContext(context.WithValue(rGrantB.Context(), common.VaultIDKey, vaultB.String()))
	wGrantB := httptest.NewRecorder()
	createRoleAssignment(cGrantB, wGrantB, rGrantB)
	if cGrantB.Err != nil {
		writeError(wGrantB, cGrantB)
	}
	assert.Equal(t, http.StatusForbidden, wGrantB.Code, "grant in a different vault must be denied")

	// Revoke in B: denied.
	cRevokeB := newCtx("b")
	rRevokeB := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/b/role-assignments/"+assignmentID.String(), nil)
	rRevokeB = rRevokeB.WithContext(context.WithValue(rRevokeB.Context(), common.VaultIDKey, vaultB.String()))
	wRevokeB := httptest.NewRecorder()
	deleteRoleAssignment(cRevokeB, wRevokeB, rRevokeB)
	if cRevokeB.Err != nil {
		writeError(wRevokeB, cRevokeB)
	}
	assert.Equal(t, http.StatusForbidden, wRevokeB.Code, "revoke in a different vault must be denied")
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `go test ./api/... -run TestRoleAssignments_DataAccessAdministrator_GrantAndRevokeComposeAcrossVaults -v`
Expected: PASS. If it fails, do not adjust the test to match broken behavior — Tasks 1-2 must be re-examined; this test composes nothing new, it only exercises what they already built.

- [ ] **Step 3: Run the full package**

Run: `go test ./api/... ./internal/services/authorization/... -v`
Expected: PASS, zero regressions.

- [ ] **Step 4: Commit**

```bash
git add api/role_assignments_test.go
git commit -m "test(api): pin Data Access Administrator as vault-scoped across grant and revoke"
```

---

## Verification Gate (run before considering this plan complete)

```bash
go build ./...
go vet ./...
go test ./api/... ./internal/services/authorization/... -v
grep -rn "requireVaultManage" --include="*.go" .
```

All must pass; the `grep` must produce no output. Manually verify against a running server once Plan `2026-08-11-06` (CLI) also lands, or directly via HTTP:

```bash
curl -X POST $BASE/api/v1/vaults/prod/role-assignments \
  -H "Authorization: Bearer $NON_ADMIN_TOKEN_WITH_DAA_ROLE" \
  -d '{"principal":"alice","role":"Key Vault Secrets User"}'
# Expected: 201, if the caller holds Key Vault Data Access Administrator in "prod".
```
