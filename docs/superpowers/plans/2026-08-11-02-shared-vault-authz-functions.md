# Shared Vault-Authorization Functions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three shared, parameterized authorization functions (`CanManageVault`, `CanPurgeVault`, `CanManageRoleAssignments`) that both the HTTP API and the CLI will call, replacing the single-purpose, `api`-package-private `requireVaultManage`.

**Architecture:** New file `internal/services/authorization/vault_authz.go`, containing three pure functions that take `(ctx, accountRole string, <service dependency>, principalID, vaultID uuid.UUID, ...)` and return `bool`. Each: the global `admin` role short-circuits to `true`; otherwise the function consults the injected `AccessPolicyService` and/or `RoleAssignmentService` interface (both already defined in this package). No HTTP or CLI code changes yet — this plan produces a fully unit-tested, standalone authorization primitive that later plans wire in.

**Tech Stack:** Go, standard library `testing`, `github.com/google/uuid`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` — read §1 before starting.
- Depends on Plan `2026-08-11-01-azure-role-data-model.md` — `model.ActionVaultPurge`, `model.ActionRoleAssignmentsWrite`, `model.ActionRoleAssignmentsDelete` must already exist.
- Every function must fail closed: a `nil` service dependency, a service error, or an unrecognized decision returns `false`, never `true`.
- `admin` account role always short-circuits to `true`, matching the existing `requireVaultManage` behavior exactly (`api/role_assignments.go:44-61`) — do not change this precedent.
- `go build ./...` and `go vet ./...` must pass after every task.

---

### Task 1: `CanManageVault`

**Files:**
- Create: `internal/services/authorization/vault_authz.go`
- Create: `internal/services/authorization/vault_authz_test.go`

**Interfaces:**
- Consumes: `common.HasRequiredRole(userRole string, requiredRoles ...string) bool` (`common/auth_helper.go:44`); `AccessPolicyService.CheckAccess(ctx, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error)` (already defined, `internal/services/authorization/access_policy_service.go:31`); `AccessAllowed` (`internal/services/authorization/access_policy_service.go:19`); `model.PolicyResourceVaults`, `model.OpManage` (`model/access_policy.go:31`, `:53`).
- Produces: `func CanManageVault(ctx context.Context, accountRole string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool`.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/authorization/vault_authz_test.go`:

```go
package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// fakeAccessPolicyService is a minimal test double for AccessPolicyService,
// returning a fixed decision/error for CheckAccess. The remaining interface
// methods are no-ops; no test in this file exercises them.
type fakeAccessPolicyService struct {
	decision AccessDecision
	err      error
}

func (f *fakeAccessPolicyService) CheckAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (AccessDecision, error) {
	return f.decision, f.err
}
func (f *fakeAccessPolicyService) CreatePolicy(context.Context, *model.AccessPolicy) error { return nil }
func (f *fakeAccessPolicyService) GetPolicy(context.Context, uuid.UUID) (*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) ListPolicies(context.Context) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) ListByPrincipal(context.Context, uuid.UUID) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) UpdatePolicy(context.Context, *model.AccessPolicy) error { return nil }
func (f *fakeAccessPolicyService) DeletePolicy(context.Context, uuid.UUID) error           { return nil }

func TestCanManageVault_AdminAlwaysAllowed(t *testing.T) {
	// Even a policy service that would deny must not be consulted for admin.
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	if !CanManageVault(context.Background(), model.RoleAdmin, policies, uuid.New(), uuid.New()) {
		t.Fatal("admin must always be allowed to manage vaults")
	}
}

func TestCanManageVault_NonAdminAllowedOnPolicyAllow(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed}
	if !CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with an allow policy must be allowed")
	}
}

func TestCanManageVault_NonAdminDeniedOnPolicyDeny(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	if CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with a deny policy must be denied")
	}
}

func TestCanManageVault_NonAdminDeniedOnFallback(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	if CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with no matching policy (fallback) must be denied — vault management has no other grant source")
	}
}

func TestCanManageVault_NonAdminDeniedOnServiceError(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed, err: errors.New("db down")}
	if CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("a service error must fail closed, not fail open")
	}
}

func TestCanManageVault_NonAdminDeniedOnNilService(t *testing.T) {
	if CanManageVault(context.Background(), model.RoleUser, nil, uuid.New(), uuid.New()) {
		t.Fatal("a nil AccessPolicyService must fail closed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/authorization/... -run TestCanManageVault -v`
Expected: FAIL — compile error, `undefined: CanManageVault`.

- [ ] **Step 3: Write the implementation**

Create `internal/services/authorization/vault_authz.go`:

```go
// Package authorization — vault_authz.go provides shared, parameterized
// authorization checks for vault-management operations, callable from both
// the HTTP API (api package) and the CLI (cmd package). They replace the
// single-purpose, api-package-private requireVaultManage: see
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md
// §1 for the design rationale.
package authorization

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// CanManageVault reports whether principalID may perform vault-management
// operations (create, list, get, update, delete) against vaultID: the global
// admin account role, or an access-policy allow on (vaults, manage) scoped
// to vaultID or global. A nil policies service, a service error, or any
// decision other than AccessAllowed denies — this function fails closed.
func CanManageVault(ctx context.Context, accountRole string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool {
	if common.HasRequiredRole(accountRole, string(model.RoleAdmin)) {
		return true
	}
	if policies == nil {
		return false
	}
	decision, err := policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
	if err != nil {
		return false
	}
	return decision == AccessAllowed
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/authorization/... -run TestCanManageVault -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/vault_authz.go internal/services/authorization/vault_authz_test.go
git commit -m "feat(authorization): add CanManageVault shared authorization check"
```

---

### Task 2: `CanPurgeVault`

**Files:**
- Modify: `internal/services/authorization/vault_authz.go` (append function)
- Modify: `internal/services/authorization/vault_authz_test.go` (append tests)

**Interfaces:**
- Consumes: `RoleAssignmentService.HasDataAction(ctx, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error)` (already defined, `internal/services/authorization/role_assignment_service.go:61`); `model.ActionVaultPurge` (Plan 1, Task 1); the real `RoleAssignmentService` constructed via `NewRoleAssignmentService` plus the existing `fakeRoleRepo`/`fakePolicyRepo`/`fakeUserLookup`/`newSvc` test helpers already defined in `internal/services/authorization/role_assignment_service_test.go` (same test package — reused as-is, no changes).
- Produces: `func CanPurgeVault(ctx context.Context, accountRole string, roles RoleAssignmentService, principalID, vaultID uuid.UUID) bool`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/services/authorization/vault_authz_test.go`:

```go
func TestCanPurgeVault_AdminAlwaysAllowed(t *testing.T) {
	if !CanPurgeVault(context.Background(), model.RoleAdmin, nil, uuid.New(), uuid.New()) {
		t.Fatal("admin must always be allowed to purge, even with a nil role-assignment service")
	}
}

func TestCanPurgeVault_NonAdminAllowedWithPurgeOperatorRole(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	principalID := uuid.New()
	vaultID := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultPurgeOperator,
	}

	if !CanPurgeVault(context.Background(), model.RoleUser, svc, principalID, vaultID) {
		t.Fatal("a principal holding Key Vault Purge Operator in this vault must be allowed to purge it")
	}
}

func TestCanPurgeVault_NonAdminDeniedWithWrongRole(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	principalID := uuid.New()
	vaultID := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultReader,
	}

	if CanPurgeVault(context.Background(), model.RoleUser, svc, principalID, vaultID) {
		t.Fatal("Key Vault Reader must not grant vault purge")
	}
}

func TestCanPurgeVault_NonAdminDeniedInWrongVault(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	principalID := uuid.New()
	grantedVault := uuid.New()
	targetVault := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: grantedVault, Role: model.RoleKeyVaultPurgeOperator,
	}

	if CanPurgeVault(context.Background(), model.RoleUser, svc, principalID, targetVault) {
		t.Fatal("a Purge Operator grant in vault A must not authorize purging vault B")
	}
}

func TestCanPurgeVault_NonAdminDeniedWithNoAssignments(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	if CanPurgeVault(context.Background(), model.RoleUser, svc, uuid.New(), uuid.New()) {
		t.Fatal("no role assignments at all must deny")
	}
}

func TestCanPurgeVault_NonAdminDeniedOnNilService(t *testing.T) {
	if CanPurgeVault(context.Background(), model.RoleUser, nil, uuid.New(), uuid.New()) {
		t.Fatal("a nil RoleAssignmentService must fail closed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/authorization/... -run TestCanPurgeVault -v`
Expected: FAIL — compile error, `undefined: CanPurgeVault`.

- [ ] **Step 3: Write the implementation**

Append to `internal/services/authorization/vault_authz.go`:

```go

// CanPurgeVault reports whether principalID may permanently purge vaultID:
// the global admin account role, or a Key Vault Purge Operator role
// assignment held in vaultID. A nil roles service, a service error, or no
// matching assignment denies — this function fails closed.
func CanPurgeVault(ctx context.Context, accountRole string, roles RoleAssignmentService, principalID, vaultID uuid.UUID) bool {
	if common.HasRequiredRole(accountRole, string(model.RoleAdmin)) {
		return true
	}
	if roles == nil {
		return false
	}
	allowed, err := roles.HasDataAction(ctx, principalID, vaultID, model.ActionVaultPurge)
	if err != nil {
		return false
	}
	return allowed
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/authorization/... -run TestCanPurgeVault -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/vault_authz.go internal/services/authorization/vault_authz_test.go
git commit -m "feat(authorization): add CanPurgeVault shared authorization check"
```

---

### Task 3: `CanManageRoleAssignments`

**Files:**
- Modify: `internal/services/authorization/vault_authz.go` (append function)
- Modify: `internal/services/authorization/vault_authz_test.go` (append tests)

**Interfaces:**
- Consumes: everything from Tasks 1-2, plus `model.ActionRoleAssignmentsWrite`/`ActionRoleAssignmentsDelete` (Plan 1, Task 1) and `model.RoleKeyVaultDataAccessAdministrator` (Plan 1, Task 2).
- Produces: `func CanManageRoleAssignments(ctx context.Context, accountRole string, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, write bool) bool`. `write=true` checks the create/grant action; `write=false` checks the revoke action.

- [ ] **Step 1: Write the failing tests**

Append to `internal/services/authorization/vault_authz_test.go`:

```go
func TestCanManageRoleAssignments_AdminAlwaysAllowed(t *testing.T) {
	if !CanManageRoleAssignments(context.Background(), model.RoleAdmin, nil, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("admin must always be allowed, write=true")
	}
	if !CanManageRoleAssignments(context.Background(), model.RoleAdmin, nil, nil, uuid.New(), uuid.New(), false) {
		t.Fatal("admin must always be allowed, write=false")
	}
}

func TestCanManageRoleAssignments_NonAdminAllowedByAccessPolicy(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed}
	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("an allow access-policy on (vaults, manage) must grant write, preserving today's documented behavior")
	}
	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, nil, uuid.New(), uuid.New(), false) {
		t.Fatal("an allow access-policy on (vaults, manage) must also grant delete")
	}
}

func TestCanManageRoleAssignments_NonAdminAllowedByDataAccessAdministrator(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	roleSvc := newSvc(rr, pr, ul)
	policies := &fakeAccessPolicyService{decision: AccessFallback}

	principalID := uuid.New()
	vaultID := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultDataAccessAdministrator,
	}

	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, roleSvc, principalID, vaultID, true) {
		t.Fatal("Data Access Administrator must grant write")
	}
	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, roleSvc, principalID, vaultID, false) {
		t.Fatal("Data Access Administrator must grant delete")
	}
}

func TestCanManageRoleAssignments_NonAdminDeniedInWrongVault(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	roleSvc := newSvc(rr, pr, ul)
	policies := &fakeAccessPolicyService{decision: AccessFallback}

	principalID := uuid.New()
	grantedVault := uuid.New()
	targetVault := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: grantedVault, Role: model.RoleKeyVaultDataAccessAdministrator,
	}

	if CanManageRoleAssignments(context.Background(), model.RoleUser, policies, roleSvc, principalID, targetVault, true) {
		t.Fatal("Data Access Administrator in vault A must not authorize managing role assignments in vault B")
	}
}

func TestCanManageRoleAssignments_NonAdminDeniedWithNothing(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	if CanManageRoleAssignments(context.Background(), model.RoleUser, policies, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("no policy allow and no role service must deny")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/authorization/... -run TestCanManageRoleAssignments -v`
Expected: FAIL — compile error, `undefined: CanManageRoleAssignments`.

- [ ] **Step 3: Write the implementation**

Append to `internal/services/authorization/vault_authz.go`:

```go

// CanManageRoleAssignments reports whether principalID may create
// (write=true) or revoke (write=false) role assignments in vaultID: the
// global admin account role, an access-policy allow on (vaults, manage)
// scoped to vaultID or global (preserves the pre-existing documented
// behavior), or a Key Vault Data Access Administrator role assignment held
// in vaultID. A nil dependency, a service error, or no matching grant
// denies — this function fails closed.
func CanManageRoleAssignments(ctx context.Context, accountRole string, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, write bool) bool {
	if common.HasRequiredRole(accountRole, string(model.RoleAdmin)) {
		return true
	}
	if policies != nil {
		if decision, err := policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID); err == nil && decision == AccessAllowed {
			return true
		}
	}
	if roles == nil {
		return false
	}
	action := model.ActionRoleAssignmentsWrite
	if !write {
		action = model.ActionRoleAssignmentsDelete
	}
	allowed, err := roles.HasDataAction(ctx, principalID, vaultID, action)
	if err != nil {
		return false
	}
	return allowed
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/authorization/... -v`
Expected: PASS for the entire package, including every pre-existing test (confirms no regression).

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/vault_authz.go internal/services/authorization/vault_authz_test.go
git commit -m "feat(authorization): add CanManageRoleAssignments shared authorization check"
```

---

## Verification Gate (run before considering this plan complete)

```bash
go build ./...
go vet ./...
go test ./internal/services/authorization/... -v
```

All must pass. These three functions are not yet called from anywhere outside their own tests — `go vet` will not flag them as unused because they are exported, but confirm with:

```bash
grep -rn "CanManageVault\|CanPurgeVault\|CanManageRoleAssignments" --include="*.go" . | grep -v _test.go | grep -v vault_authz.go
```

Expected: no output (nothing calls them yet — that wiring is later plans).
