# Multi-Role: API & Vault-Authorization Call-Site Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every remaining `api/`-package authorization check, plus the
shared `vault_authz.go` primitives (`CanManageVault`, `CanPurgeVault`,
`CanManageRoleAssignments`) and everything that feeds them a role, moves
from a single role string to `[]string`. Also fixes a previously-unknown gap:
`RBACService.HasPermission` does an exact `map[string]Permission` lookup
keyed by role string — not comma-aware at all — so a multi-role user
silently lost every RBAC-mapped HTTP endpoint permission today, on top of
everything the design spec already named.

**Architecture:** `vault_authz.go`'s three functions change their
`accountRole string` parameter to `accountRoles []string` and switch
`common.HasRequiredRole` to `common.HasAnyRole` internally. Every
`callerIdentity`-shaped helper that feeds them (three near-identical CLI
copies plus one API copy) changes its return type the same way.
`RBACService.ValidateEndpointAccess`/`HasPermission` change to accept
`roles []string` and iterate — `HasPermission` itself stays single-role
(the permission map is genuinely per-role), with the iteration happening one
level up.

**Tech Stack:** Go.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- Depends on Plan 03 (`common.HasAnyRole`) and Plan 04 (`model.Claims.Roles`).
- `RBACService.HasPermission(role string, permission Permission) bool` does
  NOT change signature — it's a legitimate single-role primitive. Only
  `ValidateEndpointAccess` changes, to loop over multiple roles calling
  `HasPermission` for each.
- `api/role_assignments.go`'s `callerIdentity` and the three CLI
  `callerIdentity` functions (`cmd/vaults/authz.go`,
  `cmd/vault-access/authz.go`, `cmd/vault-webhook/authz.go`) are four
  independent copies of the same logic (not a shared function) — all four
  need the identical edit.

---

### Task 1: `api/oauth2.go`, `api/jwks.go`, `api/access_policies.go`, `api/audit.go`

**Files:**
- Modify: `api/oauth2.go:199,240,262,287,314`, `api/jwks.go:49`,
  `api/access_policies.go:33`, `api/audit.go:67,99,143,191,215`
- Test: each file's corresponding `_test.go`

**Interfaces:**
- Consumes: `common.HasAnyRole` (Plan 03), `c.Claims.Roles` (Plan 04, once
  `model.Claims.Roles` exists — `c.Claims` is a `*model.Claims`).

- [ ] **Step 1: Write the failing test**

Pick one representative handler per file (e.g. `createServiceAccount` in
`api/oauth2.go`, `rotateJWKS` in `jwks.go`, `requireAccessPolicyAdmin` in
`access_policies.go`, `getAuditLogs` in `audit.go`) and update or add a test
asserting a caller with `Roles: []string{"secrets_manager", "admin"}`
(multi-role, admin present but not sole/first role) is granted access.
Match each file's existing test pattern.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run "ServiceAccount|JWKS|AccessPolicy|Audit" -v 2>&1 | head -80`
Expected: FAIL — compile errors (`c.Claims.Role` undefined)

- [ ] **Step 3: Apply the transform to `oauth2.go`, `jwks.go`, `access_policies.go`**

All 7 sites across these 3 files share the identical shape:

Before:
```go
	if !common.HasRequiredRole(c.Claims.Role, model.RoleAdmin) {
```
After:
```go
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
```

Apply to `oauth2.go` lines 199, 240, 262, 287, 314 (createServiceAccount,
listServiceAccounts, getServiceAccount, deleteServiceAccount,
rotateServiceAccountSecret), `jwks.go:49` (rotateJWKS), and
`access_policies.go:33` (requireAccessPolicyAdmin).

- [ ] **Step 4: Apply the transform to `audit.go`**

All 5 sites in this file are strict equality, not `HasRequiredRole`:

Before (shown for `getAuditLogs`, line 67):
```go
	role := c.Claims.Role
	if role != string(model.RoleAdmin) {
```
After:
```go
	roles := c.Claims.Roles
	if !common.HasAnyRole(roles, model.RoleAdmin) {
```

Apply identically at lines 67, 99, 143, 191, 215 — each is its own handler
function with a local `role`/`role !=` pair; rename the local variable to
`roles` at each site and update any later use of `role` in that same
function (check for logging statements referencing the local variable by
name after the gate) to use `roles` instead.

Also confirm `"rocketvault/common"` is imported in `audit.go` — add it if
not already present.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./api/... -run "ServiceAccount|JWKS|AccessPolicy|Audit" -v`
Expected: PASS

- [ ] **Step 6: Full `api/` package test run**

Run: `go test ./api/... -v 2>&1 | tail -60`
Expected: all PASS — fix any remaining `.Role`/`Role:` compile errors in
this package's other test files mechanically.

- [ ] **Step 7: Commit**

```bash
git add api/oauth2.go api/jwks.go api/access_policies.go api/audit.go
git commit -m "fix(api): migrate oauth2/jwks/access-policy/audit authorization gates to claims.Roles/HasAnyRole"
```

---

### Task 2: `vault_authz.go` and its four `callerIdentity` callers

**Files:**
- Modify: `internal/services/authorization/vault_authz.go` (`CanManageVault`,
  `CanPurgeVault`, `CanManageRoleAssignments`)
- Modify: `cmd/vaults/authz.go` (`callerIdentity`, and every function that
  destructures its `role` return value)
- Modify: `cmd/vault-access/authz.go` (same, package `vaultaccess`)
- Modify: `cmd/vault-webhook/authz.go` (same, package `vaultwebhook`)
- Modify: `api/role_assignments.go` (`callerIdentity`, plus the
  `isGlobalAdmin := common.HasRequiredRole(role, ...)` lines at ~82 and ~226)
- Modify: `cmd/vault-access/grant.go:69`, `cmd/vault-access/revoke.go:54`
  (`isGlobalAdmin := common.HasRequiredRole(callerRole, ...)`)
- Test: each modified package's corresponding `_test.go`

**Interfaces:**
- Produces:
  - `CanManageVault(ctx, accountRoles []string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool`
  - `CanPurgeVault(ctx, accountRoles []string, roles RoleAssignmentService, principalID, vaultID uuid.UUID) bool`
  - `CanManageRoleAssignments(ctx, accountRoles []string, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, write bool) bool`
  - `callerIdentity(ctx) (roles []string, principalID uuid.UUID, err error)`
    (three CLI copies, same shape each)
  - `callerIdentity(c *Context) (roles []string, principalID uuid.UUID, ok bool)`
    (API copy)

- [ ] **Step 1: Write the failing test**

`internal/services/authorization/vault_authz_test.go` almost certainly has
direct tests of `CanManageVault`/`CanPurgeVault`/`CanManageRoleAssignments`
today (they're exported, pure functions taking a role string — easy to unit
test, and this project tests thoroughly per every earlier plan's findings).
Update its fixture calls from `accountRole: "admin"` to `accountRoles:
[]string{"admin"}`-shaped arguments, and add one case per function passing
`[]string{"secrets_manager", "admin"}` (multi-role) to confirm it still
grants access.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/... -run "CanManageVault|CanPurgeVault|CanManageRoleAssignments" -v`
Expected: FAIL — compile error (parameter type mismatch)

- [ ] **Step 3: Change `vault_authz.go`**

All three functions get the identical parameter rename plus
`HasRequiredRole` → `HasAnyRole` swap. Shown for `CanManageVault`:

```go
func CanManageVault(ctx context.Context, accountRoles []string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return true
	}
	...
```

Apply the identical `accountRole string` → `accountRoles []string` and
`common.HasRequiredRole(accountRole, ...)` → `common.HasAnyRole(accountRoles, ...)`
change to `CanPurgeVault` and `CanManageRoleAssignments` — no other logic in
any of the three functions changes.

- [ ] **Step 4: Change the three CLI `callerIdentity` functions**

`cmd/vaults/authz.go`:
```go
func callerIdentity(ctx context.Context) (roles []string, principalID uuid.UUID, err error) {
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	return claims.Roles, claims.UserID, nil
}
```

Every caller in the same file destructures the return as `role, principalID,
err := callerIdentity(ctx)` — rename the local variable to `roles` at each
call site (there are 4 in this file: `requireCanCreateVault`,
`requireCanListVaults`, `requireCanManageVault`, `requireCanPurgeVault`) and
pass `roles` (not `role`) into the `authz.CanManageVault`/`CanPurgeVault`
call each function makes.

Apply the identical transform to `cmd/vault-access/authz.go` (package
`vaultaccess`, one caller: `requireCanManageRoleAssignments`) and
`cmd/vault-webhook/authz.go` (package `vaultwebhook`, one caller:
`requireCanManageVault`).

- [ ] **Step 5: Change `api/role_assignments.go`'s `callerIdentity`**

```go
func callerIdentity(c *Context) (roles []string, principalID uuid.UUID, ok bool) {
	principalID, err := uuid.Parse(c.Claims.UserID)
	return c.Claims.Roles, principalID, err == nil
}
```

Both call sites in this file (`createRoleAssignment` around line 65,
`revokeRoleAssignment` around line 218) destructure this as `role, callerID,
ok := callerIdentity(c)` — rename to `roles` and update:
- the `authzServices.CanManageRoleAssignments(r.Context(), role, ...)` call
  → pass `roles`
- the `isGlobalAdmin := common.HasRequiredRole(role, string(model.RoleAdmin))`
  line (both occurrences) → `common.HasAnyRole(roles, string(model.RoleAdmin))`

- [ ] **Step 6: Change `cmd/vault-access/grant.go` and `revoke.go`**

Both files destructure `callerIdentity(ctx)` as `callerRole, _, err :=
callerIdentity(ctx)` then compute `isGlobalAdmin := common.HasRequiredRole
(callerRole, string(model.RoleAdmin))`. Rename to `callerRoles` and change
to `common.HasAnyRole(callerRoles, string(model.RoleAdmin))` in both files.

- [ ] **Step 7: Run test to verify it passes, then the full affected packages**

Run: `go test ./internal/services/authorization/... -v`
Expected: PASS

Run: `go test ./cmd/vaults/... ./cmd/vault-access/... ./cmd/vault-webhook/... ./api/... -v 2>&1 | tail -80`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/services/authorization/vault_authz.go cmd/vaults/authz.go cmd/vault-access/authz.go cmd/vault-webhook/authz.go api/role_assignments.go cmd/vault-access/grant.go cmd/vault-access/revoke.go
git commit -m "fix(authz): thread multi-role through CanManageVault/CanPurgeVault/CanManageRoleAssignments and every caller"
```

---

### Task 3: `RoleKey` context value + `RBACService.ValidateEndpointAccess`

**Files:**
- Modify: `internal/middleware/middleware.go` (`AuthenticationMiddleware`'s
  `context.WithValue(ctx, common.RoleKey, claims.Role)`,
  `AuthorizationMiddleware`'s `role, ok := ...Value(common.RoleKey).(string)`)
- Modify: `api/context.go:172` (`role, _ := ...Value(common.RoleKey).(string)`)
- Modify: `internal/services/authorization/rbac_service.go`
  (`ValidateEndpointAccess`)
- Test: `internal/middleware/middleware_test.go`,
  `internal/services/authorization/rbac_service_test.go`

**Interfaces:**
- Produces: `ValidateEndpointAccess(roles []string, method, path string) error`
  — `HasPermission(role string, permission Permission) bool` is unchanged
  (still single-role; `ValidateEndpointAccess` now loops).

- [ ] **Step 1: Write the failing test**

`internal/services/authorization/rbac_vault_routes_test.go` already has
`TestValidateEndpointAccess_DataPlaneRoutesDelegate` and
`TestValidateEndpointAccess_VaultManagementRoutes` — add a case (in that
file or a new one alongside it) asserting that a caller whose roles are
`[]string{"user", "secrets_manager"}` (a role combination where "user" alone
would be denied but "secrets_manager" alone would be allowed for some
endpoint) is granted access — this is the exact bug class this task exists
to fix: `HasPermission` today does an exact map lookup on the whole
comma-string, so a multi-role caller was previously always "unknown role,"
denied outright.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/... -run TestValidateEndpointAccess -v`
Expected: FAIL — compile error (parameter type) or, if written against the
current signature first, a real behavioral failure (multi-role caller
denied)

- [ ] **Step 3: Change `ValidateEndpointAccess`**

```go
func (s *rbacService) ValidateEndpointAccess(roles []string, method, path string) error {
	permission := s.mapEndpointToPermission(method, path)
	if permission == "" {
		return nil
	}

	for _, role := range roles {
		if s.HasPermission(role, permission) {
			logrus.WithFields(logrus.Fields{
				"roles":      roles,
				"method":     method,
				"path":       path,
				"permission": string(permission),
			}).Debug("Access granted")
			return nil
		}
	}

	s.logger.LogAuditError("", "authorization", "failed",
		fmt.Sprintf("Access denied for roles %v to %s %s", roles, method, path), nil)
	logrus.WithFields(logrus.Fields{
		"roles":                roles,
		"method":               method,
		"path":                 path,
		"required_permission": string(permission),
	}).Warn("Access denied: insufficient permissions")
	return fmt.Errorf("insufficient permissions: %s required", permission)
}
```

`HasPermission` itself is unchanged — do not touch it.

- [ ] **Step 4: Change `RoleKey`'s stored type in `middleware.go`**

`AuthenticationMiddleware`:
```go
		ctx = context.WithValue(ctx, common.RoleKey, claims.Roles)
```

`AuthorizationMiddleware`:
```go
		roles, ok := r.Context().Value(common.RoleKey).([]string)
		if !ok {
			m.logger.LogAuditError("", "authz", "failed", "Missing role in context", nil)
			http.Error(w, "Forbidden: missing role", http.StatusForbidden)
			return
		}

		if err := m.container.GetRBACService().ValidateEndpointAccess(roles, r.Method, r.URL.Path); err != nil {
			m.logger.LogAuditError("", "authz", "failed", "Access denied", err)
			logrus.WithFields(logrus.Fields{
				"roles":  roles,
				"method": r.Method,
				"path":   r.URL.Path,
			}).Warn("Authorization failed")
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}
```

- [ ] **Step 5: Change `api/context.go`'s consumer**

```go
		roles, _ := r.Context().Value(common.RoleKey).([]string)

		if a.ServiceContainer != nil {
			if err := a.ServiceContainer.GetRBACService().ValidateEndpointAccess(roles, r.Method, r.URL.Path); err != nil {
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/services/authorization/... -run TestValidateEndpointAccess -v`
Expected: PASS

- [ ] **Step 7: Full repo build and test**

Run: `go build ./... && go test ./... 2>&1 | grep -v "^ok" | head -100`
Expected: `go build` clean; any remaining test failures should now be
confined to Plan 10's scope (OIDC path, `cmd/root.go` passthrough) — this is
the natural checkpoint to confirm before moving to Plan 10.

- [ ] **Step 8: Commit**

```bash
git add internal/middleware/middleware.go api/context.go internal/services/authorization/rbac_service.go internal/middleware/middleware_test.go internal/services/authorization/rbac_vault_routes_test.go
git commit -m "fix(authz): RoleKey carries []string, ValidateEndpointAccess checks every role (was: exact map lookup on one string, silently denying multi-role callers)"
```
