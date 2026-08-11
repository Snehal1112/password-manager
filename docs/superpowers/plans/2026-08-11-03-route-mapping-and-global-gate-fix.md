# Route Mapping and Global Gate Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Map the new vault-purge route to its data action, remove the global admin-only gate on every `/vaults/...` route (the root cause identified in the design), and prove — through a genuinely full middleware chain, not the partial one every existing vault-authz test uses — that this makes the vault-management handlers' existing per-vault checks reachable for non-admins for the first time.

**Architecture:** Two small, surgical changes (`data_actions.go` gains one new route case; `rbac_service.go` stops returning a global permission for `/vaults` paths), plus a fix to the test harness that was supposed to catch exactly this class of bug but didn't (`buildChainedVaultAPI` omits `AuthenticationMiddleware`/`AuthorizationMiddleware` entirely today).

**Tech Stack:** Go, standard library `testing`/`net/http/httptest`, `github.com/stretchr/testify`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` — read the "Root cause" section and §2 before starting.
- Depends on Plan `2026-08-11-01-azure-role-data-model.md` (`model.ActionVaultPurge` must exist).
- Does **not** depend on Plan `2026-08-11-04-api-vault-handlers.md` — `createVault`/`listVaults` do not yet have handler-level checks at the point this plan runs, and Task 3's regression test must not assume they do (see Task 3 notes).
- `getVault`/`updateVault`/`deleteVault` (`api/vault.go`) already call the pre-existing `requireVaultManage` function today — this plan does not rename or touch that function (Plan 4 does). This plan only removes the global block that makes those existing calls unreachable.
- `go build ./...` and `go vet ./...` must pass after every task.

---

### Task 1: Map the vault-purge route to its data action

**Files:**
- Modify: `internal/services/authorization/data_actions.go:44-74` (the `MapRouteToDataAction` switch)
- Test: `internal/services/authorization/data_actions_test.go` (append)

**Interfaces:**
- Consumes: `model.ActionVaultPurge` (Plan 1, Task 1).
- Produces: `MapRouteToDataAction("DELETE", ".../vaults/{name}/purge")` now returns `(model.ActionVaultPurge, RouteVaultData)` instead of `("", RouteUnmanaged)`.

- [ ] **Step 1: Write the failing test**

Append to `internal/services/authorization/data_actions_test.go` (inside the existing `TestMapRouteToDataAction` function's `cases` slice — add these two entries anywhere in the slice, e.g. right after the last certificate-related case and before the closing `}` of `cases`):

```go
		{"purge vault", http.MethodDelete, "/api/v1/vaults/prod/purge", model.ActionVaultPurge, RouteVaultData},
```

If `TestMapRouteToDataAction`'s table is closed and iterated in a single loop already (it is, per the existing file), this one addition to the table is the entire test change. Also append a standalone test for the wrong-method case:

```go

// TestMapRouteToDataAction_PurgeWrongMethodIsUnmapped proves a non-DELETE
// method on the purge path yields RouteVaultData with no action, so
// PolicyMiddleware's deny-by-default (empty action) path rejects it rather
// than silently falling through to RouteUnmanaged.
func TestMapRouteToDataAction_PurgeWrongMethodIsUnmapped(t *testing.T) {
	action, kind := MapRouteToDataAction(http.MethodGet, "/api/v1/vaults/prod/purge")
	if kind != RouteVaultData {
		t.Fatalf("kind = %v, want RouteVaultData", kind)
	}
	if action != "" {
		t.Fatalf("action = %q, want empty (GET is not a valid purge method)", action)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/authorization/... -run 'TestMapRouteToDataAction' -v`
Expected: FAIL — the new `"purge vault"` case in the table gets `("", RouteUnmanaged)` instead of `(model.ActionVaultPurge, RouteVaultData)`.

- [ ] **Step 3: Add the route mapping**

In `internal/services/authorization/data_actions.go`, inside `MapRouteToDataAction`'s `switch` statement (currently the four cases for `deleted`, `secrets`, `keys`, `certificates`, ending at line 71 with the `certificates` case, followed by `}` at line 72 and `return "", RouteUnmanaged` at line 73), add a new case before the switch's closing `}`:

```go
	case p == "purge":
		if method == http.MethodDelete {
			return model.ActionVaultPurge, RouteVaultData
		}
		return "", RouteVaultData
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/authorization/... -run 'TestMapRouteToDataAction' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/data_actions.go internal/services/authorization/data_actions_test.go
git commit -m "feat(authorization): map vault purge route to ActionVaultPurge"
```

---

### Task 2: Exempt all `/vaults/...` paths from the global admin-only gate

**Files:**
- Modify: `internal/services/authorization/rbac_service.go:220-247` (`mapEndpointToPermission`)
- Modify: `internal/services/authorization/rbac_vault_routes_test.go:68-111` (replace `TestValidateEndpointAccess_VaultManagementRoutes` entirely — its current assertions pin the exact behavior this task inverts)

**Interfaces:**
- Consumes: nothing new.
- Produces: `mapEndpointToPermission(method, "/api/v1/vaults...")` now returns `""` for every path under `/vaults`, not just `RouteVaultData` ones. `PermissionManageVaults` (`internal/services/authorization/rbac_service.go:49`) is left defined and still part of `admin`'s permission bundle (`getDefaultRolePermissions`, line 96) — only its use inside `mapEndpointToPermission` is removed. Do not delete the constant or remove it from `admin`'s bundle.

- [ ] **Step 1: Replace the pinned test that asserts the old (buggy) behavior**

In `internal/services/authorization/rbac_vault_routes_test.go`, replace the entire `TestValidateEndpointAccess_VaultManagementRoutes` function (currently lines 68-111, from the `// TestValidateEndpointAccess_VaultManagementRoutes verifies...` comment through its closing `}`) with:

```go
// TestValidateEndpointAccess_VaultManagementRoutes verifies that vault
// management routes (/api/v1/vaults[/{name}]) are NOT gated by the global
// RBAC layer for any role, admin or not. This inverts the pre-2026-08-11
// behavior: mapEndpointToPermission used to require the admin-only
// vaults:manage permission here, which made every handler-level
// CanManageVault check (api/vault.go) unreachable for non-admins in
// production — see
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md,
// "Root cause". Vault management is now authorized entirely by the
// handler's own per-vault check.
func TestValidateEndpointAccess_VaultManagementRoutes(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	cases := []struct {
		name   string
		role   string
		method string
		path   string
	}{
		{"user reaches create vault gate", model.RoleUser, "POST", "/api/v1/vaults"},
		{"user reaches delete vault gate", model.RoleUser, "DELETE", "/api/v1/vaults/prod"},
		{"user reaches update vault gate", model.RoleUser, "PATCH", "/api/v1/vaults/prod"},
		{"service-account reaches delete vault gate", model.RoleServiceAccount, "DELETE", "/api/v1/vaults/prod"},
		{"secrets-manager reaches delete vault gate", model.RoleSecretsManager, "DELETE", "/api/v1/vaults/prod"},
		{"admin reaches create vault gate", model.RoleAdmin, "POST", "/api/v1/vaults"},
		{"admin reaches delete vault gate", model.RoleAdmin, "DELETE", "/api/v1/vaults/prod"},
		{"admin reaches get vault gate", model.RoleAdmin, "GET", "/api/v1/vaults/prod"},
		{"admin reaches list vaults gate", model.RoleAdmin, "GET", "/api/v1/vaults"},
		{"non-admin reaches purge vault gate", model.RoleUser, "DELETE", "/api/v1/vaults/prod/purge"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := svc.ValidateEndpointAccess(c.role, c.method, c.path); err != nil {
				t.Fatalf("ValidateEndpointAccess(%s, %s, %s) = %v, want nil — the global layer must defer entirely to the handler's own check", c.role, c.method, c.path, err)
			}
		})
	}

	// User management keeps its global permissions; it is not a vault data plane.
	if err := svc.ValidateEndpointAccess(model.RoleUser, "POST", "/api/v1/users"); err == nil {
		t.Fatal("user creation must still require the global users:create permission")
	}
}
```

Note: `"non-admin reaches purge vault gate"` exercises the route added in Task 1 — it is a `RouteVaultData` route (`MapRouteToDataAction` returns `RouteVaultData` for it), so it was already exempted by the pre-existing `if _, kind := MapRouteToDataAction(...); kind == RouteVaultData { return "" }` check at the top of `mapEndpointToPermission` — this case should pass even before Step 3 below, and is included here as a permanent regression pin, not because Task 1 alone was insufficient.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/authorization/... -run TestValidateEndpointAccess_VaultManagementRoutes -v`
Expected: FAIL on every non-purge case — `mapEndpointToPermission` still returns `PermissionManageVaults` for `/vaults` paths, so `ValidateEndpointAccess` returns a non-nil error for every non-admin role.

- [ ] **Step 3: Remove the global permission requirement for `/vaults` paths**

In `internal/services/authorization/rbac_service.go`, replace the `mapEndpointToPermission` function's doc comment and body. Currently (lines 220-247):

```go
// mapEndpointToPermission maps HTTP endpoints to the global permission they
// require. It deliberately answers "" for every vault data-plane route.
//
// Before P2 this function stripped the "vaults/{name}/" prefix and returned the
// same global permission as the flat equivalent, which made RBAC vault-agnostic
// by construction: any principal holding a global permission could operate on
// any vault by name. Those routes are now authorized by PolicyMiddleware
// against the caller's role assignments in the resolved vault, and a second,
// vault-blind gate here would only contradict that decision — a Key Vault
// Crypto Officer in one vault would be refused for holding the global "user"
// role.
//
// Vault management and user management are not data-plane routes and keep their
// global permissions.
func (s *rbacService) mapEndpointToPermission(method, path string) Permission {
	// Vault data-plane routes are authorized per vault, not per global role.
	if _, kind := MapRouteToDataAction(method, path); kind == RouteVaultData {
		return ""
	}

	// Normalize path for comparison.
	path = strings.TrimPrefix(path, DataPlaneBasePath)
	path = strings.TrimPrefix(path, "/")

	// A bare "vaults" or "vaults/{name}" path is vault management.
	if strings.HasPrefix(path, "vaults") {
		return PermissionManageVaults
	}
```

Replace with:

```go
// mapEndpointToPermission maps HTTP endpoints to the global permission they
// require. It deliberately answers "" for every vault data-plane route AND
// every vault-management route (create/list/get/update/delete a vault,
// purge, and role-assignment management).
//
// Before P2 this function stripped the "vaults/{name}/" prefix and returned the
// same global permission as the flat equivalent, which made RBAC vault-agnostic
// by construction: any principal holding a global permission could operate on
// any vault by name. Those routes are now authorized by PolicyMiddleware
// against the caller's role assignments in the resolved vault, and a second,
// vault-blind gate here would only contradict that decision — a Key Vault
// Crypto Officer in one vault would be refused for holding the global "user"
// role.
//
// Before 2026-08-11 this function additionally required the admin-only
// PermissionManageVaults for every /vaults path, including vault management
// and role-assignment routes. That made every handler-level per-vault check
// (CanManageVault, CanManageRoleAssignments — internal/services/authorization/vault_authz.go)
// unreachable for non-admins: this vault-blind global gate ran and denied
// the request before the handler's vault-aware check ever got a chance. See
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md,
// "Root cause", for the full analysis. Vault management now defers entirely
// to the handler, the same way vault data-plane routes already did.
//
// User management is not a vault route at all and keeps its global permissions.
func (s *rbacService) mapEndpointToPermission(method, path string) Permission {
	// Vault data-plane routes are authorized per vault, not per global role.
	if _, kind := MapRouteToDataAction(method, path); kind == RouteVaultData {
		return ""
	}

	// Normalize path for comparison.
	path = strings.TrimPrefix(path, DataPlaneBasePath)
	path = strings.TrimPrefix(path, "/")

	// Every /vaults path — management (create/list/get/update/delete/purge)
	// and role-assignment management alike — defers entirely to the
	// handler's own CanManageVault/CanManageRoleAssignments check.
	if strings.HasPrefix(path, "vaults") {
		return ""
	}
```

(The remainder of the function — the `users` handling and the final `return ""` — is unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/authorization/... -v`
Expected: PASS for the entire package. In particular, confirm `TestVaultManagePermission_OnlyAdmin` (`rbac_vault_routes_test.go`) still passes unchanged — it tests `HasPermission`/the permission bundle directly, not the endpoint mapping, so it is unaffected by this change.

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/rbac_service.go internal/services/authorization/rbac_vault_routes_test.go
git commit -m "fix(authorization): stop gating all /vaults routes on the global admin-only permission"
```

---

### Task 3: Fix the full-chain test harness and add the closing regression test

**Files:**
- Modify: `api/vault_authz_test.go:130-190` (`buildChainedVaultAPI` and the tests that follow it)

**Interfaces:**
- Consumes: the real `authorization.NewRBACService` (already used elsewhere; no new import beyond what `api/vault_authz_test.go` already has via `authzServices "rocketvault/internal/services/authorization"`), `mockAccessPolicyService` (already defined in `api/access_policies_test.go`, same package).
- Produces: `buildChainedVaultAPI` now wires `AuthorizationMiddleware` with a real `RBACService`, so a test using it observes actual production authorization behavior for `/vaults/...` routes, not a permissive stand-in.

**Do not** run this task before Task 2 lands — the harness fix will make every non-admin request to `/vaults/{name}` 403 again if Task 2's global-gate exemption isn't in place yet (the harness would then correctly reproduce the pre-fix bug, which is the point, but the "allowed with grant" test below requires Task 2 to be live to pass).

- [ ] **Step 1: Write the failing tests**

In `api/vault_authz_test.go`, append after the existing `TestVaultManage_ScopedToDefault_CannotReachOtherVault` function (end of file):

```go

// TestVaultManage_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant
// proves that, through the REAL production middleware chain (VaultResolution
// -> Policy -> Authorization, with a real RBACService, not permissiveRBAC), a
// non-admin caller holding no vaults:manage grant at all is denied on every
// existing vault-management route. createVault and listVaults are
// deliberately excluded here: they gain their own handler-level check in a
// later plan (2026-08-11-04) and have none yet at this point in the sequence
// — they are not yet protected by anything but this test's absence proves
// nothing about them either way.
func TestVaultManage_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	router, _ := buildChainedVaultAPI(policySvc)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/vaults/prod"},
		{http.MethodPatch, "/api/v1/vaults/prod"},
		{http.MethodDelete, "/api/v1/vaults/prod"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
			ctx = context.WithValue(ctx, common.RoleKey, string(model.RoleUser))
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403 (no grant, real middleware chain)", w.Code)
			}
		})
	}
}

// TestVaultManage_RealAuthorizationMiddleware_NonAdminAllowedWithGrant proves
// the positive case through the real chain: a non-admin with a matching
// vaults:manage allow policy on the target vault reaches the handler and
// succeeds. Before the 2026-08-11 fix this was unreachable in production
// regardless of the policy decision — AuthorizationMiddleware 403'd the
// request before PolicyMiddleware's allow decision, or the handler's own
// check, could matter. No existing test proved this positive case through a
// chain that includes AuthorizationMiddleware; this is the first one that
// does.
func TestVaultManage_RealAuthorizationMiddleware_NonAdminAllowedWithGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	router, prodID := buildChainedVaultAPI(policySvc)
	defID := uuid.MustParse(model.DefaultVaultID)

	// The ambient PolicyMiddleware check (default vault, since {name} routes
	// bypass VaultResolutionMiddleware) and the handler's own re-check
	// (target vault "prod") are two distinct CheckAccess calls; both must
	// allow for a 200.
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, defID).
		Return(authzServices.AccessAllowed, nil)
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessAllowed, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, string(model.RoleUser))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (matching grant, real middleware chain)", w.Code)
	}
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `go test ./api/... -run 'TestVaultManage_RealAuthorizationMiddleware' -v`
Expected: FAIL on `TestVaultManage_RealAuthorizationMiddleware_NonAdminAllowedWithGrant` (403 instead of 200) — `buildChainedVaultAPI` does not yet wire `AuthorizationMiddleware`, so this test doesn't even exercise the real gate; more precisely, run it AFTER Step 3 below is reverted to confirm the *old* harness gives a false pass. To see the concrete failure this task fixes, temporarily verify: with `AuthorizationMiddleware` absent from the chain, `TestVaultManage_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant` would also fail (it currently expects 403, but with no `AuthorizationMiddleware` and no handler check on POST/GET /vaults... — since this test only covers GET/PATCH/DELETE /vaults/{name}, which already have `requireVaultManage`, denial already happens via that pre-existing handler check even without `AuthorizationMiddleware` wired in — so the "denied" test alone would misleadingly pass even before Step 3). This is exactly why the "allowed with grant" test is the one that actually catches the missing middleware: only it fails without `AuthorizationMiddleware` wired in an unrelated way. Confirm this understanding by running both tests before Step 3 and noting `NonAdminAllowedWithGrant` FAILs while `NonAdminDeniedWithoutGrant` unexpectedly PASSes (for the wrong reason) — this is the concrete evidence the harness gap was real.

- [ ] **Step 3: Fix the harness**

In `api/vault_authz_test.go`, in `buildChainedVaultAPI` (currently lines 130-162), make two changes:

1. Remove the `rbacSvc: permissiveRBAC{},` line from the `container := &vaultSvcTestContainer{...}` literal — `vaultSvcTestContainer.GetRBACService()` (`api/vault_test.go:179-186`) already falls back to `authzServices.NewRBACService(nil)` (the real implementation) when `rbacSvc` is unset, so simply not setting it is sufficient.
2. Add `mw.AuthorizationMiddleware` to the `.Use(...)` call.

Before:

```go
	container := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		rbacSvc:   permissiveRBAC{},
		logger:    userTestLog(),
	}
	a := &app.App{ServiceContainer: container}
	a.Logger = userTestLog()

	mw := middleware.NewMiddleware(container)

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.ApiRoot.Use(mw.VaultResolutionMiddleware, mw.PolicyMiddleware)
```

After:

```go
	container := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		logger:    userTestLog(),
	}
	a := &app.App{ServiceContainer: container}
	a.Logger = userTestLog()

	mw := middleware.NewMiddleware(container)

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.ApiRoot.Use(mw.VaultResolutionMiddleware, mw.PolicyMiddleware, mw.AuthorizationMiddleware)
```

Also update the function's doc comment (currently: "wires the production middleware chain (VaultResolution -> Policy) ahead of the vaults management handlers, exactly as api.go does") to remove the now-inaccurate parenthetical and state the real chain:

```go
// buildChainedVaultAPI wires the production middleware chain (VaultResolution
// -> Policy -> Authorization) ahead of the vaults management handlers,
// matching api.go's ApiRoot.Use(...) order for everything except
// CORS/RateLimit/Authentication — this harness injects identity directly into
// the request context instead of validating a real bearer token, so
// AuthenticationMiddleware is intentionally not wired in. The container
// serves both the default vault (which VaultResolutionMiddleware falls back
// to for {name} routes) and a distinct target vault "prod".
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./api/... -run 'TestVaultManage' -v`
Expected: PASS for `TestVaultManage_ScopedToDefault_CannotReachOtherVault` (pre-existing, unaffected), `TestVaultManage_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant`, and `TestVaultManage_RealAuthorizationMiddleware_NonAdminAllowedWithGrant`.

Then run the full package to confirm no regressions:

Run: `go test ./api/... -v`
Expected: PASS across the board, including every pre-existing `TestGetVault_*`/`TestUpdateVault_*`/`TestDeleteVault_*` test (those use `buildAuthzVaultAPI`/`doVaultRequestAs`, which this task does not touch).

- [ ] **Step 5: Commit**

```bash
git add api/vault_authz_test.go
git commit -m "test(api): wire real AuthorizationMiddleware into the vault full-chain regression harness"
```

---

## Verification Gate (run before considering this plan complete)

```bash
go build ./...
go vet ./...
go test ./api/... ./internal/services/authorization/... -v
```

All must pass. This plan closes the root-cause bug for the three vault-management routes that already had handler-level checks (`getVault`/`updateVault`/`deleteVault`). `createVault`/`listVaults` and the new purge endpoint remain to be wired in Plan `2026-08-11-04-api-vault-handlers.md` — do not consider vault-management authorization fully fixed until that plan lands too.
