# Vault Management Authorization Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close a broken-access-control hole where `GET/PATCH/DELETE /api/v1/vaults/{name}` perform **no** authorization check against the *target* vault named in the path. A principal whose `vaults:manage` grant is scoped only to the default vault can currently read, modify, or soft-delete **any** vault by name. The fix applies the existing `requireVaultManage` gate — resolving the target vault by name (not by ambient context) — to `getVault`, `updateVault`, and `deleteVault`.

**Architecture:** `VaultResolutionMiddleware` intentionally skips the `/vaults/{name}` management routes (they use `{name}`, not `{vault_name}`, so the middleware falls back to the **default** vault — see the comment in `InitVault`, `api/vault.go:14-23`). Consequently `PolicyMiddleware` (`internal/middleware/middleware.go:408`) evaluates `vaults:manage` against the default vault's ID, never the path's target. The handlers must therefore re-authorize against the **target** vault's own ID. We reuse `requireVaultManage(c, r, vaultID)` from `api/role_assignments.go:26-42`, but because these routes carry no vault ID in the path (and the context vault is the wrong one), we resolve the target vault by name via `VaultService.GetVault` and pass the returned `*model.Vault`'s `.ID`. Check order per route is: **resolve by name (404 if absent) → authorize (403 if denied) → act** — surfacing not-found before forbidden, matching Azure Key Vault. `createVault` and `listVaults` are out of scope.

**Tech Stack:** Go 1.24.2, `net/http`, Gorilla Mux, `rocketvault/internal/services/vaults.VaultService`, `rocketvault/internal/services/authorization.AccessPolicyService`, `github.com/google/uuid`, testify (`assert`/`mock`). Full-chain regression test wires `rocketvault/internal/middleware` (`VaultResolutionMiddleware` + `PolicyMiddleware`).

**Spec:** `docs/superpowers/specs/2026-07-19-vault-management-authz-fix-design.md` — §"The Bug", §"Fix", §"Design Decisions" (uniform `OpManage`; not-found-before-forbidden; create/list out of scope; full-middleware-chain regression test), §"Follow-Up".

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `api/vault.go` | Modify | Add `requireVaultManage` gate to `getVault`, `updateVault`, `deleteVault` (resolve target by name first) |
| `api/vault_test.go` | Modify | Extend the shared `vaultSvcTestContainer` so it can serve a configurable `AccessPolicyService`, `RBACService`, and `*logging.Logger`; add non-admin request/build helpers |
| `api/vault_authz_test.go` | Create | New authorization unit tests (Tasks 1-2) and the full-middleware-chain 403 regression test (Task 3) |

No production files other than `api/vault.go` change. `requireVaultManage` already exists (`api/role_assignments.go:26-42`) and is unchanged. `VaultService.GetVault` already returns `*model.Vault` with an `.ID uuid.UUID` field (`internal/services/vaults/vault_service.go:108-110`, `model/vault.go:26`).

### Shared-helper prerequisite (do this in Task 1, before its test)

Three methods on the shared `vaultSvcTestContainer` in `api/vault_test.go` currently `panic`, which blocks any test that reaches the access-policy layer. Make them configurable **additively** so existing admin-role tests are unaffected (they never call these methods because the admin short-circuit in `requireVaultManage` returns before `GetAccessPolicyService` is touched).

Add three fields to the struct (currently `api/vault_test.go:136-141`):

```go
type vaultSvcTestContainer struct {
	vaultSvc  vaultServices.VaultService
	secretSvc secretServices.SecretService
	keySvc    keyServices.KeyService
	certSvc   certServices.CertificateService
	policySvc authzServices.AccessPolicyService // added: served to requireVaultManage / PolicyMiddleware
	rbacSvc   authzServices.RBACService         // added: overrides the default RBAC when set
	logger    *logging.Logger                   // added: NewMiddleware calls GetLogger()
}
```

Replace the panicking `GetAccessPolicyService` (currently `api/vault_test.go:197-199`):

```go
func (c *vaultSvcTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return c.policySvc
}
```

Make `GetRBACService` honor an override while preserving today's default (currently `api/vault_test.go:150-154`):

```go
func (c *vaultSvcTestContainer) GetRBACService() authzServices.RBACService {
	if c.rbacSvc != nil {
		return c.rbacSvc
	}
	// The vault management routes map to no specific permission, so a real RBAC
	// service grants access regardless of role.
	return authzServices.NewRBACService(nil)
}
```

Make `GetLogger` honor an override while preserving today's panic-on-unexpected-use (currently `api/vault_test.go:246-248`):

```go
func (c *vaultSvcTestContainer) GetLogger() *logging.Logger {
	if c.logger != nil {
		return c.logger
	}
	panic("unexpected call: GetLogger")
}
```

Then add two test helpers near `newVaultTestAPI`/`doVaultRequest` (currently `api/vault_test.go:280-316`). Refactor `newVaultTestAPI` to delegate, and add a role-parameterized request helper:

```go
// newVaultTestAPIWithContainer wires the vaults subrouter to the given container.
func newVaultTestAPIWithContainer(container *vaultSvcTestContainer) *API {
	a := &app.App{ServiceContainer: container}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.InitVault()
	return api
}

// doVaultRequestAs issues an authed request carrying the given role. The real
// AuthenticationMiddleware would set these context values; tests inject them.
func doVaultRequestAs(api *API, role, method, path string, body []byte) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	ctx := context.WithValue(r.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, role)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)
	return w
}
```

Keep the existing `newVaultTestAPI`/`doVaultRequest` behavior. Simplest: leave `newVaultTestAPI` as-is (it still constructs `&vaultSvcTestContainer{vaultSvc: svc}`), and have `doVaultRequest` delegate:

```go
func doVaultRequest(api *API, method, path string, body []byte) *httptest.ResponseRecorder {
	return doVaultRequestAs(api, string(model.RoleAdmin), method, path, body)
}
```

> **Why a permissive/non-admin split matters (verified against the code).** Two independent gates guard these routes:
> 1. **Coarse RBAC** — `ApiSessionRequired` calls `RBACService.ValidateEndpointAccess(role, …)` (`api/context.go:143-154`), which maps `vaults/{name}` to `PermissionManageVaults` (`internal/services/authorization/rbac_service.go:231-239`). By default **only `RoleAdmin`** carries that permission (`rbac_service.go:90-96`).
> 2. **Fine-grained access policy** — `requireVaultManage` short-circuits to `true` for admins and otherwise calls `AccessPolicyService.CheckAccess(...)` scoped to a specific vault ID (`api/role_assignments.go:27-41`).
>
> An admin passes gate 1 but bypasses gate 2 (short-circuit), so admins cannot exercise the scoped denial. The exploitable principal is therefore a **non-admin whose role carries the coarse `vaults:manage` capability** (a customized/expanded role) while their fine-grained policy is scoped to a single vault. To isolate the fine-grained fix under test, the new tests use a **permissive RBAC stub** (representing "coarse capability granted") plus a non-admin role, so the only thing that can produce a 403 is `requireVaultManage`.

Add a tiny permissive RBAC stub to `api/vault_authz_test.go` (only 3 methods on the interface — `internal/services/authorization/rbac_service.go:58-62`):

```go
// permissiveRBAC grants every endpoint, isolating the per-vault access-policy
// gate as the sole source of 403 in these tests.
type permissiveRBAC struct{}

func (permissiveRBAC) HasPermission(string, authzServices.Permission) bool { return true }
func (permissiveRBAC) GetRolePermissions(string) []authzServices.Permission { return nil }
func (permissiveRBAC) ValidateEndpointAccess(role, method, path string) error { return nil }
```

---

## Task 1: Authorize `getVault` against the target vault

**Files:**
- Modify: `api/vault.go` (`getVault`, currently lines 112-130)
- Modify: `api/vault_test.go` (shared-helper prerequisite above)
- Create: `api/vault_authz_test.go`

### Step 1: Write failing tests

First complete the **shared-helper prerequisite** section above (fields, `GetAccessPolicyService`/`GetRBACService`/`GetLogger`, `newVaultTestAPIWithContainer`, `doVaultRequestAs`, `permissiveRBAC`). Then create `api/vault_authz_test.go`:

```go
// Package api — authorization tests for vault.go management handlers.
package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// buildAuthzVaultAPI wires a vault API whose access-policy decisions are driven by
// the given mock, and whose coarse RBAC is permissive so the per-vault gate is the
// only source of 403. It seeds a single target vault "prod" and returns its ID.
func buildAuthzVaultAPI(policySvc authzServices.AccessPolicyService) (*API, uuid.UUID) {
	repo := newVaultFakeRepo()
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	container := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		rbacSvc:   permissiveRBAC{},
	}
	return newVaultTestAPIWithContainer(container), id
}

// TestGetVault_ForbiddenWhenNotScopedToTargetVault proves that a non-admin whose
// vaults:manage grant does NOT cover the target vault gets 403, not 200.
func TestGetVault_ForbiddenWhenNotScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	// No policy covers prod's ID -> AccessFallback -> requireVaultManage denies.
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults/prod", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGetVault_AllowedWhenScopedToTargetVault proves that a matching vaults:manage
// grant on the target vault still returns 200.
func TestGetVault_AllowedWhenScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	api, id := buildAuthzVaultAPI(policySvc)
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, id).
		Return(authzServices.AccessAllowed, nil)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults/prod", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetVault_NotFoundBeforeForbidden proves a missing vault yields 404 even for a
// principal that would otherwise be denied (not-found precedes forbidden).
func TestGetVault_NotFoundBeforeForbidden(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults/ghost", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
```

### Step 2: Run to confirm tests fail

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestGetVault_Forbidden|TestGetVault_Allowed|TestGetVault_NotFoundBeforeForbidden" -v 2>&1 | tail -25
```

Expected: `TestGetVault_ForbiddenWhenNotScopedToTargetVault` **FAILs** — the handler returns `200` because no authorization check exists yet. (`TestGetVault_AllowedWhenScopedToTargetVault` and `TestGetVault_NotFoundBeforeForbidden` already pass — they document the intended positive/ordering behavior.)

### Step 3: Add the authorization gate to `getVault`

In `api/vault.go`, replace `getVault` (lines 112-130) with:

```go
// getVault handles the request to retrieve a single vault by name.
func getVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.GetVault(r.Context(), name)
	if err != nil {
		c.SetNotFound("vault")
		return
	}

	// Authorize against the TARGET vault named in the path. These {name} routes
	// bypass VaultResolutionMiddleware, so PolicyMiddleware only evaluated the
	// default vault; re-check vaults:manage against this vault's own ID.
	if !requireVaultManage(c, r, vault.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}
```

### Step 4: Build and re-run the tests

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestGetVault|TestCreateVault_AndList" -v 2>&1 | tail -30
```

Expected: all `TestGetVault_*` PASS, and the pre-existing `TestGetVault_NotFound` / `TestCreateVault_AndList` still PASS (admin short-circuit keeps them green).

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add api/vault.go api/vault_test.go api/vault_authz_test.go && git commit -S -m "fix(vault): authorize getVault against the target vault by name"
```

---

## Task 2: Authorize `updateVault` and `deleteVault` against the target vault

**Files:**
- Modify: `api/vault.go` (`updateVault` lines 132-173, `deleteVault` lines 175-198)
- Modify: `api/vault_authz_test.go` (add write-path tests)

### Step 1: Write failing tests

Append to `api/vault_authz_test.go`:

```go
// TestUpdateVault_ForbiddenWhenNotScopedToTargetVault proves PATCH is gated.
func TestUpdateVault_ForbiddenWhenNotScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	body := []byte(`{"enabled":false}`)
	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodPatch, "/api/v1/vaults/prod", body)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestUpdateVault_NotFoundBeforeForbidden proves a missing target yields 404, and
// the gate runs before the update mutates anything.
func TestUpdateVault_NotFoundBeforeForbidden(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	body := []byte(`{"enabled":false}`)
	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodPatch, "/api/v1/vaults/ghost", body)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteVault_ForbiddenWhenNotScopedToTargetVault proves DELETE is gated.
func TestDeleteVault_ForbiddenWhenNotScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodDelete, "/api/v1/vaults/prod", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
```

### Step 2: Run to confirm tests fail

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestUpdateVault_Forbidden|TestUpdateVault_NotFoundBeforeForbidden|TestDeleteVault_Forbidden" -v 2>&1 | tail -25
```

Expected: `TestUpdateVault_ForbiddenWhenNotScopedToTargetVault` and `TestDeleteVault_ForbiddenWhenNotScopedToTargetVault` **FAIL** — the handlers return `200`/`204` with no authorization check. `TestUpdateVault_NotFoundBeforeForbidden` passes already (`UpdateVault` maps `ErrVaultNotFound` to 404 today).

### Step 3: Add the gate to `updateVault`

`updateVault` currently parses the body **before** touching the service (lines 132-173). Restructure so the target is resolved and authorized **before** any body parsing or mutation. Replace `updateVault` (lines 132-173) with:

```go
// updateVault handles the request to update a vault by name.
func updateVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	// Resolve the target vault first (404), then authorize against it (403), before
	// reading the body or mutating anything. These {name} routes bypass
	// VaultResolutionMiddleware, so the ambient policy check covered only the
	// default vault. UpdateVault re-reads the vault internally; the extra read here
	// is deliberate and cheap.
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		c.SetNotFound("vault")
		return
	}
	if !requireVaultManage(c, r, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	req, err := model.UpdateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Read the acting user ID from claims. Absence is not fatal here; we fall
	// back to the nil UUID so callers without a parseable claim still succeed.
	var updatedBy uuid.UUID
	if userIDStr, ok := c.Claims["user_id"].(string); ok {
		if parsed, perr := uuid.Parse(userIDStr); perr == nil {
			updatedBy = parsed
		}
	}

	vault, err := svc.UpdateVault(r.Context(), name, *req, updatedBy)
	if err != nil {
		// The not-found sentinel maps to 404; validation and other failures are
		// client errors. GetVault above already covers the common not-found case;
		// this branch remains as defense in depth against a concurrent delete.
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInvalidParam(err.Error())
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))

	c.Logger.Printf("Vault %s updated", name)
}
```

### Step 4: Add the gate to `deleteVault`

Replace `deleteVault` (lines 175-198) with:

```go
// deleteVault handles the soft-delete of a vault by name.
func deleteVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	// Resolve the target (404) and authorize (403) before deleting. The default
	// vault resolves successfully here; the "cannot delete the default vault"
	// refusal is still enforced by DeleteVault below and surfaces as a 400.
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		c.SetNotFound("vault")
		return
	}
	if !requireVaultManage(c, r, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	if err := svc.DeleteVault(r.Context(), name); err != nil {
		// The not-found sentinel maps to 404; all other failures (such as the
		// refusal to delete the default vault) are client errors.
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInvalidParam(err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)

	c.Logger.Printf("Vault %s deleted", name)
}
```

> **Note on existing tests staying green.** `TestDeleteVault_RefusesDefault` and `TestDeleteVault_Success` use the admin role: `GetVault` succeeds, `requireVaultManage` short-circuits to `true` on the admin claim (never calling the panicking-by-default policy service unless overridden), and the pre-existing behavior (400 for default, 204 for success) is preserved.

### Step 5: Build and run the full vault test set

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "Vault" -v 2>&1 | tail -40
```

Expected: all vault handler tests (new authorization tests + pre-existing `TestCreateVault_AndList`, `TestGetVault_NotFound`, `TestDeleteVault_RefusesDefault`, `TestDeleteVault_Success`) PASS.

### Step 6: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add api/vault.go api/vault_authz_test.go && git commit -S -m "fix(vault): authorize updateVault and deleteVault against the target vault by name"
```

---

## Task 3: Full-middleware-chain 403 regression test

The Task 1-2 tests exercise the handler through `ApiSessionRequired` only. This task proves the fix holds **through the real middleware chain** — `VaultResolutionMiddleware` → `PolicyMiddleware` → `ApiSessionRequired`-wrapped handler — where a principal's `vaults:manage` grant is scoped to vault **A** (the default vault, which the middleware resolves) yet they hit `/vaults/{B's name}`. Before the fix, the ambient policy check against A passes and the handler acts on B. This end-to-end regression pins that down.

> **Gap note:** No full-chain test that wires `VaultResolutionMiddleware` together with `PolicyMiddleware` and a real handler exists anywhere in the repo today — the middleware tests in `internal/middleware/middleware_test.go:883-1010` drive `PolicyMiddleware` in isolation. This task newly establishes that harness in `package api` (which already imports `rocketvault/internal/middleware`, per `api/api.go:12`, so there is no import cycle).

**Files:**
- Modify: `api/vault_authz_test.go` (add the chained harness and regression test)

### Step 1: Write the failing test

Append to `api/vault_authz_test.go`. Add the `rocketvault/internal/middleware` import to its import block:

```go
import (
	// ...existing imports...
	"github.com/gorilla/mux"

	"rocketvault/app"
	"rocketvault/internal/middleware"
)
```

Then add:

```go
// buildChainedVaultAPI wires the production middleware chain (VaultResolution ->
// Policy) ahead of the vaults management handlers, exactly as api.go does. The
// container serves both the default vault (which VaultResolutionMiddleware falls
// back to for {name} routes) and a distinct target vault "prod".
func buildChainedVaultAPI(policySvc authzServices.AccessPolicyService) (http.Handler, uuid.UUID) {
	repo := newVaultFakeRepo()
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)

	// Default vault "A" (resolved by the middleware for /vaults/{name}).
	defID := uuid.MustParse(model.DefaultVaultID)
	repo.byName[model.DefaultVaultName] = &model.Vault{ID: defID, Name: model.DefaultVaultName, Enabled: true}
	repo.byID[defID.String()] = repo.byName[model.DefaultVaultName]

	// Target vault "B" the caller is NOT scoped to.
	prodID := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: prodID, Name: "prod", Enabled: true}
	repo.byID[prodID.String()] = repo.byName["prod"]

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
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.InitVault()
	return router, prodID
}

// TestVaultManage_ScopedToDefault_CannotReachOtherVault is the core regression:
// a non-admin whose vaults:manage grant covers ONLY the default vault gets 403
// when hitting another vault by name, even though the middleware chain's ambient
// check against the default vault passes.
func TestVaultManage_ScopedToDefault_CannotReachOtherVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	router, prodID := buildChainedVaultAPI(policySvc)

	defID := uuid.MustParse(model.DefaultVaultID)
	// Ambient middleware check against the default vault (A) is allowed...
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, defID).
		Return(authzServices.AccessAllowed, nil)
	// ...but the handler's re-check against the target vault (B) is not.
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessFallback, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, string(model.RoleUser))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}
```

Ensure `context`, `net/http/httptest`, and `rocketvault/common` are imported in `api/vault_authz_test.go` (add them to the import block if not already present).

### Step 2: Run to confirm the test fails without the fix

If Tasks 1-2 are already committed, this test passes immediately. To confirm it genuinely guards the regression, temporarily revert the `getVault` gate (comment out the `requireVaultManage` block from Task 1 Step 3), run:

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestVaultManage_ScopedToDefault_CannotReachOtherVault" -v 2>&1 | tail -20
```

Expected without the gate: **FAIL** — returns `200` because the ambient default-vault check passed. Restore the gate afterward.

### Step 3: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestVaultManage_ScopedToDefault_CannotReachOtherVault" -v 2>&1 | tail -20
```

Expected: PASS with the gate in place.

### Step 4: Run the full suite

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|^ok" | tail -40
```

Expected: all packages `ok`, no `FAIL`.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add api/vault_authz_test.go && git commit -S -m "test(vault): full middleware-chain regression for cross-vault manage authz"
```

---

## Self-Review

**Spec coverage:**
- "getVault/updateVault/deleteVault perform no authz against the target vault" → `requireVaultManage(c, r, vault.ID)` added to all three, resolving the target by name via `VaultService.GetVault`. ✅
- Design decision 1 (uniform `OpManage`; no read-level op) → `getVault` uses the same `requireVaultManage` gate as the write paths, because the `vaults` policy resource defines only `OpManage` (`internal/middleware/middleware.go:367-370`; `requireVaultManage` hard-codes `model.OpManage`). ✅
- Design decision 2 (not-found before forbidden) → each handler calls `GetVault` (404) **before** `requireVaultManage` (403); `updateVault` resolves/authorizes before body parsing and mutation. ✅
- Design decision 3 (create/list out of scope) → `createVault` and `listVaults` untouched. ✅
- Design decision 4 (full-middleware-chain regression) → Task 3 wires `VaultResolutionMiddleware` + `PolicyMiddleware` exactly as `api/api.go:67-74`, proving default-scoped `vaults:manage` yields 403 on another vault; the isolation revert step in Task 3 Step 2 confirms it fails without the fix. ✅

**Placeholder scan:** No `TODO`, `FIXME`, `TBD`, or "add appropriate error handling" placeholders. Every error branch resolves to a concrete `Set*` call (`SetNotFound`, `SetPermissionError`, `SetInvalidParam`) with a fixed status. ✅

**Type consistency (verified by reading the code):**
- `requireVaultManage(c *Context, r *http.Request, vaultID uuid.UUID) bool` — signature at `api/role_assignments.go:26`; called with `vault.ID` / `target.ID`. ✅
- `VaultService.GetVault(ctx context.Context, name string) (*model.Vault, error)` — `internal/services/vaults/vault_service.go:37,108-110`. ✅
- `model.Vault.ID` is `uuid.UUID` — `model/vault.go:26`; passes directly into `requireVaultManage`'s `uuid.UUID` param with no conversion. ✅
- `mux.Vars(r)["name"]` returns `string`, fed to `GetVault(name string)`. ✅
- `Context.SetPermissionError(permission string)` → 403 (`api/context.go:68-71`); `SetNotFound(resource string)` → 404 (`api/context.go:74-77`). ✅
- `RBACService` interface is exactly `HasPermission`, `GetRolePermissions`, `ValidateEndpointAccess` (`internal/services/authorization/rbac_service.go:58-62`) — `permissiveRBAC` implements all three. ✅
- `AccessPolicyService.CheckAccess(ctx, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error)` — matches the `mockAccessPolicyService` in `api/access_policies_test.go:46-49` and the `.On("CheckAccess", …)` argument order used in the new tests. ✅
- `middleware.NewMiddleware(container Container) *Middleware` calls `container.GetLogger()` (`internal/middleware/middleware.go:112,131`); the extended `vaultSvcTestContainer.GetLogger` returns the injected `*logging.Logger`. ✅
- `vaultSvcTestContainer` continues to satisfy both `container.ServiceContainerInterface` and `middleware.Container` — only method **bodies** changed (added fields, replaced panics), no signature changes. ✅

---

## Follow-Up

Deferred to their own spec+plan pairs (see the same list in `docs/superpowers/specs/2026-07-19-vault-management-authz-fix-design.md` §Follow-Up):

- **[High]** Introduce a shared `repositories.ErrNotFound` sentinel and thread it end-to-end so services stop string-wrapping not-found and handlers can distinguish 404 from 500 reliably.
- **[High]** Wrap the vault delete/recover cascade (`DeleteVault`/`RecoverVault` in `internal/services/vaults/vault_service.go`) in a `WithTx` transaction so a mid-cascade failure cannot leave the vault row and its contents in inconsistent soft-delete states.
- **[Medium]** (before shipping Postgres HA) Add a `pg_advisory_lock` around `SetupSchema`/`finalizeVaultIndexes` to prevent a multi-instance startup race, and consolidate the two divergent migration systems (`cmd/migrate.go`'s `MigrationRunner` vs. `internal/db/db.go`'s `migrateSchema()`).
- **[Medium]** Add a Postgres migration advisory lock and consolidate the two migration systems (`createOptimizedSchema` + `migrateSchema`) so concurrent boots cannot race the schema.
