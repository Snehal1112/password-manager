# API Vault Handlers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the last handler-level gap in vault management (`createVault`/`listVaults` had no check at all), migrate `getVault`/`updateVault`/`deleteVault` from the old `requireVaultManage` to the new shared `CanManageVault`, and add the vault-purge HTTP endpoint.

**Architecture:** `api/vault.go` gains a small `callerIdentity` helper (shared by all six handlers in the file) and calls into `internal/services/authorization`'s `CanManageVault`. The new `purgeVault` handler needs no explicit authorization call of its own — it's registered on the vault-scoped router, so `PolicyMiddleware`'s existing deny-by-default `RouteVaultData` check (wired to `ActionVaultPurge` in Plan 3) authorizes it, the same way every secrets/keys/certificates route already works.

**Tech Stack:** Go, `net/http/httptest`, `github.com/stretchr/testify/assert`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` — read §2 and §3 before starting.
- Depends on: Plan `2026-08-11-01` (data model), Plan `2026-08-11-02` (`CanManageVault`), Plan `2026-08-11-03` (global gate removed, `ActionVaultPurge` route mapping).
- `createVault`/`listVaults` use the "global-only" grant check: pass `uuid.Nil` as the vault ID to `CanManageVault`, which — because `AccessPolicyService.CheckAccess` matches `vault_id = ? OR vault_id IS NULL`, and no real vault has ID `uuid.Nil` — only matches a *global* (`vault_id: null`) `vaults:manage` allow policy, not a vault-specific one. This is a deliberate, narrower interpretation than "any vault-scoped grant" (which would require a new repository query this design does not add) — document this precisely in code comments, and do not silently broaden it.
- `requireVaultManage` (`api/role_assignments.go`) is **not** deleted in this plan — `api/role_assignments.go` still calls it until Plan `2026-08-11-05` migrates those call sites too.
- `go build ./...` and `go vet ./...` must pass after every task.

---

### Task 1: `createVault` gains an authorization check

**Files:**
- Modify: `api/vault.go:1-86` (imports + `createVault`)
- Test: `api/vault_authz_test.go` (append)

**Interfaces:**
- Consumes: `authorization.CanManageVault(ctx, accountRole string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool` (Plan 2, Task 1).
- Produces: a new unexported `callerIdentity(c *Context) (role string, principalID uuid.UUID, ok bool)` helper in `api/vault.go`, reused by every task in this plan.

- [ ] **Step 1: Write the failing test**

Append to `api/vault_authz_test.go`:

```go
// TestCreateVault_ForbiddenWithoutGlobalGrant proves a non-admin with no
// global vaults:manage policy cannot create a vault. Before this task,
// createVault had no handler-level check at all — it relied entirely on the
// now-removed global admin-only gate (Plan 2026-08-11-03).
func TestCreateVault_ForbiddenWithoutGlobalGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	body, _ := json.Marshal(map[string]any{"name": "newvault"})
	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodPost, "/api/v1/vaults", body)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestCreateVault_AllowedWithGlobalGrant proves a non-admin WITH a global
// (vault_id: null) vaults:manage allow policy can create a vault.
func TestCreateVault_AllowedWithGlobalGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessAllowed, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	body, _ := json.Marshal(map[string]any{"name": "newvault"})
	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodPost, "/api/v1/vaults", body)
	assert.Equal(t, http.StatusCreated, w.Code)
}
```

`json` must already be imported in `api/vault_authz_test.go` — if not, add `"encoding/json"` to its import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run 'TestCreateVault_ForbiddenWithoutGlobalGrant|TestCreateVault_AllowedWithGlobalGrant' -v`
Expected: FAIL — both currently return 201 regardless of the mock (no check exists yet), so `TestCreateVault_ForbiddenWithoutGlobalGrant` fails (got 201, want 403); `TestCreateVault_AllowedWithGlobalGrant` passes by coincidence today but must remain passing after the fix — run both to establish the baseline.

- [ ] **Step 3: Add the `callerIdentity` helper and wire the check**

In `api/vault.go`, add `authzServices "rocketvault/internal/services/authorization"` to the import block (currently: `"errors"`, `"net/http"`, `"github.com/google/uuid"`, `"github.com/gorilla/mux"`, `vaultServices "rocketvault/internal/services/vaults"`, `"rocketvault/model"`).

Add this helper function anywhere in `api/vault.go` above `createVault` (e.g. immediately after the `vaultSvc` helper, currently ending at line 46):

```go

// callerIdentity extracts the acting principal's account role and user ID
// from the session claims. Returns ok=false if either is missing or
// malformed, in which case the caller must treat this as an internal error,
// not a permission denial — a malformed claim is a bug, not a 403.
func callerIdentity(c *Context) (role string, principalID uuid.UUID, ok bool) {
	role, _ = c.Claims["role"].(string)
	userIDStr, _ := c.Claims["user_id"].(string)
	principalID, err := uuid.Parse(userIDStr)
	return role, principalID, err == nil
}
```

Replace `createVault` (currently lines 48-86):

```go
// createVault handles the creation of a new vault.
func createVault(c *Context, w http.ResponseWriter, r *http.Request) {
	req, err := model.CreateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Get the creator user ID from JWT claims.
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.CreateVault(r.Context(), *req, userID)
	if err != nil {
		// Validation and duplicate failures are client errors.
		c.SetInvalidParam(err.Error())
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson()))

	c.Logger.Printf("User %s created vault %s", userIDStr, vault.Name)
}
```

with:

```go
// createVault handles the creation of a new vault. Vault creation has no
// single target vault to check against, so the authorization check uses
// uuid.Nil, matching only a GLOBAL (vault_id: null) vaults:manage allow
// policy — a vault-scoped grant on some other existing vault does not confer
// the ability to create a new one. See the design doc §2 for why this is a
// deliberately narrower interpretation than "any vault-scoped grant".
func createVault(c *Context, w http.ResponseWriter, r *http.Request) {
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, uuid.Nil) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	req, err := model.CreateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.CreateVault(r.Context(), *req, userID)
	if err != nil {
		// Validation and duplicate failures are client errors.
		c.SetInvalidParam(err.Error())
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson()))

	c.Logger.Printf("User %s created vault %s", userID, vault.Name)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./api/... -run 'TestCreateVault' -v`
Expected: PASS. Also run `go test ./api/... -v` in full to confirm `TestCreateVault_AndList` (`api/vault_test.go`, uses `doVaultRequest` with `model.RoleAdmin` — unaffected, admin always passes) still passes.

- [ ] **Step 5: Commit**

```bash
git add api/vault.go api/vault_authz_test.go
git commit -m "fix(api): require an authorization check on createVault"
```

---

### Task 2: `listVaults` check + migrate `getVault`/`updateVault`/`deleteVault` to `CanManageVault`

**Files:**
- Modify: `api/vault.go:88-258` (`listVaults`, `getVault`, `updateVault`, `deleteVault`)
- Test: `api/vault_authz_test.go` (append)

**Interfaces:**
- Consumes: `callerIdentity` (Task 1), `authorization.CanManageVault` (Plan 2).
- Produces: `getVault`/`updateVault`/`deleteVault` no longer call `requireVaultManage`; their behavior is otherwise unchanged (same admin short-circuit, same access-policy fallback, same vault-ID-under-test).

- [ ] **Step 1: Write the failing test**

Append to `api/vault_authz_test.go`:

```go
// TestListVaults_ForbiddenWithoutGlobalGrant mirrors TestCreateVault's case
// for the list endpoint.
func TestListVaults_ForbiddenWithoutGlobalGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestListVaults_ForbiddenWithoutGlobalGrant -v`
Expected: FAIL — got 200, want 403 (no check exists on `listVaults` yet).

- [ ] **Step 3: Wire the check into `listVaults`, and swap the other three handlers**

Replace `listVaults` (currently lines 88-115):

```go
// listVaults handles the request to list vaults, optionally including soft-deleted ones.
func listVaults(c *Context, w http.ResponseWriter, r *http.Request) {
	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	vaults, err := svc.ListVaults(r.Context(), includeDeleted)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	responses := make([]model.VaultResponse, len(vaults))
	for i := range vaults {
		responses[i] = vaults[i].ToResponse()
	}

	response := model.ListVaultsResponse{
		Vaults: responses,
		Total:  len(responses),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}
```

with:

```go
// listVaults handles the request to list vaults, optionally including
// soft-deleted ones. Like createVault, there is no single target vault, so
// the check uses uuid.Nil (global grant only — see createVault's comment).
func listVaults(c *Context, w http.ResponseWriter, r *http.Request) {
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, uuid.Nil) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	vaults, err := svc.ListVaults(r.Context(), includeDeleted)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	responses := make([]model.VaultResponse, len(vaults))
	for i := range vaults {
		responses[i] = vaults[i].ToResponse()
	}

	response := model.ListVaultsResponse{
		Vaults: responses,
		Total:  len(responses),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}
```

In `getVault`, replace:

```go
	// Authorize against the TARGET vault named in the path. These {name} routes
	// bypass VaultResolutionMiddleware, so PolicyMiddleware only evaluated the
	// default vault; re-check vaults:manage against this vault's own ID.
	if !requireVaultManage(c, r, vault.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
```

with:

```go
	// Authorize against the TARGET vault named in the path. These {name} routes
	// bypass VaultResolutionMiddleware, so PolicyMiddleware only evaluated the
	// default vault; re-check vaults:manage against this vault's own ID.
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, vault.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
```

In `updateVault`, replace:

```go
	if !requireVaultManage(c, r, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
```

with:

```go
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
```

Note: `updateVault` later re-derives `updatedBy` from claims with its own block (`var updatedBy uuid.UUID; if userIDStr, ok := c.Claims["user_id"].(string); ...`). Since `callerIdentity` now already parses `userID` earlier in the same function, replace that later block:

```go
	// Read the acting user ID from claims. Absence is not fatal here; we fall
	// back to the nil UUID so callers without a parseable claim still succeed.
	var updatedBy uuid.UUID
	if userIDStr, ok := c.Claims["user_id"].(string); ok {
		if parsed, perr := uuid.Parse(userIDStr); perr == nil {
			updatedBy = parsed
		}
	}

	vault, err := svc.UpdateVault(r.Context(), name, *req, updatedBy)
```

with:

```go
	vault, err := svc.UpdateVault(r.Context(), name, *req, userID)
```

(`userID` here is guaranteed valid — `callerIdentity` already returned `ok=true` — so the separate "absence is not fatal" fallback is no longer needed; the authorization check above it already requires a parseable identity.)

In `deleteVault`, replace:

```go
	if !requireVaultManage(c, r, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
```

with:

```go
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	_ = userID // not needed by DeleteVault; identity is only used for the check above
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./api/... -v`
Expected: PASS for the entire package — in particular, every pre-existing `TestGetVault_*`, `TestUpdateVault_*`, `TestDeleteVault_*` test (`api/vault_test.go`, `api/vault_authz_test.go`) must still pass unchanged, since `CanManageVault`'s behavior for a non-nil vault ID is identical to the old `requireVaultManage`'s.

- [ ] **Step 5: Commit**

```bash
git add api/vault.go api/vault_authz_test.go
git commit -m "fix(api): require an authorization check on listVaults; migrate getVault/updateVault/deleteVault to CanManageVault"
```

---

### Task 3: Vault-purge HTTP endpoint

**Files:**
- Modify: `internal/services/vaults/vault_service.go:22-27` (new sentinel), `:368-406` (`PurgeVault`)
- Modify: `api/vault.go` (new `purgeVault` handler, updated `InitVault`)
- Modify: `api/api.go:29-37` (`InitVault`'s doc comment — mention the new route)
- Modify: `api/vault_test.go:322-342` (`newVaultTestAPI`), `:476-492` (`newVaultTestAPIWithContainer`) — wire `VaultScoped`
- Modify: `api/vault_authz_test.go:130-162` (`buildChainedVaultAPI`) — wire `VaultScoped`
- Test: `api/vault_test.go` (append)

**Interfaces:**
- Consumes: `vaultServices.VaultService.PurgeVault(ctx, name string) error` (existing), `mux.Vars(r)["vault_name"]` (existing pattern, used identically by `api/role_assignments.go`).
- Produces: `vaultServices.ErrVaultPurgeProtected` (new sentinel), `DELETE /api/v1/vaults/{vault_name}/purge` → 204 on success, 404 if the vault doesn't exist, 400 if it's the default vault or purge-protected, 403 if no role assignment grants `ActionVaultPurge` in that vault (enforced by `PolicyMiddleware`, not this handler).

- [ ] **Step 1: Wire `VaultScoped` into the three test-harness builders that call `InitVault`**

This must happen before writing the failing test below — without it, `InitVault` (once it registers a route on `api.BaseRoutes.VaultScoped`, added in Step 4) will nil-pointer-panic in every existing test that calls it, not just the new one.

In `api/vault_test.go`, `newVaultTestAPI` (currently lines 322-342), change:

```go
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.InitVault()
	return api, repo
```

to:

```go
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.BaseRoutes.VaultScoped = api.BaseRoutes.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	api.InitVault()
	return api, repo
```

In the same file, `newVaultTestAPIWithContainer` (currently lines 476-492), apply the identical change (same two lines: add `VaultScoped` before `InitVault()`).

In `api/vault_authz_test.go`, `buildChainedVaultAPI` (currently around lines 130-162, already modified by Plan `2026-08-11-03`), change:

```go
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.InitVault()
	return router, prodID
```

to:

```go
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.BaseRoutes.VaultScoped = api.BaseRoutes.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	api.InitVault()
	return router, prodID
```

Run `go build ./...` now to confirm this alone compiles (it should — `VaultScoped` already exists as a field on `Routes`, `api/api.go:22`).

- [ ] **Step 2: Write the failing tests**

Append to `api/vault_test.go`:

```go
// TestPurgeVault_Success permanently removes a soft-deleted vault.
func TestPurgeVault_Success(t *testing.T) {
	api, repo := newVaultTestAPI()
	id := uuid.New()
	deletedAt := nowForVaultTest()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true, DeletedAt: &deletedAt}
	repo.byID[id.String()] = repo.byName["stg"]

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg/purge", nil)
	assert.Equal(t, http.StatusNoContent, w.Code)

	_, err := repo.ReadByID(context.Background(), id)
	assert.Error(t, err, "purged vault must no longer be readable")
}

// TestPurgeVault_RefusesDefault confirms the default vault cannot be purged.
func TestPurgeVault_RefusesDefault(t *testing.T) {
	api, repo := newVaultTestAPI()
	defID := uuid.MustParse(model.DefaultVaultID)
	repo.byName[model.DefaultVaultName] = &model.Vault{ID: defID, Name: model.DefaultVaultName, Enabled: true}
	repo.byID[defID.String()] = repo.byName[model.DefaultVaultName]

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/"+model.DefaultVaultName+"/purge", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPurgeVault_RefusesPurgeProtected confirms a purge-protected vault cannot be purged.
func TestPurgeVault_RefusesPurgeProtected(t *testing.T) {
	api, repo := newVaultTestAPI()
	id := uuid.New()
	deletedAt := nowForVaultTest()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true, PurgeProtection: true, DeletedAt: &deletedAt}
	repo.byID[id.String()] = repo.byName["stg"]

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg/purge", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPurgeVault_NotFound confirms a missing vault returns 404.
func TestPurgeVault_NotFound(t *testing.T) {
	api, _ := newVaultTestAPI()

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/ghost/purge", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
```

`"context"` must already be imported in `api/vault_test.go` — it is (used by the fake repo methods).

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./api/... -run TestPurgeVault -v`
Expected: FAIL with 404 on every case (no route matches `/purge` yet, since `InitVault` doesn't register it) — except `TestPurgeVault_NotFound`, which would misleadingly pass (both "no route" and "vault not found" produce 404). This is fine; Step 5 below confirms the real behavior once the route exists.

- [ ] **Step 4: Add the `ErrVaultPurgeProtected` sentinel and fix `PurgeVault`'s error wrapping**

In `internal/services/vaults/vault_service.go`, immediately after the existing `ErrDefaultVaultProtected` declaration (currently lines 25-27):

```go
// ErrDefaultVaultProtected is returned when an operation refuses to act on
// the default vault (e.g. delete, purge).
var ErrDefaultVaultProtected = errors.New("default vault is protected from this operation")
```

add:

```go

// ErrVaultPurgeProtected is returned when PurgeVault refuses to act because
// the vault has purge protection enabled.
var ErrVaultPurgeProtected = errors.New("vault is protected from purge")
```

Then, in `PurgeVault` (currently lines 369-406), replace:

```go
func (s *vaultService) PurgeVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be purged")
	}
```

with:

```go
func (s *vaultService) PurgeVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be purged: %w", ErrDefaultVaultProtected)
	}
```

and replace:

```go
	if v.PurgeProtection {
		return fmt.Errorf("vault %q is protected from purge", name)
	}
```

with:

```go
	if v.PurgeProtection {
		return fmt.Errorf("vault %q is protected from purge: %w", name, ErrVaultPurgeProtected)
	}
```

- [ ] **Step 5: Add the `purgeVault` handler and route registration**

In `api/vault.go`, append the new handler after `deleteVault` (end of file):

```go

// purgeVault permanently removes a vault. Registered on the vault-scoped
// router (/vaults/{vault_name}/purge), so VaultResolutionMiddleware resolves
// the target vault and PolicyMiddleware's deny-by-default check (RouteVaultData,
// ActionVaultPurge — internal/services/authorization/data_actions.go) already
// authorizes the request before this handler runs. No handler-level
// authorization call is needed here, matching every other vault data-plane
// route (secrets/keys/certificates).
func purgeVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["vault_name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	if err := svc.PurgeVault(r.Context(), name); err != nil {
		switch {
		case errors.Is(err, vaultServices.ErrVaultNotFound):
			c.SetNotFound("vault")
		case errors.Is(err, vaultServices.ErrDefaultVaultProtected), errors.Is(err, vaultServices.ErrVaultPurgeProtected):
			c.SetInvalidParam(err.Error())
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
	c.Logger.Printf("Vault %s purged", name)
}
```

Then update `InitVault` (currently lines 29-37):

```go
func (api *API) InitVault() {
	v := api.BaseRoutes.Vaults

	v.Handle("", ApiSessionRequired(api.App, createVault)).Methods("POST")
	v.Handle("", ApiSessionRequired(api.App, listVaults)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, getVault)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, updateVault)).Methods("PATCH")
	v.Handle("/{name}", ApiSessionRequired(api.App, deleteVault)).Methods("DELETE")
}
```

to:

```go
func (api *API) InitVault() {
	v := api.BaseRoutes.Vaults

	v.Handle("", ApiSessionRequired(api.App, createVault)).Methods("POST")
	v.Handle("", ApiSessionRequired(api.App, listVaults)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, getVault)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, updateVault)).Methods("PATCH")
	v.Handle("/{name}", ApiSessionRequired(api.App, deleteVault)).Methods("DELETE")

	// Vault-scoped: resolved via VaultResolutionMiddleware, authorized via
	// PolicyMiddleware's deny-by-default data-plane check, not a handler-level one.
	api.BaseRoutes.VaultScoped.Handle("/purge", ApiSessionRequired(api.App, purgeVault)).Methods("DELETE")
}
```

Also update the doc comment immediately above `InitVault` (currently lines 14-23) to add the new endpoint to the list:

```go
//   - POST   /vaults         : Create a new vault.
//   - GET    /vaults         : List vaults (honors ?include_deleted=true).
//   - GET    /vaults/{name}  : Get a vault by name.
//   - PATCH  /vaults/{name}  : Update a vault.
//   - DELETE /vaults/{name}  : Soft-delete a vault.
//   - DELETE /vaults/{vault_name}/purge : Permanently purge a vault.
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./api/... ./internal/services/vaults/... -v`
Expected: PASS across both packages, with zero regressions — confirm specifically that `TestDeleteVault_RefusesDefault` (`api/vault_test.go`) still passes (it exercises `DeleteVault`'s own, separately-worded `ErrDefaultVaultProtected` wrapping, which this task does not touch) and that no test relies on `PurgeVault`'s old, unwrapped error strings.

- [ ] **Step 7: Commit**

```bash
git add internal/services/vaults/vault_service.go api/vault.go api/api.go api/vault_test.go api/vault_authz_test.go
git commit -m "feat(api): add DELETE /vaults/{vault_name}/purge endpoint"
```

---

## Verification Gate (run before considering this plan complete)

```bash
go build ./...
go vet ./...
go test ./api/... ./internal/services/vaults/... ./internal/services/authorization/... -v
```

All must pass. Manually verify the new endpoint end-to-end once the server can run against a real database:

```bash
go run main.go serve &
# ... bootstrap admin, log in, create+delete a vault named "tmp" ...
curl -s -i -X DELETE $BASE/api/v1/vaults/tmp/purge -H "Authorization: Bearer $TOKEN"
# Expected: 204 with a valid role assignment or admin; 403 without one.
```
