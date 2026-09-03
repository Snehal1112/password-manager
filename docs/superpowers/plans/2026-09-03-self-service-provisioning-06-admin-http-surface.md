# Grant Admin HTTP Surface — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a platform operator the REST endpoints to issue, list and revoke provisioning grants — the once-per-customer action that replaces the once-per-vault support ticket.

**Architecture:** An instance-level collection, not nested under `/vaults/{name}/...`, because a grant has no vault to scope to. Routes are keyed on `principal_id`, which is `UNIQUE`, so there is no separate grant id in any URL. Gated to the global admin role only, following `requireAccessPolicyAdmin`.

**Tech Stack:** Go 1.24, gorilla/mux, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §4

**Depends on:** `…-05-scoped-list-vaults.md` (and transitively the grant service from plan 02).
**Followed by:** `…-07-cli-surface.md`.

## Global Constraints

- **This tier is non-delegable, permanently.** Only the global `admin` account role may issue, amend or revoke a grant. A grantee able to amend grants could raise its own quota and the bound would be decorative. Do not add a delegated role for this, even by analogy with `Key Vault Data Access Administrator`.
- Route registration follows `api/api.go`'s existing `BaseRoutes` pattern; new subrouters are added to the router-name list at `api/api.go:171`.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Routes and handlers

**Files:**
- Create: `api/vault_provisioning_grants.go`
- Modify: `api/api.go` (add the `VaultProvisioningGrants` subrouter beside `AccessPolicies` at lines 35-36 and 124-125; call the new init beside `api.InitAccessPolicies()` at line 158; add the router name to the list at line 171)
- Test: `api/vault_provisioning_grants_test.go`

**Interfaces:**
- Consumes: `provisioning.GrantService` via `c.App.ServiceContainer.GetGrantService()` from plan 02.
- Produces:
  - `func (api *API) InitVaultProvisioningGrants()`
  - `PUT /api/v1/vault-provisioning-grants/{principal_id}` — body `{"quota": 5}`, returns `201` on first issue, `200` on quota change
  - `DELETE /api/v1/vault-provisioning-grants/{principal_id}` — `204`
  - `GET /api/v1/vault-provisioning-grants` — `200`, array
  - `type IssueGrantRequest struct { Quota int \`json:"quota"\` }`
  - Plan 07's CLI mirrors these semantics.

- [ ] **Step 1: Write the failing test**

Create `api/vault_provisioning_grants_test.go`:

```go
func TestIssueGrant_AdminCanIssue(t *testing.T) {
	api := newTestAPIAsAdmin(t)
	principal := uuid.New()

	w := doVaultRequest(api, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+principal.String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusCreated, w.Code)
	var got model.VaultProvisioningGrant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, 5, got.Quota)
	require.Equal(t, principal, got.PrincipalID)
}

func TestIssueGrant_NonAdminForbidden(t *testing.T) {
	api := newTestAPIAsUser(t)

	w := doVaultRequest(api, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+uuid.New().String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusForbidden, w.Code,
		"issuing a provisioning grant is admin-only and deliberately non-delegable")
}

func TestIssueGrant_GranteeCannotRaiseOwnQuota(t *testing.T) {
	principal := uuid.New()
	// Authenticated AS the grantee, who holds a grant but is not an admin.
	api := newTestAPIAsGrantee(t, principal, 2)

	w := doVaultRequest(api, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+principal.String(), []byte(`{"quota":99}`))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a grantee raising its own quota would make the bound decorative")
}

func TestIssueGrant_RejectsNonPositiveQuota(t *testing.T) {
	api := newTestAPIAsAdmin(t)

	for _, body := range []string{`{"quota":0}`, `{"quota":-1}`} {
		w := doVaultRequest(api, http.MethodPut,
			"/api/v1/vault-provisioning-grants/"+uuid.New().String(), []byte(body))
		require.Equal(t, http.StatusBadRequest, w.Code, "body %s", body)
	}
}

func TestIssueGrant_RejectsMalformedPrincipalID(t *testing.T) {
	api := newTestAPIAsAdmin(t)

	w := doVaultRequest(api, http.MethodPut,
		"/api/v1/vault-provisioning-grants/not-a-uuid", []byte(`{"quota":5}`))

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeGrant_AdminCanRevoke(t *testing.T) {
	principal := uuid.New()
	api := newTestAPIAsAdminWithGrant(t, principal, 5)

	w := doVaultRequest(api, http.MethodDelete,
		"/api/v1/vault-provisioning-grants/"+principal.String(), nil)

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestListGrants_AdminOnly(t *testing.T) {
	api := newTestAPIAsUser(t)

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vault-provisioning-grants", nil)

	require.Equal(t, http.StatusForbidden, w.Code)
}
```

Build the helpers on `api/vault_webhook_test.go`'s existing `doVaultRequest` and test-API constructors.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/ -run 'TestIssueGrant|TestRevokeGrant|TestListGrants' -v`
Expected: FAIL — `404`, routes not registered.

- [ ] **Step 3: Write the handlers**

Create `api/vault_provisioning_grants.go`:

```go
package api

// Provisioning-grant management. A grant is a bounded right to create vaults,
// the delegated alternative to a global vaults:manage policy (which also
// confers authority over every vault that already exists).
//
// A grant is not scoped to any vault -- there is no vault yet when one is
// created -- so these are instance-level routes rather than sub-resources of
// /vaults/{name}, mirroring /access-policies.
//
//   - PUT    /vault-provisioning-grants/{principal_id} : issue or re-quota.
//   - DELETE /vault-provisioning-grants/{principal_id} : revoke.
//   - GET    /vault-provisioning-grants                : list all.

// InitVaultProvisioningGrants registers provisioning-grant routes.
func (api *API) InitVaultProvisioningGrants() {
	r := api.BaseRoutes.VaultProvisioningGrants
	r.Handle("", ApiSessionRequired(api.App, listVaultProvisioningGrants)).Methods("GET")
	r.Handle("/{principal_id}", ApiSessionRequired(api.App, upsertVaultProvisioningGrant)).Methods("PUT")
	r.Handle("/{principal_id}", ApiSessionRequired(api.App, deleteVaultProvisioningGrant)).Methods("DELETE")
}

// IssueGrantRequest is the body of a PUT. The principal comes from the path,
// so it is deliberately absent here -- accepting it in both places would
// invite them to disagree.
type IssueGrantRequest struct {
	Quota int `json:"quota"`
}

// requireGrantAdmin gates provisioning-grant management to the global admin
// role. This tier is deliberately non-delegable: a principal able to amend
// grants could raise its own quota, and the bound the grant exists to impose
// would be decorative. Mirrors requireAccessPolicyAdmin in api/access_policies.go.
func requireGrantAdmin(c *Context) bool {
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage vault provisioning grants")
		return false
	}
	return true
}

func upsertVaultProvisioningGrant(c *Context, w http.ResponseWriter, r *http.Request) {
	if !requireGrantAdmin(c) {
		return
	}
	principalID, err := uuid.Parse(mux.Vars(r)["principal_id"])
	if err != nil {
		c.SetInvalidParam("principal_id")
		return
	}
	var req IssueGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}

	svc := c.App.ServiceContainer.GetGrantService()
	existing, existsErr := svc.GetGrant(r.Context(), principalID)
	_ = existing

	g, err := svc.IssueGrant(r.Context(), principalID, req.Quota, c.Claims.UserID)
	if errors.Is(err, model.ErrInvalidQuota) || errors.Is(err, model.ErrInvalidPrincipal) {
		c.SetInvalidParam("quota")
		return
	}
	if err != nil {
		c.SetInternalError(err)
		return
	}

	status := http.StatusCreated
	if existsErr == nil {
		status = http.StatusOK // an existing grant was re-quotaed, not created
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(g)
}

func deleteVaultProvisioningGrant(c *Context, w http.ResponseWriter, r *http.Request) {
	if !requireGrantAdmin(c) {
		return
	}
	principalID, err := uuid.Parse(mux.Vars(r)["principal_id"])
	if err != nil {
		c.SetInvalidParam("principal_id")
		return
	}
	// Revocation stops future creation only. It deliberately leaves the
	// principal's existing vaults and its rights over them intact: cascading
	// would let one DELETE strip a customer's access to live vaults.
	if err := c.App.ServiceContainer.GetGrantService().RevokeGrant(r.Context(), principalID); err != nil {
		c.SetInternalError(err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func listVaultProvisioningGrants(c *Context, w http.ResponseWriter, r *http.Request) {
	if !requireGrantAdmin(c) {
		return
	}
	grants, err := c.App.ServiceContainer.GetGrantService().ListGrants(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}
	if grants == nil {
		grants = []*model.VaultProvisioningGrant{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(grants)
}
```

Add the imports the file needs, and match the surrounding files' error-response helpers exactly (`c.SetInvalidParam`, `c.SetPermissionError`, `c.SetInternalError`) rather than writing status codes by hand.

The `grants == nil` normalisation matters: a nil slice marshals to JSON `null`, and a client iterating the response would fault. `listSecrets` has the same guard.

- [ ] **Step 4: Register the routes**

In `api/api.go`:

```go
	VaultProvisioningGrants *mux.Router // /api/v1/vault-provisioning-grants
```

beside the `AccessPolicies` field (line 35), then beside line 124:

```go
	r.VaultProvisioningGrants = r.ApiRoot.PathPrefix("/vault-provisioning-grants").Subrouter()
```

then `api.InitVaultProvisioningGrants()` beside line 158, and `"VaultProvisioningGrants"` in the router-name list at line 171.

Confirm the new prefix does not collide with `resolvePolicy`'s `"/vaults"` match (`internal/middleware/middleware.go:422`) — `/vault-provisioning-grants` does not begin with `/vaults`, but assert it rather than assuming.

- [ ] **Step 5: Run tests**

Run: `go test ./api/ -v && go test ./internal/middleware/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add api/vault_provisioning_grants.go api/vault_provisioning_grants_test.go api/api.go
git commit -S -m "feat(api): add provisioning-grant admin endpoints"
```

---

### Task 2: Middleware and route-contract checks

**Files:**
- Test: `api/vault_provisioning_grants_test.go`, `internal/middleware/middleware_test.go`

**Interfaces:**
- Consumes: everything from task 1. Adds no new symbols.

New instance-level routes pass through `PolicyMiddleware` and `mapEndpointToPermission` like any other. `mapEndpointToPermission` (`internal/services/authorization/rbac_service.go:257`) returns `""` only for `vaults*` prefixes; whatever it returns for `vault-provisioning-grants` must not produce a confusing pre-handler rejection that masks the handler's own 403.

- [ ] **Step 1: Write the failing test**

```go
func TestVaultProvisioningGrants_NonAdminGetsHandlerForbidden(t *testing.T) {
	api := newTestAPIAsUser(t)

	w := doVaultRequest(api, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+uuid.New().String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Contains(t, w.Body.String(), "admin role required",
		"the refusal must come from requireGrantAdmin, not from an unrelated middleware mapping")
}

func TestVaultProvisioningGrants_DoesNotResolveAVault(t *testing.T) {
	api := newTestAPIAsAdmin(t)

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vault-provisioning-grants", nil)

	require.Equal(t, http.StatusOK, w.Code,
		"the route must not be mistaken for a vault-scoped path by VaultResolutionMiddleware")
}
```

- [ ] **Step 2: Run and fix**

Run: `go test ./api/ -run TestVaultProvisioningGrants -v`

If the non-admin request is rejected before reaching `requireGrantAdmin`, add an explicit case for the `vault-provisioning-grants` prefix in `mapEndpointToPermission` returning `""` (delegate to the handler), matching how `vaults*` is already handled.

- [ ] **Step 3: Assert the rate-limit interaction**

Routes that resolve no vault count against the default vault's budget (`internal/middleware/vault_rate_limit.go`). That is correct and intended here, since a grant belongs to no vault. Add a note to that effect in the handler file's header comment so a future reader does not "fix" it.

- [ ] **Step 4: Run everything and commit**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS

```bash
git add api/ internal/services/authorization/rbac_service.go internal/middleware/
git commit -S -m "test(api): pin provisioning-grant route and middleware behavior"
```
