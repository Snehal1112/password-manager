// Package api — authorization tests for vault.go management handlers.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/middleware"
	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// --- buildAuthzVaultAPI ---

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

// --- Authorization Tests ---

// TestGetVault_ForbiddenWhenNotScopedToTargetVault proves that a non-admin whose
// vaults:manage grant does NOT cover the target vault gets 403, not 200.
func TestGetVault_ForbiddenWhenNotScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	// No policy covers prod's ID -> AccessFallback -> CanManageVault denies.
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

// --- Full middleware chain regression ---

// buildChainedVaultAPI wires the production middleware chain (VaultResolution
// -> Policy -> Authorization) ahead of the vaults management handlers,
// matching api.go's ApiRoot.Use(...) order for everything except
// CORS/RateLimit/Authentication — this harness injects identity directly into
// the request context instead of validating a real bearer token, so
// AuthenticationMiddleware is intentionally not wired in. The container
// serves both the default vault (which VaultResolutionMiddleware falls back
// to for {name} routes) and a distinct target vault "prod".
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
		logger:    userTestLog(),
	}
	a := &app.App{ServiceContainer: container}
	a.Logger = userTestLog()

	mw := middleware.NewMiddleware(container)

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.ApiRoot.Use(mw.VaultResolutionMiddleware, mw.PolicyMiddleware, mw.AuthorizationMiddleware)
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
