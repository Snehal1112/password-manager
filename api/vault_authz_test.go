// Package api — authorization tests for vault.go management handlers.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/common"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/middleware"
	"rocketvault/internal/repositories"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/internal/services/provisioning"
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

// buildAuthzVaultAPIForCreate is like buildAuthzVaultAPI, but backs the vault
// service with a real in-memory SQLite database and wires TxBeginner plus a
// CreatorGranter (noopCreatorGranter, defined further down alongside
// newTestAPIWithGrant). A caller with a global vaults:manage policy is not
// quota-bounded, so GrantLocker is deliberately left unwired -- it must never
// be consulted on this path.
func buildAuthzVaultAPIForCreate(t *testing.T, policySvc authzServices.AccessPolicyService) *API {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE vaults (
		id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		purge_protection BOOLEAN NOT NULL DEFAULT 0,
		retention_days INTEGER NOT NULL DEFAULT 90,
		created_by TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		scheduled_purge_at TIMESTAMP NULL,
		tags TEXT NOT NULL DEFAULT '{}',
		updated_at TIMESTAMP NULL,
		updated_by TEXT NULL
	)`)
	require.NoError(t, err)

	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	vaultRepo := repositories.NewVaultRepository(conn, nil)

	svc := vaultServices.NewVaultService(vaultRepo, vaultNoopCascade{}, nil)
	svc.SetTxBeginner(conn)
	svc.SetCreatorGranter(noopCreatorGranter{})

	container := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		rbacSvc:   permissiveRBAC{},
		grantSvc:  &fakeGrantService{},
	}
	return newVaultTestAPIWithContainer(container)
}

// --- Authorization Tests ---

// TestGetVault_ForbiddenWhenNotScopedToTargetVault proves that a non-admin whose
// vaults:manage grant does NOT cover the target vault gets 403, not 200.
func TestGetVault_ForbiddenWhenNotScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	// No policy covers prod's ID -> AccessFallback -> CanManageVault denies.
	// A get targets one vault, so the decision comes from
	// CheckVaultScopedAccess; CheckAccess is stubbed to the same fallback so
	// the fixture describes one principal consistently.
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults/prod", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGetVault_AllowedWhenScopedToTargetVault proves that a matching vaults:manage
// grant on the target vault still returns 200. The grant is vault-scoped: that
// is the only shape that confers management of one vault, a global (vault_id
// NULL) allow no longer does.
func TestGetVault_AllowedWhenScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	api, id := buildAuthzVaultAPI(policySvc)
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, id).
		Return(authzServices.AccessAllowed, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything,
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
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
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
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything,
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
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
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
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything,
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
	api.BaseRoutes.VaultScoped = api.BaseRoutes.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
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
	// ...but the handler's vault-scoped re-check against the target vault (B)
	// is not. The handler consults CheckVaultScopedAccess; CheckAccess is
	// stubbed alongside it because PolicyMiddleware still uses that one.
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessFallback, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleUser)})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestVaultManage_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant
// proves that, through the REAL production middleware chain (VaultResolution
// -> Policy -> Authorization, with a real RBACService, not permissiveRBAC), a
// non-admin caller holding no vaults:manage grant at all is denied on every
// {name}-scoped vault-management route. createVault is covered separately by
// TestCreateVault_ForbiddenWithoutGlobalGrant, which exercises its
// handler-level global (uuid.Nil) CanManageVault check; listVaults no longer
// has an equivalent 403 case -- see
// TestListVaults_EmptyWithoutGlobalGrantOrScopedPolicy.
func TestVaultManage_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
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
			ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleUser)})
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
	// (target vault "prod") are two distinct calls; both must allow for a 200.
	// They now hit different methods: the middleware still uses CheckAccess,
	// while the handler uses the vault-scoped check. A real vault-scoped allow
	// row on "prod" satisfies both, which is why both are stubbed allowed --
	// only a NULL-scoped row would make them disagree.
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, defID).
		Return(authzServices.AccessAllowed, nil)
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessAllowed, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessAllowed, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleUser)})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (matching grant, real middleware chain)", w.Code)
	}
}

// --- Vault-purge regression: real middleware chain, soft-deleted target ---

// buildChainedVaultAPIForPurge mirrors buildChainedVaultAPI but additionally
// wires a configurable RoleAssignmentService (needed because PolicyMiddleware's
// deny-by-default check for RouteVaultData routes, e.g. purge, calls
// HasDataAction, not CheckAccess) and seeds the target vault "prod" as
// SOFT-DELETED -- purge's normal precondition, per VaultService.PurgeVault's
// own findDeleted-first logic. It returns the repo too, so callers can assert
// the vault is genuinely gone after a successful purge.
func buildChainedVaultAPIForPurge(policySvc authzServices.AccessPolicyService, roleSvc authzServices.RoleAssignmentService) (http.Handler, *vaultFakeRepo, uuid.UUID) {
	repo := newVaultFakeRepo()
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)

	// Default vault "A" (irrelevant here -- the purge route resolves via
	// {vault_name}, never falls back to the default).
	defID := uuid.MustParse(model.DefaultVaultID)
	repo.byName[model.DefaultVaultName] = &model.Vault{ID: defID, Name: model.DefaultVaultName, Enabled: true}
	repo.byID[defID.String()] = repo.byName[model.DefaultVaultName]

	// Target vault "B", soft-deleted -- the normal state a vault is purged from.
	prodID := uuid.New()
	deletedAt := nowForVaultTest()
	repo.byName["prod"] = &model.Vault{ID: prodID, Name: "prod", Enabled: true, DeletedAt: &deletedAt}
	repo.byID[prodID.String()] = repo.byName["prod"]

	container := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		roleSvc:   roleSvc,
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
	api.BaseRoutes.VaultScoped = api.BaseRoutes.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	api.InitVault()
	return router, repo, prodID
}

// TestPurgeVault_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant is the
// regression pin for the VaultResolutionMiddleware purge bug: through the
// REAL production middleware chain, a non-admin caller holding no Purge
// Operator role assignment is denied (403) when purging a SOFT-DELETED
// vault -- the normal precondition for purge. Before the middleware fix,
// VaultResolutionMiddleware's active-only GetVault call 404'd on this exact
// soft-deleted vault before PolicyMiddleware's deny-by-default check ever
// ran, so this test would have incorrectly observed 404 instead of the real
// 403 authorization decision.
func TestPurgeVault_RealAuthorizationMiddleware_NonAdminDeniedWithoutGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	roleSvc := &mockRoleAssignmentService{}
	router, _, prodID := buildChainedVaultAPIForPurge(policySvc, roleSvc)

	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, prodID, model.ActionVaultPurge).
		Return(false, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/purge", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleUser)})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestPurgeVault_GlobalAdminDeniedWithoutPurgeOperatorGrant documents an
// intentional, load-bearing asymmetry: the HTTP purge route is authorized
// entirely by PolicyMiddleware's deny-by-default HasDataAction check, which
// has NO admin bypass. A global admin holding no Key Vault Purge Operator
// assignment in the target vault is denied (403). This matches real Azure
// semantics -- Key Vault Administrator does not include vault purge, and
// model.AzureRoleDataActions deliberately omits ActionVaultPurge from that
// bundle. The CLI's `vaults purge` DOES short-circuit for admin (via
// CanPurgeVault); that is a separate, pre-existing convenience for CLI vault
// management, not a contradiction of this test.
func TestPurgeVault_GlobalAdminDeniedWithoutPurgeOperatorGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	roleSvc := &mockRoleAssignmentService{}
	router, repo, prodID := buildChainedVaultAPIForPurge(policySvc, roleSvc)

	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, prodID, model.ActionVaultPurge).
		Return(false, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/purge", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleAdmin)})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"a global admin without an explicit Purge Operator grant must be denied over HTTP")

	// The vault must still be there: the request was rejected, not performed.
	_, err := repo.ReadByID(context.Background(), prodID)
	assert.NoError(t, err, "a denied purge must not remove the vault")
}

// TestPurgeVault_RealAuthorizationMiddleware_NonAdminAllowedWithGrant proves
// the positive case through the real chain: a non-admin WITH a Purge
// Operator role assignment scoped to the target vault CAN purge it --
// including a SOFT-DELETED one, purge's normal precondition -- and it is
// genuinely gone afterward.
func TestPurgeVault_RealAuthorizationMiddleware_NonAdminAllowedWithGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	roleSvc := &mockRoleAssignmentService{}
	router, repo, prodID := buildChainedVaultAPIForPurge(policySvc, roleSvc)

	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, prodID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, prodID, model.ActionVaultPurge).
		Return(true, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/purge", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleUser)})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	_, err := repo.ReadByID(context.Background(), prodID)
	assert.Error(t, err, "purged vault must no longer be readable")
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
// (vault_id: null) vaults:manage allow policy can create a vault. After the
// global-grant narrowing, such a caller is not quota-bounded but still needs
// creator grants over what it creates -- its global allow no longer covers
// the vault it just made -- so this now takes CreateVaultProvisioned's
// transactional creator-granting path just like a provisioning-grant holder
// does, and buildAuthzVaultAPI's fake, non-transactional repo can't support
// that. buildAuthzVaultAPIForCreate backs the vault service with a real
// in-memory SQLite database and wires TxBeginner plus a CreatorGranter
// instead.
func TestCreateVault_AllowedWithGlobalGrant(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessAllowed, nil)
	api := buildAuthzVaultAPIForCreate(t, policySvc)

	body, _ := json.Marshal(map[string]any{"name": "newvault"})
	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodPost, "/api/v1/vaults", body)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestListVaults_EmptyWithoutGlobalGrantOrScopedPolicy proves list is no
// longer a global-grant-or-403 decision like createVault's: a caller with
// neither the admin role nor a global vaults:manage grant, and no scoped
// policy lister wired (buildAuthzVaultAPI does not set one), gets 200 with
// an empty list rather than a 403 -- an empty list leaks the same
// information a denial would, minus the confirmation that vaults exist.
func TestListVaults_EmptyWithoutGlobalGrantOrScopedPolicy(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	var got model.ListVaultsResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Empty(t, got.Vaults)
}

// --- CanCreateVault three-way decision: provisioning-grant path ---

// fakeGrantService is a minimal test double for provisioning.GrantService,
// returning a fixed grant (or ErrGrantNotFound) for any principal. Only
// GetGrant is exercised by CanCreateVault; the remaining methods are unused
// here and are no-ops.
type fakeGrantService struct {
	grant *model.VaultProvisioningGrant
}

func (f *fakeGrantService) IssueGrant(context.Context, uuid.UUID, int, uuid.UUID) (*model.VaultProvisioningGrant, error) {
	return nil, nil
}

func (f *fakeGrantService) GetGrant(context.Context, uuid.UUID) (*model.VaultProvisioningGrant, error) {
	if f.grant == nil {
		return nil, provisioning.ErrGrantNotFound
	}
	return f.grant, nil
}

func (f *fakeGrantService) RevokeGrant(context.Context, uuid.UUID, uuid.UUID) error { return nil }

func (f *fakeGrantService) ListGrants(context.Context) ([]*model.VaultProvisioningGrant, error) {
	return nil, nil
}

// noopCreatorGranter satisfies vaultServices.CreatorGranter by accepting
// every write and recording nothing -- this package's tests only need the
// quota-bounded create to succeed, not to inspect the grant rows it writes
// (that's covered in internal/services/vaults/vault_provisioned_create_test.go).
type noopCreatorGranter struct{}

func (noopCreatorGranter) CreatePolicyTx(context.Context, rvdb.DBTX, *model.AccessPolicy) error {
	return nil
}

func (noopCreatorGranter) CreateRoleTx(context.Context, rvdb.DBTX, *model.RoleAssignment) error {
	return nil
}

// newTestAPIWithGrant builds a vault API whose caller holds a provisioning
// grant but neither the admin role nor a global vaults:manage policy --
// exercising createVault's CreateRightProvisioningGrant path. The caller in
// every doVaultRequestAs request carries the fixed vaultTestUserID, so
// principalID is not used to key the fake grantSvc -- it mirrors
// internal/services/authorization/vault_authz_test.go's stubGrantReader,
// which returns its fixed grant/error for any principal. That fake only
// drives CanCreateVault's authorization decision, though: the handler now
// calls CreateVaultProvisioned(quotaBounded=true), whose own quota check
// runs inside a real transaction against the real vault and
// vault_provisioning_grants tables (vault_service.go's row-lock quota
// check), so this helper backs the vault service with a real in-memory
// SQLite database and seeds a grant row keyed to vaultTestUserID -- the
// only principal that will ever actually be checked.
func newTestAPIWithGrant(t *testing.T, principalID uuid.UUID, quota int) *API {
	t.Helper()
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessFallback, nil)

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE vaults (
		id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		purge_protection BOOLEAN NOT NULL DEFAULT 0,
		retention_days INTEGER NOT NULL DEFAULT 90,
		created_by TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		scheduled_purge_at TIMESTAMP NULL,
		tags TEXT NOT NULL DEFAULT '{}',
		updated_at TIMESTAMP NULL,
		updated_by TEXT NULL
	)`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`CREATE TABLE vault_provisioning_grants (
		id TEXT PRIMARY KEY,
		principal_id TEXT UNIQUE NOT NULL,
		quota INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT NOT NULL
	)`)
	require.NoError(t, err)

	callerID := uuid.MustParse(vaultTestUserID)
	_, err = sqlDB.Exec(
		"INSERT INTO vault_provisioning_grants (id, principal_id, quota, created_by) VALUES (?, ?, ?, ?)",
		uuid.New().String(), callerID.String(), quota, callerID.String())
	require.NoError(t, err)

	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	vaultRepo := repositories.NewVaultRepository(conn, nil)
	grantRepo := repositories.NewVaultProvisioningGrantRepository(conn)

	svc := vaultServices.NewVaultService(vaultRepo, vaultNoopCascade{}, nil)
	svc.SetTxBeginner(conn)
	svc.SetGrantLocker(grantRepo)
	// CreatorGranter must be wired too: vaultService.CreateVaultProvisioned
	// fails closed when it's nil (a quota-bounded create whose creator ends
	// up with no rights over what it made would permanently strand a quota
	// slot). This handler-level test only cares that the create succeeds, not
	// what the grant writes contain -- see
	// internal/services/vaults/vault_provisioned_create_test.go for that.
	svc.SetCreatorGranter(noopCreatorGranter{})

	grant := &model.VaultProvisioningGrant{ID: uuid.New(), PrincipalID: principalID, Quota: quota}
	cont := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		rbacSvc:   permissiveRBAC{},
		grantSvc:  &fakeGrantService{grant: grant},
	}
	return newVaultTestAPIWithContainer(cont)
}

// newTestAPINoGrant builds a vault API whose caller holds none of the three
// creation rights: no admin role, no global vaults:manage policy, and no
// provisioning grant.
func newTestAPINoGrant(t *testing.T) *API {
	t.Helper()
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessFallback, nil)
	repo := newVaultFakeRepo()
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	cont := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		rbacSvc:   permissiveRBAC{},
		grantSvc:  &fakeGrantService{},
	}
	return newVaultTestAPIWithContainer(cont)
}

// TestCreateVault_ProvisioningGrantHolderAllowed proves a non-admin caller
// with no global policy but a provisioning grant can still create a vault --
// the new CreateRightProvisioningGrant path.
func TestCreateVault_ProvisioningGrantHolderAllowed(t *testing.T) {
	api := newTestAPIWithGrant(t, uuid.New(), 5)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodPost, "/api/v1/vaults",
		[]byte(`{"name":"acme-prod"}`))

	require.Equal(t, http.StatusCreated, w.Code,
		"a provisioning-grant holder must be able to create a vault")
}

// TestCreateVault_NoRightStillForbidden proves a caller with none of the
// three rights -- admin, global policy, or provisioning grant -- is still
// refused.
func TestCreateVault_NoRightStillForbidden(t *testing.T) {
	api := newTestAPINoGrant(t)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodPost, "/api/v1/vaults",
		[]byte(`{"name":"acme-prod"}`))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a principal with neither admin, a global policy, nor a grant is still refused")
}
