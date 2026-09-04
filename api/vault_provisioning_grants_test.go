// Package api — unit tests for vault_provisioning_grants.go handlers.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/provisioning"
	"rocketvault/model"
)

// --- fakeGrantRepo: an in-memory VaultProvisioningGrantRepositoryInterface,
// mirroring internal/services/provisioning/grant_service_test.go's fixture of
// the same shape. Tests here exercise the real grantService on top of it,
// rather than stubbing GrantService directly, so 400s produced by the real
// model.ErrInvalidQuota/ErrInvalidPrincipal validation are exercised too. ---

type fakeGrantRepo struct {
	grants map[uuid.UUID]*model.VaultProvisioningGrant
	// getErr, when set, is returned by GetByPrincipal instead of the normal
	// not-found sentinel -- simulates a genuine lookup failure (e.g. a DB
	// outage), distinct from "no grant exists yet".
	getErr error
}

func newFakeGrantRepo() *fakeGrantRepo {
	return &fakeGrantRepo{grants: map[uuid.UUID]*model.VaultProvisioningGrant{}}
}

// Upsert mirrors the real repository's
// `ON CONFLICT (principal_id) DO UPDATE SET quota = excluded.quota`: on a
// conflicting principal_id, only Quota changes.
func (f *fakeGrantRepo) Upsert(_ context.Context, g *model.VaultProvisioningGrant) error {
	if existing, ok := f.grants[g.PrincipalID]; ok {
		existing.Quota = g.Quota
		return nil
	}
	f.grants[g.PrincipalID] = g
	return nil
}

func (f *fakeGrantRepo) GetByPrincipal(_ context.Context, id uuid.UUID) (*model.VaultProvisioningGrant, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	g, ok := f.grants[id]
	if !ok {
		return nil, repositories.ErrNotFound
	}
	return g, nil
}

func (f *fakeGrantRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.grants, id)
	return nil
}

// List mirrors the real repository's zero-value behavior: a nil slice when
// there are no grants, not an empty-but-non-nil one. Returning a non-nil
// empty slice here would make TestListGrants_EmptyReturnsEmptyArrayNotNull
// vacuous -- the handler's nil-guard could be deleted and the fake would
// still hand it a marshalable value, so the test would never notice.
func (f *fakeGrantRepo) List(_ context.Context) ([]*model.VaultProvisioningGrant, error) {
	var out []*model.VaultProvisioningGrant
	for _, g := range f.grants {
		out = append(out, g)
	}
	return out, nil
}

// LockAndReadQuotaTx satisfies the widened
// VaultProvisioningGrantRepositoryInterface. Never exercised here -- these
// tests operate purely on the HTTP-facing GrantService surface, not the
// transactional vault-creation path.
func (f *fakeGrantRepo) LockAndReadQuotaTx(_ context.Context, _ db.DBTX, _ uuid.UUID) (int, error) {
	return 0, nil
}

// --- test API construction ---

// newGrantTestAPIWithGrants builds an API whose provisioning-grant subrouter
// is wired to a real GrantService, backed by an in-memory repository
// pre-seeded with seed (may be empty).
func newGrantTestAPIWithGrants(t *testing.T, seed ...*model.VaultProvisioningGrant) *API {
	t.Helper()
	repo := newFakeGrantRepo()
	for _, g := range seed {
		repo.grants[g.PrincipalID] = g
	}
	svc := provisioning.NewGrantService(repo, nil)
	cont := &vaultSvcTestContainer{grantSvc: svc, policySvc: &mockAccessPolicyService{}, logger: userTestLog()}
	return newGrantTestAPI(cont)
}

// newGrantTestAPIWithGetErr builds a provisioning-grant test API whose
// repository fails every GetByPrincipal lookup with getErr, a genuine error
// distinct from "no grant exists yet" -- for proving that upsertVaultProvisioningGrant's
// pre-read surfaces a real lookup failure as a 500 instead of silently
// treating it as "this is a create".
func newGrantTestAPIWithGetErr(t *testing.T, getErr error) *API {
	t.Helper()
	repo := newFakeGrantRepo()
	repo.getErr = getErr
	svc := provisioning.NewGrantService(repo, nil)
	cont := &vaultSvcTestContainer{grantSvc: svc, policySvc: &mockAccessPolicyService{}, logger: userTestLog()}
	return newGrantTestAPI(cont)
}

// newGrantTestAPI builds a minimal API with only the provisioning-grant
// subrouter registered, using the given service container.
func newGrantTestAPI(cont container.ServiceContainerInterface) *API {
	a := &app.App{ServiceContainer: cont}
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
	api.BaseRoutes.VaultProvisioningGrants = api.BaseRoutes.ApiRoot.PathPrefix("/vault-provisioning-grants").Subrouter()
	api.InitVaultProvisioningGrants()
	return api
}

// doGrantRequestAs issues a request through the API router, authenticated as
// callerID holding role. Unlike doVaultRequest/doVaultRequestAs (which
// hardcode vaultTestUserID), the caller identity varies here because
// TestIssueGrant_GranteeCannotRaiseOwnQuota must authenticate AS the
// principal whose grant is under test.
func doGrantRequestAs(api *API, callerID uuid.UUID, role, method, path string, body []byte) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	ctx := context.WithValue(r.Context(), common.UserIDKey, callerID.String())
	ctx = context.WithValue(ctx, common.RoleKey, []string{role})
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)
	return w
}

// --- tests ---

func TestIssueGrant_AdminCanIssue(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)
	admin := uuid.New()
	principal := uuid.New()

	w := doGrantRequestAs(api, admin, model.RoleAdmin, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+principal.String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusCreated, w.Code)
	var got model.VaultProvisioningGrant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, 5, got.Quota)
	require.Equal(t, principal, got.PrincipalID)
}

func TestIssueGrant_NonAdminForbidden(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)

	w := doGrantRequestAs(api, uuid.New(), model.RoleUser, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+uuid.New().String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusForbidden, w.Code,
		"issuing a provisioning grant is admin-only and deliberately non-delegable")
}

func TestIssueGrant_GranteeCannotRaiseOwnQuota(t *testing.T) {
	principal := uuid.New()
	// principal already holds a grant but is not an admin.
	api := newGrantTestAPIWithGrants(t, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 2, CreatedBy: uuid.New(),
	})

	// Authenticated AS the grantee itself.
	w := doGrantRequestAs(api, principal, model.RoleUser, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+principal.String(), []byte(`{"quota":99}`))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a grantee raising its own quota would make the bound decorative")
}

func TestIssueGrant_RejectsNonPositiveQuota(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)
	admin := uuid.New()

	for _, body := range []string{`{"quota":0}`, `{"quota":-1}`} {
		w := doGrantRequestAs(api, admin, model.RoleAdmin, http.MethodPut,
			"/api/v1/vault-provisioning-grants/"+uuid.New().String(), []byte(body))
		require.Equal(t, http.StatusBadRequest, w.Code, "body %s", body)
	}
}

func TestIssueGrant_RejectsMalformedPrincipalID(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)
	admin := uuid.New()

	w := doGrantRequestAs(api, admin, model.RoleAdmin, http.MethodPut,
		"/api/v1/vault-provisioning-grants/not-a-uuid", []byte(`{"quota":5}`))

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// TestIssueGrant_NilPrincipalReportsAgainstPrincipalID proves the nil-UUID
// case -- valid UUID syntax, but model.ErrInvalidPrincipal at the service
// layer -- is reported against "principal_id", not "quota". The quota in
// this request is otherwise valid, so a "quota" message here would mislead
// a caller into looking at the wrong field.
func TestIssueGrant_NilPrincipalReportsAgainstPrincipalID(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)
	admin := uuid.New()

	w := doGrantRequestAs(api, admin, model.RoleAdmin, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+uuid.Nil.String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "principal_id")
	require.NotContains(t, w.Body.String(), "quota")
}

// TestIssueGrant_GetGrantLookupErrorSurfacesAsInternalError proves a genuine
// GetGrant failure (e.g. a DB outage) during the pre-read is reported as a
// 500, not silently swallowed and misreported as "this principal has no
// grant yet, so issue one" (which would still succeed, wrongly reporting 201
// for what may in fact already be an existing grant).
func TestIssueGrant_GetGrantLookupErrorSurfacesAsInternalError(t *testing.T) {
	api := newGrantTestAPIWithGetErr(t, errors.New("connection refused"))
	admin := uuid.New()

	w := doGrantRequestAs(api, admin, model.RoleAdmin, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+uuid.New().String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestIssueGrant_ReIssueReturns200(t *testing.T) {
	principal := uuid.New()
	api := newGrantTestAPIWithGrants(t, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 3, CreatedBy: uuid.New(),
	})
	admin := uuid.New()

	w := doGrantRequestAs(api, admin, model.RoleAdmin, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+principal.String(), []byte(`{"quota":7}`))

	require.Equal(t, http.StatusOK, w.Code,
		"re-quotaing an existing grant must be a 200, not a 201")
	var got model.VaultProvisioningGrant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, 7, got.Quota)
}

func TestRevokeGrant_AdminCanRevoke(t *testing.T) {
	principal := uuid.New()
	api := newGrantTestAPIWithGrants(t, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 5, CreatedBy: uuid.New(),
	})
	admin := uuid.New()

	w := doGrantRequestAs(api, admin, model.RoleAdmin, http.MethodDelete,
		"/api/v1/vault-provisioning-grants/"+principal.String(), nil)

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestRevokeGrant_NonAdminForbidden(t *testing.T) {
	principal := uuid.New()
	api := newGrantTestAPIWithGrants(t, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 5, CreatedBy: uuid.New(),
	})

	w := doGrantRequestAs(api, principal, model.RoleUser, http.MethodDelete,
		"/api/v1/vault-provisioning-grants/"+principal.String(), nil)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestListGrants_AdminOnly(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)

	w := doGrantRequestAs(api, uuid.New(), model.RoleUser, http.MethodGet,
		"/api/v1/vault-provisioning-grants", nil)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestListGrants_AdminSeesAll(t *testing.T) {
	api := newGrantTestAPIWithGrants(t,
		&model.VaultProvisioningGrant{ID: uuid.New(), PrincipalID: uuid.New(), Quota: 1, CreatedBy: uuid.New()},
		&model.VaultProvisioningGrant{ID: uuid.New(), PrincipalID: uuid.New(), Quota: 2, CreatedBy: uuid.New()},
	)

	w := doGrantRequestAs(api, uuid.New(), model.RoleAdmin, http.MethodGet,
		"/api/v1/vault-provisioning-grants", nil)

	require.Equal(t, http.StatusOK, w.Code)
	var got []model.VaultProvisioningGrant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got, 2)
}

// TestListGrants_EmptyReturnsEmptyArrayNotNull pins the nil-slice-to-JSON-null
// guard in listVaultProvisioningGrants: a nil slice marshals to `null`, which
// would fault a client iterating the response.
func TestListGrants_EmptyReturnsEmptyArrayNotNull(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)

	w := doGrantRequestAs(api, uuid.New(), model.RoleAdmin, http.MethodGet,
		"/api/v1/vault-provisioning-grants", nil)

	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, "[]", w.Body.String())
}

// --- route-contract pinning tests ---
//
// mapEndpointToPermission (internal/services/authorization/rbac_service.go)
// matches "vaults" as a bare prefix, and resolvePolicy
// (internal/middleware/middleware.go) matches "/vaults" as a substring.
// Neither matches "/vault-provisioning-grants" ("vault-" differs from
// "vaults" at the 6th character, and "/vault-provisioning-grants" does not
// contain "/vaults"), so these routes fall through both to no mapped
// permission/policy and reach the handler, which is the only place that
// gates them. TestMapEndpointToPermission_VaultProvisioningGrantsReturnsEmpty
// (internal/services/authorization/rbac_vault_routes_test.go) and
// TestResolvePolicy_VaultProvisioningGrantsDoesNotMatchVaultsSubstring
// (internal/middleware/middleware_test.go) pin those two mappers directly.
// The two tests below pin the handler-level consequence: a non-admin's 403
// must actually come from requireGrantAdmin (not some other gate), and an
// admin's GET must succeed rather than being diverted into vault-management
// handling.

// TestVaultProvisioningGrants_NonAdminGetsHandlerForbidden proves the 403 a
// non-admin caller gets carries requireGrantAdmin's own message, not a
// generic rejection from an unrelated mapping.
func TestVaultProvisioningGrants_NonAdminGetsHandlerForbidden(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)

	w := doGrantRequestAs(api, uuid.New(), model.RoleUser, http.MethodPut,
		"/api/v1/vault-provisioning-grants/"+uuid.New().String(), []byte(`{"quota":5}`))

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Contains(t, w.Body.String(), "admin role required",
		"the refusal must come from requireGrantAdmin, not from an unrelated middleware mapping")
}

// TestVaultProvisioningGrants_DoesNotResolveAVault proves the list route is
// not mistaken for a vault-scoped path: it reaches listVaultProvisioningGrants
// and returns 200, rather than being routed as vault-management (which would
// still require the caller resolve or hold rights on some named vault).
func TestVaultProvisioningGrants_DoesNotResolveAVault(t *testing.T) {
	api := newGrantTestAPIWithGrants(t)

	w := doGrantRequestAs(api, uuid.New(), model.RoleAdmin, http.MethodGet,
		"/api/v1/vault-provisioning-grants", nil)

	require.Equal(t, http.StatusOK, w.Code,
		"the route must not be mistaken for a vault-scoped path")
}
