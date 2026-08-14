package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/repositories"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

type scopeStubCertService struct {
	certServices.CertificateService

	cert      *model.Certificate
	certErr   error
	list      []model.Certificate
	lastScope model.Scope

	// policyRepo backs the certificate-policy methods below. Tests that only
	// exercise the cert-access denial path (certErr set) never reach it.
	policyRepo repositories.CertificatePolicyRepositoryInterface
}

func (s *scopeStubCertService) GetCertificate(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	s.lastScope = scope
	return s.cert, s.certErr
}

func (s *scopeStubCertService) ListCertificates(_ context.Context, scope model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	s.lastScope = scope
	return s.list, nil
}

// GetCertificatePolicy, UpsertCertificatePolicy and DeleteCertificatePolicy
// mirror the real CertificateService: verify cert access first (recording the
// scope via GetCertificate above), then delegate to policyRepo.

func (s *scopeStubCertService) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByCertificateIDAny(ctx, certID)
}

func (s *scopeStubCertService) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return nil, err
	}
	now := time.Now()
	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           scope.ActorID(),
		ValidityMonths:   req.ValidityMonths,
		KeyType:          req.KeyType,
		KeySize:          req.KeySize,
		Curve:            req.Curve,
		Subject:          req.Subject,
		SANs:             req.SANs,
		AutoRenew:        req.AutoRenew,
		DaysBeforeExpiry: req.DaysBeforeExpiry,
		IssuerName:       req.IssuerName,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByCertificateIDAny(ctx, certID)
}

func (s *scopeStubCertService) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return err
	}
	return s.policyRepo.DeleteByCertificateIDAny(ctx, certID)
}

// newCertHandlerFixture wires a Context whose container returns svc as the
// certificate service. vaultName != "" marks a vault-scoped route.
func newCertHandlerFixture(t *testing.T, svc certServices.CertificateService, certID uuid.UUID,
	vaultName string) (*Context, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	c := newCertCtx(svc, jwt.MapClaims{"user_id": uuid.NewString()})
	c.Params.CertificateID = certID.String()

	return c, httptest.NewRecorder(), newScopeRequest(t, uuid.New(), vaultName)
}

func TestListCertificatesUsesTheScopeFromTheRoute(t *testing.T) {
	svc := &scopeStubCertService{list: []model.Certificate{{ID: uuid.New(), Name: "c"}}}

	c, w, r := newCertHandlerFixture(t, svc, uuid.New(), "team-a")
	listCertificates(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())

	c, w, r = newCertHandlerFixture(t, svc, uuid.New(), "")
	listCertificates(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
}

func TestGetCertificateMapsErrors(t *testing.T) {
	certID := uuid.New()

	svc := &scopeStubCertService{certErr: certServices.ErrCertLifecycleDenied}
	c, w, r := newCertHandlerFixture(t, svc, certID, "team-a")
	getCertificate(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)

	svc = &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	c, w, r = newCertHandlerFixture(t, svc, certID, "team-a")
	getCertificate(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}

func TestGetCertificatePolicyResolvesTheCertificateThroughTheScope(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	c, w, r := newCertHandlerFixture(t, svc, certID, "team-a")

	getCertificatePolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}

// --- Flat-route certificate-policy ownership boundary ---
//
// Inlining the route-type check into scopeFromRequest had a second, intentional
// effect on the three certificate-policy handlers, not just a mechanical rename.
// Before this task:
//
//   - getCertificatePolicy/deleteCertificatePolicy's flat-route branch
//     authorized on repo.GetByCertificateID(ctx, certID, userID) /
//     DeleteByCertificateID(ctx, certID, userID) alone -- i.e. "did this
//     caller author the certificate_policies row" (certificate_policies.user_id).
//   - upsertCertificatePolicy's flat-route branch had NO certificate check
//     at all: the `if vaultScoped { ... }` guard in the old code meant any
//     authenticated caller could create or replace a policy for any
//     certificate_id, whether or not they had ever seen that certificate.
//
// Resolving the certificate through certService.GetCertificate first
// closes both gaps: all three handlers now authorize on "does the caller own
// the certificate" (certificates.user_id, via the scope), then use the
// owner-agnostic policy-repository method because the scope already vouched
// for the certificate. These tests pin that boundary on the flat route,
// mirroring the vault-scoped equivalents in vault_scoped_keys_certs_test.go
// (TestGetCertificatePolicy_VaultScopedRoute_UsesGetByCertificateIDAny,
// TestUpsertCertificatePolicy_VaultScopedRoute_VerifiesCertInVaultFirst).

// newCertPolicyScopeCtx builds a Context wired with both a certificate
// service and a certificate-policy repository, for testing the
// certificate-ownership boundary on the flat-route policy handlers. The
// handlers under test only ever go through svc, but when svc is the
// hand-rolled scopeStubCertService its own policy methods delegate to repo,
// so wire it through here for callers that don't set it themselves.
func newCertPolicyScopeCtx(svc certServices.CertificateService,
	repo repositories.CertificatePolicyRepositoryInterface, certID uuid.UUID) *Context {
	if stub, ok := svc.(*scopeStubCertService); ok && stub.policyRepo == nil {
		stub.policyRepo = repo
	}
	a := &app.App{ServiceContainer: &certSvcContainer{certSvc: svc, certPolicyRepo: repo}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"user_id": uuid.NewString()},
		Params: &ApiParams{CertificateID: certID.String(), PerPage: 60},
	}
}

// newFlatPolicyRequest builds a legacy flat-route request (no vault_name path
// variable, so scopeFromRequest yields an owner scope) for a
// certificate-policy endpoint, with an optional body.
func newFlatPolicyRequest(t *testing.T, method string, certID uuid.UUID, body []byte) *http.Request {
	t.Helper()

	path := "/api/v1/certificates/" + certID.String() + "/policy"
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	return r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, uuid.New().String()))
}

// TestUpsertCertificatePolicy_FlatRouteDeniesNonOwnedCertificate pins the
// certificate-ownership check upsertCertificatePolicy gained as a side effect
// of this task. Before this task, the flat route performed no certificate
// check whatsoever: any authenticated caller could create or replace a
// policy for any certificate_id. GetCertificate failing must now deny
// the request before the policy repository is ever touched.
func TestUpsertCertificatePolicy_FlatRouteDeniesNonOwnedCertificate(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	repo := &mockCertPolicyRepo{}

	c := newCertPolicyScopeCtx(svc, repo, certID)
	w := httptest.NewRecorder()
	body := []byte(`{"validity_months":12,"key_type":"RSA","key_size":2048}`)
	r := newFlatPolicyRequest(t, http.MethodPut, certID, body)

	upsertCertificatePolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
	repo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
}

// TestUpsertCertificatePolicy_FlatRouteAllowsOwnedCertificate confirms the
// same-owner case still succeeds once the new ownership check is in place.
func TestUpsertCertificatePolicy_FlatRouteAllowsOwnedCertificate(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{} // GetCertificate succeeds (nil, nil).
	repo := &mockCertPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(nil)
	repo.On("GetByCertificateIDAny", mock.Anything, certID).Return(&model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certID, ValidityMonths: 12,
	}, nil)

	c := newCertPolicyScopeCtx(svc, repo, certID)
	w := httptest.NewRecorder()
	body := []byte(`{"validity_months":12,"key_type":"RSA","key_size":2048}`)
	r := newFlatPolicyRequest(t, http.MethodPut, certID, body)

	upsertCertificatePolicy(c, w, r)

	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
	repo.AssertExpectations(t)
}

// TestGetCertificatePolicy_FlatRouteDeniesNonOwnedCertificate pins that
// reading a certificate's policy on the flat route now requires owning the
// certificate itself (via GetCertificate), not merely having authored
// the policy row (the pre-task repo.GetByCertificateID(certID, userID)
// predicate).
func TestGetCertificatePolicy_FlatRouteDeniesNonOwnedCertificate(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	repo := &mockCertPolicyRepo{}

	c := newCertPolicyScopeCtx(svc, repo, certID)
	w := httptest.NewRecorder()
	r := newFlatPolicyRequest(t, http.MethodGet, certID, nil)

	getCertificatePolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
	repo.AssertNotCalled(t, "GetByCertificateIDAny", mock.Anything, mock.Anything)
}

// TestDeleteCertificatePolicy_FlatRouteDeniesNonOwnedCertificate mirrors the
// GET case for delete.
func TestDeleteCertificatePolicy_FlatRouteDeniesNonOwnedCertificate(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	repo := &mockCertPolicyRepo{}

	c := newCertPolicyScopeCtx(svc, repo, certID)
	w := httptest.NewRecorder()
	r := newFlatPolicyRequest(t, http.MethodDelete, certID, nil)

	deleteCertificatePolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
	repo.AssertNotCalled(t, "DeleteByCertificateIDAny", mock.Anything, mock.Anything)
}
