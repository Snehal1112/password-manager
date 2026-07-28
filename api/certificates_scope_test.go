package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
}

func (s *scopeStubCertService) GetCertificateScoped(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	s.lastScope = scope
	return s.cert, s.certErr
}

func (s *scopeStubCertService) ListCertificatesScoped(_ context.Context, scope model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	s.lastScope = scope
	return s.list, nil
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
