// Package api — internal tests for certificate handlers.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	oauth2Services "rocketvault/internal/services/oauth2"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
	"rocketvault/model"
)

// --- mock CertificateService ---

type mockCertService struct {
	mock.Mock
}

func (m *mockCertService) CreateSelfSignedCertificate(ctx context.Context, req certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *mockCertService) CreateCASignedCertificate(ctx context.Context, req certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *mockCertService) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	args := m.Called(ctx, certID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Certificate), args.Error(1)
}

func (m *mockCertService) ListCertificates(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *mockCertService) UpdateCertificate(ctx context.Context, req certServices.UpdateCertificateRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockCertService) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, certID, scope)
	return args.Error(0)
}

func (m *mockCertService) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, certID, userID, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *mockCertService) ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error {
	args := m.Called(ctx, certID, userID, role)
	return args.Error(0)
}

func (m *mockCertService) ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	args := m.Called(ctx, keyID, userID, role)
	return args.Error(0)
}

// --- certSvcContainer: container that provides CertificateService ---

type certSvcContainer struct {
	certSvc        certServices.CertificateService
	certPolicyRepo repositories.CertificatePolicyRepositoryInterface
}

func (c *certSvcContainer) GetCertificateService() certServices.CertificateService { return c.certSvc }
func (c *certSvcContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *certSvcContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *certSvcContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *certSvcContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *certSvcContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *certSvcContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *certSvcContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *certSvcContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	if c.certPolicyRepo != nil {
		return c.certPolicyRepo
	}
	// Default stub: unused unless a test both reaches the repository call and
	// forgets to configure expectations on it.
	return &mockCertPolicyRepo{}
}
func (c *certSvcContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *certSvcContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *certSvcContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *certSvcContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *certSvcContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *certSvcContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *certSvcContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *certSvcContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *certSvcContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *certSvcContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *certSvcContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *certSvcContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *certSvcContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *certSvcContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *certSvcContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *certSvcContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *certSvcContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *certSvcContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *certSvcContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *certSvcContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *certSvcContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *certSvcContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *certSvcContainer) GetDatabase() *sql.DB       { panic("unexpected call: GetDatabase") }
func (c *certSvcContainer) GetLogger() *logging.Logger { panic("unexpected call: GetLogger") }
func (c *certSvcContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *certSvcContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *certSvcContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *certSvcContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *certSvcContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *certSvcContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *certSvcContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *certSvcContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *certSvcContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *certSvcContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *certSvcContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *certSvcContainer) Close() error { return nil }

// newCertCtx builds a Context backed by the given CertificateService mock.
func newCertCtx(svc certServices.CertificateService, claims jwt.MapClaims) *Context {
	a := &app.App{ServiceContainer: &certSvcContainer{certSvc: svc}}
	return &Context{
		App:    a,
		Claims: claims,
		Params: &ApiParams{PerPage: 60},
	}
}

const certTestUserID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

func certAdminClaims() jwt.MapClaims {
	return jwt.MapClaims{"role": model.RoleAdmin, "user_id": certTestUserID}
}

// certLegacyOwnerScope is the exact scope scopeFromRequest builds for a legacy
// flat route (no vault_name mux var): an owner scope carrying the default
// vault id as its advisory vault and certTestUserID as the owner/actor.
func certLegacyOwnerScope() model.Scope {
	return model.NewOwnerScope(uuid.MustParse(model.DefaultVaultID), uuid.MustParse(certTestUserID))
}

// certDeleteScope is the scope deleteCertificate builds: vault-scoped on both
// route shapes, with the real caller as the audit actor. The actor must never
// be uuid.Nil, or every certificate deletion is attributed to nobody.
func certDeleteScope() model.Scope {
	return model.NewVaultScope(uuid.MustParse(model.DefaultVaultID), uuid.MustParse(certTestUserID))
}

// ============================================================
// certToDomainResponse
// ============================================================

func TestCertToDomainResponse_PopulatesFields(t *testing.T) {
	certID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	cert := &model.Certificate{
		ID:        certID,
		Name:      "my-cert",
		UserID:    userID,
		CreatedAt: now,
		Tags:      []string{"tag1"},
		AutoRenew: true,
		Enabled:   true,
	}

	resp := certToDomainResponse(cert)
	assert.Equal(t, certID, resp.ID)
	assert.Equal(t, "my-cert", resp.Name)
	assert.Equal(t, userID, resp.UserID)
	assert.Equal(t, []string{"tag1"}, resp.Tags)
	assert.True(t, resp.AutoRenew)
	assert.True(t, resp.Enabled)
}

// ============================================================
// createCertificate
// ============================================================

func TestCreateCertificate_NonAdminRole_Returns403(t *testing.T) {
	c := newCertCtx(nil, jwt.MapClaims{"role": model.RoleUser, "user_id": certTestUserID})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader([]byte(`{}`)))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateCertificate_MissingRequiredFields_Returns400(t *testing.T) {
	c := newCertCtx(nil, certAdminClaims())
	w := httptest.NewRecorder()
	// Missing key_id and validity_days.
	body, _ := json.Marshal(map[string]any{"name": "cert"})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateCertificate_InvalidKeyID_Returns400(t *testing.T) {
	c := newCertCtx(nil, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "cert", "key_id": "not-uuid", "validity_days": 30})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateCertificate_ServiceError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).
		Return(nil, errors.New("key not found"))

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":          "mycert",
		"key_id":        uuid.New().String(),
		"validity_days": 365,
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateCertificate_Success_Returns201(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(365 * 24 * time.Hour)
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).
		Return(&certServices.CreateCertificateResult{
			CertID:    certID,
			Name:      "mycert",
			CreatedAt: now,
			ExpiresAt: &expiresAt,
		}, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":          "mycert",
		"key_id":        uuid.New().String(),
		"validity_days": 365,
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listCertificates
// ============================================================

func TestListCertificates_ServiceError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	// Legacy flat route (no vault_name) yields an owner scope.
	svc.On("ListCertificates", mock.Anything, certLegacyOwnerScope(), repositories.CertificateFilter{}).
		Return([]model.Certificate{}, errors.New("db error"))

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates", nil)

	listCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListCertificates_Success_Returns200(t *testing.T) {
	svc := &mockCertService{}
	certs := []model.Certificate{
		{ID: uuid.New(), Name: "cert1", CreatedAt: time.Now()},
	}
	// Legacy flat route (no vault_name) yields an owner scope.
	svc.On("ListCertificates", mock.Anything, certLegacyOwnerScope(), repositories.CertificateFilter{}).Return(certs, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates", nil)

	listCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.NotNil(t, body["certificates"])
	svc.AssertExpectations(t)
}

// ============================================================
// getCertificate
// ============================================================

func TestGetCertificate_InvalidCertID_Returns400(t *testing.T) {
	c := newCertCtx(nil, certAdminClaims())
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/bad", nil)

	getCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertificate_NotFound_Returns404(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	// Legacy flat route (no vault_name) yields an owner scope.
	// The service returns the not-found sentinel, which maps to 404.
	svc.On("GetCertificate", mock.Anything, certID, certLegacyOwnerScope()).Return(nil, certServices.ErrCertNotFound)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String(), nil)

	getCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetCertificate_Success_Returns200(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	userID := uuid.MustParse(certTestUserID)
	// Legacy flat route (no vault_name) yields an owner scope.
	svc.On("GetCertificate", mock.Anything, certID, certLegacyOwnerScope()).Return(&model.Certificate{
		ID: certID, Name: "cert1", UserID: userID, CreatedAt: time.Now(),
	}, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String(), nil)

	getCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// updateCertificate
// ============================================================

func TestUpdateCertificate_InvalidCertID_Returns400(t *testing.T) {
	c := newCertCtx(nil, certAdminClaims())
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/certificates/bad", bytes.NewReader([]byte(`{}`)))

	updateCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateCertificate_NoFieldsProvided_Returns400(t *testing.T) {
	certID := uuid.New()
	c := newCertCtx(nil, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	// Empty body means no update fields.
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String(), bytes.NewReader([]byte(`{}`)))

	updateCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateCertificate_ServiceError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	svc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	name := "new-name"
	body, _ := json.Marshal(UpdateCertificateAPIRequest{Name: &name})
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String(), bytes.NewReader(body))

	updateCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateCertificate_NotFound_Returns404(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	// UpdateCertificate returns GetCertificate's error, which wraps ErrCertNotFound.
	svc.On("UpdateCertificate", mock.Anything, mock.Anything).
		Return(fmt.Errorf("update certificate: %w", certServices.ErrCertNotFound))

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	name := "new-name"
	body, _ := json.Marshal(UpdateCertificateAPIRequest{Name: &name})
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String(), bytes.NewReader(body))

	updateCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateCertificate_Success_Returns200(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	userID := uuid.MustParse(certTestUserID)
	svc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(nil)
	// updateCertificate builds an owner scope with an advisory nil vault id
	// (see api/certificates.go: it is not yet vault-scope aware).
	svc.On("GetCertificate", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Certificate{
		ID: certID, Name: "new-name", UserID: userID, CreatedAt: time.Now(),
	}, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	name := "new-name"
	body, _ := json.Marshal(UpdateCertificateAPIRequest{Name: &name})
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String(), bytes.NewReader(body))

	updateCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// deleteCertificate
// ============================================================

func TestDeleteCertificate_InvalidCertID_Returns400(t *testing.T) {
	c := newCertCtx(nil, certAdminClaims())
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/bad", nil)

	deleteCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteCertificate_ServiceError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	// deleteCertificate builds a vault scope from the (default, in tests)
	// resolved vault id, with a nil actor id.
	svc.On("DeleteCertificate", mock.Anything, certID, certDeleteScope()).Return(errors.New("db error"))

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/"+certID.String(), nil)

	deleteCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteCertificate_Success_Returns200(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	svc.On("DeleteCertificate", mock.Anything, certID, certDeleteScope()).Return(nil)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/"+certID.String(), nil)

	deleteCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestDeleteCertificate_NotFound_Returns404 verifies that a not-found sentinel
// from the service maps to 404 rather than 500.
func TestDeleteCertificate_NotFound_Returns404(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	svc.On("DeleteCertificate", mock.Anything, certID, certDeleteScope()).
		Return(certServices.ErrCertNotFound)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/"+certID.String(), nil)

	deleteCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// TestGetCertificate_LifecycleDenied_Returns403 verifies that a disabled/expired
// certificate yields 403 rather than 404.
func TestGetCertificate_LifecycleDenied_Returns403(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	svc.On("GetCertificate", mock.Anything, certID, certLegacyOwnerScope()).
		Return(nil, certServices.ErrCertLifecycleDenied)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String(), nil)

	getCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertExpectations(t)
}

// TestGetCertificate_InternalError_Returns500 verifies a genuine server fault
// yields 500 rather than 404.
func TestGetCertificate_InternalError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	svc.On("GetCertificate", mock.Anything, certID, certLegacyOwnerScope()).
		Return(nil, errors.New("disk I/O"))

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String(), nil)

	getCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}
