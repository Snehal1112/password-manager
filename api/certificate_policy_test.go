// Package api — internal tests for certificate policy handlers.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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

// --- mock CertificatePolicyRepository ---

type mockCertPolicyRepo struct {
	mock.Mock
}

func (m *mockCertPolicyRepo) Upsert(ctx context.Context, policy *model.CertificatePolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *mockCertPolicyRepo) GetByCertificateID(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error) {
	args := m.Called(ctx, certID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificatePolicy), args.Error(1)
}

func (m *mockCertPolicyRepo) DeleteByCertificateID(ctx context.Context, certID, userID uuid.UUID) error {
	args := m.Called(ctx, certID, userID)
	return args.Error(0)
}

// --- certPolicyRepoContainer ---

type certPolicyRepoContainer struct {
	repo repositories.CertificatePolicyRepositoryInterface
}

func (c *certPolicyRepoContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	return c.repo
}
func (c *certPolicyRepoContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *certPolicyRepoContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *certPolicyRepoContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *certPolicyRepoContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *certPolicyRepoContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *certPolicyRepoContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *certPolicyRepoContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *certPolicyRepoContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *certPolicyRepoContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *certPolicyRepoContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *certPolicyRepoContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *certPolicyRepoContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *certPolicyRepoContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *certPolicyRepoContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *certPolicyRepoContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *certPolicyRepoContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *certPolicyRepoContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *certPolicyRepoContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *certPolicyRepoContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *certPolicyRepoContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *certPolicyRepoContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *certPolicyRepoContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *certPolicyRepoContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *certPolicyRepoContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *certPolicyRepoContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *certPolicyRepoContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *certPolicyRepoContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *certPolicyRepoContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *certPolicyRepoContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *certPolicyRepoContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *certPolicyRepoContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *certPolicyRepoContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *certPolicyRepoContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *certPolicyRepoContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *certPolicyRepoContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *certPolicyRepoContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *certPolicyRepoContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *certPolicyRepoContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *certPolicyRepoContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *certPolicyRepoContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *certPolicyRepoContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *certPolicyRepoContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *certPolicyRepoContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *certPolicyRepoContainer) Close() error { return nil }

const cpTestUserID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

// newCertPolicyCtx builds a Context backed by the given policy repo mock.
func newCertPolicyCtx(repo repositories.CertificatePolicyRepositoryInterface, certIDStr string) *Context {
	a := &app.App{ServiceContainer: &certPolicyRepoContainer{repo: repo}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"user_id": cpTestUserID},
		Params: &ApiParams{CertificateID: certIDStr, PerPage: 60},
	}
}

// ============================================================
// getCertificatePolicy
// ============================================================

func TestGetCertificatePolicy_InvalidCertID_Returns400(t *testing.T) {
	c := newCertPolicyCtx(nil, "bad-cert-id")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/bad/policy", nil)

	getCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertificatePolicy_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(cpTestUserID)
	repo := &mockCertPolicyRepo{}
	repo.On("GetByCertificateID", mock.Anything, certID, userID).Return(nil, errors.New("not found"))

	c := newCertPolicyCtx(repo, certID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String()+"/policy", nil)

	getCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	repo.AssertExpectations(t)
}

func TestGetCertificatePolicy_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(cpTestUserID)
	repo := &mockCertPolicyRepo{}
	repo.On("GetByCertificateID", mock.Anything, certID, userID).Return(&model.CertificatePolicy{
		ID:            uuid.New(),
		CertificateID: certID,
		UserID:        userID,
	}, nil)

	c := newCertPolicyCtx(repo, certID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String()+"/policy", nil)

	getCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

// ============================================================
// upsertCertificatePolicy
// ============================================================

func TestUpsertCertificatePolicy_InvalidCertID_Returns400(t *testing.T) {
	c := newCertPolicyCtx(nil, "bad")
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"validity_months": 12})
	r := httptest.NewRequest(http.MethodPut, "/certificates/bad/policy", bytes.NewReader(body))

	upsertCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertCertificatePolicy_InvalidBody_Returns400(t *testing.T) {
	certID := uuid.New()
	c := newCertPolicyCtx(nil, certID.String())
	w := httptest.NewRecorder()
	// Malformed JSON.
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String()+"/policy", bytes.NewReader([]byte(`{bad json}`)))

	upsertCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertCertificatePolicy_UpsertError_Returns500(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(cpTestUserID)
	repo := &mockCertPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newCertPolicyCtx(repo, certID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"validity_months": 12, "key_type": "RSA"})
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String()+"/policy", bytes.NewReader(body))

	upsertCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	_ = userID
	repo.AssertExpectations(t)
}

func TestUpsertCertificatePolicy_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(cpTestUserID)
	repo := &mockCertPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(nil)
	repo.On("GetByCertificateID", mock.Anything, certID, userID).Return(&model.CertificatePolicy{
		ID:             uuid.New(),
		CertificateID:  certID,
		UserID:         userID,
		ValidityMonths: 12,
	}, nil)

	c := newCertPolicyCtx(repo, certID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"validity_months": 12, "key_type": "RSA"})
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String()+"/policy", bytes.NewReader(body))

	upsertCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

// ============================================================
// deleteCertificatePolicy
// ============================================================

func TestDeleteCertificatePolicy_InvalidCertID_Returns400(t *testing.T) {
	c := newCertPolicyCtx(nil, "bad")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/bad/policy", nil)

	deleteCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteCertificatePolicy_ServiceError_Returns500(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(cpTestUserID)
	repo := &mockCertPolicyRepo{}
	repo.On("DeleteByCertificateID", mock.Anything, certID, userID).Return(errors.New("db error"))

	c := newCertPolicyCtx(repo, certID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/"+certID.String()+"/policy", nil)

	deleteCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	repo.AssertExpectations(t)
}

func TestDeleteCertificatePolicy_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(cpTestUserID)
	repo := &mockCertPolicyRepo{}
	repo.On("DeleteByCertificateID", mock.Anything, certID, userID).Return(nil)

	c := newCertPolicyCtx(repo, certID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/"+certID.String()+"/policy", nil)

	deleteCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}
