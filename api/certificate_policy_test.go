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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	rvconfig "rocketvault/config"
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
	"rocketvault/internal/services/provisioning"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
	"rocketvault/internal/certcache"
	"rocketvault/internal/vaultcache"
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

func (m *mockCertPolicyRepo) GetByCertificateIDAny(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error) {
	args := m.Called(ctx, certID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificatePolicy), args.Error(1)
}

func (m *mockCertPolicyRepo) DeleteByCertificateIDAny(ctx context.Context, certID uuid.UUID) error {
	args := m.Called(ctx, certID)
	return args.Error(0)
}

func (m *mockCertPolicyRepo) ListByVault(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.CertificatePolicyWithCertName), args.Error(1)
}

// --- certPolicyRepoContainer ---

type certPolicyRepoContainer struct {
	certSvc certServices.CertificateService
}

func (c *certPolicyRepoContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *certPolicyRepoContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
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
func (c *certPolicyRepoContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
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
func (c *certPolicyRepoContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
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
func (c *certPolicyRepoContainer) GetGrantService() provisioning.GrantService {
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
	return c.certSvc
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
func (c *certPolicyRepoContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *certPolicyRepoContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *certPolicyRepoContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
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

// newCertPolicyCtx builds a Context backed by the given policy repo mock. The
// certificate service is a scope stub that reports the certificate as found
// and delegates its policy methods to repo, since these tests exercise the
// policy repository, not the certificate pre-check.
func newCertPolicyCtx(repo repositories.CertificatePolicyRepositoryInterface, certIDStr string) *Context {
	a := &app.App{ServiceContainer: &certPolicyRepoContainer{certSvc: &scopeStubCertService{policyRepo: repo}}}
	return &Context{
		App:    a,
		Claims: RequestClaims{UserID: cpTestUserID},
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
	repo := &mockCertPolicyRepo{}
	repo.On("GetByCertificateIDAny", mock.Anything, certID).Return(nil, errors.New("not found"))

	c := newCertPolicyCtx(repo, certID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String()+"/policy", nil)

	getCertificatePolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "policy not found", c.Err.Message,
		"a policy-repo failure (cert exists) must keep the generic 'policy' 404 message")
	repo.AssertExpectations(t)
}

// TestGetCertificatePolicy_CertNotFound_Returns404WithCertificateMessage and
// TestGetCertificatePolicy_CertLifecycleDenied_Returns404WithCertificateMessage
// pin the message-text half of the fix: before this task, both cert-check
// failure modes (not-found and lifecycle-denied) were collapsed into the same
// generic "policy not found" 404 as any policy-repo failure. The pre-refactor
// handler always distinguished them as "certificate not found" — restore
// that distinction now that the cert check lives inside CertificateService.
func TestGetCertificatePolicy_CertNotFound_Returns404WithCertificateMessage(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	a := &app.App{ServiceContainer: &certSvcContainer{certSvc: svc}}
	c := &Context{
		App:    a,
		Claims: RequestClaims{UserID: uuid.NewString()},
		Params: &ApiParams{CertificateID: certID.String(), PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String()+"/policy", nil)

	getCertificatePolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, "certificate not found", c.Err.Message)
}

func TestGetCertificatePolicy_CertLifecycleDenied_Returns404WithCertificateMessage(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{certErr: certServices.ErrCertLifecycleDenied}
	a := &app.App{ServiceContainer: &certSvcContainer{certSvc: svc}}
	c := &Context{
		App:    a,
		Claims: RequestClaims{UserID: uuid.NewString()},
		Params: &ApiParams{CertificateID: certID.String(), PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String()+"/policy", nil)

	getCertificatePolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode,
		"lifecycle-denied must still map to 404, not writeCertificateError's 403")
	assert.Equal(t, "certificate not found", c.Err.Message)
}

func TestGetCertificatePolicy_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(cpTestUserID)
	repo := &mockCertPolicyRepo{}
	repo.On("GetByCertificateIDAny", mock.Anything, certID).Return(&model.CertificatePolicy{
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
	repo.On("GetByCertificateIDAny", mock.Anything, certID).Return(&model.CertificatePolicy{
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
	repo := &mockCertPolicyRepo{}
	repo.On("DeleteByCertificateIDAny", mock.Anything, certID).Return(errors.New("db error"))

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
	repo := &mockCertPolicyRepo{}
	repo.On("DeleteByCertificateIDAny", mock.Anything, certID).Return(nil)

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
