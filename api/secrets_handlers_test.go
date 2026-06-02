// Package api — internal tests for secret CRUD and version handlers.
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
	"time"

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

// --- mock SecretService ---

type mockSecretService struct {
	mock.Mock
}

func (m *mockSecretService) CreateSecret(ctx context.Context, req secretServices.CreateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *mockSecretService) UpdateSecret(ctx context.Context, req secretServices.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockSecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *mockSecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	args := m.Called(ctx, userID, tags)
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *mockSecretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, userID)
	return args.Error(0)
}

func (m *mockSecretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	args := m.Called(ctx, secretID, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *mockSecretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	args := m.Called(ctx, vaultID, tags)
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *mockSecretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	args := m.Called(ctx, secretID, vaultID)
	return args.Error(0)
}

func (m *mockSecretService) GenerateSecret(ctx context.Context, req secretServices.GenerateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *mockSecretService) ExportSecrets(ctx context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
	args := m.Called(ctx, req)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockSecretService) ImportSecrets(ctx context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*secretServices.ImportResult), args.Error(1)
}

func (m *mockSecretService) GetSecretVersions(ctx context.Context, secretID, userID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *mockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *mockSecretService) GetLatestSecretVersion(ctx context.Context, secretID, userID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

// --- secretSvcTestContainer ---

type secretSvcTestContainer struct {
	secretSvc secretServices.SecretService
}

func (c *secretSvcTestContainer) GetSecretService() secretServices.SecretService { return c.secretSvc }
func (c *secretSvcTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *secretSvcTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *secretSvcTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *secretSvcTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *secretSvcTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *secretSvcTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *secretSvcTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *secretSvcTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *secretSvcTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *secretSvcTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *secretSvcTestContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *secretSvcTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *secretSvcTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *secretSvcTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *secretSvcTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *secretSvcTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *secretSvcTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *secretSvcTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *secretSvcTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *secretSvcTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *secretSvcTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *secretSvcTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *secretSvcTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *secretSvcTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *secretSvcTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *secretSvcTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *secretSvcTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *secretSvcTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *secretSvcTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *secretSvcTestContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *secretSvcTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *secretSvcTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *secretSvcTestContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *secretSvcTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *secretSvcTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *secretSvcTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *secretSvcTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *secretSvcTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *secretSvcTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *secretSvcTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *secretSvcTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *secretSvcTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *secretSvcTestContainer) Close() error { return nil }

const secretHTestUserID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

// newSecretCtx builds a Context backed by the given SecretService mock.
func newSecretCtx(svc secretServices.SecretService) *Context {
	a := &app.App{ServiceContainer: &secretSvcTestContainer{secretSvc: svc}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"user_id": secretHTestUserID},
		Params: &ApiParams{PerPage: 60},
		Logger: userTestLog(),
	}
}

// makeSecretModel returns a minimal valid *model.Secret for test use.
func makeSecretModel(secretID uuid.UUID) *model.Secret {
	return &model.Secret{
		ID:        secretID,
		Name:      "test-secret",
		Value:     "secret-value",
		UserID:    uuid.MustParse(secretHTestUserID),
		Version:   1,
		CreatedAt: time.Now(),
		Enabled:   true,
	}
}

// ============================================================
// createSecret
// ============================================================

func TestCreateSecret_MissingName_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"value": "val"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSecret_MissingValue_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mysecret"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSecret_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("CreateSecret", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mysecret", "value": "myvalue"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateSecret_Success_Returns201(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("CreateSecret", mock.Anything, mock.Anything).Return(makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mysecret", "value": "myvalue"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listSecrets
// ============================================================

func TestListSecrets_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) uses per-user visibility via ListSecrets.
	svc.On("ListSecrets", mock.Anything, uuid.MustParse(secretHTestUserID), mock.Anything).Return([]model.Secret{}, errors.New("db error"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListSecrets_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) uses per-user visibility via ListSecrets.
	svc.On("ListSecrets", mock.Anything, uuid.MustParse(secretHTestUserID), mock.Anything).Return([]model.Secret{*makeSecretModel(secretID)}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getSecret
// ============================================================

func TestGetSecret_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad", nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) uses per-user visibility via GetSecret.
	// The service returns the not-found sentinel, which maps to 404.
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return(nil, secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) uses per-user visibility via GetSecret.
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return(makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// updateSecret
// ============================================================

func TestUpdateSecret_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/secrets/bad", bytes.NewReader([]byte(`{"name":"new"}`)))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateSecret_NoChanges_Returns400(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return(makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	// Same name and value as makeSecretModel — no actual changes.
	body, _ := json.Marshal(map[string]any{"name": "test-secret", "value": "secret-value"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateSecret_ServiceError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	original := makeSecretModel(secretID)
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return(original, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	original := makeSecretModel(secretID)
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return(original, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// deleteSecret
// ============================================================

func TestDeleteSecret_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/bad", nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSecret_ServiceError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("DeleteSecretInVault", mock.Anything, secretID, mock.Anything).Return(errors.New("db error"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("DeleteSecretInVault", mock.Anything, secretID, mock.Anything).Return(nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestDeleteSecret_MissingUserIDClaim_Returns500 verifies the missing user_id claim path.
func TestDeleteSecret_MissingUserIDClaim_Returns500(t *testing.T) {
	secretID := uuid.New()
	// Context with no user_id claim.
	c := &Context{
		App:    &app.App{},
		Claims: jwt.MapClaims{},
		Params: &ApiParams{SecretID: secretID.String(), PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestListSecrets_MissingUserIDClaim_Returns500 verifies the missing user_id claim path.
func TestListSecrets_MissingUserIDClaim_Returns500(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: jwt.MapClaims{},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// generateSecret
// ============================================================

func TestGenerateSecret_MissingName_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"length": 16})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateSecret_InvalidLength_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "gen", "length": 4})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateSecret_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("GenerateSecret", mock.Anything, mock.Anything).Return(nil, errors.New("generation failed"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "gen", "length": 16})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestGenerateSecret_Success_Returns201(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GenerateSecret", mock.Anything, mock.Anything).Return(makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "gen", "length": 16})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listSecretVersionsHandler
// ============================================================

func TestListSecretVersionsHandler_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad/versions", nil)

	listSecretVersionsHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListSecretVersionsHandler_ServiceError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersions", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return([]model.SecretVersion{}, errors.New("db error"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions", nil)

	listSecretVersionsHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListSecretVersionsHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersions", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return([]model.SecretVersion{
		{SecretID: secretID, Version: 1},
	}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions", nil)

	listSecretVersionsHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getSecretVersionHandler
// ============================================================

func TestGetSecretVersionHandler_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad/versions/1", nil)

	getSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretVersionHandler_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersion", mock.Anything, secretID, 1, uuid.MustParse(secretHTestUserID)).Return(nil, errors.New("not found"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), Version: 1, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/1", nil)

	getSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetSecretVersionHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersion", mock.Anything, secretID, 1, uuid.MustParse(secretHTestUserID)).Return(&model.SecretVersion{
		SecretID: secretID, Version: 1, Value: "val",
	}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), Version: 1, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/1", nil)

	getSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getLatestSecretVersionHandler
// ============================================================

func TestGetLatestSecretVersionHandler_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad/versions/latest", nil)

	getLatestSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetLatestSecretVersionHandler_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetLatestSecretVersion", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return(nil, errors.New("not found"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/latest", nil)

	getLatestSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetLatestSecretVersionHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetLatestSecretVersion", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).Return(&model.SecretVersion{
		SecretID: secretID, Version: 2, Value: "latest",
	}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/latest", nil)

	getLatestSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// exportSecrets
// ============================================================

func TestExportSecrets_InvalidFormat_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "xml"})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportSecrets_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.Anything).Return([]byte{}, errors.New("export failed"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "json"})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestExportSecrets_JSON_Success_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.Anything).Return([]byte(`[]`), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "json"})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// Status-code distinction for DELETE (Issue 8) and GET (Issue 9)
// ============================================================

// TestDeleteSecret_NotFound_Returns404 verifies that a not-found sentinel from
// the service maps to 404 rather than 500.
func TestDeleteSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("DeleteSecretInVault", mock.Anything, secretID, mock.Anything).
		Return(secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// TestGetSecret_LifecycleDenied_Returns403 verifies that a disabled/expired
// secret yields 403 rather than 404.
func TestGetSecret_LifecycleDenied_Returns403(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).
		Return(nil, secretServices.ErrSecretLifecycleDenied)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertExpectations(t)
}

// TestGetSecret_DecryptError_Returns500 verifies that a genuine server fault
// (e.g. decrypt failure) yields 500 rather than 404.
func TestGetSecret_DecryptError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).
		Return(nil, errors.New("disk I/O"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// TestGetSecret_NotFoundSentinel_Returns404 verifies the not-found sentinel
// still yields 404.
func TestGetSecret_NotFoundSentinel_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecret", mock.Anything, secretID, uuid.MustParse(secretHTestUserID)).
		Return(nil, secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}
