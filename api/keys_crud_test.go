// Package api — internal tests for key CRUD handlers.
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

// --- mock KeyService ---

type mockKeyService struct {
	mock.Mock
}

func (m *mockKeyService) CreateRSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}

func (m *mockKeyService) CreateECDSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}

func (m *mockKeyService) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, keyID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]model.Key), args.Error(1)
}

func (m *mockKeyService) ListKeysWithFilters(ctx context.Context, userID *uuid.UUID, keyType string, tags []string, isAdmin bool) ([]model.Key, error) {
	args := m.Called(ctx, userID, keyType, tags, isAdmin)
	return args.Get(0).([]model.Key), args.Error(1)
}

func (m *mockKeyService) UpdateKey(ctx context.Context, req keyServices.UpdateKeyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockKeyService) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, keyID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyService) GetKeyInVault(ctx context.Context, keyID, vaultID uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, keyID, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyService) ListKeysInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	args := m.Called(ctx, vaultID, keyType, tags)
	return args.Get(0).([]model.Key), args.Error(1)
}

func (m *mockKeyService) DeleteKeyInVault(ctx context.Context, keyID, vaultID uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, keyID, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyService) RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, keyID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}

func (m *mockKeyService) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	args := m.Called(ctx, keyID, userID, role)
	return args.Error(0)
}

// --- keySvcTestContainer ---

type keySvcTestContainer struct {
	keySvc  keyServices.KeyService
	keyRepo repositories.KeyRepositoryInterface
}

func (c *keySvcTestContainer) GetKeyService() keyServices.KeyService { return c.keySvc }
func (c *keySvcTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	return c.keyRepo
}
func (c *keySvcTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *keySvcTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *keySvcTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *keySvcTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *keySvcTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *keySvcTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *keySvcTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *keySvcTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *keySvcTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *keySvcTestContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *keySvcTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *keySvcTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *keySvcTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *keySvcTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *keySvcTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *keySvcTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *keySvcTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *keySvcTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *keySvcTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *keySvcTestContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *keySvcTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *keySvcTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *keySvcTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *keySvcTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *keySvcTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *keySvcTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *keySvcTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *keySvcTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *keySvcTestContainer) GetDatabase() *sql.DB       { panic("unexpected call: GetDatabase") }
func (c *keySvcTestContainer) GetLogger() *logging.Logger { panic("unexpected call: GetLogger") }
func (c *keySvcTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *keySvcTestContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *keySvcTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *keySvcTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *keySvcTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *keySvcTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *keySvcTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *keySvcTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *keySvcTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *keySvcTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *keySvcTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *keySvcTestContainer) Close() error { return nil }

const keyTestUserID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

// newKeyCtx builds a Context backed by the given KeyService mock.
func newKeyCtx(svc keyServices.KeyService) *Context {
	a := &app.App{ServiceContainer: &keySvcTestContainer{keySvc: svc}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"role": string(model.RoleAdmin), "user_id": keyTestUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

// newKeyCtxWithRepo builds a Context with both KeyService and KeyRepository available.
func newKeyCtxWithRepo(svc keyServices.KeyService, repo repositories.KeyRepositoryInterface) *Context {
	a := &app.App{ServiceContainer: &keySvcTestContainer{keySvc: svc, keyRepo: repo}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"role": string(model.RoleAdmin), "user_id": keyTestUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

// makeKeyModel returns a minimal valid *model.Key for test use.
func makeKeyModel(keyID uuid.UUID) *model.Key {
	now := time.Now()
	return &model.Key{
		ID:        keyID,
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		UserID:    uuid.MustParse(keyTestUserID),
		CreatedAt: now,
		Enabled:   true,
	}
}

// ============================================================
// createKey
// ============================================================

func TestCreateKey_InvalidType_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "k", "type": "INVALID"})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateKey_MissingName_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"type": "RSA"})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateKey_NonAdminRole_Returns403(t *testing.T) {
	c := newKeyCtx(nil)
	c.Claims = jwt.MapClaims{"role": string(model.RoleUser), "user_id": keyTestUserID}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "k", "type": "RSA"})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateKey_RSA_ServiceError_Returns500(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("CreateRSAKey", mock.Anything, mock.Anything).Return(nil, errors.New("key creation failed"))

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mykey", "type": "RSA", "bits": 2048})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateKey_RSA_Success_Returns201(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("CreateRSAKey", mock.Anything, mock.Anything).Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "mykey"}, nil)
	svc.On("GetKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).Return(makeKeyModel(keyID), nil)

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mykey", "type": "RSA", "bits": 2048})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateKey_ECDSA_Success_Returns201(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("CreateECDSAKey", mock.Anything, mock.Anything).Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "eckey"}, nil)
	svc.On("GetKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).Return(makeKeyModel(keyID), nil)

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "eckey", "type": "ECDSA", "curve": "P-256"})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateKey_InvalidRSABits_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	w := httptest.NewRecorder()
	// 1024 is not an allowed RSA key size.
	body, _ := json.Marshal(map[string]any{"name": "mykey", "type": "RSA", "bits": 1024})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateKey_InvalidECDSACurve_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "eckey", "type": "ECDSA", "curve": "P-999"})
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// listKeys
// ============================================================

func TestListKeys_ServiceError_Returns500(t *testing.T) {
	svc := &mockKeyService{}
	// Legacy flat route (no vault_name) uses per-user visibility via ListKeys.
	svc.On("ListKeys", mock.Anything, uuid.MustParse(keyTestUserID)).
		Return([]model.Key{}, errors.New("db error"))

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)

	listKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListKeys_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	// Legacy flat route (no vault_name) uses per-user visibility via ListKeys.
	svc.On("ListKeys", mock.Anything, uuid.MustParse(keyTestUserID)).
		Return([]model.Key{*makeKeyModel(keyID)}, nil)

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)

	listKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getKey
// ============================================================

func TestGetKey_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	c.Params = &ApiParams{KeyID: "bad-uuid", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/bad", nil)

	getKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	// Legacy flat route (no vault_name) uses per-user visibility via GetKey.
	// The service returns the not-found sentinel, which maps to 404.
	svc.On("GetKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).Return(nil, keyServices.ErrKeyNotFound)

	c := newKeyCtx(svc)
	c.Claims = jwt.MapClaims{"role": string(model.RoleUser), "user_id": keyTestUserID}
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String(), nil)

	getKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	// Legacy flat route (no vault_name) uses per-user visibility via GetKey.
	svc.On("GetKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).Return(makeKeyModel(keyID), nil)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String(), nil)

	getKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// updateKey
// ============================================================

func TestUpdateKey_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/keys/bad", bytes.NewReader([]byte(`{}`)))

	updateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateKey_NoFieldsProvided_Returns400(t *testing.T) {
	keyID := uuid.New()
	c := newKeyCtx(nil)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	// Empty body has no update fields.
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String(), bytes.NewReader([]byte(`{}`)))

	updateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateKey_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("UpdateKey", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	name := "updated"
	body, _ := json.Marshal(UpdateKeyRequest{Name: &name})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String(), bytes.NewReader(body))

	updateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	// UpdateKey wraps ErrKeyNotFound; errors.Is must still match through the chain.
	svc.On("UpdateKey", mock.Anything, mock.Anything).
		Return(fmt.Errorf("update key: %w", keyServices.ErrKeyNotFound))

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	name := "updated"
	body, _ := json.Marshal(UpdateKeyRequest{Name: &name})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String(), bytes.NewReader(body))

	updateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("UpdateKey", mock.Anything, mock.Anything).Return(nil)
	svc.On("GetKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).Return(makeKeyModel(keyID), nil)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	name := "updated"
	body, _ := json.Marshal(UpdateKeyRequest{Name: &name})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String(), bytes.NewReader(body))

	updateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// deleteKey
// ============================================================

func TestDeleteKey_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/bad", nil)

	deleteKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteKey_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("DeleteKeyInVault", mock.Anything, keyID, mock.Anything).Return(nil, errors.New("db error"))

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String(), nil)

	deleteKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	now := time.Now()
	svc := &mockKeyService{}
	deleted := makeKeyModel(keyID)
	deleted.DeletedAt = &now
	svc.On("DeleteKeyInVault", mock.Anything, keyID, mock.Anything).Return(deleted, nil)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String(), nil)

	deleteKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestDeleteKey_NotFound_Returns404 verifies that a not-found sentinel from the
// service maps to 404 rather than 500.
func TestDeleteKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("DeleteKeyInVault", mock.Anything, keyID, mock.Anything).
		Return(nil, keyServices.ErrKeyNotFound)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String(), nil)

	deleteKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// TestGetKey_LifecycleDenied_Returns403 verifies that a disabled/expired key
// yields 403 rather than 404.
func TestGetKey_LifecycleDenied_Returns403(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("GetKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).
		Return(nil, keyServices.ErrKeyLifecycleDenied)

	c := newKeyCtx(svc)
	c.Claims = jwt.MapClaims{"role": string(model.RoleUser), "user_id": keyTestUserID}
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String(), nil)

	getKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertExpectations(t)
}

// TestGetKey_InternalError_Returns500 verifies a genuine server fault yields 500
// rather than 404.
func TestGetKey_InternalError_Returns500(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("GetKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).
		Return(nil, errors.New("disk I/O"))

	c := newKeyCtx(svc)
	c.Claims = jwt.MapClaims{"role": string(model.RoleUser), "user_id": keyTestUserID}
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String(), nil)

	getKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// rotateKey
// ============================================================

func TestRotateKey_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/bad/rotate", nil)

	rotateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotateKey_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RotateKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).Return(nil, errors.New("rotate failed"))

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/rotate", nil)

	rotateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestRotateKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	newKeyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RotateKey", mock.Anything, keyID, uuid.MustParse(keyTestUserID)).Return(&keyServices.CreateKeyResult{KeyID: newKeyID, Name: "test-key"}, nil)
	svc.On("GetKey", mock.Anything, newKeyID, uuid.MustParse(keyTestUserID)).Return(makeKeyModel(newKeyID), nil)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/rotate", nil)

	rotateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listKeyVersions
// ============================================================

type stubKeyVersionRepo struct {
	stubKeyRepo
	versions []model.KeyVersion
	err      error
}

func (s *stubKeyVersionRepo) ListVersions(_ context.Context, _, _ uuid.UUID) ([]model.KeyVersion, error) {
	return s.versions, s.err
}

func TestListKeyVersions_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtxWithRepo(nil, nil)
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/bad/versions", nil)

	listKeyVersions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListKeyVersions_RepositoryError_Returns500(t *testing.T) {
	keyID := uuid.New()
	repo := &stubKeyVersionRepo{
		stubKeyRepo: stubKeyRepo{},
		err:         errors.New("db error"),
	}

	c := newKeyCtxWithRepo(nil, repo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/versions", nil)

	listKeyVersions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListKeyVersions_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	repo := &stubKeyVersionRepo{
		stubKeyRepo: stubKeyRepo{},
		versions:    []model.KeyVersion{{KeyID: keyID, Version: 1}},
	}

	c := newKeyCtxWithRepo(nil, repo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/versions", nil)

	listKeyVersions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// wrapKey
// ============================================================

func TestWrapKey_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	c.App.ServiceContainer = &cryptoTestContainer{}
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/bad/wrap", bytes.NewReader([]byte(`{}`)))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWrapKey_MissingPlaintext_Returns400(t *testing.T) {
	keyID := uuid.New()
	c := newKeyCtx(nil)
	c.App.ServiceContainer = &cryptoTestContainer{}
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/wrap", bytes.NewReader([]byte(`{"plaintext_key":""}`)))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// unwrapKey
// ============================================================

func TestUnwrapKey_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	c.App.ServiceContainer = &cryptoTestContainer{}
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/bad/unwrap", bytes.NewReader([]byte(`{}`)))

	unwrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUnwrapKey_MissingWrappedKey_Returns400(t *testing.T) {
	keyID := uuid.New()
	c := newKeyCtx(nil)
	c.App.ServiceContainer = &cryptoTestContainer{}
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/unwrap", bytes.NewReader([]byte(`{"wrapped_key":""}`)))

	unwrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
