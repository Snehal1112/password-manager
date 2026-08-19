// Package api — internal tests for key CRUD handlers.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
	"rocketvault/internal/vaultcache"
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

func (m *mockKeyService) CreateOctKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}

func (m *mockKeyService) GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyService) ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}

func (m *mockKeyService) UpdateKey(ctx context.Context, req keyServices.UpdateKeyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockKeyService) DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyService) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}

func (m *mockKeyService) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	args := m.Called(ctx, keyID, userID, role)
	return args.Error(0)
}

func (m *mockKeyService) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}

func (m *mockKeyService) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}

func (m *mockKeyService) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}

func (m *mockKeyService) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyRotationPolicy), args.Error(1)
}

func (m *mockKeyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, scope, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyRotationPolicy), args.Error(1)
}

func (m *mockKeyService) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}

func (m *mockKeyService) ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.KeyVersion), args.Error(1)
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
func (c *keySvcTestContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
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
func (c *keySvcTestContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (c *keySvcTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *keySvcTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *keySvcTestContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
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
func (c *keySvcTestContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *keySvcTestContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
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

// keyLegacyVaultScope is the exact scope scopeFromRequest builds for a legacy
// flat route (no vault_name mux var): a vault scope carrying the default vault
// id and keyTestUserID as the actor. Flat routes used to yield an owner scope
// here, which is the 2026-08-16 cross-vault bypass this fixture now pins shut.
func keyLegacyVaultScope() model.Scope {
	return model.NewVaultScope(uuid.MustParse(model.DefaultVaultID), uuid.MustParse(keyTestUserID))
}

// newKeyCtx builds a Context backed by the given KeyService mock.
func newKeyCtx(svc keyServices.KeyService) *Context {
	a := &app.App{ServiceContainer: &keySvcTestContainer{keySvc: svc}}
	return &Context{
		App:    a,
		Claims: RequestClaims{Role: string(model.RoleAdmin), UserID: keyTestUserID},
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
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(makeKeyModel(keyID), nil)

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
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(makeKeyModel(keyID), nil)

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

// TestCreateKey_ECDSA_P256K_Success_Returns201 pins a bug found during the
// 2026-08-19 Azure parity audit: vvalidation.ValidateKeyCreate's curve
// allowlist predated P-256K support and rejected it before this handler's
// own (already-correct) four-curve check ever ran. See known-bugs.md B24.
func TestCreateKey_ECDSA_P256K_Success_Returns201(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("CreateECDSAKey", mock.Anything, mock.Anything).Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "eckey"}, nil)
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(makeKeyModel(keyID), nil)

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "eckey", "type": "ECDSA", "curve": "P-256K"})
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

// TestCreateKey_ECDSA_P256K_NoHSMMechanism_Returns400 pins a bug found while
// following up on B24: once ValidateKeyCreate allowed P-256K through, an
// HSM-enabled instance (PKCS#11 has no P-256K mechanism) fell through to an
// uncaught 500 instead of a clean 400, since crypto.ErrUnsupportedCurve was
// never special-cased alongside crypto.ErrOctKeysRequireHSM.
func TestCreateKey_ECDSA_P256K_NoHSMMechanism_Returns400(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("CreateECDSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Curve == "P-256K"
	})).Return(nil, fmt.Errorf("failed to generate ECDSA key: %w", crypto.ErrUnsupportedCurve))

	c := newKeyCtx(svc)
	body, _ := json.Marshal(map[string]any{"name": "eckey", "type": "ECDSA", "curve": "P-256K"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
	svc.AssertNotCalled(t, "GetKey", mock.Anything, mock.Anything, mock.Anything)
}

func TestCreateKey_OctType_CallsCreateOctKey(t *testing.T) {
	svc := &mockKeyService{}
	keyID := uuid.New()
	svc.On("CreateOctKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Bits == 256
	})).Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "aes-key", Type: model.KeyTypeOct, CreatedAt: time.Now()}, nil)
	svc.On("GetKey", mock.Anything, keyID, mock.Anything).Return(&model.Key{
		ID: keyID, Name: "aes-key", Type: model.KeyTypeOct, Bits: 256, Enabled: true,
	}, nil)

	c := newKeyCtx(svc)
	body, _ := json.Marshal(map[string]any{"name": "aes-key", "type": "oct", "bits": 256})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateKey_OctType_InvalidBits_Returns400(t *testing.T) {
	c := newKeyCtx(&mockKeyService{})
	body, _ := json.Marshal(map[string]any{"name": "aes-key", "type": "oct", "bits": 100})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateKey_OctType_NoHSM_Returns400 verifies that when the key provider
// isn't HSM-backed, CreateOctKey's crypto.ErrOctKeysRequireHSM (wrapped, as the
// real service does) is surfaced as a 400 client error rather than a 500.
func TestCreateKey_OctType_NoHSM_Returns400(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("CreateOctKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Bits == 256
	})).Return(nil, fmt.Errorf("failed to generate AES key: %w", crypto.ErrOctKeysRequireHSM))

	c := newKeyCtx(svc)
	body, _ := json.Marshal(map[string]any{"name": "aes-key", "type": "oct", "bits": 256})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
	svc.AssertNotCalled(t, "GetKey", mock.Anything, mock.Anything, mock.Anything)
}

// ============================================================
// listKeys
// ============================================================

func TestListKeys_ServiceError_Returns500(t *testing.T) {
	svc := &mockKeyService{}
	// Legacy flat route (no vault_name) yields a default-vault scope.
	svc.On("ListKeys", mock.Anything, keyLegacyVaultScope(), repositories.KeyFilter{}).
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
	// Legacy flat route (no vault_name) yields a default-vault scope.
	svc.On("ListKeys", mock.Anything, keyLegacyVaultScope(), repositories.KeyFilter{}).
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
	// Legacy flat route (no vault_name) yields a default-vault scope.
	// The service returns the not-found sentinel, which maps to 404.
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(nil, keyServices.ErrKeyNotFound)

	c := newKeyCtx(svc)
	c.Claims = RequestClaims{Role: string(model.RoleUser), UserID: keyTestUserID}
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
	// Legacy flat route (no vault_name) yields a default-vault scope.
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(makeKeyModel(keyID), nil)

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
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(makeKeyModel(keyID), nil)

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
	svc.On("DeleteKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(nil, errors.New("db error"))

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
	svc.On("DeleteKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(deleted, nil)

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
	svc.On("DeleteKey", mock.Anything, keyID, keyLegacyVaultScope()).
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
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).
		Return(nil, keyServices.ErrKeyLifecycleDenied)

	c := newKeyCtx(svc)
	c.Claims = RequestClaims{Role: string(model.RoleUser), UserID: keyTestUserID}
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
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).
		Return(nil, errors.New("disk I/O"))

	c := newKeyCtx(svc)
	c.Claims = RequestClaims{Role: string(model.RoleUser), UserID: keyTestUserID}
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

// TestRotateKey_P256K_NoHSMMechanism_Returns400 pins the shared writeKeyError
// mapping added alongside TestCreateKey_ECDSA_P256K_NoHSMMechanism_Returns400
// (B24 follow-up): RotateKey hits the identical crypto.ErrUnsupportedCurve
// via GenerateECDSAKey(ctx, "P-256K") for an ES256K key on an HSM-enabled
// instance, and must not fall through to a 500 either.
func TestRotateKey_P256K_NoHSMMechanism_Returns400(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RotateKey", mock.Anything, keyID, keyLegacyVaultScope()).
		Return(nil, fmt.Errorf("key generation failed: %w", crypto.ErrUnsupportedCurve))

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/rotate", nil)

	rotateKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
}

func TestRotateKey_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RotateKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(nil, errors.New("rotate failed"))

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
	svc.On("RotateKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(&keyServices.CreateKeyResult{KeyID: newKeyID, Name: "test-key"}, nil)
	// rotateKey re-fetches with the same vault scope that authorized the rotation.
	svc.On("GetKey", mock.Anything, newKeyID, keyLegacyVaultScope()).Return(makeKeyModel(newKeyID), nil)

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

func TestListKeyVersions_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyCtx(nil)
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/bad/versions", nil)

	listKeyVersions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListKeyVersions_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ListKeyVersions", mock.Anything, keyID, keyLegacyVaultScope()).
		Return(nil, errors.New("db error"))

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/versions", nil)

	listKeyVersions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListKeyVersions_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ListKeyVersions", mock.Anything, keyID, keyLegacyVaultScope()).
		Return([]model.KeyVersion{{KeyID: keyID, Version: 1}}, nil)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/versions", nil)

	listKeyVersions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestListKeyVersions_UnauthorizedKeyIsNotFound pins that the handler
// authorizes through the service's scope-aware read before returning
// versions, so it behaves like getKey on the same route instead of silently
// returning an empty list.
func TestListKeyVersions_UnauthorizedKeyIsNotFound(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ListKeyVersions", mock.Anything, keyID, keyLegacyVaultScope()).
		Return(nil, keyServices.ErrKeyNotFound)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/versions", nil)

	listKeyVersions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
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

// TestWrapKey_AES256KW_Success_Returns200 covers the HTTP -> handler ->
// response wiring for a successful wrap. It deliberately uses A256KW, not
// A256CBC: AES-CBC wrap is rejected for HSM-backed keys because wrap/unwrap has
// no IV channel (see TestWrapKey_HSMKey_RejectsAES256CBC in
// internal/services/keys, which pins that gate against the real service — a
// stubbed CryptoService cannot exercise it).
func TestWrapKey_AES256KW_Success_Returns200(t *testing.T) {
	wrapped := []byte("wrapped-kw-ciphertext")
	svc := &stubCryptoSvc{
		wrapKeyFn: func(_ context.Context, req keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
			assert.Equal(t, testKeyIDStr, req.KeyID.String())
			assert.Equal(t, "A256KW", req.Algorithm)
			assert.Equal(t, []byte("plaintext key material"), req.PlaintextKey)
			return &keyServices.WrapKeyResult{WrappedKey: wrapped, Algorithm: "A256KW"}, nil
		},
	}

	c := newCryptoContext(svc)
	c.Params = &ApiParams{KeyID: testKeyIDStr, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+testKeyIDStr+"/wrap", jsonBody(t, map[string]any{
		"plaintext_key": base64.StdEncoding.EncodeToString([]byte("plaintext key material")),
		"algorithm":     "A256KW",
	}))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp WrapKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, base64.StdEncoding.EncodeToString(wrapped), resp.WrappedKey)
	assert.Equal(t, "A256KW", resp.Algorithm)
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
