// Package api — internal tests for key rotation policy handlers.
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

// --- mock KeyRotationPolicyRepository ---

type mockKeyRotationPolicyRepo struct {
	mock.Mock
}

func (m *mockKeyRotationPolicyRepo) Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *mockKeyRotationPolicyRepo) GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyRotationPolicy), args.Error(1)
}

func (m *mockKeyRotationPolicyRepo) DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, keyID, scope)
	return args.Error(0)
}

func (m *mockKeyRotationPolicyRepo) ListByVault(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicyWithKeyName, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.KeyRotationPolicyWithKeyName), args.Error(1)
}

func (m *mockKeyRotationPolicyRepo) GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.KeyRotationPolicy), args.Error(1)
}

func (m *mockKeyRotationPolicyRepo) MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error {
	args := m.Called(ctx, keyID, scope, at, rotateAfterDays)
	return args.Error(0)
}

// --- keyRotationPolicyRepoContainer ---

type keyRotationPolicyRepoContainer struct {
	keySvc keyServices.KeyService
}

func (c *keyRotationPolicyRepoContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *keyRotationPolicyRepoContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *keyRotationPolicyRepoContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *keyRotationPolicyRepoContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *keyRotationPolicyRepoContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *keyRotationPolicyRepoContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *keyRotationPolicyRepoContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *keyRotationPolicyRepoContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *keyRotationPolicyRepoContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *keyRotationPolicyRepoContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *keyRotationPolicyRepoContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *keyRotationPolicyRepoContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *keyRotationPolicyRepoContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (c *keyRotationPolicyRepoContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *keyRotationPolicyRepoContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *keyRotationPolicyRepoContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *keyRotationPolicyRepoContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *keyRotationPolicyRepoContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (c *keyRotationPolicyRepoContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *keyRotationPolicyRepoContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *keyRotationPolicyRepoContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *keyRotationPolicyRepoContainer) GetGrantService() provisioning.GrantService {
	return nil
}
func (c *keyRotationPolicyRepoContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *keyRotationPolicyRepoContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *keyRotationPolicyRepoContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *keyRotationPolicyRepoContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *keyRotationPolicyRepoContainer) GetKeyService() keyServices.KeyService {
	return c.keySvc
}
func (c *keyRotationPolicyRepoContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *keyRotationPolicyRepoContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *keyRotationPolicyRepoContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *keyRotationPolicyRepoContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *keyRotationPolicyRepoContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *keyRotationPolicyRepoContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *keyRotationPolicyRepoContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *keyRotationPolicyRepoContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *keyRotationPolicyRepoContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *keyRotationPolicyRepoContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *keyRotationPolicyRepoContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *keyRotationPolicyRepoContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *keyRotationPolicyRepoContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *keyRotationPolicyRepoContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (c *keyRotationPolicyRepoContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *keyRotationPolicyRepoContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *keyRotationPolicyRepoContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *keyRotationPolicyRepoContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *keyRotationPolicyRepoContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *keyRotationPolicyRepoContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *keyRotationPolicyRepoContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *keyRotationPolicyRepoContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *keyRotationPolicyRepoContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *keyRotationPolicyRepoContainer) Close() error { return nil }

const krpTestUserID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

// newKeyRotationPolicyCtx builds a Context backed by the given policy repo
// mock. The key service is a scope stub that reports the key as found and
// delegates its policy methods to repo, since these tests exercise the
// policy repository, not the key pre-check.
func newKeyRotationPolicyCtx(repo repositories.KeyRotationPolicyRepositoryInterface, keyIDStr string) *Context {
	a := &app.App{ServiceContainer: &keyRotationPolicyRepoContainer{keySvc: &scopeStubKeyService{policyRepo: repo}}}
	return &Context{
		App:    a,
		Claims: RequestClaims{UserID: krpTestUserID},
		Params: &ApiParams{KeyID: keyIDStr, PerPage: 60},
	}
}

// newKeyRotationPolicyCtxKeyNotVisible builds a Context whose key-service
// pre-check fails, simulating a caller that cannot see the parent key (e.g.
// wrong scope, deleted key). This exercises the actual security boundary of
// these handlers: this mock's GetByKeyID/DeleteByKeyID succeed regardless of
// the scope passed in, so the keySvc.GetKey pre-check is what stops an
// unauthorized caller from reading or mutating another key's rotation policy
// through them. The stub error
// wraps ErrKeyNotFound, matching what the real KeyService.GetKey always
// returns on a failed read (never a bare, unwrapped error) -- see
// keyService.GetKey in internal/services/keys/key_service.go.
func newKeyRotationPolicyCtxKeyNotVisible(repo repositories.KeyRotationPolicyRepositoryInterface, keyIDStr string) *Context {
	a := &app.App{ServiceContainer: &keyRotationPolicyRepoContainer{
		keySvc: &scopeStubKeyService{keyErr: keyServices.ErrKeyNotFound, policyRepo: repo},
	}}
	return &Context{
		App:    a,
		Claims: RequestClaims{UserID: krpTestUserID},
		Params: &ApiParams{KeyID: keyIDStr, PerPage: 60},
	}
}

// ============================================================
// getKeyRotationPolicy
// ============================================================

func TestGetKeyRotationPolicy_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyRotationPolicyCtx(nil, "bad-key-id")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/bad/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetKeyRotationPolicy_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("GetByKeyID", mock.Anything, keyID, mock.Anything).Return(nil, errors.New("not found"))

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "rotation policy not found", c.Err.Message,
		"a policy-repo failure (key exists) must keep the generic 'rotation policy' 404 message")
	repo.AssertExpectations(t)
}

// TestGetKeyRotationPolicy_KeyNotFound_Returns404WithKeyMessage and
// TestGetKeyRotationPolicy_KeyLifecycleDenied_Returns404WithKeyMessage pin the
// message-text half of the fix: both key-check failure modes (not-found and
// lifecycle-denied) must produce the blanket "key not found" 404 the
// pre-refactor handler always used, distinct from the generic "rotation
// policy not found" 404 a policy-repo failure produces.
func TestGetKeyRotationPolicy_KeyNotFound_Returns404WithKeyMessage(t *testing.T) {
	keyID := uuid.New()
	svc := &scopeStubKeyService{keyErr: keyServices.ErrKeyNotFound}
	c := newKeyCtx(svc)
	c.Params.KeyID = keyID.String()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, "key not found", c.Err.Message)
}

func TestGetKeyRotationPolicy_KeyLifecycleDenied_Returns404WithKeyMessage(t *testing.T) {
	keyID := uuid.New()
	svc := &scopeStubKeyService{keyErr: keyServices.ErrKeyLifecycleDenied}
	c := newKeyCtx(svc)
	c.Params.KeyID = keyID.String()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode,
		"lifecycle-denied must still map to 404, not writeKeyError's 403")
	assert.Equal(t, "key not found", c.Err.Message)
}

func TestGetKeyRotationPolicy_KeyNotVisible_Returns404(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	// No .On(...) expectations: the key pre-check must short-circuit before
	// the handler ever reaches the policy repository.

	c := newKeyRotationPolicyCtxKeyNotVisible(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	repo.AssertExpectations(t)
}

func TestGetKeyRotationPolicy_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(krpTestUserID)
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("GetByKeyID", mock.Anything, keyID, mock.Anything).Return(&model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, RotateAfterDays: 90,
	}, nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

// ============================================================
// upsertKeyRotationPolicy
// ============================================================

func TestUpsertKeyRotationPolicy_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyRotationPolicyCtx(nil, "bad")
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 90})
	r := httptest.NewRequest(http.MethodPut, "/keys/bad/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertKeyRotationPolicy_InvalidBody_Returns400(t *testing.T) {
	keyID := uuid.New()
	c := newKeyRotationPolicyCtx(nil, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader([]byte(`{bad json}`)))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertKeyRotationPolicy_KeyNotVisible_Returns404(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	// No .On(...) expectations: the key pre-check must short-circuit before
	// the handler ever reaches the policy repository.

	c := newKeyRotationPolicyCtxKeyNotVisible(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 90, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	repo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_UpsertError_Returns500(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 90, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	repo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(krpTestUserID)
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(nil)
	repo.On("GetByKeyID", mock.Anything, keyID, mock.Anything).Return(&model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, RotateAfterDays: 90, Enabled: true,
	}, nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 90, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_RotateAfterDaysZeroWhenEnabled_Returns400(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	// No expectations: validation should fail before reaching the repo.

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 0, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotNil(t, c.Err, "validation should set an error for RotateAfterDays < 7 when enabled")
	repo.AssertNotCalled(t, "Upsert")
}

func TestUpsertKeyRotationPolicy_NegativeRotateAfterDaysWhenEnabled_Returns400(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": -1, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	repo.AssertNotCalled(t, "Upsert")
}

func TestUpsertKeyRotationPolicy_RotateAfterDaysLessThan7WhenEnabled_Returns400(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 3, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	repo.AssertNotCalled(t, "Upsert")
}

func TestUpsertKeyRotationPolicy_RotateAfterDaysLessThan7WhenDisabled_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(krpTestUserID)
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(nil)
	repo.On("GetByKeyID", mock.Anything, keyID, mock.Anything).Return(&model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, RotateAfterDays: 3, Enabled: false,
	}, nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 3, "enabled": false})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code, "RotateAfterDays < 7 should be allowed when rotation is disabled")
	repo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_RotateAfterDays7WhenEnabled_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(krpTestUserID)
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(nil)
	repo.On("GetByKeyID", mock.Anything, keyID, mock.Anything).Return(&model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, RotateAfterDays: 7, Enabled: true,
	}, nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 7, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code, "RotateAfterDays 7 (minimum) should be accepted when enabled")
	repo.AssertExpectations(t)
}

// ============================================================
// deleteKeyRotationPolicy
// ============================================================

func TestDeleteKeyRotationPolicy_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyRotationPolicyCtx(nil, "bad")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/bad/rotationpolicy", nil)

	deleteKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteKeyRotationPolicy_KeyNotVisible_Returns404(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	// No .On(...) expectations: the key pre-check must short-circuit before
	// the handler ever reaches the policy repository.

	c := newKeyRotationPolicyCtxKeyNotVisible(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	deleteKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	repo.AssertExpectations(t)
}

func TestDeleteKeyRotationPolicy_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("DeleteByKeyID", mock.Anything, keyID, mock.Anything).Return(errors.New("db error"))

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	deleteKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	repo.AssertExpectations(t)
}

func TestDeleteKeyRotationPolicy_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("DeleteByKeyID", mock.Anything, keyID, mock.Anything).Return(nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	deleteKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}
