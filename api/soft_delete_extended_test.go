// Package api — additional tests for soft-delete handlers (secrets, keys, certificates).
package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"rocketvault/app"
	"rocketvault/common"
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

// errTest is a sentinel error used by stub repositories in soft-delete tests.
var errTest = errors.New("test error")

// ============================================================
// stub secret service for soft-delete tests
// ============================================================

// stubSecretService is a minimal secretServices.SecretService stub for the
// soft-delete handler tests. It embeds the (nil) interface so any method
// beyond the five soft-delete-related ones below panics with a nil-pointer
// dereference if called, surfacing accidental use.
type stubSecretService struct {
	secretServices.SecretService

	deletedInVault    []model.Secret
	deletedInVaultErr error

	softDeletedInVault    bool
	softDeletedInVaultErr error

	softDeletedForUser    bool
	softDeletedForUserErr error

	recoverErr error
	purgeErr   error

	// Records which authorization branch the handler exercised.
	userCheckCalled  bool
	vaultCheckCalled bool
}

func (s *stubSecretService) ListDeletedSecretsInVault(_ context.Context, _ uuid.UUID) ([]model.Secret, error) {
	return s.deletedInVault, s.deletedInVaultErr
}

func (s *stubSecretService) IsSecretSoftDeletedInVault(_ context.Context, _, _ uuid.UUID) (bool, error) {
	s.vaultCheckCalled = true
	return s.softDeletedInVault, s.softDeletedInVaultErr
}

func (s *stubSecretService) IsSecretSoftDeletedForUser(_ context.Context, _, _ uuid.UUID) (bool, error) {
	s.userCheckCalled = true
	return s.softDeletedForUser, s.softDeletedForUserErr
}

func (s *stubSecretService) RecoverSecret(_ context.Context, _ uuid.UUID) error {
	return s.recoverErr
}

func (s *stubSecretService) PurgeSecret(_ context.Context, _ uuid.UUID) error {
	return s.purgeErr
}

// ============================================================
// stub certificate repository for soft-delete tests
// ============================================================

type stubCertRepo struct {
	listDeleted    []*model.Certificate
	listDeletedErr error
	recoverErr     error
	purgeErr       error
}

func (s *stubCertRepo) Create(_ context.Context, _ *model.Certificate) error {
	panic("unexpected call: Create")
}
func (s *stubCertRepo) Read(_ context.Context, _ uuid.UUID) (*model.Certificate, error) {
	panic("unexpected call: Read")
}
func (s *stubCertRepo) Update(_ context.Context, _ *model.Certificate) error {
	panic("unexpected call: Update")
}
func (s *stubCertRepo) Delete(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: Delete")
}
func (s *stubCertRepo) Revoke(_ context.Context, _ uuid.UUID, _, _ string) error {
	panic("unexpected call: Revoke")
}
func (s *stubCertRepo) SoftDelete(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: SoftDelete")
}
func (s *stubCertRepo) RecoverCertificate(_ context.Context, _ uuid.UUID) error {
	return s.recoverErr
}
func (s *stubCertRepo) PurgeCertificate(_ context.Context, _ uuid.UUID) error {
	return s.purgeErr
}
func (s *stubCertRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error {
	panic("unexpected call: SetPurgeProtection")
}
func (s *stubCertRepo) ListByUser(_ context.Context, _ uuid.UUID, _ string, _ []string) ([]model.Certificate, error) {
	panic("unexpected call: ListByUser")
}
func (s *stubCertRepo) ListRevoked(_ context.Context, _ uuid.UUID) ([]model.RevokedCertificate, error) {
	panic("unexpected call: ListRevoked")
}
func (s *stubCertRepo) ListSoftDeleted(_ context.Context, _ uuid.UUID) ([]*model.Certificate, error) {
	return s.listDeleted, s.listDeletedErr
}
func (s *stubCertRepo) ListAll(_ context.Context) ([]model.Certificate, error) {
	panic("unexpected call: ListAll")
}
func (s *stubCertRepo) ListInVault(_ context.Context, _ uuid.UUID, _ string, _ []string) ([]model.Certificate, error) {
	panic("unexpected call: ListInVault")
}
func (s *stubCertRepo) ReadInVault(_ context.Context, _, _ uuid.UUID) (*model.Certificate, error) {
	panic("unexpected call: ReadInVault")
}
func (s *stubCertRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	panic("unexpected call: SoftDeleteVaultContents")
}
func (s *stubCertRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	panic("unexpected call: RecoverVaultContents")
}

// ============================================================
// multi-repo containers
// ============================================================

// sdSecretSvcContainer wires only GetSecretService.
type sdSecretSvcContainer struct {
	secretSvc secretServices.SecretService
}

func (c *sdSecretSvcContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *sdSecretSvcContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *sdSecretSvcContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *sdSecretSvcContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *sdSecretSvcContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *sdSecretSvcContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *sdSecretSvcContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *sdSecretSvcContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *sdSecretSvcContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *sdSecretSvcContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *sdSecretSvcContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *sdSecretSvcContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *sdSecretSvcContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *sdSecretSvcContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *sdSecretSvcContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *sdSecretSvcContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *sdSecretSvcContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *sdSecretSvcContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *sdSecretSvcContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *sdSecretSvcContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *sdSecretSvcContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *sdSecretSvcContainer) GetSecretService() secretServices.SecretService {
	return c.secretSvc
}
func (c *sdSecretSvcContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *sdSecretSvcContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *sdSecretSvcContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *sdSecretSvcContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *sdSecretSvcContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *sdSecretSvcContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *sdSecretSvcContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *sdSecretSvcContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *sdSecretSvcContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *sdSecretSvcContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *sdSecretSvcContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *sdSecretSvcContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *sdSecretSvcContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *sdSecretSvcContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *sdSecretSvcContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *sdSecretSvcContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *sdSecretSvcContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *sdSecretSvcContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *sdSecretSvcContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *sdSecretSvcContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *sdSecretSvcContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *sdSecretSvcContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *sdSecretSvcContainer) Close() error { return nil }

// certRepoTestContainer wires only GetCertificateRepository.
type certRepoTestContainer struct {
	certRepo repositories.CertificateRepositoryInterface
}

func (c *certRepoTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	return c.certRepo
}
func (c *certRepoTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *certRepoTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *certRepoTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *certRepoTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *certRepoTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *certRepoTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *certRepoTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *certRepoTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *certRepoTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *certRepoTestContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *certRepoTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *certRepoTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *certRepoTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *certRepoTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *certRepoTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *certRepoTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *certRepoTestContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *certRepoTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *certRepoTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *certRepoTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *certRepoTestContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *certRepoTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *certRepoTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *certRepoTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *certRepoTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *certRepoTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *certRepoTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *certRepoTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *certRepoTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *certRepoTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *certRepoTestContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *certRepoTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *certRepoTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *certRepoTestContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *certRepoTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *certRepoTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *certRepoTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *certRepoTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *certRepoTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *certRepoTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *certRepoTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *certRepoTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *certRepoTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *certRepoTestContainer) Close() error { return nil }

// ============================================================
// helpers
// ============================================================

const sdExtUserID = "c3d4e5f6-a7b8-9012-cdef-123456789012"

func newSecretSvcCtx(svc secretServices.SecretService) *Context {
	a := &app.App{ServiceContainer: &sdSecretSvcContainer{secretSvc: svc}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"user_id": sdExtUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

func newKeyRepoCtxExt(repo repositories.KeyRepositoryInterface) *Context {
	a := &app.App{ServiceContainer: &keyRepoTestContainer{keyRepo: repo}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"user_id": sdExtUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

func newCertRepoCtx(repo repositories.CertificateRepositoryInterface) *Context {
	a := &app.App{ServiceContainer: &certRepoTestContainer{certRepo: repo}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"user_id": sdExtUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

// newVaultScopedRequest builds a request that looks like it was served by a
// vault-scoped route: it carries the "vault_name" mux var (so
// isVaultScopedRoute is true) and the resolved vault id in the request context.
func newVaultScopedRequest(method, target, vaultName string, vaultID uuid.UUID) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r = mux.SetURLVars(r, map[string]string{"vault_name": vaultName})
	ctx := context.WithValue(r.Context(), common.VaultIDKey, vaultID.String())
	return r.WithContext(ctx)
}

// ============================================================
// userIDFromClaims
// ============================================================

func TestUserIDFromClaims_MissingClaim_ReturnsFalse(t *testing.T) {
	c := &Context{Claims: jwt.MapClaims{}, Params: &ApiParams{}}
	id, ok := userIDFromClaims(c)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
}

func TestUserIDFromClaims_InvalidUUID_ReturnsFalse(t *testing.T) {
	c := &Context{Claims: jwt.MapClaims{"user_id": "not-uuid"}, Params: &ApiParams{}}
	id, ok := userIDFromClaims(c)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
}

func TestUserIDFromClaims_ValidUUID_ReturnsTrue(t *testing.T) {
	c := &Context{Claims: jwt.MapClaims{"user_id": sdExtUserID}, Params: &ApiParams{}}
	id, ok := userIDFromClaims(c)
	assert.True(t, ok)
	assert.Equal(t, uuid.MustParse(sdExtUserID), id)
}

// ============================================================
// listDeletedSecrets
// ============================================================

func TestListDeletedSecrets_RepoError_Returns500(t *testing.T) {
	svc := &stubSecretService{deletedInVaultErr: errTest}
	c := newSecretSvcCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil)

	listDeletedSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListDeletedSecrets_EmptyList_Returns200(t *testing.T) {
	svc := &stubSecretService{deletedInVault: []model.Secret{}}
	c := newSecretSvcCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil)

	listDeletedSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListDeletedSecrets_WithDeletedItems_Returns200(t *testing.T) {
	now := time.Now()
	svc := &stubSecretService{
		deletedInVault: []model.Secret{
			{ID: uuid.New(), Name: "deleted-secret", DeletedAt: &now},
		},
	}
	c := newSecretSvcCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil)

	listDeletedSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// recoverSecret
// ============================================================

func TestRecoverSecret_InvalidID_Returns400(t *testing.T) {
	svc := &stubSecretService{}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/secrets/bad/restore", nil)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	// The user-ownership check reports no matching soft-deleted secret.
	svc := &stubSecretService{softDeletedForUser: false}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/secrets/"+secretID.String()+"/restore", nil)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRecoverSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &stubSecretService{softDeletedForUser: true}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/secrets/"+secretID.String()+"/restore", nil)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRecoverSecret_VaultScoped_OtherUsersSecret_Returns200 verifies that on a
// vault-scoped route, vault membership is sufficient: a secret that belongs to
// the vault but to a DIFFERENT user is recoverable. The user-scoped branch
// would 404 here because s.UserID != caller.
func TestRecoverSecret_VaultScoped_OtherUsersSecret_Returns200(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	// Vault membership check succeeds regardless of who owns the secret; the
	// user-ownership check would fail if the handler mistakenly used it.
	svc := &stubSecretService{softDeletedInVault: true}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodPost,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/restore", "prod", vaultID)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, svc.vaultCheckCalled, "vault-scoped route must verify via IsSecretSoftDeletedInVault")
	assert.False(t, svc.userCheckCalled, "vault-scoped route must NOT fall back to user-ownership check")
}

// TestRecoverSecret_VaultScoped_SecretNotInVault_Returns404 verifies that a
// secret absent from the resolved vault is not recoverable, even though it
// would be visible to the caller via user-ownership.
func TestRecoverSecret_VaultScoped_SecretNotInVault_Returns404(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	// The secret is not present in the vault, even though it would pass a
	// user-ownership check if the handler mistakenly used it.
	svc := &stubSecretService{softDeletedInVault: false}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodPost,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/restore", "prod", vaultID)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.True(t, svc.vaultCheckCalled, "vault-scoped route must verify via IsSecretSoftDeletedInVault")
	assert.False(t, svc.userCheckCalled, "vault-scoped route must NOT fall back to user-ownership check")
}

// TestRecoverSecret_VaultScoped_NotSoftDeleted_Returns404 verifies that a row
// present in the vault but NOT soft-deleted (DeletedAt == nil) is not
// recoverable, guarding against recovering a live secret.
func TestRecoverSecret_VaultScoped_NotSoftDeleted_Returns404(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	svc := &stubSecretService{softDeletedInVault: false}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodPost,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/restore", "prod", vaultID)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================
// purgeSecret
// ============================================================

func TestPurgeSecret_InvalidID_Returns400(t *testing.T) {
	svc := &stubSecretService{}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/secrets/bad/purge", nil)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &stubSecretService{softDeletedForUser: false}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/secrets/"+secretID.String()+"/purge", nil)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPurgeSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &stubSecretService{softDeletedForUser: true}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/secrets/"+secretID.String()+"/purge", nil)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestPurgeSecret_VaultScoped_OtherUsersSecret_Returns200 verifies vault
// membership is sufficient to purge a soft-deleted secret owned by another user.
func TestPurgeSecret_VaultScoped_OtherUsersSecret_Returns200(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	svc := &stubSecretService{softDeletedInVault: true}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodDelete,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/purge", "prod", vaultID)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, svc.vaultCheckCalled, "vault-scoped route must verify via IsSecretSoftDeletedInVault")
	assert.False(t, svc.userCheckCalled, "vault-scoped route must NOT fall back to user-ownership check")
}

// TestPurgeSecret_VaultScoped_SecretNotInVault_Returns404 verifies a secret
// absent from the resolved vault cannot be purged even if the caller owns it.
func TestPurgeSecret_VaultScoped_SecretNotInVault_Returns404(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	svc := &stubSecretService{softDeletedInVault: false}
	c := newSecretSvcCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodDelete,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/purge", "prod", vaultID)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.True(t, svc.vaultCheckCalled, "vault-scoped route must verify via IsSecretSoftDeletedInVault")
	assert.False(t, svc.userCheckCalled, "vault-scoped route must NOT fall back to user-ownership check")
}

// ============================================================
// listDeletedKeys
// ============================================================

func TestListDeletedKeys_RepoError_Returns500(t *testing.T) {
	repo := &stubKeyRepo{softDeletedErr: errTest}
	c := newKeyRepoCtxExt(repo)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys", nil)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListDeletedKeys_Success_Returns200(t *testing.T) {
	now := time.Now()
	repo := &stubKeyRepo{
		softDeletedKeys: []*model.Key{
			{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now},
		},
	}
	c := newKeyRepoCtxExt(repo)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys", nil)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// recoverKey (using stubKeyRepoWithRecover)
// ============================================================

type stubKeyRepoWithRecover struct {
	stubKeyRepo
	recoverErr error
}

func (s *stubKeyRepoWithRecover) RecoverKey(_ context.Context, _ uuid.UUID) error {
	return s.recoverErr
}

func TestRecoverKey_InvalidID_Returns400(t *testing.T) {
	repo := &stubKeyRepoWithRecover{}
	c := newKeyRepoCtxExt(repo)
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/bad/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	repo := &stubKeyRepoWithRecover{stubKeyRepo: stubKeyRepo{softDeletedKeys: []*model.Key{}}}
	c := newKeyRepoCtxExt(repo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRecoverKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	now := time.Now()
	repo := &stubKeyRepoWithRecover{
		stubKeyRepo: stubKeyRepo{
			softDeletedKeys: []*model.Key{
				{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now},
			},
		},
	}
	c := newKeyRepoCtxExt(repo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// purgeKey
// ============================================================

type stubKeyRepoWithPurge struct {
	stubKeyRepo
	purgeErr error
}

func (s *stubKeyRepoWithPurge) PurgeKey(_ context.Context, _ uuid.UUID) error {
	return s.purgeErr
}

func TestPurgeKey_InvalidID_Returns400(t *testing.T) {
	repo := &stubKeyRepoWithPurge{}
	c := newKeyRepoCtxExt(repo)
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/bad/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	now := time.Now()
	repo := &stubKeyRepoWithPurge{
		stubKeyRepo: stubKeyRepo{
			softDeletedKeys: []*model.Key{
				{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now},
			},
		},
	}
	c := newKeyRepoCtxExt(repo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/"+keyID.String()+"/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// listDeletedCertificates
// ============================================================

func TestListDeletedCertificates_RepoError_Returns500(t *testing.T) {
	repo := &stubCertRepo{listDeletedErr: errTest}
	c := newCertRepoCtx(repo)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListDeletedCertificates_Success_Returns200(t *testing.T) {
	now := time.Now()
	repo := &stubCertRepo{
		listDeleted: []*model.Certificate{
			{ID: uuid.New(), Name: "cert", DeletedAt: &now},
		},
	}
	c := newCertRepoCtx(repo)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// recoverCertificate
// ============================================================

func TestRecoverCertificate_InvalidID_Returns400(t *testing.T) {
	repo := &stubCertRepo{}
	c := newCertRepoCtx(repo)
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/bad/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverCertificate_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	repo := &stubCertRepo{listDeleted: []*model.Certificate{}}
	c := newCertRepoCtx(repo)
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRecoverCertificate_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	now := time.Now()
	repo := &stubCertRepo{
		listDeleted: []*model.Certificate{
			{ID: certID, Name: "cert", DeletedAt: &now},
		},
	}
	c := newCertRepoCtx(repo)
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// purgeCertificate
// ============================================================

func TestPurgeCertificate_InvalidID_Returns400(t *testing.T) {
	repo := &stubCertRepo{}
	c := newCertRepoCtx(repo)
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/bad/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeCertificate_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	repo := &stubCertRepo{listDeleted: []*model.Certificate{}}
	c := newCertRepoCtx(repo)
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPurgeCertificate_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	now := time.Now()
	repo := &stubCertRepo{
		listDeleted: []*model.Certificate{
			{ID: certID, Name: "cert", DeletedAt: &now},
		},
	}
	c := newCertRepoCtx(repo)
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}
