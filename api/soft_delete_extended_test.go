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
// stub secret repository for soft-delete tests
// ============================================================

type stubSecretRepo struct {
	listDeleted    []model.Secret
	listDeletedErr error
	recoverErr     error
	purgeErr       error

	// vaultDeleted, when non-nil, is returned by ListInVaultIncludeDeleted so
	// tests can distinguish the vault-scoped authorization branch from the
	// user-scoped one. When nil the method falls back to listDeleted.
	vaultDeleted    []model.Secret
	vaultDeletedSet bool
	// Records which authorization branch the handler exercised.
	userListCalled  bool
	vaultListCalled bool
}

func (s *stubSecretRepo) Create(_ context.Context, _ *model.Secret) error {
	panic("unexpected call: Create")
}
func (s *stubSecretRepo) Read(_ context.Context, _ uuid.UUID) (*model.Secret, error) {
	panic("unexpected call: Read")
}
func (s *stubSecretRepo) ReadByOwner(_ context.Context, _, _ uuid.UUID) (*model.Secret, error) {
	panic("unexpected call: ReadByOwner")
}
func (s *stubSecretRepo) ReadScoped(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
	panic("unexpected call: ReadScoped")
}
func (s *stubSecretRepo) Update(_ context.Context, _ *model.Secret) error {
	panic("unexpected call: Update")
}
func (s *stubSecretRepo) UpdateScoped(_ context.Context, _ *model.Secret, _ model.Scope) error {
	panic("unexpected call: UpdateScoped")
}
func (s *stubSecretRepo) UpdateInVault(_ context.Context, _ *model.Secret) error {
	panic("unexpected call: UpdateInVault")
}
func (s *stubSecretRepo) Delete(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: Delete")
}
func (s *stubSecretRepo) SoftDelete(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: SoftDelete")
}
func (s *stubSecretRepo) RecoverSecret(_ context.Context, _ uuid.UUID) error {
	return s.recoverErr
}
func (s *stubSecretRepo) ListByUser(_ context.Context, _ uuid.UUID, _ []string) ([]model.Secret, error) {
	panic("unexpected call: ListByUser")
}
func (s *stubSecretRepo) ListScoped(_ context.Context, _ model.Scope, _ repositories.SecretFilter) ([]model.Secret, error) {
	panic("unexpected call: ListScoped")
}
func (s *stubSecretRepo) ListByUserIncludeDeleted(_ context.Context, _ uuid.UUID, _ []string) ([]model.Secret, error) {
	s.userListCalled = true
	return s.listDeleted, s.listDeletedErr
}
func (s *stubSecretRepo) ExportSecrets(_ context.Context, _ model.ExportOptions) ([]byte, error) {
	panic("unexpected call: ExportSecrets")
}
func (s *stubSecretRepo) ImportSecrets(_ context.Context, _ []byte, _ model.ImportOptions) (int, error) {
	panic("unexpected call: ImportSecrets")
}
func (s *stubSecretRepo) GetVersions(_ context.Context, _ uuid.UUID) ([]model.SecretVersion, error) {
	panic("unexpected call: GetVersions")
}
func (s *stubSecretRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.SecretVersion, error) {
	panic("unexpected call: GetVersion")
}
func (s *stubSecretRepo) GetLatestVersion(_ context.Context, _ uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected call: GetLatestVersion")
}
func (s *stubSecretRepo) PurgeSecret(_ context.Context, _ uuid.UUID) error {
	return s.purgeErr
}
func (s *stubSecretRepo) ReadInVault(_ context.Context, _, _ uuid.UUID) (*model.Secret, error) {
	panic("unexpected call: ReadInVault")
}
func (s *stubSecretRepo) ListInVault(_ context.Context, _ uuid.UUID, _ []string) ([]model.Secret, error) {
	panic("unexpected call: ListInVault")
}
func (s *stubSecretRepo) ListInVaultIncludeDeleted(_ context.Context, _ uuid.UUID, _ []string) ([]model.Secret, error) {
	s.vaultListCalled = true
	if s.vaultDeletedSet {
		return s.vaultDeleted, s.listDeletedErr
	}
	return s.listDeleted, s.listDeletedErr
}
func (s *stubSecretRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	panic("unexpected call: SoftDeleteVaultContents")
}
func (s *stubSecretRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	panic("unexpected call: RecoverVaultContents")
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
func (s *stubCertRepo) ReadScoped(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Certificate, error) {
	panic("unexpected call: ReadScoped")
}
func (s *stubCertRepo) UpdateScoped(_ context.Context, _ *model.Certificate, _ model.Scope) error {
	panic("unexpected call: UpdateScoped")
}
func (s *stubCertRepo) ListScoped(_ context.Context, _ model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	panic("unexpected call: ListScoped")
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
func (s *stubCertRepo) ListByUser(_ context.Context, _ uuid.UUID, _ []string) ([]model.Certificate, error) {
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
func (s *stubCertRepo) ListInVault(_ context.Context, _ uuid.UUID, _ []string) ([]model.Certificate, error) {
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

// secretRepoTestContainer wires only GetSecretRepository.
type secretRepoTestContainer struct {
	secretRepo repositories.SecretRepositoryInterface
}

func (c *secretRepoTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	return c.secretRepo
}
func (c *secretRepoTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *secretRepoTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *secretRepoTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *secretRepoTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *secretRepoTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *secretRepoTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *secretRepoTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *secretRepoTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *secretRepoTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *secretRepoTestContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *secretRepoTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *secretRepoTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *secretRepoTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *secretRepoTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *secretRepoTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *secretRepoTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *secretRepoTestContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *secretRepoTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *secretRepoTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *secretRepoTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *secretRepoTestContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *secretRepoTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *secretRepoTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *secretRepoTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *secretRepoTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *secretRepoTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *secretRepoTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *secretRepoTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *secretRepoTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *secretRepoTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *secretRepoTestContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *secretRepoTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *secretRepoTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *secretRepoTestContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *secretRepoTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *secretRepoTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *secretRepoTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *secretRepoTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *secretRepoTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *secretRepoTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *secretRepoTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *secretRepoTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *secretRepoTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *secretRepoTestContainer) Close() error { return nil }

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

func newSecretRepoCtx(repo repositories.SecretRepositoryInterface) *Context {
	a := &app.App{ServiceContainer: &secretRepoTestContainer{secretRepo: repo}}
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
	repo := &stubSecretRepo{listDeletedErr: errTest}
	c := newSecretRepoCtx(repo)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil)

	listDeletedSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListDeletedSecrets_EmptyList_Returns200(t *testing.T) {
	repo := &stubSecretRepo{listDeleted: []model.Secret{}}
	c := newSecretRepoCtx(repo)
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
	repo := &stubSecretRepo{
		listDeleted: []model.Secret{
			{ID: uuid.New(), Name: "deleted-secret", DeletedAt: &now},
		},
	}
	c := newSecretRepoCtx(repo)
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
	repo := &stubSecretRepo{}
	c := newSecretRepoCtx(repo)
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
	// List returns entries but none matching secretID+userID.
	repo := &stubSecretRepo{listDeleted: []model.Secret{}}
	c := newSecretRepoCtx(repo)
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
	userID := uuid.MustParse(sdExtUserID)
	now := time.Now()
	repo := &stubSecretRepo{
		listDeleted: []model.Secret{
			{ID: secretID, UserID: userID, Name: "s", DeletedAt: &now},
		},
	}
	c := newSecretRepoCtx(repo)
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
	otherUser := uuid.New() // deliberately not sdExtUserID
	vaultID := uuid.New()
	now := time.Now()
	repo := &stubSecretRepo{
		// User-scoped listing is empty: if the wrong branch runs, we get 404.
		listDeleted:     []model.Secret{},
		vaultDeletedSet: true,
		vaultDeleted: []model.Secret{
			{ID: secretID, UserID: otherUser, Name: "s", DeletedAt: &now},
		},
	}
	c := newSecretRepoCtx(repo)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodPost,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/restore", "prod", vaultID)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, repo.vaultListCalled, "vault-scoped route must verify via ListInVaultIncludeDeleted")
	assert.False(t, repo.userListCalled, "vault-scoped route must NOT fall back to user-ownership check")
}

// TestRecoverSecret_VaultScoped_SecretNotInVault_Returns404 verifies that a
// secret absent from the resolved vault is not recoverable, even though it
// would be visible to the caller via user-ownership.
func TestRecoverSecret_VaultScoped_SecretNotInVault_Returns404(t *testing.T) {
	secretID := uuid.New()
	userID := uuid.MustParse(sdExtUserID)
	vaultID := uuid.New()
	now := time.Now()
	repo := &stubSecretRepo{
		// The caller owns the secret (user-scoped would pass)...
		listDeleted: []model.Secret{
			{ID: secretID, UserID: userID, Name: "s", DeletedAt: &now},
		},
		// ...but it is not present in the vault.
		vaultDeletedSet: true,
		vaultDeleted:    []model.Secret{},
	}
	c := newSecretRepoCtx(repo)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodPost,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/restore", "prod", vaultID)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.True(t, repo.vaultListCalled, "vault-scoped route must verify via ListInVaultIncludeDeleted")
	assert.False(t, repo.userListCalled, "vault-scoped route must NOT fall back to user-ownership check")
}

// TestRecoverSecret_VaultScoped_NotSoftDeleted_Returns404 verifies that a row
// present in the vault but NOT soft-deleted (DeletedAt == nil) is not
// recoverable, guarding against recovering a live secret.
func TestRecoverSecret_VaultScoped_NotSoftDeleted_Returns404(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	repo := &stubSecretRepo{
		vaultDeletedSet: true,
		vaultDeleted: []model.Secret{
			{ID: secretID, UserID: uuid.New(), Name: "s", DeletedAt: nil},
		},
	}
	c := newSecretRepoCtx(repo)
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
	repo := &stubSecretRepo{}
	c := newSecretRepoCtx(repo)
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
	repo := &stubSecretRepo{listDeleted: []model.Secret{}}
	c := newSecretRepoCtx(repo)
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
	userID := uuid.MustParse(sdExtUserID)
	now := time.Now()
	repo := &stubSecretRepo{
		listDeleted: []model.Secret{
			{ID: secretID, UserID: userID, Name: "s", DeletedAt: &now},
		},
	}
	c := newSecretRepoCtx(repo)
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
	otherUser := uuid.New()
	vaultID := uuid.New()
	now := time.Now()
	repo := &stubSecretRepo{
		listDeleted:     []model.Secret{},
		vaultDeletedSet: true,
		vaultDeleted: []model.Secret{
			{ID: secretID, UserID: otherUser, Name: "s", DeletedAt: &now},
		},
	}
	c := newSecretRepoCtx(repo)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodDelete,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/purge", "prod", vaultID)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, repo.vaultListCalled, "vault-scoped route must verify via ListInVaultIncludeDeleted")
	assert.False(t, repo.userListCalled, "vault-scoped route must NOT fall back to user-ownership check")
}

// TestPurgeSecret_VaultScoped_SecretNotInVault_Returns404 verifies a secret
// absent from the resolved vault cannot be purged even if the caller owns it.
func TestPurgeSecret_VaultScoped_SecretNotInVault_Returns404(t *testing.T) {
	secretID := uuid.New()
	userID := uuid.MustParse(sdExtUserID)
	vaultID := uuid.New()
	now := time.Now()
	repo := &stubSecretRepo{
		listDeleted: []model.Secret{
			{ID: secretID, UserID: userID, Name: "s", DeletedAt: &now},
		},
		vaultDeletedSet: true,
		vaultDeleted:    []model.Secret{},
	}
	c := newSecretRepoCtx(repo)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := newVaultScopedRequest(http.MethodDelete,
		"/vaults/prod/deleted/secrets/"+secretID.String()+"/purge", "prod", vaultID)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.True(t, repo.vaultListCalled, "vault-scoped route must verify via ListInVaultIncludeDeleted")
	assert.False(t, repo.userListCalled, "vault-scoped route must NOT fall back to user-ownership check")
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
