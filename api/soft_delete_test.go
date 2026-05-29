/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package api — unit tests for soft-delete handlers.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
	"rocketvault/internal/signing"
	"rocketvault/model"
)

// --- stub key repository ---

// stubKeyRepo is a minimal KeyRepositoryInterface stub for handler tests.
// Only ListSoftDeleted is implemented; all other methods panic.
type stubKeyRepo struct {
	softDeletedKeys []*model.Key
	softDeletedErr  error
}

func (s *stubKeyRepo) ListSoftDeleted(_ context.Context, _ uuid.UUID) ([]*model.Key, error) {
	return s.softDeletedKeys, s.softDeletedErr
}

// The following methods satisfy KeyRepositoryInterface but are not called by getDeletedKey.
func (s *stubKeyRepo) Create(_ context.Context, _ *model.Key) error {
	panic("unexpected call: Create")
}
func (s *stubKeyRepo) Read(_ context.Context, _ uuid.UUID) (*model.Key, error) {
	panic("unexpected call: Read")
}
func (s *stubKeyRepo) Update(_ context.Context, _ *model.Key) error {
	panic("unexpected call: Update")
}
func (s *stubKeyRepo) Delete(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: Delete")
}
func (s *stubKeyRepo) ListByUser(_ context.Context, _ *uuid.UUID, _ string, _ []string) ([]model.Key, error) {
	panic("unexpected call: ListByUser")
}
func (s *stubKeyRepo) UpdateRevocationStatus(_ context.Context, _ uuid.UUID, _ bool) error {
	panic("unexpected call: UpdateRevocationStatus")
}
func (s *stubKeyRepo) SoftDelete(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: SoftDelete")
}
func (s *stubKeyRepo) RecoverKey(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: RecoverKey")
}
func (s *stubKeyRepo) PurgeKey(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: PurgeKey")
}
func (s *stubKeyRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error {
	panic("unexpected call: SetPurgeProtection")
}
func (s *stubKeyRepo) ReadDeleted(_ context.Context, _ uuid.UUID) (*model.Key, error) {
	panic("unexpected call: ReadDeleted")
}
func (s *stubKeyRepo) CreateVersion(_ context.Context, _ uuid.UUID, _ int, _ string) error {
	panic("unexpected call: CreateVersion")
}
func (s *stubKeyRepo) ListVersions(_ context.Context, _, _ uuid.UUID) ([]model.KeyVersion, error) {
	panic("unexpected call: ListVersions")
}
func (s *stubKeyRepo) ListInVault(_ context.Context, _ uuid.UUID, _ string, _ []string) ([]model.Key, error) {
	panic("unexpected call: ListInVault")
}
func (s *stubKeyRepo) ReadInVault(_ context.Context, _, _ uuid.UUID) (*model.Key, error) {
	panic("unexpected call: ReadInVault")
}
func (s *stubKeyRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: SoftDeleteVaultContents")
}
func (s *stubKeyRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID) error {
	panic("unexpected call: RecoverVaultContents")
}

// --- stub service container ---

// keyRepoTestContainer satisfies container.ServiceContainerInterface with a
// stub key repository. All other methods panic to surface accidental calls.
type keyRepoTestContainer struct {
	keyRepo repositories.KeyRepositoryInterface
}

func (c *keyRepoTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	return c.keyRepo
}

func (c *keyRepoTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *keyRepoTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *keyRepoTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *keyRepoTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *keyRepoTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *keyRepoTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *keyRepoTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *keyRepoTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *keyRepoTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *keyRepoTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *keyRepoTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *keyRepoTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *keyRepoTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *keyRepoTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *keyRepoTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *keyRepoTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *keyRepoTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *keyRepoTestContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *keyRepoTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *keyRepoTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *keyRepoTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *keyRepoTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *keyRepoTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *keyRepoTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *keyRepoTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *keyRepoTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *keyRepoTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *keyRepoTestContainer) GetDatabase() *sql.DB {
	panic("unexpected call: GetDatabase")
}
func (c *keyRepoTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *keyRepoTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *keyRepoTestContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *keyRepoTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *keyRepoTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *keyRepoTestContainer) GetKeyProvider() crypto.KeyProvider              { return nil }
func (c *keyRepoTestContainer) GetSigningProvider() signing.SigningKeyProvider  { return nil }
func (c *keyRepoTestContainer) GetItemBackupService() *backup.ItemBackupService { return nil }
func (c *keyRepoTestContainer) GetKeyCache() keycache.Cache                     { return nil }
func (c *keyRepoTestContainer) GetCryptoMetrics() metrics.CryptoMetrics         { return nil }
func (c *keyRepoTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	panic("unexpected call: GetAuditService")
}
func (c *keyRepoTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	panic("unexpected call: GetComplianceReportService")
}
func (c *keyRepoTestContainer) Close() error { return nil }

// --- helpers ---

const sdTestUserIDStr = "c3d4e5f6-a7b8-9012-cdef-123456789012"

// newGetDeletedKeyContext builds a minimal Context wired to the given key repo stub.
func newGetDeletedKeyContext(repo repositories.KeyRepositoryInterface) *Context {
	a := &app.App{ServiceContainer: &keyRepoTestContainer{keyRepo: repo}}
	return &Context{
		App: a,
		Claims: jwt.MapClaims{
			"user_id": sdTestUserIDStr,
		},
	}
}

// --- tests ---

// TestGetDeletedKey_Found_Returns200 verifies that getDeletedKey returns 200
// with the expected JSON fields when the key exists in the soft-deleted list.
func TestGetDeletedKey_Found_Returns200(t *testing.T) {
	targetID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	deletedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	repo := &stubKeyRepo{
		softDeletedKeys: []*model.Key{
			{
				ID:        targetID,
				Name:      "my-rsa-key",
				Type:      model.KeyTypeRSA,
				DeletedAt: &deletedAt,
			},
		},
	}

	c := newGetDeletedKeyContext(repo)
	c.Params = &ApiParams{KeyID: targetID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys/"+targetID.String(), nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, targetID.String(), body["id"])
	assert.Equal(t, "my-rsa-key", body["name"])
	assert.Equal(t, model.KeyTypeRSA, body["type"])
	assert.NotNil(t, body["deleted_at"], "deleted_at must be present in the response")
}

// TestGetDeletedKey_NotFound_Returns404 verifies that getDeletedKey returns 404
// when no soft-deleted key with the requested ID exists.
func TestGetDeletedKey_NotFound_Returns404(t *testing.T) {
	existingID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	requestedID := uuid.MustParse("ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb")
	deletedAt := time.Now()

	repo := &stubKeyRepo{
		softDeletedKeys: []*model.Key{
			{
				ID:        existingID,
				Name:      "other-key",
				Type:      model.KeyTypeECDSA,
				DeletedAt: &deletedAt,
			},
		},
	}

	c := newGetDeletedKeyContext(repo)
	c.Params = &ApiParams{KeyID: requestedID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys/"+requestedID.String(), nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}
