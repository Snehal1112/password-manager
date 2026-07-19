// Package api — unit tests for vault.go management handlers.
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
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/backup"
	"rocketvault/internal/container"
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

// --- in-memory vault repository for tests ---

type vaultFakeRepo struct {
	byName map[string]*model.Vault
	byID   map[string]*model.Vault
	// readErr, when set, is returned by ReadByName/ReadByID instead of the
	// normal not-found sentinel -- simulates a real failure (e.g. DB outage).
	readErr error
}

func newVaultFakeRepo() *vaultFakeRepo {
	return &vaultFakeRepo{byName: map[string]*model.Vault{}, byID: map[string]*model.Vault{}}
}

var errVaultFakeNotFound = repositories.ErrNotFound

func (f *vaultFakeRepo) Create(_ context.Context, v *model.Vault) error {
	if _, ok := f.byName[v.Name]; ok {
		return errors.New("duplicate vault name")
	}
	cp := *v
	f.byName[v.Name] = &cp
	f.byID[v.ID.String()] = &cp
	return nil
}
func (f *vaultFakeRepo) ReadByName(_ context.Context, n string) (*model.Vault, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byName[n]; ok && v.DeletedAt == nil {
		return v, nil
	}
	return nil, errVaultFakeNotFound
}
func (f *vaultFakeRepo) ReadByID(_ context.Context, id uuid.UUID) (*model.Vault, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byID[id.String()]; ok {
		return v, nil
	}
	return nil, errVaultFakeNotFound
}
func (f *vaultFakeRepo) List(context.Context) ([]model.Vault, error) {
	var out []model.Vault
	for _, v := range f.byName {
		if v.DeletedAt == nil {
			out = append(out, *v)
		}
	}
	return out, nil
}
func (f *vaultFakeRepo) ListDeleted(context.Context) ([]model.Vault, error) {
	var out []model.Vault
	for _, v := range f.byName {
		if v.DeletedAt != nil {
			out = append(out, *v)
		}
	}
	return out, nil
}
func (f *vaultFakeRepo) Update(_ context.Context, v *model.Vault) error {
	// Stamp updated_at like the real VaultRepository.Update does.
	now := nowForVaultTest()
	v.UpdatedAt = &now
	f.byName[v.Name] = v
	f.byID[v.ID.String()] = v
	return nil
}
func (f *vaultFakeRepo) SoftDelete(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		now := nowForVaultTest()
		v.DeletedAt = &now
	}
	return nil
}
func (f *vaultFakeRepo) Recover(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		v.DeletedAt = nil
	}
	return nil
}
func (f *vaultFakeRepo) Purge(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		delete(f.byName, v.Name)
		delete(f.byID, id.String())
	}
	return nil
}

func nowForVaultTest() time.Time { return time.Unix(1700000000, 0) }

// --- noop cascade for tests ---

type vaultNoopCascade struct{}

func (vaultNoopCascade) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (vaultNoopCascade) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error { return nil }

// --- vaultSvcTestContainer ---

type vaultSvcTestContainer struct {
	vaultSvc  vaultServices.VaultService
	secretSvc secretServices.SecretService
	keySvc    keyServices.KeyService
	certSvc   certServices.CertificateService
	policySvc authzServices.AccessPolicyService
	rbacSvc   authzServices.RBACService
	logger    *logging.Logger
}

func (c *vaultSvcTestContainer) GetVaultService() vaultServices.VaultService { return c.vaultSvc }
func (c *vaultSvcTestContainer) GetSecretService() secretServices.SecretService {
	if c.secretSvc != nil {
		return c.secretSvc
	}
	panic("unexpected call: GetSecretService")
}
func (c *vaultSvcTestContainer) GetRBACService() authzServices.RBACService {
	if c.rbacSvc != nil {
		return c.rbacSvc
	}
	// The vault management routes map to no specific permission, so a real RBAC
	// service grants access regardless of role.
	return authzServices.NewRBACService(nil)
}
func (c *vaultSvcTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *vaultSvcTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *vaultSvcTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *vaultSvcTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *vaultSvcTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *vaultSvcTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *vaultSvcTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *vaultSvcTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *vaultSvcTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *vaultSvcTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *vaultSvcTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *vaultSvcTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *vaultSvcTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *vaultSvcTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *vaultSvcTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	if c.policySvc != nil {
		return c.policySvc
	}
	panic("unexpected call: GetAccessPolicyService")
}
func (c *vaultSvcTestContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *vaultSvcTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *vaultSvcTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *vaultSvcTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *vaultSvcTestContainer) GetKeyService() keyServices.KeyService {
	if c.keySvc != nil {
		return c.keySvc
	}
	panic("unexpected call: GetKeyService")
}
func (c *vaultSvcTestContainer) GetCertificateService() certServices.CertificateService {
	if c.certSvc != nil {
		return c.certSvc
	}
	panic("unexpected call: GetCertificateService")
}
func (c *vaultSvcTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *vaultSvcTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *vaultSvcTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *vaultSvcTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *vaultSvcTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *vaultSvcTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *vaultSvcTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *vaultSvcTestContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *vaultSvcTestContainer) GetLogger() *logging.Logger {
	if c.logger != nil {
		return c.logger
	}
	panic("unexpected call: GetLogger")
}
func (c *vaultSvcTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *vaultSvcTestContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *vaultSvcTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *vaultSvcTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *vaultSvcTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *vaultSvcTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *vaultSvcTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *vaultSvcTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *vaultSvcTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *vaultSvcTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *vaultSvcTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *vaultSvcTestContainer) Close() error { return nil }

const vaultTestUserID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

// newVaultTestAPI builds an API whose vaults subrouter is wired to a real,
// in-memory-backed vault service so the handlers exercise genuine logic.
func newVaultTestAPI() (*API, *vaultFakeRepo) {
	repo := newVaultFakeRepo()
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: svc}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.InitVault()
	return api, repo
}

// doVaultRequest issues an authed request through the API router and returns the recorder.
// The request carries the user_id and an admin role in context, as the real auth
// middleware would for an operator authorized to manage vaults (vaults:manage).
func doVaultRequest(api *API, method, path string, body []byte) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	ctx := context.WithValue(r.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, string(model.RoleAdmin))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)
	return w
}

// TestCreateVault_AndList creates a vault then confirms it appears in the list.
func TestCreateVault_AndList(t *testing.T) {
	api, _ := newVaultTestAPI()

	body, _ := json.Marshal(map[string]any{"name": "prod"})
	w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults", body)
	assert.Equal(t, http.StatusCreated, w.Code)

	var created model.VaultResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	assert.Equal(t, "prod", created.Name)
	assert.True(t, created.Enabled)

	w = doVaultRequest(api, http.MethodGet, "/api/v1/vaults", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var list model.ListVaultsResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	assert.Equal(t, 1, list.Total)
	assert.Equal(t, "prod", list.Vaults[0].Name)
}

// TestGetVault_NotFound confirms a missing vault returns 404.
func TestGetVault_NotFound(t *testing.T) {
	api, _ := newVaultTestAPI()

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/ghost", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteVault_RefusesDefault confirms the default vault cannot be deleted (4xx).
func TestDeleteVault_RefusesDefault(t *testing.T) {
	api, repo := newVaultTestAPI()
	defID := uuid.MustParse(model.DefaultVaultID)
	repo.byName[model.DefaultVaultName] = &model.Vault{ID: defID, Name: model.DefaultVaultName, Enabled: true}
	repo.byID[defID.String()] = repo.byName[model.DefaultVaultName]

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/"+model.DefaultVaultName, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetVault_InternalErrorIsNotReportedAsNotFound proves a genuine repository
// failure (e.g. a DB outage) surfaces as 500, not a misleading 404.
func TestGetVault_InternalErrorIsNotReportedAsNotFound(t *testing.T) {
	api, repo := newVaultTestAPI()
	repo.readErr = errors.New("connection refused")

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/anything", nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateVault_InternalErrorIsNotReportedAsNotFound(t *testing.T) {
	api, repo := newVaultTestAPI()
	repo.readErr = errors.New("connection refused")

	body := []byte(`{"enabled":false}`)
	w := doVaultRequest(api, http.MethodPatch, "/api/v1/vaults/anything", body)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteVault_InternalErrorIsNotReportedAsNotFound(t *testing.T) {
	api, repo := newVaultTestAPI()
	repo.readErr = errors.New("connection refused")

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/anything", nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestDeleteVault_Success soft-deletes an existing vault and returns 204.
func TestDeleteVault_Success(t *testing.T) {
	api, repo := newVaultTestAPI()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg", nil)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// --- permissiveRBAC: an RBAC service that allows everything ---

type permissiveRBAC struct{}

func (p permissiveRBAC) HasPermission(role string, permission authzServices.Permission) bool {
	return true
}

func (p permissiveRBAC) GetRolePermissions(role string) []authzServices.Permission {
	return []authzServices.Permission{}
}

func (p permissiveRBAC) ValidateEndpointAccess(role, method, path string) error {
	return nil
}

// --- newVaultTestAPIWithContainer ---

// newVaultTestAPIWithContainer builds an API using the provided test container.
func newVaultTestAPIWithContainer(cont container.ServiceContainerInterface) *API {
	a := &app.App{ServiceContainer: cont}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Vaults = api.BaseRoutes.ApiRoot.PathPrefix("/vaults").Subrouter()
	api.InitVault()
	return api
}

// --- doVaultRequestAs ---

// doVaultRequestAs issues an authed request through the API router with a specific role.
func doVaultRequestAs(api *API, role, method, path string, body []byte) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	ctx := context.WithValue(r.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, role)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)
	return w
}
