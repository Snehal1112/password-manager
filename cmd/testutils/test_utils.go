package testutils

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"rocketvault/common"
	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/crypto"
	"rocketvault/model"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/signing"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	oauth2Services "rocketvault/internal/services/oauth2"
)

// TestContext holds common test utilities and mocks
type TestContext struct {
	Ctx              context.Context
	MockContainer    *MockServiceContainer
	MockUserService  *MockUserService
	MockSecretService *MockSecretService
	MockAuthService   *MockAuthenticationService
	MockRBACService   *MockRBACService
	TestUserID       uuid.UUID
	Logger           *logging.Logger
}

// NewTestContext creates a new test context with mocks
func NewTestContext(t *testing.T) *TestContext {
	testUserID := uuid.New()
	logger := &logging.Logger{Logger: logrus.New()}

	// Create mocks
	mockContainer := &MockServiceContainer{}
	mockUserService := &MockUserService{}
	mockSecretService := &MockSecretService{}
	mockAuthService := &MockAuthenticationService{}
	mockRBACService := &MockRBACService{}

	// Setup mock container to return mock services
	mockContainer.On("GetUserService").Return(mockUserService)
	mockContainer.On("GetSecretService").Return(mockSecretService)
	mockContainer.On("GetAuthenticationService").Return(mockAuthService)
	mockContainer.On("GetRBACService").Return(mockRBACService)
	mockContainer.On("GetLogger").Return(logger)
	mockContainer.On("Close").Return(nil)

	// Create test claims for authentication
	testClaims := &model.Claims{
		UserID:   testUserID,
		Username: "testuser",
		Role:     model.RoleAdmin,
	}

	// Create context with service container and authentication
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ServiceContainerKey, mockContainer)
	ctx = context.WithValue(ctx, common.UserIDKey, testUserID)
	ctx = context.WithValue(ctx, common.ClaimsKey, testClaims)
	ctx = context.WithValue(ctx, common.LogKey, logger)

	return &TestContext{
		Ctx:              ctx,
		MockContainer:    mockContainer,
		MockUserService:  mockUserService,
		MockSecretService: mockSecretService,
		MockAuthService:   mockAuthService,
		MockRBACService:   mockRBACService,
		TestUserID:       testUserID,
		Logger:           logger,
	}
}

// CreateTestCommand creates a command with test context
func (tc *TestContext) CreateTestCommand(cmd *cobra.Command) *cobra.Command {
	cmd.SetContext(tc.Ctx)
	return cmd
}

// Mock Service Container implements ServiceContainerInterface for testing
type MockServiceContainer struct {
	mock.Mock
}

// Repository getters - return nil for unused repositories
func (m *MockServiceContainer) GetUserRepository() repositories.UserRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	return nil
}

// Authentication service getters - return nil for unused services
func (m *MockServiceContainer) GetPasswordService() authServices.PasswordService {
	return nil
}

func (m *MockServiceContainer) GetTOTPService() authServices.TOTPService {
	return nil
}

func (m *MockServiceContainer) GetJWTService() authServices.JWTService {
	return nil
}

func (m *MockServiceContainer) GetAuthenticationService() authServices.AuthenticationService {
	args := m.Called()
	return args.Get(0).(authServices.AuthenticationService)
}

// Authorization service getters
func (m *MockServiceContainer) GetRBACService() authzServices.RBACService {
	args := m.Called()
	return args.Get(0).(authzServices.RBACService)
}

func (m *MockServiceContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return nil
}

func (m *MockServiceContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	return nil
}

// Business service getters
func (m *MockServiceContainer) GetUserService() userServices.UserService {
	args := m.Called()
	return args.Get(0).(userServices.UserService)
}

func (m *MockServiceContainer) GetSecretService() secretServices.SecretService {
	args := m.Called()
	return args.Get(0).(secretServices.SecretService)
}

func (m *MockServiceContainer) GetCachedSecretService() secretServices.SecretService {
	// For testing, return the same mock service as GetSecretService
	args := m.Called()
	if len(args) == 0 {
		// Fallback to GetSecretService if not explicitly mocked
		return m.GetSecretService()
	}
	return args.Get(0).(secretServices.SecretService)
}

func (m *MockServiceContainer) GetKeyService() keyServices.KeyService {
	args := m.Called()
	if len(args) == 0 || args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(keyServices.KeyService)
}

func (m *MockServiceContainer) GetCertificateService() certServices.CertificateService {
	return nil
}

func (m *MockServiceContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	return nil
}

func (m *MockServiceContainer) GetCryptoService() keyServices.CryptoService {
	return nil
}

// Secret component service getters - return nil for unused services
func (m *MockServiceContainer) GetCryptographyService() secretServices.CryptographyService {
	return nil
}

func (m *MockServiceContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	args := m.Called()
	if len(args) == 0 {
		return nil
	}
	return args.Get(0).(secretServices.VersioningServiceInterface)
}

func (m *MockServiceContainer) GetTagService() secretServices.TagService {
	return nil
}

func (m *MockServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
	args := m.Called()
	if len(args) == 0 || args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(secretServices.RotationServiceInterface)
}

func (m *MockServiceContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	args := m.Called()
	if len(args) == 0 {
		return nil
	}
	return args.Get(0).(secretServices.SchedulerServiceInterface)
}

// Infrastructure getters
func (m *MockServiceContainer) GetDatabase() *sql.DB {
	return nil
}

func (m *MockServiceContainer) GetLogger() *logging.Logger {
	args := m.Called()
	if len(args) == 0 || args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*logging.Logger)
}

// Cache getters
func (m *MockServiceContainer) GetSecretCache() *cache.SecretCache {
	return nil
}

func (m *MockServiceContainer) GetCacheConfig() *cache.CacheConfig {
	return nil
}

// Retry service getter
func (m *MockServiceContainer) GetRetryService() retryServices.RetryService {
	return nil
}

// GetSigningProvider returns nil — signing provider is not used in CLI tests.
func (m *MockServiceContainer) GetSigningProvider() signing.SigningKeyProvider {
	return nil
}

// GetItemBackupService returns nil — backup service is not used in CLI tests.
func (m *MockServiceContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}

// GetKeyProvider returns nil — key provider is not used in CLI tests.
func (m *MockServiceContainer) GetKeyProvider() crypto.KeyProvider {
	return nil
}

// Lifecycle management
func (m *MockServiceContainer) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Mock User Service
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) CreateUser(ctx context.Context, req userServices.CreateUserRequest) (*userServices.CreateUserResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*userServices.CreateUserResult), args.Error(1)
}

func (m *MockUserService) GetUser(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, req userServices.UpdateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) ListUsers(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *MockUserService) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserService) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Mock Secret Service
type MockSecretService struct {
	mock.Mock
}

func (m *MockSecretService) CreateSecret(ctx context.Context, req secretServices.CreateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) UpdateSecret(ctx context.Context, req secretServices.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockSecretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, userID)
	return args.Error(0)
}

func (m *MockSecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	args := m.Called(ctx, userID, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GenerateSecret(ctx context.Context, req secretServices.GenerateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) ExportSecrets(ctx context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSecretService) ImportSecrets(ctx context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*secretServices.ImportResult), args.Error(1)
}

// Mock Authentication Service
type MockAuthenticationService struct {
	mock.Mock
}

func (m *MockAuthenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, username, password, totpCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) ValidateSession(ctx context.Context, token string) (*authServices.JWTClaims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.JWTClaims), args.Error(1)
}

func (m *MockAuthenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*authServices.RefreshTokenResult, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.RefreshTokenResult), args.Error(1)
}

func (m *MockAuthenticationService) RevokeSession(ctx context.Context, sessionID string, reason string) error {
	args := m.Called(ctx, sessionID, reason)
	return args.Error(0)
}

func (m *MockAuthenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

// Mock RBAC Service
type MockRBACService struct {
	mock.Mock
}

func (m *MockRBACService) HasPermission(role string, permission authzServices.Permission) bool {
	args := m.Called(role, permission)
	return args.Bool(0)
}

func (m *MockRBACService) GetRolePermissions(role string) []authzServices.Permission {
	args := m.Called(role)
	return args.Get(0).([]authzServices.Permission)
}

func (m *MockRBACService) ValidateEndpointAccess(role, method, path string) error {
	args := m.Called(role, method, path)
	return args.Error(0)
}

// Test Data Factory
func CreateTestUser() *model.User {
	return &model.User{
		ID:           uuid.New(),
		Username:     "testuser",
		PasswordHash: "$2a$10$test.hash",
		Role:         model.RoleUser,
		TOTPSecret:   "testsecret",
	}
}

func CreateTestSecret() *model.Secret {
	return &model.Secret{
		ID:      uuid.New(),
		UserID:  uuid.New(),
		Name:    "test-secret",
		Value:   "secret-value",
		Version: 1,
		Tags:    []string{"test", "sample"},
	}
}