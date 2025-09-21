package testutils

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"password-manager/common"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
	secretServices "password-manager/internal/services/secrets"
	userServices "password-manager/internal/services/users"
	authServices "password-manager/internal/services/auth"
	authzServices "password-manager/internal/services/authorization"
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
	mockContainer.On("Close").Return(nil)

	// Create context with service container
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ServiceContainerKey, mockContainer)
	ctx = context.WithValue(ctx, common.UserIDKey, testUserID)
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

// Mock Service Container
type MockServiceContainer struct {
	mock.Mock
}

func (m *MockServiceContainer) GetUserService() userServices.UserService {
	args := m.Called()
	return args.Get(0).(userServices.UserService)
}

func (m *MockServiceContainer) GetSecretService() secretServices.SecretService {
	args := m.Called()
	return args.Get(0).(secretServices.SecretService)
}

func (m *MockServiceContainer) GetAuthenticationService() authServices.AuthenticationService {
	args := m.Called()
	return args.Get(0).(authServices.AuthenticationService)
}

func (m *MockServiceContainer) GetRBACService() authzServices.RBACService {
	args := m.Called()
	return args.Get(0).(authzServices.RBACService)
}

func (m *MockServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
	args := m.Called()
	return args.Get(0).(secretServices.RotationServiceInterface)
}

func (m *MockServiceContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	args := m.Called()
	return args.Get(0).(secretServices.SchedulerServiceInterface)
}

func (m *MockServiceContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	args := m.Called()
	return args.Get(0).(secretServices.VersioningServiceInterface)
}

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

func (m *MockUserService) GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, req userServices.UpdateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserService) ListUsers(ctx context.Context) ([]domain.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.User), args.Error(1)
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

func (m *MockSecretService) CreateSecret(ctx context.Context, req secretServices.CreateSecretRequest) (*domain.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Secret), args.Error(1)
}

func (m *MockSecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*domain.Secret, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Secret), args.Error(1)
}

func (m *MockSecretService) UpdateSecret(ctx context.Context, req secretServices.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockSecretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, userID)
	return args.Error(0)
}

func (m *MockSecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	args := m.Called(ctx, userID, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Secret), args.Error(1)
}

func (m *MockSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]domain.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.SecretVersion), args.Error(1)
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
func CreateTestUser() *domain.User {
	return &domain.User{
		ID:           uuid.New(),
		Username:     "testuser",
		PasswordHash: "$2a$10$test.hash",
		Role:         domain.RoleUser,
		TOTPSecret:   "testsecret",
	}
}

func CreateTestSecret() *domain.Secret {
	return &domain.Secret{
		ID:      uuid.New(),
		UserID:  uuid.New(),
		Name:    "test-secret",
		Value:   "secret-value",
		Version: 1,
		Tags:    []string{"test", "sample"},
	}
}