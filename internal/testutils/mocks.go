// Package testutils provides shared mock implementations for internal service tests.
package testutils

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"rocketvault/model"
	"rocketvault/internal/logging"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	secretServices "rocketvault/internal/services/secrets"
)

// NewTestLogger returns a logger suitable for use in tests.
func NewTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// --- MockAuthenticationService ---

// MockAuthenticationService mocks authServices.AuthenticationService.
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

func (m *MockAuthenticationService) RevokeSession(ctx context.Context, sessionID, reason string) error {
	args := m.Called(ctx, sessionID, reason)
	return args.Error(0)
}

func (m *MockAuthenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

// --- MockRBACService ---

// MockRBACService mocks authzServices.RBACService.
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

// --- MockSecretRepository ---

// MockSecretRepository mocks repositories.SecretRepositoryInterface.
type MockSecretRepository struct {
	mock.Mock
}

func (m *MockSecretRepository) Create(ctx context.Context, secret *model.Secret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockSecretRepository) Read(ctx context.Context, id uuid.UUID) (*model.Secret, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepository) ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*model.Secret, error) {
	args := m.Called(ctx, id, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepository) Update(ctx context.Context, secret *model.Secret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockSecretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	args := m.Called(ctx, userID, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretRepository) ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	args := m.Called(ctx, userID, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretRepository) ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSecretRepository) ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error) {
	args := m.Called(ctx, data, options)
	return args.Int(0), args.Error(1)
}

func (m *MockSecretRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepository) RecoverSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// --- MockCryptographyService ---

// MockCryptographyService mocks secretServices.CryptographyService.
type MockCryptographyService struct {
	mock.Mock
}

func (m *MockCryptographyService) EncryptSecret(plaintext string) (string, error) {
	args := m.Called(plaintext)
	return args.String(0), args.Error(1)
}

func (m *MockCryptographyService) DecryptSecret(ciphertext string) (string, error) {
	args := m.Called(ciphertext)
	return args.String(0), args.Error(1)
}

// --- MockVersioningService ---

// MockVersioningService mocks secretServices.VersioningServiceInterface.
type MockVersioningService struct {
	mock.Mock
}

func (m *MockVersioningService) CreateVersion(ctx context.Context, req secretServices.CreateVersionRequest) (*model.SecretVersion, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockVersioningService) GetVersions(ctx context.Context, secretID, userID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *MockVersioningService) GetVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockVersioningService) GetLatestVersion(ctx context.Context, secretID, userID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockVersioningService) DeleteVersions(ctx context.Context, secretID, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, userID)
	return args.Error(0)
}

func (m *MockVersioningService) DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, version, userID)
	return args.Error(0)
}

func (m *MockVersioningService) RollbackToVersion(ctx context.Context, req secretServices.RollbackRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

// --- MockTagService ---

// MockTagService mocks secretServices.TagService.
type MockTagService struct {
	mock.Mock
}

func (m *MockTagService) AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	args := m.Called(ctx, secretID, tags)
	return args.Error(0)
}

func (m *MockTagService) RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	args := m.Called(ctx, secretID, tags)
	return args.Error(0)
}

func (m *MockTagService) RemoveAllTags(ctx context.Context, secretID uuid.UUID) error {
	args := m.Called(ctx, secretID)
	return args.Error(0)
}

func (m *MockTagService) GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockTagService) FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error) {
	args := m.Called(ctx, userID, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uuid.UUID), args.Error(1)
}

// --- Test data factories ---

// NewSecret returns a minimal Secret for use in tests.
func NewSecret(userID uuid.UUID) *model.Secret {
	return &model.Secret{
		ID:      uuid.New(),
		UserID:  userID,
		Name:    "test-secret",
		Value:   "plaintext-value",
		Version: 1,
		Tags:    []string{},
	}
}
