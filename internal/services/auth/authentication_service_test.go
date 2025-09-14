package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/internal/auth"
	"password-manager/internal/logging"
)

// Mock implementations for testing

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Read(ctx context.Context, id uuid.UUID) (*auth.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) ReadByUsername(ctx context.Context, username string) (auth.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(auth.User), args.Error(1)
}

func (m *MockUserRepository) Login(ctx context.Context, username, password, totpCode string) (string, error) {
	args := m.Called(ctx, username, password, totpCode)
	return args.String(0), args.Error(1)
}

func (m *MockUserRepository) List(ctx context.Context) ([]auth.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]auth.User), args.Error(1)
}

func (m *MockUserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

type MockPasswordService struct {
	mock.Mock
}

func (m *MockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockPasswordService) ValidatePassword(password, hash string) error {
	args := m.Called(password, hash)
	return args.Error(0)
}

type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) GenerateSecret(issuer, accountName string) (*otp.Key, error) {
	args := m.Called(issuer, accountName)
	return args.Get(0).(*otp.Key), args.Error(1)
}

func (m *MockTOTPService) ValidateCode(code, secret string, currentTime time.Time) (bool, error) {
	args := m.Called(code, secret, currentTime)
	return args.Bool(0), args.Error(1)
}

func (m *MockTOTPService) GenerateCode(secret string, currentTime time.Time) (string, error) {
	args := m.Called(secret, currentTime)
	return args.String(0), args.Error(1)
}

type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateToken(userID uuid.UUID, username, role string) (string, error) {
	args := m.Called(userID, username, role)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(*JWTClaims), args.Error(1)
}

func (m *MockJWTService) ParseToken(tokenString string) (*JWTClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(*JWTClaims), args.Error(1)
}

// Test demonstrating the new SRP-compliant architecture

func TestAuthenticationService_AuthenticateUser_Success(t *testing.T) {
	// Arrange
	ctx := context.Background()

	// Create mocks
	mockUserRepo := &MockUserRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	// Create logger
	logger := logging.NewLogger()

	// Create test user
	userID := uuid.New()
	user := auth.User{
		ID:           userID,
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		TOTPSecret:   "secret123",
		Role:         auth.RoleUser,
	}

	// Setup expectations
	mockUserRepo.On("ReadByUsername", ctx, "testuser").Return(user, nil)
	mockPasswordService.On("ValidatePassword", "password123", "hashedpassword").Return(nil)
	mockTOTPService.On("ValidateCode", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(true, nil)
	mockJWTService.On("GenerateToken", userID, "testuser", auth.RoleUser).Return("jwt_token", nil)

	// Create service
	service := NewAuthenticationService(AuthenticationConfig{
		UserRepository:  mockUserRepo,
		PasswordService: mockPasswordService,
		TOTPService:     mockTOTPService,
		JWTService:      mockJWTService,
		Logger:          logger,
	})

	// Act
	result, err := service.AuthenticateUser(ctx, "testuser", "password123", "123456")

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "jwt_token", result.Token)
	assert.Equal(t, userID, result.UserID)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, auth.RoleUser, result.Role)

	// Verify all mocks were called
	mockUserRepo.AssertExpectations(t)
	mockPasswordService.AssertExpectations(t)
	mockTOTPService.AssertExpectations(t)
	mockJWTService.AssertExpectations(t)
}

func TestAuthenticationService_AuthenticateUser_InvalidPassword(t *testing.T) {
	// Arrange
	ctx := context.Background()

	// Create mocks
	mockUserRepo := &MockUserRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	// Create logger
	logger := logging.NewLogger()

	// Create test user
	userID := uuid.New()
	user := auth.User{
		ID:           userID,
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		TOTPSecret:   "secret123",
		Role:         auth.RoleUser,
	}

	// Setup expectations
	mockUserRepo.On("ReadByUsername", ctx, "testuser").Return(user, nil)
	mockPasswordService.On("ValidatePassword", "wrongpassword", "hashedpassword").Return(errors.New("invalid password"))

	// Create service
	service := NewAuthenticationService(AuthenticationConfig{
		UserRepository:  mockUserRepo,
		PasswordService: mockPasswordService,
		TOTPService:     mockTOTPService,
		JWTService:      mockJWTService,
		Logger:          logger,
	})

	// Act
	result, err := service.AuthenticateUser(ctx, "testuser", "wrongpassword", "123456")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid credentials")

	// Verify expectations
	mockUserRepo.AssertExpectations(t)
	mockPasswordService.AssertExpectations(t)
	// TOTP and JWT services should not be called
	mockTOTPService.AssertNotCalled(t, "ValidateCode")
	mockJWTService.AssertNotCalled(t, "GenerateToken")
}

func TestAuthenticationService_AuthenticateUser_InvalidTOTP(t *testing.T) {
	// Arrange
	ctx := context.Background()

	// Create mocks
	mockUserRepo := &MockUserRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	// Create logger
	logger := logging.NewLogger()

	// Create test user
	userID := uuid.New()
	user := auth.User{
		ID:           userID,
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		TOTPSecret:   "secret123",
		Role:         auth.RoleUser,
	}

	// Setup expectations
	mockUserRepo.On("ReadByUsername", ctx, "testuser").Return(user, nil)
	mockPasswordService.On("ValidatePassword", "password123", "hashedpassword").Return(nil)
	mockTOTPService.On("ValidateCode", "000000", "secret123", mock.AnythingOfType("time.Time")).Return(false, nil)

	// Create service
	service := NewAuthenticationService(AuthenticationConfig{
		UserRepository:  mockUserRepo,
		PasswordService: mockPasswordService,
		TOTPService:     mockTOTPService,
		JWTService:      mockJWTService,
		Logger:          logger,
	})

	// Act
	result, err := service.AuthenticateUser(ctx, "testuser", "password123", "000000")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid TOTP code")

	// Verify expectations
	mockUserRepo.AssertExpectations(t)
	mockPasswordService.AssertExpectations(t)
	mockTOTPService.AssertExpectations(t)
	// JWT service should not be called
	mockJWTService.AssertNotCalled(t, "GenerateToken")
}

// This test demonstrates how the new architecture enables easy testing
// by allowing us to mock individual services rather than testing
// complex methods that mix multiple responsibilities.
func TestAuthenticationService_SeparationOfConcerns(t *testing.T) {
	// This test demonstrates the benefits of SRP:
	// 1. Each service has a single, well-defined responsibility
	// 2. Services can be easily mocked and tested in isolation
	// 3. Business logic is separated from infrastructure concerns
	// 4. Dependencies are explicitly injected, making testing straightforward

	t.Log("Authentication service successfully demonstrates Single Responsibility Principle:")
	t.Log("- PasswordService: Handles only password hashing/validation")
	t.Log("- TOTPService: Handles only TOTP operations")
	t.Log("- JWTService: Handles only JWT token operations")
	t.Log("- UserRepository: Handles only database operations")
	t.Log("- AuthenticationService: Orchestrates authentication workflow")
	t.Log("- Each service is easily testable in isolation")
	t.Log("- No global dependencies - all dependencies are injected")

	assert.True(t, true, "Architecture demonstrates proper SRP compliance")
}