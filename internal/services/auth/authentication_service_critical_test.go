package auth

// Critical path tests for ValidateSession, RefreshAccessToken, and RevokeSession.
// The mock types and helpers are defined in authentication_service_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"password-manager/internal/domain"
	"password-manager/internal/logging"
)

func newAuthService(
	userRepo *MockUserRepository,
	sessionRepo *MockSessionRepository,
	pwd *MockPasswordService,
	totp *MockTOTPService,
	jwt *MockJWTService,
) AuthenticationService {
	return NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   pwd,
		TOTPService:       totp,
		JWTService:        jwt,
		Logger:            logging.InitLogger(),
	})
}

// --- AuthenticateUser: user not found ---

func TestAuthenticateUser_UserNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	userRepo.On("ReadByUsername", ctx, "nobody").Return(domain.User{}, errors.New("not found"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	result, err := svc.AuthenticateUser(ctx, "nobody", "pass", "123456")

	require.Error(t, err)
	assert.Nil(t, result)
	pwd.AssertNotCalled(t, "ValidatePassword")
	totp.AssertNotCalled(t, "ValidateCode")
}

// --- ValidateSession ---

func TestValidateSession_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	claims := &JWTClaims{UserID: userID, Username: "alice", Role: domain.RoleUser}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "good-token").Return(claims, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	got, err := svc.ValidateSession(ctx, "good-token")

	require.NoError(t, err)
	assert.Equal(t, userID, got.UserID)
	assert.Equal(t, "alice", got.Username)
}

func TestValidateSession_InvalidToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "bad-token").Return((*JWTClaims)(nil), errors.New("token expired"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	_, err := svc.ValidateSession(ctx, "bad-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session")
}

// --- RefreshAccessToken ---

func TestRefreshAccessToken_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	session := &domain.Session{
		ID:       sessionID,
		UserID:   userID,
		Revoked:  false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user := &domain.User{ID: userID, Username: "bob", Role: domain.RoleUser}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)
	userRepo.On("Read", ctx, userID).Return(user, nil)
	jwt.On("GenerateToken", userID, "bob", domain.RoleUser).Return("new-token", nil)
	sessionRepo.On("UpdateSessionLastUsed", ctx, sessionID, mock.AnythingOfType("time.Time")).Return(nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	result, err := svc.RefreshAccessToken(ctx, "refresh-token-value")

	require.NoError(t, err)
	assert.Equal(t, "new-token", result.Token)
	assert.Equal(t, "bob", result.Username)
	jwt.AssertExpectations(t)
}

func TestRefreshAccessToken_RevokedSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Revoked:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	_, err := svc.RefreshAccessToken(ctx, "revoked-refresh-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session revoked")
}

func TestRefreshAccessToken_ExpiredSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Revoked:   false,
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
	}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	_, err := svc.RefreshAccessToken(ctx, "expired-refresh-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")
}

func TestRefreshAccessToken_InvalidRefreshToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(nil, errors.New("not found"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	_, err := svc.RefreshAccessToken(ctx, "unknown-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

// --- RevokeSession ---

func TestRevokeSession_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("RevokeSession", ctx, sessionID, "logout").Return(nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	err := svc.RevokeSession(ctx, sessionID.String(), "logout")

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
}

func TestRevokeSession_InvalidSessionIDFormat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	err := svc.RevokeSession(ctx, "not-a-uuid", "logout")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session ID format")
	sessionRepo.AssertNotCalled(t, "RevokeSession")
}
