package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// AuthenticationResult represents the result of a successful authentication.
type AuthenticationResult struct {
	Token        string // Access token
	RefreshToken string // Refresh token
	UserID       uuid.UUID
	Username     string
	Role         string
}

// RefreshTokenResult represents the result of a successful token refresh.
type RefreshTokenResult struct {
	Token        string // New access token
	RefreshToken string // New refresh token (if rotation is enabled)
	UserID       uuid.UUID
	Username     string
	Role         string
	ExpiresAt    time.Time
}

// AuthenticationService orchestrates the user authentication workflow.
// It coordinates password validation, TOTP verification, and token generation
// while maintaining separation of concerns between different auth components.
type AuthenticationService interface {
	AuthenticateUser(ctx context.Context, username, password, totpCode string) (*AuthenticationResult, error)
	ValidateSession(ctx context.Context, token string) (*JWTClaims, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (*RefreshTokenResult, error)
	RevokeSession(ctx context.Context, sessionID string, reason string) error
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error
}

// authenticationService implements AuthenticationService by coordinating
// multiple auth services and the user repository.
type authenticationService struct {
	userRepo         repositories.UserRepositoryInterface
	sessionRepo      repositories.SessionRepositoryInterface
	passwordService  PasswordService
	totpService      TOTPService
	jwtService       JWTService
	logger           *logging.Logger
}

// AuthenticationConfig holds the dependencies for authentication service.
type AuthenticationConfig struct {
	UserRepository   repositories.UserRepositoryInterface
	SessionRepository repositories.SessionRepositoryInterface
	PasswordService  PasswordService
	TOTPService      TOTPService
	JWTService       JWTService
	Logger           *logging.Logger
}

// NewAuthenticationService creates a new AuthenticationService with the provided dependencies.
// It orchestrates the authentication workflow by coordinating different auth services.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	An AuthenticationService implementation for user authentication.
func NewAuthenticationService(config AuthenticationConfig) AuthenticationService {
	return &authenticationService{
		userRepo:         config.UserRepository,
		sessionRepo:      config.SessionRepository,
		passwordService:  config.PasswordService,
		totpService:      config.TOTPService,
		jwtService:       config.JWTService,
		logger:           config.Logger,
	}
}

// AuthenticateUser performs complete user authentication including password and TOTP verification.
// It orchestrates the multi-step authentication process and returns access and refresh tokens
// upon successful authentication.
//
// Parameters:
//
//	ctx: The context for the authentication operation.
//	username: The user's username.
//	password: The user's plaintext password.
//	totpCode: The TOTP code from the user's MFA device.
//
// Returns:
//
//	Authentication result with access token, refresh token, and user information, or an error if authentication fails.
func (s *authenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*AuthenticationResult, error) {
	logrus.WithField("username", username).Info("Starting user authentication")

	// Retrieve user from repository
	user, err := s.userRepo.ReadByUsername(ctx, username)
	if err != nil {
		s.logger.LogAuditError("", "authenticate_user", "failed", "User not found", err)
		logrus.WithField("username", username).Warn("Authentication failed: user not found")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Validate password
	if err := s.passwordService.ValidatePassword(password, user.PasswordHash); err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Invalid password", err)
		logrus.WithFields(logrus.Fields{
			"username": username,
			"user_id":  user.ID.String(),
		}).Warn("Authentication failed: invalid password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Validate TOTP code
	valid, err := s.totpService.ValidateCode(totpCode, user.TOTPSecret, time.Now())
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "TOTP validation error", err)
		logrus.WithError(err).Error("TOTP validation error")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if !valid {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Invalid TOTP code", nil)
		logrus.WithFields(logrus.Fields{
			"username":  username,
			"user_id":   user.ID.String(),
			"totp_code": totpCode,
		}).Warn("Authentication failed: invalid TOTP code")
		return nil, fmt.Errorf("invalid TOTP code")
	}

	// Generate access token (short-lived)
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Failed to generate JWT token", err)
		logrus.WithError(err).Error("Failed to generate JWT token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Generate refresh token (long-lived)
	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Failed to generate refresh token", err)
		logrus.WithError(err).Error("Failed to generate refresh token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Create session in database
	session := &domain.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		RefreshTokenHash: s.hashRefreshToken(refreshToken),
		DeviceInfo:       "", // Can be populated from request context
		IPAddress:        "", // Can be populated from request context
		UserAgent:        "", // Can be populated from request context
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour), // 7 days
		LastUsedAt:       time.Now(),
		CreatedAt:        time.Now(),
		Revoked:          false,
	}

	if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Failed to create session", err)
		logrus.WithError(err).Error("Failed to create session")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Log successful authentication
	s.logger.LogAuditInfo(user.ID.String(), "authenticate_user", "success", "User authenticated successfully")
	logrus.WithFields(logrus.Fields{
		"username": username,
		"user_id":  user.ID.String(),
		"role":     user.Role,
		"session_id": session.ID.String(),
	}).Info("User authenticated successfully with session")

	return &AuthenticationResult{
		Token:        accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
	}, nil
}

// ValidateSession validates a JWT token and returns the user claims.
// It provides session validation for authenticated requests,
// ensuring tokens are valid and not expired.
//
// Parameters:
//
//	ctx: The context for the validation operation.
//	token: The JWT token to validate.
//
// Returns:
//
//	The validated JWT claims or an error if validation fails.
func (s *authenticationService) ValidateSession(ctx context.Context, token string) (*JWTClaims, error) {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		s.logger.LogAuditError("", "validate_session", "failed", "Invalid session token", err)
		return nil, fmt.Errorf("invalid session: %w", err)
	}

	// Additional session validation could be added here
	// (e.g., check if user is still active, check token revocation list)

	s.logger.LogAuditInfo(claims.UserID.String(), "validate_session", "success", "Session validated successfully")
	return claims, nil
}

// RefreshAccessToken refreshes an access token using a valid refresh token.
// It validates the refresh token, creates a new access token, and optionally
// rotates the refresh token for enhanced security.
//
// Parameters:
//
//	ctx: The context for the refresh operation.
//	refreshToken: The refresh token to use for getting a new access token.
//
// Returns:
//
//	Refresh token result with new access token and optional new refresh token, or an error if refresh fails.
func (s *authenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*RefreshTokenResult, error) {
	logrus.Info("Starting token refresh")

	// Hash the refresh token for database lookup
	refreshTokenHash := s.hashRefreshToken(refreshToken)

	// Get session by refresh token
	session, err := s.sessionRepo.GetSessionByRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		s.logger.LogAuditError("", "refresh_access_token", "failed", "Invalid or expired refresh token", err)
		logrus.WithError(err).Warn("Token refresh failed: invalid refresh token")
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if session is revoked
	if session.Revoked {
		s.logger.LogAuditError(session.UserID.String(), "refresh_access_token", "failed", "Session is revoked", nil)
		logrus.WithField("session_id", session.ID.String()).Warn("Token refresh failed: session revoked")
		return nil, fmt.Errorf("session revoked")
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		s.logger.LogAuditError(session.UserID.String(), "refresh_access_token", "failed", "Session expired", nil)
		logrus.WithField("session_id", session.ID.String()).Warn("Token refresh failed: session expired")
		return nil, fmt.Errorf("session expired")
	}

	// Get user information
	user, err := s.userRepo.Read(ctx, session.UserID)
	if err != nil {
		s.logger.LogAuditError(session.UserID.String(), "refresh_access_token", "failed", "User not found", err)
		logrus.WithError(err).Error("Token refresh failed: user not found")
		return nil, fmt.Errorf("user not found")
	}

	// Generate new access token
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "refresh_access_token", "failed", "Failed to generate access token", err)
		logrus.WithError(err).Error("Token refresh failed: could not generate access token")
		return nil, fmt.Errorf("failed to generate access token")
	}

	// Update session last used time
	if err := s.sessionRepo.UpdateSessionLastUsed(ctx, session.ID, time.Now()); err != nil {
		s.logger.LogAuditError(user.ID.String(), "refresh_access_token", "failed", "Failed to update session last used", err)
		logrus.WithError(err).Warn("Token refresh failed: could not update session last used")
		// Continue with refresh even if this fails
	}

	// For now, we'll keep the same refresh token (no rotation)
	// In a production system, you might want to implement refresh token rotation

	// Log successful token refresh
	s.logger.LogAuditInfo(user.ID.String(), "refresh_access_token", "success", "Access token refreshed successfully")
	logrus.WithFields(logrus.Fields{
		"user_id":     user.ID.String(),
		"username":    user.Username,
		"session_id":  session.ID.String(),
	}).Info("Access token refreshed successfully")

	return &RefreshTokenResult{
		Token:        accessToken,
		RefreshToken: refreshToken, // Same refresh token for now
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
		ExpiresAt:    time.Now().Add(time.Hour), // 1 hour from now
	}, nil
}

// RevokeSession revokes a specific user session.
//
// Parameters:
//
//	ctx: The context for the revocation operation.
//	sessionID: The ID of the session to revoke.
//	reason: The reason for revocation.
//
// Returns:
//
//	An error if revocation fails.
func (s *authenticationService) RevokeSession(ctx context.Context, sessionID string, reason string) error {
	sessionIDUUID, err := uuid.Parse(sessionID)
	if err != nil {
		s.logger.LogAuditError("", "revoke_session", "failed", "Invalid session ID format", err)
		return fmt.Errorf("invalid session ID format: %w", err)
	}

	if err := s.sessionRepo.RevokeSession(ctx, sessionIDUUID, reason); err != nil {
		s.logger.LogAuditError(sessionID, "revoke_session", "failed", "Failed to revoke session", err)
		logrus.WithError(err).Error("Failed to revoke session")
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.logger.LogAuditInfo(sessionID, "revoke_session", "success", fmt.Sprintf("Session revoked: %s", reason))
	logrus.WithFields(logrus.Fields{
		"session_id": sessionID,
		"reason":     reason,
	}).Info("Session revoked successfully")

	return nil
}

// RevokeAllUserSessions revokes all active sessions for a user.
//
// Parameters:
//
//	ctx: The context for the revocation operation.
//	userID: The ID of the user whose sessions should be revoked.
//	reason: The reason for revocation.
//
// Returns:
//
//	An error if revocation fails.
func (s *authenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	if err := s.sessionRepo.RevokeAllUserSessions(ctx, userID, reason); err != nil {
		s.logger.LogAuditError(userID.String(), "revoke_all_sessions", "failed", "Failed to revoke all user sessions", err)
		logrus.WithError(err).Error("Failed to revoke all user sessions")
		return fmt.Errorf("failed to revoke all user sessions: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "revoke_all_sessions", "success", fmt.Sprintf("All sessions revoked: %s", reason))
	logrus.WithFields(logrus.Fields{
		"user_id": userID.String(),
		"reason":  reason,
	}).Info("All user sessions revoked successfully")

	return nil
}

// generateRefreshToken generates a cryptographically secure refresh token.
func (s *authenticationService) generateRefreshToken() (string, error) {
	// Generate 32 random bytes for the refresh token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// hashRefreshToken produces a SHA-256 hash of the token for storage.
// The token (32 random bytes as hex) has enough entropy that SHA-256
// without salt is safe here.
func (s *authenticationService) hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
