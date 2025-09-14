package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/auth"
	"password-manager/internal/logging"
)

// AuthenticationResult represents the result of a successful authentication.
type AuthenticationResult struct {
	Token    string
	UserID   uuid.UUID
	Username string
	Role     string
}

// AuthenticationService orchestrates the user authentication workflow.
// It coordinates password validation, TOTP verification, and token generation
// while maintaining separation of concerns between different auth components.
type AuthenticationService interface {
	AuthenticateUser(ctx context.Context, username, password, totpCode string) (*AuthenticationResult, error)
	ValidateSession(ctx context.Context, token string) (*JWTClaims, error)
}

// authenticationService implements AuthenticationService by coordinating
// multiple auth services and the user repository.
type authenticationService struct {
	userRepo        auth.UserRepository
	passwordService PasswordService
	totpService     TOTPService
	jwtService      JWTService
	logger          *logging.Logger
}

// AuthenticationConfig holds the dependencies for authentication service.
type AuthenticationConfig struct {
	UserRepository  auth.UserRepository
	PasswordService PasswordService
	TOTPService     TOTPService
	JWTService      JWTService
	Logger          *logging.Logger
}

// NewAuthenticationService creates a new AuthenticationService with the provided dependencies.
// It orchestrates the authentication workflow by coordinating different auth services.
//
// Parameters:
//   config: Configuration containing all required dependencies.
//
// Returns:
//   An AuthenticationService implementation for user authentication.
func NewAuthenticationService(config AuthenticationConfig) AuthenticationService {
	return &authenticationService{
		userRepo:        config.UserRepository,
		passwordService: config.PasswordService,
		totpService:     config.TOTPService,
		jwtService:      config.JWTService,
		logger:          config.Logger,
	}
}

// AuthenticateUser performs complete user authentication including password and TOTP verification.
// It orchestrates the multi-step authentication process and returns a session token
// upon successful authentication.
//
// Parameters:
//   ctx: The context for the authentication operation.
//   username: The user's username.
//   password: The user's plaintext password.
//   totpCode: The TOTP code from the user's MFA device.
//
// Returns:
//   Authentication result with token and user information, or an error if authentication fails.
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

	// Generate JWT token
	token, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Failed to generate JWT token", err)
		logrus.WithError(err).Error("Failed to generate JWT token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Log successful authentication
	s.logger.LogAuditInfo(user.ID.String(), "authenticate_user", "success", "User authenticated successfully")
	logrus.WithFields(logrus.Fields{
		"username": username,
		"user_id":  user.ID.String(),
		"role":     user.Role,
	}).Info("User authenticated successfully")

	return &AuthenticationResult{
		Token:    token,
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
	}, nil
}

// ValidateSession validates a JWT token and returns the user claims.
// It provides session validation for authenticated requests,
// ensuring tokens are valid and not expired.
//
// Parameters:
//   ctx: The context for the validation operation.
//   token: The JWT token to validate.
//
// Returns:
//   The validated JWT claims or an error if validation fails.
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