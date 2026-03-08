package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/services/auth"
)

// RetryAuthenticationService wraps authentication operations with retry logic
type RetryAuthenticationService interface {
	auth.AuthenticationService
}

// retryAuthenticationService implements RetryAuthenticationService with retry logic
type retryAuthenticationService struct {
	baseService  auth.AuthenticationService
	retryService RetryService
}

// NewRetryAuthenticationService creates a new retry-aware authentication service
func NewRetryAuthenticationService(baseService auth.AuthenticationService, retryService RetryService) RetryAuthenticationService {
	return &retryAuthenticationService{
		baseService:  baseService,
		retryService: retryService,
	}
}

// AuthenticateUser authenticates a user with retry logic for database operations
func (s *retryAuthenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*auth.AuthenticationResult, error) {
	var result *auth.AuthenticationResult
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.AuthenticateUser(ctx, username, password, totpCode)
		return err
	})

	return result, retryErr
}

// ValidateSession validates a session with retry logic for database operations
func (s *retryAuthenticationService) ValidateSession(ctx context.Context, token string) (*auth.JWTClaims, error) {
	var result *auth.JWTClaims
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ValidateSession(ctx, token)
		return err
	})

	return result, retryErr
}

// RefreshAccessToken refreshes an access token with retry logic for database operations
func (s *retryAuthenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*auth.RefreshTokenResult, error) {
	var result *auth.RefreshTokenResult
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.RefreshAccessToken(ctx, refreshToken)
		return err
	})

	return result, retryErr
}

// RevokeSession revokes a session with retry logic for database operations
func (s *retryAuthenticationService) RevokeSession(ctx context.Context, sessionID string, reason string) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RevokeSession(ctx, sessionID, reason)
	})
}

// RevokeAllUserSessions revokes all user sessions with retry logic for database operations
func (s *retryAuthenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RevokeAllUserSessions(ctx, userID, reason)
	})
}