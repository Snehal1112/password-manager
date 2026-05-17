package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/model"
	"rocketvault/internal/services/users"
)

// RetryUserService wraps user operations with retry logic
type RetryUserService interface {
	users.UserService
}

// retryUserService implements RetryUserService with retry logic
type retryUserService struct {
	baseService  users.UserService
	retryService RetryService
}

// NewRetryUserService creates a new retry-aware user service
func NewRetryUserService(baseService users.UserService, retryService RetryService) RetryUserService {
	return &retryUserService{
		baseService:  baseService,
		retryService: retryService,
	}
}

// CreateUser creates a user with retry logic for database operations
func (s *retryUserService) CreateUser(ctx context.Context, req users.CreateUserRequest) (*users.CreateUserResult, error) {
	var result *users.CreateUserResult
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.CreateUser(ctx, req)
		return err
	})

	return result, retryErr
}

// UpdateUser updates a user with retry logic for database operations
func (s *retryUserService) UpdateUser(ctx context.Context, req users.UpdateUserRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateUser(ctx, req)
	})
}

// GetUser retrieves a user with retry logic for database operations
func (s *retryUserService) GetUser(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	var result *model.User
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetUser(ctx, userID)
		return err
	})

	return result, retryErr
}

// GetUserByUsername retrieves a user by username with retry logic for database operations
func (s *retryUserService) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	var result *model.User
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetUserByUsername(ctx, username)
		return err
	})

	return result, retryErr
}

// ListUsers lists users with retry logic for database operations
func (s *retryUserService) ListUsers(ctx context.Context) ([]model.User, error) {
	var result []model.User
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ListUsers(ctx)
		return err
	})

	return result, retryErr
}

// DeleteUser deletes a user with retry logic for database operations
func (s *retryUserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteUser(ctx, userID)
	})
}

// ValidateBootstrapToken validates a bootstrap token with retry logic for database operations
func (s *retryUserService) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	var result bool
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ValidateBootstrapToken(ctx, token)
		return err
	})

	return result, retryErr
}

// InvalidateBootstrapToken invalidates a bootstrap token with retry logic for database operations
func (s *retryUserService) InvalidateBootstrapToken(ctx context.Context, token string) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.InvalidateBootstrapToken(ctx, token)
	})
}