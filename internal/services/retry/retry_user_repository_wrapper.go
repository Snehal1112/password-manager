package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// RetryUserRepositoryWrapper wraps user repository operations with retry logic
type RetryUserRepositoryWrapper struct {
	baseRepo     repositories.UserRepositoryInterface
	retryService RetryService
}

// NewRetryUserRepositoryWrapper creates a new retry-aware user repository wrapper
func NewRetryUserRepositoryWrapper(baseRepo repositories.UserRepositoryInterface, retryService RetryService) repositories.UserRepositoryInterface {
	return &RetryUserRepositoryWrapper{
		baseRepo:     baseRepo,
		retryService: retryService,
	}
}

// Create wraps the Create operation with retry logic
func (r *RetryUserRepositoryWrapper) Create(ctx context.Context, user *model.User) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Create(ctx, user)
	})
}

// Read wraps the Read operation with retry logic
func (r *RetryUserRepositoryWrapper) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var result *model.User
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.Read(ctx, id)
		return err
	})

	return result, retryErr
}

// Update wraps the Update operation with retry logic
func (r *RetryUserRepositoryWrapper) Update(ctx context.Context, user *model.User) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Update(ctx, user)
	})
}

// Delete wraps the Delete operation with retry logic
func (r *RetryUserRepositoryWrapper) Delete(ctx context.Context, id uuid.UUID) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Delete(ctx, id)
	})
}

// ReadByUsername wraps the ReadByUsername operation with retry logic
func (r *RetryUserRepositoryWrapper) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	var result model.User
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ReadByUsername(ctx, username)
		return err
	})

	return result, retryErr
}

// ReadByExternalSubject wraps the ReadByExternalSubject operation with retry logic
func (r *RetryUserRepositoryWrapper) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	var result *model.User
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ReadByExternalSubject(ctx, provider, subject)
		return err
	})

	return result, retryErr
}

// List wraps the List operation with retry logic
func (r *RetryUserRepositoryWrapper) List(ctx context.Context) ([]model.User, error) {
	var result []model.User
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.List(ctx)
		return err
	})

	return result, retryErr
}

// ValidateBootstrapToken wraps the ValidateBootstrapToken operation with retry logic
func (r *RetryUserRepositoryWrapper) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	var result bool
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ValidateBootstrapToken(ctx, token)
		return err
	})

	return result, retryErr
}

// InvalidateBootstrapToken wraps the InvalidateBootstrapToken operation with retry logic
func (r *RetryUserRepositoryWrapper) InvalidateBootstrapToken(ctx context.Context, token string) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.InvalidateBootstrapToken(ctx, token)
	})
}
