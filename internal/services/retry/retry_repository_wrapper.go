package retry

import (
	"context"

	"github.com/google/uuid"

	"password-manager/internal/domain"
	"password-manager/internal/repositories"
)

// RetryRepositoryWrapper wraps repository operations with retry logic
type RetryRepositoryWrapper struct {
	baseRepo repositories.SecretRepositoryInterface
	retryService RetryService
}

// NewRetryRepositoryWrapper creates a new retry-aware repository wrapper
func NewRetryRepositoryWrapper(baseRepo repositories.SecretRepositoryInterface, retryService RetryService) repositories.SecretRepositoryInterface {
	return &RetryRepositoryWrapper{
		baseRepo:     baseRepo,
		retryService: retryService,
	}
}

// Create wraps the Create operation with retry logic
func (r *RetryRepositoryWrapper) Create(ctx context.Context, secret *domain.Secret) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Create(ctx, secret)
	})
}

// Read wraps the Read operation with retry logic
func (r *RetryRepositoryWrapper) Read(ctx context.Context, id uuid.UUID) (*domain.Secret, error) {
	var result *domain.Secret
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.Read(ctx, id)
		return err
	})

	return result, retryErr
}

// Update wraps the Update operation with retry logic
func (r *RetryRepositoryWrapper) Update(ctx context.Context, secret *domain.Secret) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Update(ctx, secret)
	})
}

// Delete wraps the Delete operation with retry logic
func (r *RetryRepositoryWrapper) Delete(ctx context.Context, id uuid.UUID) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Delete(ctx, id)
	})
}

// SoftDelete wraps the SoftDelete operation with retry logic
func (r *RetryRepositoryWrapper) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.SoftDelete(ctx, id)
	})
}

// ListByUser wraps the ListByUser operation with retry logic
func (r *RetryRepositoryWrapper) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	var result []domain.Secret
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ListByUser(ctx, userID, tags)
		return err
	})

	return result, retryErr
}

// ListByUserIncludeDeleted wraps the ListByUserIncludeDeleted operation with retry logic
func (r *RetryRepositoryWrapper) ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	var result []domain.Secret
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ListByUserIncludeDeleted(ctx, userID, tags)
		return err
	})

	return result, retryErr
}

// ExportSecrets wraps the ExportSecrets operation with retry logic
func (r *RetryRepositoryWrapper) ExportSecrets(ctx context.Context, options domain.ExportOptions) ([]byte, error) {
	var result []byte
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ExportSecrets(ctx, options)
		return err
	})

	return result, retryErr
}

// ImportSecrets wraps the ImportSecrets operation with retry logic
func (r *RetryRepositoryWrapper) ImportSecrets(ctx context.Context, data []byte, options domain.ImportOptions) (int, error) {
	var result int
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ImportSecrets(ctx, data, options)
		return err
	})

	return result, retryErr
}

// GetVersions wraps the GetVersions operation with retry logic
func (r *RetryRepositoryWrapper) GetVersions(ctx context.Context, secretID uuid.UUID) ([]domain.SecretVersion, error) {
	var result []domain.SecretVersion
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.GetVersions(ctx, secretID)
		return err
	})

	return result, retryErr
}

// GetVersion wraps the GetVersion operation with retry logic
func (r *RetryRepositoryWrapper) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretVersion, error) {
	var result *domain.SecretVersion
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.GetVersion(ctx, secretID, version)
		return err
	})

	return result, retryErr
}

// GetLatestVersion wraps the GetLatestVersion operation with retry logic
func (r *RetryRepositoryWrapper) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*domain.SecretVersion, error) {
	var result *domain.SecretVersion
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.GetLatestVersion(ctx, secretID)
		return err
	})

	return result, retryErr
}

// PurgeSecret wraps the PurgeSecret operation with retry logic
func (r *RetryRepositoryWrapper) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.PurgeSecret(ctx, id)
	})
}