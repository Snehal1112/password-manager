package retry

import (
	"context"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// RetryRepositoryWrapper wraps repository operations with retry logic
type RetryRepositoryWrapper struct {
	baseRepo     repositories.SecretRepositoryInterface
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
func (r *RetryRepositoryWrapper) Create(ctx context.Context, secret *model.Secret) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Create(ctx, secret)
	})
}

// Read wraps the Read operation with retry logic
func (r *RetryRepositoryWrapper) Read(ctx context.Context, id uuid.UUID) (*model.Secret, error) {
	return retried(ctx, r.retryService, func() (*model.Secret, error) {
		return r.baseRepo.Read(ctx, id)
	})
}

// ReadByOwner wraps the ReadByOwner operation with retry logic.
func (r *RetryRepositoryWrapper) ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*model.Secret, error) {
	return retried(ctx, r.retryService, func() (*model.Secret, error) {
		return r.baseRepo.ReadByOwner(ctx, id, userID)
	})
}

// Update wraps the Update operation with retry logic
func (r *RetryRepositoryWrapper) Update(ctx context.Context, secret *model.Secret) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Update(ctx, secret)
	})
}

// UpdateInVault wraps the UpdateInVault operation with retry logic
func (r *RetryRepositoryWrapper) UpdateInVault(ctx context.Context, secret *model.Secret) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.UpdateInVault(ctx, secret)
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
func (r *RetryRepositoryWrapper) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	return retried(ctx, r.retryService, func() ([]model.Secret, error) {
		return r.baseRepo.ListByUser(ctx, userID, tags)
	})
}

// ListByUserIncludeDeleted wraps the ListByUserIncludeDeleted operation with retry logic
func (r *RetryRepositoryWrapper) ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	return retried(ctx, r.retryService, func() ([]model.Secret, error) {
		return r.baseRepo.ListByUserIncludeDeleted(ctx, userID, tags)
	})
}

// ExportSecrets wraps the ExportSecrets operation with retry logic
func (r *RetryRepositoryWrapper) ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error) {
	return retried(ctx, r.retryService, func() ([]byte, error) {
		return r.baseRepo.ExportSecrets(ctx, options)
	})
}

// ImportSecrets wraps the ImportSecrets operation with retry logic
func (r *RetryRepositoryWrapper) ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error) {
	return retried(ctx, r.retryService, func() (int, error) {
		return r.baseRepo.ImportSecrets(ctx, data, options)
	})
}

// GetVersions wraps the GetVersions operation with retry logic
func (r *RetryRepositoryWrapper) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	return retried(ctx, r.retryService, func() ([]model.SecretVersion, error) {
		return r.baseRepo.GetVersions(ctx, secretID)
	})
}

// GetVersion wraps the GetVersion operation with retry logic
func (r *RetryRepositoryWrapper) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	return retried(ctx, r.retryService, func() (*model.SecretVersion, error) {
		return r.baseRepo.GetVersion(ctx, secretID, version)
	})
}

// GetLatestVersion wraps the GetLatestVersion operation with retry logic
func (r *RetryRepositoryWrapper) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	return retried(ctx, r.retryService, func() (*model.SecretVersion, error) {
		return r.baseRepo.GetLatestVersion(ctx, secretID)
	})
}

// RecoverSecret wraps the RecoverSecret operation with retry logic.
func (r *RetryRepositoryWrapper) RecoverSecret(ctx context.Context, id uuid.UUID) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.RecoverSecret(ctx, id)
	})
}

// PurgeSecret wraps the PurgeSecret operation with retry logic
func (r *RetryRepositoryWrapper) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.PurgeSecret(ctx, id)
	})
}

// ReadInVault wraps the ReadInVault operation with retry logic.
func (r *RetryRepositoryWrapper) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Secret, error) {
	return retried(ctx, r.retryService, func() (*model.Secret, error) {
		return r.baseRepo.ReadInVault(ctx, id, vaultID)
	})
}

// ListInVault wraps the ListInVault operation with retry logic.
func (r *RetryRepositoryWrapper) ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return retried(ctx, r.retryService, func() ([]model.Secret, error) {
		return r.baseRepo.ListInVault(ctx, vaultID, tags)
	})
}

// ListInVaultIncludeDeleted wraps the ListInVaultIncludeDeleted operation with retry logic.
func (r *RetryRepositoryWrapper) ListInVaultIncludeDeleted(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return retried(ctx, r.retryService, func() ([]model.Secret, error) {
		return r.baseRepo.ListInVaultIncludeDeleted(ctx, vaultID, tags)
	})
}

// SoftDeleteVaultContents wraps the SoftDeleteVaultContents operation with retry logic.
func (r *RetryRepositoryWrapper) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.SoftDeleteVaultContents(ctx, vaultID, deletedAt)
	})
}

// RecoverVaultContents wraps the RecoverVaultContents operation with retry logic.
func (r *RetryRepositoryWrapper) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.RecoverVaultContents(ctx, vaultID, deletedAt)
	})
}

// ReadScoped wraps the ReadScoped operation with retry logic.
func (r *RetryRepositoryWrapper) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	return retried(ctx, r.retryService, func() (*model.Secret, error) {
		return r.baseRepo.ReadScoped(ctx, id, scope)
	})
}

// UpdateScoped wraps the UpdateScoped operation with retry logic.
func (r *RetryRepositoryWrapper) UpdateScoped(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.UpdateScoped(ctx, secret, scope)
	})
}

// ListScoped wraps the ListScoped operation with retry logic.
func (r *RetryRepositoryWrapper) ListScoped(ctx context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	return retried(ctx, r.retryService, func() ([]model.Secret, error) {
		return r.baseRepo.ListScoped(ctx, scope, filter)
	})
}
