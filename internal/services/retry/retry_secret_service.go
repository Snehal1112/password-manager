package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// RetrySecretService wraps secret operations with retry logic
type RetrySecretService interface {
	secrets.SecretService
}

// retrySecretService implements RetrySecretService with retry logic
type retrySecretService struct {
	baseService  secrets.SecretService
	retryService RetryService
}

// NewRetrySecretService creates a new retry-aware secret service
func NewRetrySecretService(baseService secrets.SecretService, retryService RetryService) RetrySecretService {
	return &retrySecretService{
		baseService:  baseService,
		retryService: retryService,
	}
}

// GetSecret retrieves a scoped secret with retry logic.
func (s *retrySecretService) GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.GetSecret(ctx, secretID, scope)
	})
}

// ListSecrets lists scoped secrets with retry logic.
func (s *retrySecretService) ListSecrets(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	return retried(ctx, s.retryService, func() ([]model.Secret, error) {
		return s.baseService.ListSecrets(ctx, scope, tags)
	})
}

// DeleteSecret deletes a scoped secret with retry logic.
func (s *retrySecretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecret(ctx, secretID, scope)
	})
}

// ListDeletedSecrets lists scoped deleted secrets with retry logic.
func (s *retrySecretService) ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	return retried(ctx, s.retryService, func() ([]model.Secret, error) {
		return s.baseService.ListDeletedSecrets(ctx, scope)
	})
}

// CreateSecret creates a secret with retry logic for database operations
func (s *retrySecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.CreateSecret(ctx, req)
	})
}

// UpdateSecret updates a scoped secret with retry logic.
func (s *retrySecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateSecret(ctx, req)
	})
}

// GetSecretVersions retrieves secret versions with retry logic for database operations
func (s *retrySecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() ([]model.SecretVersion, error) {
		return s.baseService.GetSecretVersions(ctx, secretID, scope)
	})
}

// GetSecretVersion retrieves a specific secret version with retry logic for database operations
func (s *retrySecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetSecretVersion(ctx, secretID, version, scope)
	})
}

// GetLatestSecretVersion retrieves the latest secret version with retry logic for database operations
func (s *retrySecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetLatestSecretVersion(ctx, secretID, scope)
	})
}

// GenerateSecret generates a secret with retry logic for database operations
func (s *retrySecretService) GenerateSecret(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.GenerateSecret(ctx, req)
	})
}

// ExportSecrets exports secrets with retry logic for database operations
func (s *retrySecretService) ExportSecrets(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
	return retried(ctx, s.retryService, func() ([]byte, error) {
		return s.baseService.ExportSecrets(ctx, req)
	})
}

// ImportSecrets imports secrets with retry logic for database operations
func (s *retrySecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	return retried(ctx, s.retryService, func() (*secrets.ImportResult, error) {
		return s.baseService.ImportSecrets(ctx, req)
	})
}

// RecoverSecret recovers a scoped soft-deleted secret with retry logic.
func (s *retrySecretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RecoverSecret(ctx, secretID, scope)
	})
}

// PurgeSecret purges a scoped soft-deleted secret with retry logic.
func (s *retrySecretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.PurgeSecret(ctx, secretID, scope)
	})
}
