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

// GetSecretScoped retrieves a scoped secret with retry logic.
func (s *retrySecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.GetSecretScoped(ctx, secretID, scope)
	})
}

// ListSecretsScoped lists scoped secrets with retry logic.
func (s *retrySecretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	return retried(ctx, s.retryService, func() ([]model.Secret, error) {
		return s.baseService.ListSecretsScoped(ctx, scope, tags)
	})
}

// DeleteSecretScoped deletes a scoped secret with retry logic.
func (s *retrySecretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecretScoped(ctx, secretID, scope)
	})
}

// ListDeletedSecretsScoped lists scoped deleted secrets with retry logic.
func (s *retrySecretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	return retried(ctx, s.retryService, func() ([]model.Secret, error) {
		return s.baseService.ListDeletedSecretsScoped(ctx, scope)
	})
}

// CreateSecret creates a secret with retry logic for database operations
func (s *retrySecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.CreateSecret(ctx, req)
	})
}

// UpdateSecretScoped updates a scoped secret with retry logic.
func (s *retrySecretService) UpdateSecretScoped(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateSecretScoped(ctx, req)
	})
}

// UpdateSecret updates a secret with retry logic for database operations
func (s *retrySecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateSecret(ctx, req)
	})
}

// UpdateSecretInVault updates a vault-scoped secret with retry logic.
func (s *retrySecretService) UpdateSecretInVault(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateSecretInVault(ctx, req)
	})
}

// GetSecret retrieves a secret with retry logic for database operations
func (s *retrySecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.GetSecret(ctx, secretID, userID)
	})
}

// ListSecrets lists secrets with retry logic for database operations
func (s *retrySecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	return retried(ctx, s.retryService, func() ([]model.Secret, error) {
		return s.baseService.ListSecrets(ctx, userID, tags)
	})
}

// DeleteSecret deletes a secret with retry logic for database operations
func (s *retrySecretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecret(ctx, secretID, userID)
	})
}

// GetSecretInVault retrieves a vault-scoped secret with retry logic for database operations
func (s *retrySecretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.GetSecretInVault(ctx, secretID, vaultID)
	})
}

// ListSecretsInVault lists vault-scoped secrets with retry logic for database operations
func (s *retrySecretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return retried(ctx, s.retryService, func() ([]model.Secret, error) {
		return s.baseService.ListSecretsInVault(ctx, vaultID, tags)
	})
}

// DeleteSecretInVault deletes a vault-scoped secret with retry logic for database operations
func (s *retrySecretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecretInVault(ctx, secretID, vaultID)
	})
}

// GetSecretVersions retrieves secret versions with retry logic for database operations
func (s *retrySecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() ([]model.SecretVersion, error) {
		return s.baseService.GetSecretVersions(ctx, secretID, userID)
	})
}

// GetSecretVersion retrieves a specific secret version with retry logic for database operations
func (s *retrySecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetSecretVersion(ctx, secretID, version, userID)
	})
}

// GetLatestSecretVersion retrieves the latest secret version with retry logic for database operations
func (s *retrySecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetLatestSecretVersion(ctx, secretID, userID)
	})
}

// GetSecretVersionsInVault retrieves vault-scoped secret versions with retry logic for database operations
func (s *retrySecretService) GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() ([]model.SecretVersion, error) {
		return s.baseService.GetSecretVersionsInVault(ctx, secretID, vaultID)
	})
}

// GetSecretVersionInVault retrieves a specific vault-scoped secret version with retry logic for database operations
func (s *retrySecretService) GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetSecretVersionInVault(ctx, secretID, version, vaultID)
	})
}

// GetLatestSecretVersionInVault retrieves the latest vault-scoped secret version with retry logic for database operations
func (s *retrySecretService) GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetLatestSecretVersionInVault(ctx, secretID, vaultID)
	})
}

// GetSecretVersionsScoped retrieves every version of a secret the scope authorizes, with retry logic for database operations.
func (s *retrySecretService) GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() ([]model.SecretVersion, error) {
		return s.baseService.GetSecretVersionsScoped(ctx, secretID, scope)
	})
}

// GetSecretVersionScoped retrieves one version of a secret the scope authorizes, with retry logic for database operations.
func (s *retrySecretService) GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetSecretVersionScoped(ctx, secretID, version, scope)
	})
}

// GetLatestSecretVersionScoped retrieves the newest version of a secret the scope authorizes, with retry logic for database operations.
func (s *retrySecretService) GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	return retried(ctx, s.retryService, func() (*model.SecretVersion, error) {
		return s.baseService.GetLatestSecretVersionScoped(ctx, secretID, scope)
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

// RecoverSecretScoped recovers a scoped soft-deleted secret with retry logic.
func (s *retrySecretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RecoverSecretScoped(ctx, secretID, scope)
	})
}

// PurgeSecretScoped purges a scoped soft-deleted secret with retry logic.
func (s *retrySecretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.PurgeSecretScoped(ctx, secretID, scope)
	})
}
