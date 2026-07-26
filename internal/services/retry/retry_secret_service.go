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
	var result *model.Secret
	var err error
	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretScoped(ctx, secretID, scope)
		return err
	})
	return result, retryErr
}

// ListSecretsScoped lists scoped secrets with retry logic.
func (s *retrySecretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	var result []model.Secret
	var err error
	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ListSecretsScoped(ctx, scope, tags)
		return err
	})
	return result, retryErr
}

// DeleteSecretScoped deletes a scoped secret with retry logic.
func (s *retrySecretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecretScoped(ctx, secretID, scope)
	})
}

// ListDeletedSecretsScoped lists scoped deleted secrets with retry logic.
func (s *retrySecretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	var result []model.Secret
	var err error
	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ListDeletedSecretsScoped(ctx, scope)
		return err
	})
	return result, retryErr
}

// CreateSecret creates a secret with retry logic for database operations
func (s *retrySecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
	var result *model.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.CreateSecret(ctx, req)
		return err
	})

	return result, retryErr
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
	var result *model.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecret(ctx, secretID, userID)
		return err
	})

	return result, retryErr
}

// ListSecrets lists secrets with retry logic for database operations
func (s *retrySecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	var result []model.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ListSecrets(ctx, userID, tags)
		return err
	})

	return result, retryErr
}

// DeleteSecret deletes a secret with retry logic for database operations
func (s *retrySecretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecret(ctx, secretID, userID)
	})
}

// GetSecretInVault retrieves a vault-scoped secret with retry logic for database operations
func (s *retrySecretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	var result *model.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretInVault(ctx, secretID, vaultID)
		return err
	})

	return result, retryErr
}

// ListSecretsInVault lists vault-scoped secrets with retry logic for database operations
func (s *retrySecretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	var result []model.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ListSecretsInVault(ctx, vaultID, tags)
		return err
	})

	return result, retryErr
}

// DeleteSecretInVault deletes a vault-scoped secret with retry logic for database operations
func (s *retrySecretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecretInVault(ctx, secretID, vaultID)
	})
}

// GetSecretVersions retrieves secret versions with retry logic for database operations
func (s *retrySecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]model.SecretVersion, error) {
	var result []model.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretVersions(ctx, secretID, userID)
		return err
	})

	return result, retryErr
}

// GetSecretVersion retrieves a specific secret version with retry logic for database operations
func (s *retrySecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	var result *model.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretVersion(ctx, secretID, version, userID)
		return err
	})

	return result, retryErr
}

// GetLatestSecretVersion retrieves the latest secret version with retry logic for database operations
func (s *retrySecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.SecretVersion, error) {
	var result *model.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetLatestSecretVersion(ctx, secretID, userID)
		return err
	})

	return result, retryErr
}

// GetSecretVersionsInVault retrieves vault-scoped secret versions with retry logic for database operations
func (s *retrySecretService) GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	var result []model.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretVersionsInVault(ctx, secretID, vaultID)
		return err
	})

	return result, retryErr
}

// GetSecretVersionInVault retrieves a specific vault-scoped secret version with retry logic for database operations
func (s *retrySecretService) GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	var result *model.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretVersionInVault(ctx, secretID, version, vaultID)
		return err
	})

	return result, retryErr
}

// GetLatestSecretVersionInVault retrieves the latest vault-scoped secret version with retry logic for database operations
func (s *retrySecretService) GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	var result *model.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetLatestSecretVersionInVault(ctx, secretID, vaultID)
		return err
	})

	return result, retryErr
}

// GenerateSecret generates a secret with retry logic for database operations
func (s *retrySecretService) GenerateSecret(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error) {
	var result *model.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GenerateSecret(ctx, req)
		return err
	})

	return result, retryErr
}

// ExportSecrets exports secrets with retry logic for database operations
func (s *retrySecretService) ExportSecrets(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
	var result []byte
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ExportSecrets(ctx, req)
		return err
	})

	return result, retryErr
}

// ImportSecrets imports secrets with retry logic for database operations
func (s *retrySecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	var result *secrets.ImportResult
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ImportSecrets(ctx, req)
		return err
	})

	return result, retryErr
}
