package retry

import (
	"context"

	"github.com/google/uuid"

	"password-manager/internal/domain"
	"password-manager/internal/services/secrets"
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

// CreateSecret creates a secret with retry logic for database operations
func (s *retrySecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*domain.Secret, error) {
	var result *domain.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.CreateSecret(ctx, req)
		return err
	})

	return result, retryErr
}

// UpdateSecret updates a secret with retry logic for database operations
func (s *retrySecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateSecret(ctx, req)
	})
}

// GetSecret retrieves a secret with retry logic for database operations
func (s *retrySecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*domain.Secret, error) {
	var result *domain.Secret
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecret(ctx, secretID, userID)
		return err
	})

	return result, retryErr
}

// ListSecrets lists secrets with retry logic for database operations
func (s *retrySecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	var result []domain.Secret
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

// GetSecretVersions retrieves secret versions with retry logic for database operations
func (s *retrySecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]domain.SecretVersion, error) {
	var result []domain.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretVersions(ctx, secretID, userID)
		return err
	})

	return result, retryErr
}

// GetSecretVersion retrieves a specific secret version with retry logic for database operations
func (s *retrySecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error) {
	var result *domain.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretVersion(ctx, secretID, version, userID)
		return err
	})

	return result, retryErr
}

// GetLatestSecretVersion retrieves the latest secret version with retry logic for database operations
func (s *retrySecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.SecretVersion, error) {
	var result *domain.SecretVersion
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetLatestSecretVersion(ctx, secretID, userID)
		return err
	})

	return result, retryErr
}