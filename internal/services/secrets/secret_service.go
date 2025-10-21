package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/domain"
	"password-manager/internal/logging"
	"password-manager/internal/repositories"
)

// CreateSecretRequest represents a request to create a new secret.
type CreateSecretRequest struct {
	UserID uuid.UUID
	Name   string
	Value  string
	Tags   []string
}

// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	SecretID uuid.UUID
	UserID   uuid.UUID
	Name     *string   // Optional - nil means no change
	Value    *string   // Optional - nil means no change
	Tags     *[]string // Optional - nil means no change
}

// SecretService orchestrates secret management operations.
// It coordinates encryption, versioning, tagging, and storage
// while maintaining proper separation of concerns.
type SecretService interface {
	CreateSecret(ctx context.Context, req CreateSecretRequest) (*domain.Secret, error)
	UpdateSecret(ctx context.Context, req UpdateSecretRequest) error
	GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*domain.Secret, error)
	ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error)
	DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error
	GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]domain.SecretVersion, error)
	GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error)
	GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.SecretVersion, error)
}

// secretService implements SecretService by coordinating multiple services.
type secretService struct {
	secretRepo     repositories.SecretRepositoryInterface
	cryptoService  CryptographyService
	versionService VersioningServiceInterface
	tagService     TagService
	logger         *logging.Logger
}

// SecretServiceConfig holds the dependencies for secret service.
type SecretServiceConfig struct {
	SecretRepository repositories.SecretRepositoryInterface
	CryptoService    CryptographyService
	VersionService   VersioningServiceInterface
	TagService       TagService
	Logger           *logging.Logger
}

// NewSecretService creates a new SecretService with the provided dependencies.
// It orchestrates secret operations by coordinating different services.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	A SecretService implementation for secret management operations.
func NewSecretService(config SecretServiceConfig) SecretService {
	return &secretService{
		secretRepo:     config.SecretRepository,
		cryptoService:  config.CryptoService,
		versionService: config.VersionService,
		tagService:     config.TagService,
		logger:         config.Logger,
	}
}

// CreateSecret creates a new secret with encryption and tagging.
// It orchestrates the creation workflow by coordinating encryption,
// storage, and tag assignment.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The secret creation request.
//
// Returns:
//
//	The created secret or an error if creation fails.
func (s *secretService) CreateSecret(ctx context.Context, req CreateSecretRequest) (*domain.Secret, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": req.UserID.String(),
		"name":    req.Name,
	}).Info("Creating new secret")

	// Encrypt the secret value
	encryptedValue, err := s.cryptoService.EncryptSecret(req.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to encrypt secret", err)
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Create secret entity
	secretID := uuid.New()
	secret := &domain.Secret{
		ID:        secretID,
		UserID:    req.UserID,
		Name:      req.Name,
		Value:     encryptedValue,
		Version:   1,
		Tags:      req.Tags,
		CreatedAt: time.Now(),
	}

	// Store secret via repository (includes tag insertion)
	if err := s.secretRepo.Create(ctx, secret); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to store secret", err)
		return nil, fmt.Errorf("failed to store secret: %w", err)
	}

	// Decrypt value for return (to avoid exposing encrypted value)
	secret.Value = req.Value

	s.logger.LogAuditInfo(req.UserID.String(), "create_secret", "success",
		fmt.Sprintf("Secret created: %s", req.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"user_id":   req.UserID.String(),
		"name":      req.Name,
	}).Info("Secret created successfully")

	return secret, nil
}

// UpdateSecret updates an existing secret with versioning support.
// It creates a version of the current secret before applying updates.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The secret update request.
//
// Returns:
//
//	An error if the update fails.
func (s *secretService) UpdateSecret(ctx context.Context, req UpdateSecretRequest) error {
	logrus.WithField("secret_id", req.SecretID.String()).Info("Updating secret")

	// Get current secret
	currentSecret, err := s.secretRepo.Read(ctx, req.SecretID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Secret not found", err)
		return fmt.Errorf("secret not found: %w", err)
	}

	// Verify ownership
	if currentSecret.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Access denied", nil)
		return fmt.Errorf("access denied")
	}

	// Decrypt current value for versioning
	currentValue, err := s.cryptoService.DecryptSecret(currentSecret.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to decrypt current secret", err)
		return fmt.Errorf("failed to decrypt current secret: %w", err)
	}

	// Create version before updating
	versionReq := CreateVersionRequest{
		SecretID: currentSecret.ID,
		UserID:   req.UserID,
		Name:     currentSecret.Name,
		Value:    currentValue,
		Version:  currentSecret.Version,
	}
	_, err = s.versionService.CreateVersion(ctx, versionReq)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to create version", err)
		return fmt.Errorf("failed to create version: %w", err)
	}

	// Prepare updated secret
	updatedSecret := *currentSecret
	updatedSecret.Version++

	// Update name if provided
	if req.Name != nil {
		updatedSecret.Name = *req.Name
	}

	// Update and encrypt value if provided
	if req.Value != nil {
		encryptedValue, err := s.cryptoService.EncryptSecret(*req.Value)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to encrypt updated secret", err)
			return fmt.Errorf("failed to encrypt updated secret: %w", err)
		}
		updatedSecret.Value = encryptedValue
	}

	// Update secret via repository
	if err := s.secretRepo.Update(ctx, &updatedSecret); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	// Update tags if provided
	if req.Tags != nil {
		// Remove all existing tags and add new ones
		if err := s.tagService.RemoveAllTags(ctx, req.SecretID); err != nil {
			s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to remove old tags", err)
			return fmt.Errorf("failed to remove old tags: %w", err)
		}

		if len(*req.Tags) > 0 {
			if err := s.tagService.AddTags(ctx, req.SecretID, *req.Tags); err != nil {
				s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to add new tags", err)
				return fmt.Errorf("failed to add new tags: %w", err)
			}
		}
	}

	s.logger.LogAuditInfo(req.UserID.String(), "update_secret", "success",
		fmt.Sprintf("Secret updated: %s", updatedSecret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": req.SecretID.String(),
		"user_id":   req.UserID.String(),
		"version":   updatedSecret.Version,
	}).Info("Secret updated successfully")

	return nil
}

// GetSecret retrieves a secret by ID with decryption and tag loading.
//
// Parameters:
//
//	ctx: The context for the operation.
//	secretID: The secret's unique identifier.
//	userID: The user's unique identifier for access control.
//
// Returns:
//
//	The decrypted secret or an error if retrieval fails.
func (s *secretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*domain.Secret, error) {
	// Get secret from repository
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Secret not found", err)
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	// Verify ownership
	if secret.UserID != userID {
		s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Access denied", nil)
		return nil, fmt.Errorf("access denied")
	}

	// Decrypt value
	decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Failed to decrypt secret", err)
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = decryptedValue

	// Load tags
	tags, err := s.tagService.GetTags(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Failed to load tags", err)
		return nil, fmt.Errorf("failed to load tags: %w", err)
	}
	secret.Tags = tags

	return secret, nil
}

// ListSecrets retrieves all secrets for a user with optional tag filtering.
//
// Parameters:
//
//	ctx: The context for the operation.
//	userID: The user's unique identifier.
//	tags: Optional tags to filter by.
//
// Returns:
//
//	A slice of decrypted secrets or an error if retrieval fails.
func (s *secretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	// Get secrets from repository
	secretList, err := s.secretRepo.ListByUser(ctx, userID, tags)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Decrypt values and load tags for each secret
	for i := range secretList {
		secret := &secretList[i]

		// Decrypt value
		decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
		if err != nil {
			s.logger.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to decrypt secret", err)
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", secret.ID.String(), err)
		}
		secret.Value = decryptedValue

		// Load tags
		secretTags, err := s.tagService.GetTags(ctx, secret.ID)
		if err != nil {
			s.logger.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to load tags", err)
			return nil, fmt.Errorf("failed to load tags for secret %s: %w", secret.ID.String(), err)
		}
		secret.Tags = secretTags
	}

	logrus.WithFields(logrus.Fields{
		"user_id":      userID.String(),
		"secret_count": len(secretList),
	}).Debug("Listed secrets for user")

	return secretList, nil
}

// DeleteSecret removes a secret and its associated data.
//
// Parameters:
//
//	ctx: The context for the operation.
//	secretID: The secret's unique identifier.
//	userID: The user's unique identifier for access control.
//
// Returns:
//
//	An error if deletion fails.
func (s *secretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	// Verify secret exists and ownership
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "delete_secret", "failed", "Secret not found", err)
		return fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		s.logger.LogAuditError(userID.String(), "delete_secret", "failed", "Access denied", nil)
		return fmt.Errorf("access denied")
	}

	// Remove all tags first
	if err := s.tagService.RemoveAllTags(ctx, secretID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_secret", "failed", "Failed to remove tags", err)
		return fmt.Errorf("failed to remove tags: %w", err)
	}

	// Delete secret via repository
	if err := s.secretRepo.Delete(ctx, secretID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_secret", "failed", "Failed to delete secret", err)
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "delete_secret", "success",
		fmt.Sprintf("Secret deleted: %s", secret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"user_id":   userID.String(),
	}).Info("Secret deleted successfully")

	return nil
}

// GetSecretVersions retrieves all versions of a secret.
//
// Parameters:
//
//	ctx: The context for the operation.
//	secretID: The secret's unique identifier.
//
// Returns:
//
//	A slice of secret versions or an error if retrieval fails.
func (s *secretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]domain.SecretVersion, error) {
	return s.versionService.GetVersions(ctx, secretID, userID)
}

// GetSecretVersion retrieves a specific version of a secret.
//
// Parameters:
//
//	ctx: The context for the operation.
//	secretID: The secret's unique identifier.
//	version: The version number to retrieve.
//
// Returns:
//
//	The secret version or an error if not found.
func (s *secretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error) {
	return s.versionService.GetVersion(ctx, secretID, version, userID)
}

// GetLatestSecretVersion retrieves the latest version of a secret.
//
// Parameters:
//
//	ctx: The context for the operation.
//	secretID: The secret's unique identifier.
//
// Returns:
//
//	The latest secret version or an error if not found.
func (s *secretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.SecretVersion, error) {
	return s.versionService.GetLatestVersion(ctx, secretID, userID)
}
