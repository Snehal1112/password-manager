// Package secrets provides business logic services for secret management operations.
// This package follows the established service layer patterns with dependency injection
// and proper separation of concerns.
package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// VersioningServiceInterface defines the business logic contract for secret versioning operations.
// It orchestrates version creation, retrieval, and management with proper encryption handling.
type VersioningServiceInterface interface {
	// Version creation and management
	CreateVersion(ctx context.Context, req CreateVersionRequest) (*domain.SecretVersion, error)
	GetVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]domain.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.SecretVersion, error)
	DeleteVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) error
	DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) error

	// Version rollback
	RollbackToVersion(ctx context.Context, req RollbackRequest) (*domain.Secret, error)
}

// CreateVersionRequest represents the request to create a new secret version.
type CreateVersionRequest struct {
	SecretID uuid.UUID `json:"secret_id" validate:"required"`
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	Name     string    `json:"name" validate:"required,min=1,max=255"`
	Value    string    `json:"value" validate:"required,min=1"`
	Version  int       `json:"version" validate:"required,min=1"`
}

// RollbackRequest represents the request to rollback a secret to a specific version.
type RollbackRequest struct {
	SecretID      uuid.UUID `json:"secret_id" validate:"required"`
	TargetVersion int       `json:"target_version" validate:"required,min=1"`
	UserID        uuid.UUID `json:"user_id" validate:"required"`
	Notes         string    `json:"notes" validate:"max=500"`
}

// versioningService implements VersioningServiceInterface.
type versioningService struct {
	versionRepo repositories.SecretVersionRepositoryInterface
	secretRepo  repositories.SecretRepositoryInterface
	userRepo    repositories.UserRepositoryInterface
	cryptoSvc   CryptographyService
	log         *logging.Logger
}

// NewVersioningService creates a new versioning service with the required dependencies.
func NewVersioningService(
	versionRepo repositories.SecretVersionRepositoryInterface,
	secretRepo repositories.SecretRepositoryInterface,
	userRepo repositories.UserRepositoryInterface,
	cryptoSvc CryptographyService,
	log *logging.Logger,
) VersioningServiceInterface {
	return &versioningService{
		versionRepo: versionRepo,
		secretRepo:  secretRepo,
		userRepo:    userRepo,
		cryptoSvc:   cryptoSvc,
		log:         log,
	}
}

// CreateVersion creates a new version of a secret with encryption and validation.
func (s *versioningService) CreateVersion(ctx context.Context, req CreateVersionRequest) (*domain.SecretVersion, error) {
	// Validate user exists
	user, err := s.userRepo.Read(ctx, req.UserID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", req.UserID).Error("User not found for version creation")
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, req.SecretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", req.SecretID).Error("Secret not found for version creation")
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != req.UserID {
		return nil, fmt.Errorf("user does not own this secret")
	}

	// Encrypt the secret value
	encryptedValue, err := s.cryptoSvc.EncryptSecret(req.Value)
	if err != nil {
		s.log.WithError(err).Error("Failed to encrypt secret version")
		return nil, fmt.Errorf("failed to encrypt secret version: %w", err)
	}

	// Create version domain object
	now := time.Now()
	version := &domain.SecretVersion{
		ID:        uuid.New(),
		SecretID:  req.SecretID,
		UserID:    user.ID,
		Name:      req.Name,
		Value:     encryptedValue, // Store encrypted value
		Version:   req.Version,
		CreatedAt: now,
	}

	err = s.versionRepo.CreateVersion(ctx, version)
	if err != nil {
		s.log.WithError(err).Error("Failed to create secret version")
		return nil, fmt.Errorf("failed to create secret version: %w", err)
	}

	s.log.WithFields(map[string]any{
		"version_id": version.ID,
		"secret_id":  version.SecretID,
		"user_id":    version.UserID,
		"version":    version.Version,
	}).Info("Secret version created successfully")

	// Return decrypted version for response
	version.Value = req.Value
	return version, nil
}

// GetVersions retrieves all versions of a secret with decryption and ownership validation.
func (s *versioningService) GetVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]domain.SecretVersion, error) {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		return nil, fmt.Errorf("user does not own this secret")
	}

	// Get encrypted versions from repository
	encryptedVersions, err := s.versionRepo.GetVersions(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret versions")
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	// Decrypt values for response
	var versions []domain.SecretVersion
	for _, encVersion := range encryptedVersions {
		decryptedValue, err := s.cryptoSvc.DecryptSecret(encVersion.Value)
		if err != nil {
			s.log.WithError(err).WithField("version_id", encVersion.ID).Error("Failed to decrypt secret version")
			return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
		}

		decVersion := encVersion
		decVersion.Value = decryptedValue
		versions = append(versions, decVersion)
	}

	return versions, nil
}

// GetVersion retrieves a specific version of a secret with decryption and ownership validation.
func (s *versioningService) GetVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error) {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		return nil, fmt.Errorf("user does not own this secret")
	}

	// Get encrypted version from repository
	encryptedVersion, err := s.versionRepo.GetVersion(ctx, secretID, version)
	if err != nil {
		s.log.WithError(err).WithFields(map[string]any{
			"secret_id": secretID,
			"version":   version,
		}).Error("Failed to get secret version")
		return nil, fmt.Errorf("failed to get secret version: %w", err)
	}

	// Decrypt value for response
	decryptedValue, err := s.cryptoSvc.DecryptSecret(encryptedVersion.Value)
	if err != nil {
		s.log.WithError(err).WithField("version_id", encryptedVersion.ID).Error("Failed to decrypt secret version")
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}

	encryptedVersion.Value = decryptedValue
	return encryptedVersion, nil
}

// GetLatestVersion retrieves the latest version of a secret with decryption and ownership validation.
func (s *versioningService) GetLatestVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.SecretVersion, error) {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		return nil, fmt.Errorf("user does not own this secret")
	}

	// Get encrypted latest version from repository
	encryptedVersion, err := s.versionRepo.GetLatestVersion(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get latest secret version")
		return nil, fmt.Errorf("failed to get latest secret version: %w", err)
	}

	// Decrypt value for response
	decryptedValue, err := s.cryptoSvc.DecryptSecret(encryptedVersion.Value)
	if err != nil {
		s.log.WithError(err).WithField("version_id", encryptedVersion.ID).Error("Failed to decrypt secret version")
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}

	encryptedVersion.Value = decryptedValue
	return encryptedVersion, nil
}

// DeleteVersions deletes all versions of a secret with ownership validation.
func (s *versioningService) DeleteVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) error {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		return fmt.Errorf("user does not own this secret")
	}

	err = s.versionRepo.DeleteVersions(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to delete secret versions")
		return fmt.Errorf("failed to delete secret versions: %w", err)
	}

	s.log.WithFields(map[string]any{
		"secret_id": secretID,
		"user_id":   userID,
	}).Info("Secret versions deleted successfully")

	return nil
}

// DeleteSpecificVersion deletes a specific version of a secret with ownership validation.
func (s *versioningService) DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) error {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		return fmt.Errorf("user does not own this secret")
	}

	err = s.versionRepo.DeleteSpecificVersion(ctx, secretID, version)
	if err != nil {
		s.log.WithError(err).WithFields(map[string]any{
			"secret_id": secretID,
			"version":   version,
		}).Error("Failed to delete secret version")
		return fmt.Errorf("failed to delete secret version: %w", err)
	}

	s.log.WithFields(map[string]any{
		"secret_id": secretID,
		"version":   version,
		"user_id":   userID,
	}).Info("Secret version deleted successfully")

	return nil
}

// RollbackToVersion rolls back a secret to a specific version.
func (s *versioningService) RollbackToVersion(ctx context.Context, req RollbackRequest) (*domain.Secret, error) {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, req.SecretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != req.UserID {
		return nil, fmt.Errorf("user does not own this secret")
	}

	// Get the target version
	targetVersion, err := s.versionRepo.GetVersion(ctx, req.SecretID, req.TargetVersion)
	if err != nil {
		return nil, fmt.Errorf("target version not found: %w", err)
	}

	// Decrypt the target version value
	decryptedValue, err := s.cryptoSvc.DecryptSecret(targetVersion.Value)
	if err != nil {
		s.log.WithError(err).Error("Failed to decrypt target version for rollback")
		return nil, fmt.Errorf("failed to decrypt target version: %w", err)
	}

	// Create new version from current state before rollback
	currentVersionReq := CreateVersionRequest{
		SecretID: req.SecretID,
		UserID:   req.UserID,
		Name:     secret.Name,
		Value:    secret.Value,
		Version:  secret.Version + 1,
	}

	_, err = s.CreateVersion(ctx, currentVersionReq)
	if err != nil {
		s.log.WithError(err).Error("Failed to create backup version during rollback")
		return nil, fmt.Errorf("failed to create backup version: %w", err)
	}

	// Update secret with target version data
	secret.Value = decryptedValue
	secret.Version = secret.Version + 2 // Increment beyond backup version

	err = s.secretRepo.Update(ctx, secret)
	if err != nil {
		s.log.WithError(err).Error("Failed to update secret during rollback")
		return nil, fmt.Errorf("failed to update secret during rollback: %w", err)
	}

	s.log.WithFields(map[string]any{
		"secret_id":      req.SecretID,
		"target_version": req.TargetVersion,
		"new_version":    secret.Version,
		"user_id":        req.UserID,
	}).Info("Secret rolled back successfully")

	return secret, nil
}
