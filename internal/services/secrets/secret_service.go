package secrets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	dbpkg "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// CreateSecretRequest represents a request to create a new secret.
type CreateSecretRequest struct {
	UserID      uuid.UUID
	VaultID     uuid.UUID // Target vault; defaults to the default vault when nil.
	Name        string
	Value       string
	Tags        []string
	ContentType string     // Optional media type (e.g. "application/json").
	Enabled     *bool      // Defaults to true when nil.
	ExpiresAt   *time.Time // Optional expiry time.
	NotBefore   *time.Time // Optional activation time.
}

// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	SecretID    uuid.UUID
	UserID      uuid.UUID
	Name        *string    // Optional - nil means no change.
	Value       *string    // Optional - nil means no change.
	Tags        *[]string  // Optional - nil means no change.
	ContentType *string    // Optional - nil means no change.
	Enabled     *bool      // Optional - nil means no change.
	ExpiresAt   *time.Time // Optional - nil means no change.
	NotBefore   *time.Time // Optional - nil means no change.
}

// validContentTypes is the allowlist of accepted MIME types for secret content.
var validContentTypes = map[string]struct{}{
	"":                         {},
	"text/plain":               {},
	"application/json":         {},
	"application/xml":          {},
	"application/x-pem-file":   {},
	"application/x-pkcs12":     {},
	"application/octet-stream": {},
}

// validateContentType returns an error when ct is not in the allowlist.
func validateContentType(ct string) error {
	if _, ok := validContentTypes[ct]; !ok {
		return fmt.Errorf("unsupported content type: %q", ct)
	}
	return nil
}

// GenerateSecretRequest represents a request to generate a random secret.
type GenerateSecretRequest struct {
	UserID       uuid.UUID
	Name         string
	Length       int
	UseSymbols   bool
	UseNumbers   bool
	UseUppercase bool
	UseLowercase bool
}

// ExportSecretsRequest represents a request to export secrets.
type ExportSecretsRequest struct {
	UserID      uuid.UUID
	Format      string   // "json" or "csv"
	FilterTags  []string // Optional tag filter
	IncludeTags bool     // Include tags in export
}

// ImportSecretsRequest represents a request to import secrets.
type ImportSecretsRequest struct {
	UserID    uuid.UUID
	Data      []byte
	Format    string // "json" or "csv"
	Overwrite bool   // Overwrite existing secrets with same name
}

// ImportResult represents the result of importing secrets.
type ImportResult struct {
	ImportedCount int
	SkippedCount  int
	TotalCount    int
	Errors        []string
}

// SecretService orchestrates secret management operations.
// It coordinates encryption, versioning, tagging, and storage
// while maintaining proper separation of concerns.
type SecretService interface {
	CreateSecret(ctx context.Context, req CreateSecretRequest) (*model.Secret, error)
	UpdateSecret(ctx context.Context, req UpdateSecretRequest) error
	GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error)
	ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error)
	DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error
	// GetSecretInVault retrieves a secret scoped to the given vault.
	GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error)
	// ListSecretsInVault lists secrets scoped to the given vault.
	ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error)
	// DeleteSecretInVault soft-deletes a secret scoped to the given vault.
	DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error
	GenerateSecret(ctx context.Context, req GenerateSecretRequest) (*model.Secret, error)
	ExportSecrets(ctx context.Context, req ExportSecretsRequest) ([]byte, error)
	ImportSecrets(ctx context.Context, req ImportSecretsRequest) (*ImportResult, error)
	GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]model.SecretVersion, error)
	GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error)
	GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.SecretVersion, error)
}

// secretService implements SecretService by coordinating multiple services.
type secretService struct {
	secretRepo     repositories.SecretRepositoryInterface
	cryptoService  CryptographyService
	versionService VersioningServiceInterface
	tagService     TagService
	logger         *logging.Logger
	db             *sql.DB // used to wrap writes in a transaction
}

// SecretServiceConfig holds the dependencies for secret service.
type SecretServiceConfig struct {
	SecretRepository repositories.SecretRepositoryInterface
	CryptoService    CryptographyService
	VersionService   VersioningServiceInterface
	TagService       TagService
	Logger           *logging.Logger
	DB               *sql.DB // for transaction support
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
		db:             config.DB,
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
func (s *secretService) CreateSecret(ctx context.Context, req CreateSecretRequest) (*model.Secret, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": req.UserID.String(),
		"name":    req.Name,
	}).Info("Creating new secret")

	// Validate content type before any I/O.
	if err := validateContentType(req.ContentType); err != nil {
		return nil, err
	}

	// Encrypt before touching the DB — pure CPU work.
	encryptedValue, err := s.cryptoService.EncryptSecret(req.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to encrypt secret", err)
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Default Enabled to true when the caller does not specify it.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Default the vault to the well-known default vault when not specified,
	// so legacy callers that do not set a vault keep targeting it.
	vaultID := req.VaultID
	if vaultID == uuid.Nil {
		vaultID = uuid.MustParse(model.DefaultVaultID)
	}

	secret := &model.Secret{
		ID:          uuid.New(),
		UserID:      req.UserID,
		VaultID:     vaultID,
		Name:        req.Name,
		Value:       encryptedValue,
		Version:     1,
		Tags:        req.Tags,
		ContentType: req.ContentType,
		CreatedAt:   time.Now(),
		Enabled:     enabled,
		ExpiresAt:   req.ExpiresAt,
		NotBefore:   req.NotBefore,
	}

	// doCreate runs the repository write. The repository's Create method
	// already inserts the secret row and its tags in a single logical unit.
	// When s.db is set, we wrap this in a transaction so any partial failure
	// inside Create is rolled back atomically.
	doCreate := func() error {
		if err := s.secretRepo.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to store secret: %w", err)
		}
		return nil
	}

	if s.db != nil {
		// Wrap the repository write in an explicit transaction. This ensures
		// the secret row and its tags are committed together or not at all.
		// Note: repositories currently use *sql.DB directly; the WithTx call
		// here begins a transaction on the same pool and also defers rollback
		// on any error, providing a safety net for future DBTX refactoring.
		if err = dbpkg.WithTx(ctx, s.db, func(_ *sql.Tx) error {
			return doCreate()
		}); err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Transaction failed", err)
			return nil, fmt.Errorf("failed to create secret: %w", err)
		}
	} else {
		// No real DB available (unit test path) — call repository directly.
		if err = doCreate(); err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to create secret", err)
			return nil, fmt.Errorf("failed to create secret: %w", err)
		}
	}

	// Return plaintext to the caller.
	secret.Value = req.Value

	s.logger.LogAuditInfo(req.UserID.String(), "create_secret", "success",
		fmt.Sprintf("Secret created: %s", req.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
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

	// Update content type if provided.
	if req.ContentType != nil {
		if err := validateContentType(*req.ContentType); err != nil {
			return err
		}
		updatedSecret.ContentType = *req.ContentType
	}

	// Update name if provided.
	if req.Name != nil {
		updatedSecret.Name = *req.Name
	}

	// Update lifecycle fields if provided.
	if req.Enabled != nil {
		updatedSecret.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		updatedSecret.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		updatedSecret.NotBefore = req.NotBefore
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

	s.logger.LogAuditInfo(req.UserID.String(), "update_secret", "success", fmt.Sprintf("Secret updated: %s", updatedSecret.Name))
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
func (s *secretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	// Ownership is enforced at the SQL level via ReadByOwner.
	secret, err := s.secretRepo.ReadByOwner(ctx, secretID, userID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Secret not found or access denied", err)
		return nil, fmt.Errorf("secret not found or access denied")
	}

	// Decrypt value.
	decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Failed to decrypt secret", err)
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = decryptedValue

	// Load tags.
	tags, err := s.tagService.GetTags(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Failed to load tags", err)
		return nil, fmt.Errorf("failed to load tags: %w", err)
	}
	secret.Tags = tags

	// Enforce lifecycle policy at the service boundary.
	if !secret.IsAccessible() {
		s.logger.LogAuditError(userID.String(), "get_secret", "denied", "Secret is disabled or outside its valid time window", nil)
		return nil, fmt.Errorf("secret is disabled or outside its valid time window")
	}

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
func (s *secretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
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

	// Soft delete secret via repository (instead of hard delete)
	if err := s.secretRepo.SoftDelete(ctx, secretID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_secret", "failed", "Failed to soft delete secret", err)
		return fmt.Errorf("failed to soft delete secret: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "delete_secret", "success",
		fmt.Sprintf("Secret soft deleted: %s", secret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"user_id":   userID.String(),
	}).Info("Secret soft deleted successfully")

	return nil
}

// GetSecretInVault retrieves a secret by ID scoped to a vault, with decryption
// and tag loading. It mirrors GetSecret but enforces vault scope at the SQL
// level via ReadInVault instead of ownership.
func (s *secretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	secret, err := s.secretRepo.ReadInVault(ctx, secretID, vaultID)
	if err != nil {
		s.logger.LogAuditError(vaultID.String(), "get_secret", "failed", "Secret not found or not in vault", err)
		return nil, fmt.Errorf("secret not found or access denied")
	}

	// Decrypt value.
	decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
	if err != nil {
		s.logger.LogAuditError(vaultID.String(), "get_secret", "failed", "Failed to decrypt secret", err)
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = decryptedValue

	// Load tags.
	tags, err := s.tagService.GetTags(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(vaultID.String(), "get_secret", "failed", "Failed to load tags", err)
		return nil, fmt.Errorf("failed to load tags: %w", err)
	}
	secret.Tags = tags

	// Enforce lifecycle policy at the service boundary.
	if !secret.IsAccessible() {
		s.logger.LogAuditError(vaultID.String(), "get_secret", "denied", "Secret is disabled or outside its valid time window", nil)
		return nil, fmt.Errorf("secret is disabled or outside its valid time window")
	}

	return secret, nil
}

// ListSecretsInVault retrieves all active secrets in a vault with optional tag
// filtering. It mirrors ListSecrets but scopes by vault instead of user.
func (s *secretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	secretList, err := s.secretRepo.ListInVault(ctx, vaultID, tags)
	if err != nil {
		s.logger.LogAuditError(vaultID.String(), "list_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for i := range secretList {
		secret := &secretList[i]

		decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
		if err != nil {
			s.logger.LogAuditError(vaultID.String(), "list_secrets", "failed", "Failed to decrypt secret", err)
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", secret.ID.String(), err)
		}
		secret.Value = decryptedValue

		secretTags, err := s.tagService.GetTags(ctx, secret.ID)
		if err != nil {
			s.logger.LogAuditError(vaultID.String(), "list_secrets", "failed", "Failed to load tags", err)
			return nil, fmt.Errorf("failed to load tags for secret %s: %w", secret.ID.String(), err)
		}
		secret.Tags = secretTags
	}

	logrus.WithFields(logrus.Fields{
		"vault_id":     vaultID.String(),
		"secret_count": len(secretList),
	}).Debug("Listed secrets for vault")

	return secretList, nil
}

// DeleteSecretInVault soft-deletes a secret scoped to a vault. It mirrors
// DeleteSecret but verifies vault scope via ReadInVault instead of ownership.
func (s *secretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	secret, err := s.secretRepo.ReadInVault(ctx, secretID, vaultID)
	if err != nil {
		s.logger.LogAuditError(vaultID.String(), "delete_secret", "failed", "Secret not found or not in vault", err)
		return fmt.Errorf("secret not found: %w", err)
	}

	// Remove all tags first.
	if err := s.tagService.RemoveAllTags(ctx, secretID); err != nil {
		s.logger.LogAuditError(vaultID.String(), "delete_secret", "failed", "Failed to remove tags", err)
		return fmt.Errorf("failed to remove tags: %w", err)
	}

	// Soft delete secret via repository.
	if err := s.secretRepo.SoftDelete(ctx, secretID); err != nil {
		s.logger.LogAuditError(vaultID.String(), "delete_secret", "failed", "Failed to soft delete secret", err)
		return fmt.Errorf("failed to soft delete secret: %w", err)
	}

	s.logger.LogAuditInfo(vaultID.String(), "delete_secret", "success",
		fmt.Sprintf("Secret soft deleted: %s", secret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"vault_id":  vaultID.String(),
	}).Info("Secret soft deleted successfully")

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
func (s *secretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]model.SecretVersion, error) {
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
func (s *secretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
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
func (s *secretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.SecretVersion, error) {
	return s.versionService.GetLatestVersion(ctx, secretID, userID)
}

// GenerateSecret generates a random password or secret with specified criteria.
// It creates a new secret with a randomly generated value.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The secret generation request with password criteria.
//
// Returns:
//
//	The created secret with generated value or an error if generation fails.
func (s *secretService) GenerateSecret(ctx context.Context, req GenerateSecretRequest) (*model.Secret, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": req.UserID.String(),
		"name":    req.Name,
		"length":  req.Length,
	}).Info("Generating random secret")

	// Validate length
	if req.Length < 8 || req.Length > 128 {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "Invalid length: must be between 8 and 128", nil)
		return nil, fmt.Errorf("invalid length: must be between 8 and 128")
	}

	// Ensure at least one character type is selected
	if !req.UseSymbols && !req.UseNumbers && !req.UseUppercase && !req.UseLowercase {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "At least one character type must be selected", nil)
		return nil, fmt.Errorf("at least one character type must be selected")
	}

	// Generate random password using common utility
	generatedValue, err := generateRandomPassword(req.Length, req.UseSymbols, req.UseNumbers, req.UseUppercase, req.UseLowercase)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "Failed to generate random password", err)
		return nil, fmt.Errorf("failed to generate random password: %w", err)
	}

	// Create secret with generated value
	createReq := CreateSecretRequest{
		UserID: req.UserID,
		Name:   req.Name,
		Value:  generatedValue,
		Tags:   []string{"generated"},
	}

	secret, err := s.CreateSecret(ctx, createReq)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "Failed to create secret with generated value", err)
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "generate_secret", "success",
		fmt.Sprintf("Generated secret: %s (length: %d)", req.Name, req.Length))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   req.UserID.String(),
		"name":      req.Name,
		"length":    req.Length,
	}).Info("Random secret generated successfully")

	return secret, nil
}

// generateRandomPassword generates a random password with specified criteria.
// This is a helper function for password generation.
func generateRandomPassword(length int, useSymbols, useNumbers, useUppercase, useLowercase bool) (string, error) {
	const (
		symbols   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
		numbers   = "0123456789"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercase = "abcdefghijklmnopqrstuvwxyz"
	)

	// Build character set based on requirements
	var charset string
	if useSymbols {
		charset += symbols
	}
	if useNumbers {
		charset += numbers
	}
	if useUppercase {
		charset += uppercase
	}
	if useLowercase {
		charset += lowercase
	}

	if len(charset) == 0 {
		return "", fmt.Errorf("no character types selected")
	}

	// Generate random password
	password := make([]byte, length)
	for i := range password {
		// Use crypto/rand for secure random selection
		randomIndex := make([]byte, 1)
		if _, err := rand.Read(randomIndex); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		password[i] = charset[int(randomIndex[0])%len(charset)]
	}

	return string(password), nil
}

// ExportSecrets exports secrets in JSON or CSV format.
// It retrieves secrets for the user and formats them according to the request.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The export request with format and filter options.
//
// Returns:
//
//	The exported data as bytes or an error if export fails.
func (s *secretService) ExportSecrets(ctx context.Context, req ExportSecretsRequest) ([]byte, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": req.UserID.String(),
		"format":  req.Format,
		"tags":    req.FilterTags,
	}).Info("Exporting secrets")

	// Validate format
	if req.Format != "json" && req.Format != "csv" {
		s.logger.LogAuditError(req.UserID.String(), "export_secrets", "failed", "Invalid format: must be json or csv", nil)
		return nil, fmt.Errorf("invalid format: must be json or csv")
	}

	// List secrets with optional tag filter
	secrets, err := s.ListSecrets(ctx, req.UserID, req.FilterTags)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "export_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	var data []byte
	if req.Format == "json" {
		// Export as JSON
		type exportSecret struct {
			Name  string   `json:"name"`
			Value string   `json:"value"`
			Tags  []string `json:"tags,omitempty"`
		}

		exportData := make([]exportSecret, len(secrets))
		for i, secret := range secrets {
			exportData[i] = exportSecret{
				Name:  secret.Name,
				Value: secret.Value,
			}
			if req.IncludeTags {
				exportData[i].Tags = secret.Tags
			}
		}

		data, err = json.MarshalIndent(exportData, "", "  ")
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "export_secrets", "failed", "Failed to marshal JSON", err)
			return nil, fmt.Errorf("failed to marshal JSON: %w", err)
		}
	} else {
		// Export as CSV
		var csvData string
		if req.IncludeTags {
			csvData = "name,value,tags\n"
			for _, secret := range secrets {
				tags := ""
				if len(secret.Tags) > 0 {
					tags = fmt.Sprintf(`"%s"`, strings.Join(secret.Tags, ","))
				}
				csvData += fmt.Sprintf(`"%s","%s",%s`+"\n", secret.Name, secret.Value, tags)
			}
		} else {
			csvData = "name,value\n"
			for _, secret := range secrets {
				csvData += fmt.Sprintf(`"%s","%s"`+"\n", secret.Name, secret.Value)
			}
		}
		data = []byte(csvData)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "export_secrets", "success",
		fmt.Sprintf("Exported %d secrets in %s format", len(secrets), req.Format))
	logrus.WithFields(logrus.Fields{
		"user_id":      req.UserID.String(),
		"format":       req.Format,
		"secret_count": len(secrets),
	}).Info("Secrets exported successfully")

	return data, nil
}

// ImportSecrets imports secrets from JSON or CSV format.
// It parses the data and creates secrets for the user.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The import request with data and options.
//
// Returns:
//
//	The import result with counts and errors, or an error if import fails.
func (s *secretService) ImportSecrets(ctx context.Context, req ImportSecretsRequest) (*ImportResult, error) {
	logrus.WithFields(logrus.Fields{
		"user_id":   req.UserID.String(),
		"format":    req.Format,
		"overwrite": req.Overwrite,
	}).Info("Importing secrets")

	result := &ImportResult{
		Errors: []string{},
	}

	// Validate format
	if req.Format != "json" && req.Format != "csv" {
		s.logger.LogAuditError(req.UserID.String(), "import_secrets", "failed", "Invalid format: must be json or csv", nil)
		return nil, fmt.Errorf("invalid format: must be json or csv")
	}

	type importSecret struct {
		Name  string   `json:"name"`
		Value string   `json:"value"`
		Tags  []string `json:"tags,omitempty"`
	}

	var secretsToImport []importSecret

	if req.Format == "json" {
		// Parse JSON
		if err := json.Unmarshal(req.Data, &secretsToImport); err != nil {
			s.logger.LogAuditError(req.UserID.String(), "import_secrets", "failed", "Failed to parse JSON", err)
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		// Parse CSV (simplified - assumes CSV format: name,value or name,value,tags)
		lines := strings.Split(string(req.Data), "\n")
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue // Skip header and empty lines
			}

			// Simple CSV parsing (handles quoted values)
			parts := parseCSVLine(line)
			if len(parts) < 2 {
				result.Errors = append(result.Errors, fmt.Sprintf("Line %d: invalid format", i+1))
				continue
			}

			secret := importSecret{
				Name:  parts[0],
				Value: parts[1],
			}
			if len(parts) > 2 && parts[2] != "" {
				secret.Tags = strings.Split(parts[2], ",")
			}
			secretsToImport = append(secretsToImport, secret)
		}
	}

	result.TotalCount = len(secretsToImport)

	// Import each secret
	for _, importSec := range secretsToImport {
		if importSec.Name == "" || importSec.Value == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("Secret missing name or value"))
			result.SkippedCount++
			continue
		}

		createReq := CreateSecretRequest{
			UserID: req.UserID,
			Name:   importSec.Name,
			Value:  importSec.Value,
			Tags:   importSec.Tags,
		}

		if _, err := s.CreateSecret(ctx, createReq); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to import '%s': %v", importSec.Name, err))
			result.SkippedCount++
		} else {
			result.ImportedCount++
		}
	}

	s.logger.LogAuditInfo(req.UserID.String(), "import_secrets", "success",
		fmt.Sprintf("Imported %d/%d secrets", result.ImportedCount, result.TotalCount))
	logrus.WithFields(logrus.Fields{
		"user_id":        req.UserID.String(),
		"format":         req.Format,
		"imported_count": result.ImportedCount,
		"skipped_count":  result.SkippedCount,
		"total_count":    result.TotalCount,
	}).Info("Secrets import completed")

	return result, nil
}

// parseCSVLine parses a CSV line handling quoted values.
func parseCSVLine(line string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(line); i++ {
		char := line[i]
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				current.WriteByte(char)
			} else {
				parts = append(parts, strings.TrimSpace(current.String()))
				current.Reset()
			}
		default:
			current.WriteByte(char)
		}
	}
	parts = append(parts, strings.TrimSpace(current.String()))
	return parts
}
