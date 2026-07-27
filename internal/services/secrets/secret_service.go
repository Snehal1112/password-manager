package secrets

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrSecretNotFound is returned when a secret does not exist or is not accessible
// within the requested scope (vault or user ownership).
var ErrSecretNotFound = errors.New("secret not found")

// ErrSecretLifecycleDenied is returned when a secret exists but is disabled or
// outside its valid time window (not_before / expires_at).
var ErrSecretLifecycleDenied = errors.New("secret is disabled or outside its valid time window")

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
	Scope       model.Scope // Authorization scope for the read and the write.
	UserID      uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	VaultID     uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	Name        *string     // Optional - nil means no change.
	Value       *string     // Optional - nil means no change.
	Tags        *[]string   // Optional - nil means no change.
	ContentType *string     // Optional - nil means no change.
	Enabled     *bool       // Optional - nil means no change.
	ExpiresAt   *time.Time  // Optional - nil means no change.
	NotBefore   *time.Time  // Optional - nil means no change.
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
	VaultID      uuid.UUID // Target vault; defaults to the default vault when nil.
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
	VaultID     uuid.UUID // Set only for vault-scoped export; zero value exports by owner.
	Format      string    // "json" or "csv"
	FilterTags  []string  // Optional tag filter
	IncludeTags bool      // Include tags in export
}

// ImportSecretsRequest represents a request to import secrets.
type ImportSecretsRequest struct {
	UserID    uuid.UUID
	VaultID   uuid.UUID // Set only for vault-scoped import; zero value uses CreateSecret's default-vault fallback.
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
	// GetSecretScoped retrieves a decrypted secret authorized by scope.
	// Canonical; GetSecret and GetSecretInVault are shims over it.
	GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error)
	// ListSecretsScoped lists decrypted secrets authorized by scope.
	ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error)
	// DeleteSecretScoped soft-deletes a secret authorized by scope.
	DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	// ListDeletedSecretsScoped lists soft-deleted secrets authorized by scope.
	ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error)
	// UpdateSecretScoped updates a secret authorized by req.Scope. The scoped
	// read is the check and the write repeats the same predicate, so there is
	// no TOCTOU window even if the row's vault changes between them.
	UpdateSecretScoped(ctx context.Context, req UpdateSecretRequest) error
	UpdateSecret(ctx context.Context, req UpdateSecretRequest) error
	// UpdateSecretInVault updates a secret scoped to a vault. Any vault
	// member may update any secret in the vault (no ownership check).
	UpdateSecretInVault(ctx context.Context, req UpdateSecretRequest) error
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
	GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error)
	GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error)
	GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error)
	// GetSecretVersionsScoped returns every version of a secret the scope authorizes.
	GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)
	// GetSecretVersionScoped returns one version the scope authorizes.
	GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)
	// GetLatestSecretVersionScoped returns the newest version the scope authorizes.
	GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)
	// RecoverSecretScoped restores a soft-deleted secret authorized by scope.
	RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	// PurgeSecretScoped permanently deletes a soft-deleted secret authorized by scope.
	PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
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

	// Persist the secret. The repository's Create method inserts the secret
	// row and its tags as a single logical unit via its own db.DB handle.
	if err = s.secretRepo.Create(ctx, secret); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to store secret", err)
		return nil, fmt.Errorf("failed to create secret: %w", err)
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

// UpdateSecretScoped updates a secret with versioning support, authorized by
// req.Scope. Authorization lives entirely in the scope: the scoped read is the
// check, and the write repeats the same predicate.
func (s *secretService) UpdateSecretScoped(ctx context.Context, req UpdateSecretRequest) error {
	actor := req.Scope.ActorID().String()
	logrus.WithFields(logrus.Fields{
		"secret_id": req.SecretID.String(),
		"scope":     req.Scope.String(),
	}).Info("Updating secret")

	currentSecret, err := s.secretRepo.ReadScoped(ctx, req.SecretID, req.Scope)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Secret not found or access denied", err)
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	currentValue, err := s.cryptoService.DecryptSecret(currentSecret.Value)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to decrypt current secret", err)
		return fmt.Errorf("failed to decrypt current secret: %w", err)
	}

	// CreateVersion gates on secret.UserID == UserID; pass the secret's real
	// owner here, not the scope's actor, so a legitimate vault-scoped update
	// by a non-owner member is not rejected by CreateVersion's internal
	// ownership check. Scope.ActorID is for audit only — never an access
	// predicate — so it must not be threaded into that gate.
	if _, err = s.versionService.CreateVersion(ctx, CreateVersionRequest{
		SecretID: currentSecret.ID,
		UserID:   currentSecret.UserID,
		Name:     currentSecret.Name,
		Value:    currentValue,
		Version:  currentSecret.Version,
	}); err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to create version", err)
		return fmt.Errorf("failed to create version: %w", err)
	}

	updatedSecret, err := applySecretUpdate(currentSecret, req, s.cryptoService.EncryptSecret)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to apply update", err)
		return err
	}

	if err := s.secretRepo.UpdateScoped(ctx, updatedSecret, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	if req.Tags != nil {
		if err := s.tagService.RemoveAllTags(ctx, req.SecretID); err != nil {
			s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to remove old tags", err)
			return fmt.Errorf("failed to remove old tags: %w", err)
		}
		if len(*req.Tags) > 0 {
			if err := s.tagService.AddTags(ctx, req.SecretID, *req.Tags); err != nil {
				s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to add new tags", err)
				return fmt.Errorf("failed to add new tags: %w", err)
			}
		}
	}

	s.logger.LogAuditInfo(actor, "update_secret", "success", fmt.Sprintf("Secret updated: %s", updatedSecret.Name))
	return nil
}

// Deprecated: shim over UpdateSecretScoped; removed in Phase 6.
func (s *secretService) UpdateSecret(ctx context.Context, req UpdateSecretRequest) error {
	req.Scope = model.NewOwnerScope(uuid.Nil, req.UserID)
	return s.UpdateSecretScoped(ctx, req)
}

// Deprecated: shim over UpdateSecretScoped; removed in Phase 6.
func (s *secretService) UpdateSecretInVault(ctx context.Context, req UpdateSecretRequest) error {
	req.Scope = model.NewVaultScope(req.VaultID, req.UserID)
	return s.UpdateSecretScoped(ctx, req)
}

// GetSecretScoped retrieves a secret authorized by scope, decrypts it, loads
// its tags, and enforces the lifecycle policy. The scoped read is the access
// check — there is no separate in-Go ownership comparison.
func (s *secretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	actor := scope.ActorID().String()

	secret, err := s.secretRepo.ReadScoped(ctx, secretID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Secret not found or access denied", err)
		return nil, fmt.Errorf("%w", ErrSecretNotFound)
	}

	decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Failed to decrypt secret", err)
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = decryptedValue

	tags, err := s.tagService.GetTags(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Failed to load tags", err)
		return nil, fmt.Errorf("failed to load tags: %w", err)
	}
	secret.Tags = tags

	if !secret.IsAccessible() {
		s.logger.LogAuditError(actor, "get_secret", "denied", "Secret is disabled or outside its valid time window", nil)
		return nil, fmt.Errorf("%w", ErrSecretLifecycleDenied)
	}

	return secret, nil
}

// ListSecretsScoped lists secrets authorized by scope, decrypting values and
// loading tags for each.
func (s *secretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	actor := scope.ActorID().String()

	secretList, err := s.secretRepo.ListScoped(ctx, scope, repositories.SecretFilter{Tags: tags})
	if err != nil {
		s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for i := range secretList {
		secret := &secretList[i]

		decryptedValue, decErr := s.cryptoService.DecryptSecret(secret.Value)
		if decErr != nil {
			s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to decrypt secret", decErr)
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", secret.ID.String(), decErr)
		}
		secret.Value = decryptedValue

		secretTags, tagErr := s.tagService.GetTags(ctx, secret.ID)
		if tagErr != nil {
			s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to load tags", tagErr)
			return nil, fmt.Errorf("failed to load tags for secret %s: %w", secret.ID.String(), tagErr)
		}
		secret.Tags = secretTags
	}

	logrus.WithFields(logrus.Fields{
		"scope":        scope.String(),
		"secret_count": len(secretList),
	}).Debug("Listed secrets")

	return secretList, nil
}

// DeleteSecretScoped soft-deletes a secret authorized by scope. The scoped read
// is the access check.
func (s *secretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	actor := scope.ActorID().String()

	secret, err := s.secretRepo.ReadScoped(ctx, secretID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Secret not found or access denied", err)
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	if err := s.tagService.RemoveAllTags(ctx, secretID); err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Failed to remove tags", err)
		return fmt.Errorf("failed to remove tags: %w", err)
	}

	if err := s.secretRepo.SoftDelete(ctx, secretID); err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Failed to soft delete secret", err)
		return fmt.Errorf("failed to soft delete secret: %w", err)
	}

	s.logger.LogAuditInfo(actor, "delete_secret", "success", fmt.Sprintf("Secret soft deleted: %s", secret.Name))
	return nil
}

// ListDeletedSecretsScoped lists soft-deleted secrets authorized by scope. The
// filter runs in SQL rather than pulling every secret into memory to discard
// most of them.
func (s *secretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	secretList, err := s.secretRepo.ListScoped(ctx, scope, repositories.SecretFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted secrets: %w", err)
	}
	return secretList, nil
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
//
// Deprecated: shim over GetSecretScoped; removed in Phase 6.
func (s *secretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	return s.GetSecretScoped(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
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
//
// Deprecated: shim over ListSecretsScoped; removed in Phase 6.
func (s *secretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	return s.ListSecretsScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), tags)
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
//
// Deprecated: shim over DeleteSecretScoped; removed in Phase 6.
func (s *secretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	return s.DeleteSecretScoped(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}

// GetSecretInVault retrieves a secret by ID scoped to a vault, with decryption
// and tag loading. It mirrors GetSecret but enforces vault scope at the SQL
// level via ReadInVault instead of ownership.
//
// Deprecated: shim over GetSecretScoped; removed in Phase 6.
func (s *secretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	return s.GetSecretScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}

// ListSecretsInVault retrieves all active secrets in a vault with optional tag
// filtering. It mirrors ListSecrets but scopes by vault instead of user.
//
// Deprecated: shim over ListSecretsScoped; removed in Phase 6.
func (s *secretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return s.ListSecretsScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), tags)
}

// DeleteSecretInVault soft-deletes a secret scoped to a vault. It mirrors
// DeleteSecret but verifies vault scope via ReadInVault instead of ownership.
//
// Deprecated: shim over DeleteSecretScoped; removed in Phase 6.
func (s *secretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	return s.DeleteSecretScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}

// ListDeletedSecretsInVault lists soft-deleted secrets scoped to a vault.
//
// Deprecated: shim over ListDeletedSecretsScoped; removed in Phase 6.
func (s *secretService) ListDeletedSecretsInVault(ctx context.Context, vaultID uuid.UUID) ([]model.Secret, error) {
	return s.ListDeletedSecretsScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil))
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

// GetSecretVersionsInVault retrieves all versions of a secret scoped to a vault.
func (s *secretService) GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	return s.versionService.GetVersionsInVault(ctx, secretID, vaultID)
}

// GetSecretVersionInVault retrieves a specific version of a secret scoped to a vault.
func (s *secretService) GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.versionService.GetVersionInVault(ctx, secretID, version, vaultID)
}

// GetLatestSecretVersionInVault retrieves the latest version of a secret scoped to a vault.
func (s *secretService) GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.versionService.GetLatestVersionInVault(ctx, secretID, vaultID)
}

func (s *secretService) GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	return s.versionService.GetVersionsScoped(ctx, secretID, scope)
}

func (s *secretService) GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	return s.versionService.GetVersionScoped(ctx, secretID, version, scope)
}

func (s *secretService) GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	return s.versionService.GetLatestVersionScoped(ctx, secretID, scope)
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

	// Create secret with generated value. Thread the target vault through so
	// the generated secret lands in the resolved vault; CreateSecret resolves
	// uuid.Nil to the default vault, matching the legacy behaviour.
	createReq := CreateSecretRequest{
		UserID:  req.UserID,
		VaultID: req.VaultID,
		Name:    req.Name,
		Value:   generatedValue,
		Tags:    []string{"generated"},
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
	var secretsList []model.Secret
	var err error
	if req.VaultID != uuid.Nil {
		secretsList, err = s.ListSecretsInVault(ctx, req.VaultID, req.FilterTags)
	} else {
		secretsList, err = s.ListSecrets(ctx, req.UserID, req.FilterTags)
	}
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

		exportData := make([]exportSecret, len(secretsList))
		for i, secret := range secretsList {
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
			for _, secret := range secretsList {
				tags := ""
				if len(secret.Tags) > 0 {
					tags = fmt.Sprintf(`"%s"`, strings.Join(secret.Tags, ","))
				}
				csvData += fmt.Sprintf(`"%s","%s",%s`+"\n", secret.Name, secret.Value, tags)
			}
		} else {
			csvData = "name,value\n"
			for _, secret := range secretsList {
				csvData += fmt.Sprintf(`"%s","%s"`+"\n", secret.Name, secret.Value)
			}
		}
		data = []byte(csvData)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "export_secrets", "success",
		fmt.Sprintf("Exported %d secrets in %s format", len(secretsList), req.Format))
	logrus.WithFields(logrus.Fields{
		"user_id":      req.UserID.String(),
		"format":       req.Format,
		"secret_count": len(secretsList),
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
			result.Errors = append(result.Errors, "Secret missing name or value")
			result.SkippedCount++
			continue
		}

		createReq := CreateSecretRequest{
			UserID:  req.UserID,
			VaultID: req.VaultID,
			Name:    importSec.Name,
			Value:   importSec.Value,
			Tags:    importSec.Tags,
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

// softDeletedInScope reports whether secretID names a soft-deleted secret the
// scope authorizes. It replaces the handler-level IsSecretSoftDeleted* checks,
// which used a different scope from the mutation that followed them.
func (s *secretService) softDeletedInScope(ctx context.Context, secretID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.secretRepo.ListScoped(ctx, scope, repositories.SecretFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted secrets: %w", err)
	}
	for _, secret := range deleted {
		if secret.ID == secretID {
			return true, nil
		}
	}
	return false, nil
}

// RecoverSecretScoped restores a soft-deleted secret authorized by scope.
func (s *secretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	inScope, err := s.softDeletedInScope(ctx, secretID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_secret", "failed",
			"Secret not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrSecretNotFound)
	}
	if err := s.secretRepo.RecoverSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to recover secret: %w", err)
	}
	return nil
}

// PurgeSecretScoped permanently deletes a soft-deleted secret authorized by scope.
func (s *secretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	inScope, err := s.softDeletedInScope(ctx, secretID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_secret", "failed",
			"Secret not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrSecretNotFound)
	}
	if err := s.secretRepo.PurgeSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to purge secret: %w", err)
	}
	return nil
}

// Deprecated: shim over softDeletedInScope; removed in Phase 6.
func (s *secretService) IsSecretSoftDeletedInVault(ctx context.Context, secretID, vaultID uuid.UUID) (bool, error) {
	return s.softDeletedInScope(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}

// Deprecated: shim over softDeletedInScope; removed in Phase 6.
func (s *secretService) IsSecretSoftDeletedForUser(ctx context.Context, secretID, userID uuid.UUID) (bool, error) {
	return s.softDeletedInScope(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over RecoverSecretScoped; removed in Phase 6.
func (s *secretService) RecoverSecret(ctx context.Context, secretID uuid.UUID) error {
	return s.RecoverSecretScoped(ctx, secretID, model.NewAdminScope(uuid.Nil))
}

// Deprecated: shim over PurgeSecretScoped; removed in Phase 6.
func (s *secretService) PurgeSecret(ctx context.Context, secretID uuid.UUID) error {
	return s.PurgeSecretScoped(ctx, secretID, model.NewAdminScope(uuid.Nil))
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
