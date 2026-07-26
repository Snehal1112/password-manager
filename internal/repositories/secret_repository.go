package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// SecretRepositoryInterface defines the interface for secret repository operations.
type SecretRepositoryInterface interface {
	Create(ctx context.Context, secret *model.Secret) error
	Read(ctx context.Context, id uuid.UUID) (*model.Secret, error)
	// ReadByOwner fetches a secret only when id and userID both match.
	ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*model.Secret, error)
	Update(ctx context.Context, secret *model.Secret) error
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverSecret(ctx context.Context, id uuid.UUID) error
	ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error)
	ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error)
	// ReadInVault fetches a secret only when id and vaultID both match.
	ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Secret, error)
	// UpdateInVault updates a secret only when it belongs to the given vault.
	// It mirrors Update but scopes by vault_id instead of user_id.
	UpdateInVault(ctx context.Context, secret *model.Secret) error
	// ListInVault lists active secrets scoped to a vault.
	ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error)
	// ListInVaultIncludeDeleted lists all secrets in a vault including soft-deleted ones.
	ListInVaultIncludeDeleted(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error)
	// SoftDeleteVaultContents soft-deletes every active secret in a vault.
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContents recovers only the secrets the cascade soft-deleted at deletedAt.
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error)
	ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error)
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error)
	PurgeSecret(ctx context.Context, id uuid.UUID) error
}

// SecretRepository implements SecretRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like encryption or versioning with performance monitoring.
type SecretRepository struct {
	db  db.DB
	log *logging.Logger
}

// executeWithMetrics wraps database operations with performance monitoring.
func (r *SecretRepository) executeWithMetrics(operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	// Record performance metrics
	db.RecordQueryExecution(duration)

	// Log slow queries
	if duration > 100*time.Millisecond {
		logrus.WithFields(logrus.Fields{
			"operation": operation,
			"duration":  duration.Milliseconds(),
		}).Warn("Slow database query detected")
	}

	return err
}

// NewSecretRepository creates a new SecretRepository instance.
// It provides pure database operations for secret entities.
//
// Parameters:
//
//	db: The database connection.
//	log: The logger for database operation logging.
//
// Returns:
//
//	A SecretRepositoryInterface implementation for secret database operations.
func NewSecretRepository(db db.DB, log *logging.Logger) SecretRepositoryInterface {
	return &SecretRepository{db: db, log: log}
}

// Create inserts a new secret into the database.
// It expects the secret value to be already encrypted.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secret: The secret entity to store (with encrypted value).
//
// Returns:
//
//	An error if the insertion fails.
func (r *SecretRepository) Create(ctx context.Context, secret *model.Secret) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"name":      secret.Name,
	}).Debug("Inserting secret into database")

	// Insert the secret into the database.
	_, err := r.db.ExecContext(
		ctx,
		"INSERT INTO secrets (id, user_id, vault_id, name, value, version, created_at, content_type, enabled, expires_at, not_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		secret.ID.String(), secret.UserID.String(), secret.VaultID.String(), secret.Name, secret.Value, secret.Version, secret.CreatedAt, secret.ContentType, secret.Enabled, secret.ExpiresAt, secret.NotBefore,
	)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "create_secret", "failed", "Failed to insert secret", err)
		return fmt.Errorf("failed to insert secret: %w", err)
	}

	// Insert tags if provided.
	for _, tag := range secret.Tags {
		_, err = r.db.ExecContext(
			ctx,
			"INSERT INTO secret_tags (secret_id, tag) VALUES (?, ?)",
			secret.ID.String(), tag,
		)
		if err != nil {
			r.log.LogAuditError(secret.UserID.String(), "create_secret", "failed", "Failed to insert tag", err)
			return fmt.Errorf("failed to insert tag: %w", err)
		}
	}

	r.log.LogAuditInfo(secret.UserID.String(), "create_secret", "success", fmt.Sprintf("Secret inserted: %s", secret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"name":      secret.Name,
	}).Debug("Secret inserted successfully")

	return nil
}

// Read retrieves a secret by ID from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	The secret entity (with encrypted value) or an error if not found.
func (r *SecretRepository) Read(ctx context.Context, id uuid.UUID) (*model.Secret, error) {
	var secret model.Secret
	var idStr, userIDStr, vaultIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, vault_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &vaultIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("secret not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	secret.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret ID: %w", err)
	}

	secret.UserID, err = uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	secret.VaultID, err = uuid.Parse(vaultIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault ID: %w", err)
	}

	// Set soft delete fields.
	secret.DeletedAt = deletedAt
	secret.PurgeProtection = purgeProtection

	return &secret, nil
}

// ReadByOwner retrieves a secret by ID only when the given userID matches the owner.
// It returns an error if the secret does not exist or is owned by a different user.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//	userID: The requesting user's identifier; must match the stored owner.
//
// Returns:
//
//	The secret entity (with encrypted value) or an error if not found / access denied.
func (r *SecretRepository) ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*model.Secret, error) {
	var secret model.Secret
	var idStr, userIDStr, vaultIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, vault_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
		id.String(), userID.String(),
	).Scan(&idStr, &userIDStr, &vaultIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("secret not found or access denied")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	var parseErr error
	secret.ID, parseErr = uuid.Parse(idStr)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse secret ID: %w", parseErr)
	}

	secret.UserID, parseErr = uuid.Parse(userIDStr)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", parseErr)
	}

	secret.VaultID, parseErr = uuid.Parse(vaultIDStr)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse vault ID: %w", parseErr)
	}

	// Set soft delete fields.
	secret.DeletedAt = deletedAt
	secret.PurgeProtection = purgeProtection

	return &secret, nil
}

// Update updates a secret in the database.
// It expects the secret value to be already encrypted and version to be pre-incremented.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secret: The secret entity with updated fields.
//
// Returns:
//
//	An error if the update fails.
func (r *SecretRepository) Update(ctx context.Context, secret *model.Secret) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"version":   secret.Version,
	}).Debug("Updating secret in database")

	result, err := r.db.ExecContext(
		ctx,
		"UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ?, enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND user_id = ?",
		secret.Name, secret.Value, secret.Version, secret.ContentType, secret.Enabled, secret.ExpiresAt, secret.NotBefore, secret.ID.String(), secret.UserID.String(),
	)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Secret not found for update", nil)
		return fmt.Errorf("secret not found")
	}

	r.log.LogAuditInfo(secret.UserID.String(), "update_secret", "success", fmt.Sprintf("Secret updated: %s", secret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"version":   secret.Version,
	}).Debug("Secret updated successfully")

	return nil
}

// Delete removes a secret from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *SecretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	logrus.WithField("secret_id", id.String()).Debug("Deleting secret from database")

	result, err := r.db.ExecContext(ctx, "DELETE FROM secrets WHERE id = ?", id.String())
	if err != nil {
		r.log.LogAuditError("", "delete_secret", "failed", "Failed to delete secret", err)
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError("", "delete_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError("", "delete_secret", "failed", "Secret not found for deletion", nil)
		return fmt.Errorf("secret not found")
	}

	r.log.LogAuditInfo("", "delete_secret", "success", "Secret deleted successfully")
	logrus.WithField("secret_id", id.String()).Debug("Secret deleted successfully")

	return nil
}

// SoftDelete marks a secret as deleted without removing it from the database.
// This implements soft delete functionality for compliance and recovery purposes.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *SecretRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	logrus.WithField("secret_id", id.String()).Debug("Soft deleting secret from database")

	now := time.Now()
	result, err := r.db.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
		now, id.String())
	if err != nil {
		r.log.LogAuditError("", "soft_delete_secret", "failed", "Failed to soft delete secret", err)
		return fmt.Errorf("failed to soft delete secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError("", "soft_delete_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError("", "soft_delete_secret", "failed", "Secret not found or already deleted", nil)
		return fmt.Errorf("secret not found or already deleted")
	}

	r.log.LogAuditInfo("", "soft_delete_secret", "success", "Secret soft deleted successfully")
	logrus.WithField("secret_id", id.String()).Debug("Secret soft deleted successfully")

	return nil
}

// RecoverSecret restores a soft-deleted secret by clearing its deleted_at timestamp.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the secret is not found in a deleted state or the update fails.
func (r *SecretRepository) RecoverSecret(ctx context.Context, id uuid.UUID) error {
	logrus.WithField("secret_id", id.String()).Debug("Recovering soft-deleted secret")

	result, err := r.db.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = NULL, scheduled_purge_at = NULL WHERE id = ? AND deleted_at IS NOT NULL",
		id.String())
	if err != nil {
		r.log.LogAuditError("", "recover_secret", "failed", "Failed to recover secret", err)
		return fmt.Errorf("failed to recover secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError("", "recover_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError("", "recover_secret", "failed", "Secret not found in deleted state", nil)
		return fmt.Errorf("secret not found in deleted state")
	}

	r.log.LogAuditInfo("", "recover_secret", "success", "Secret recovered successfully")
	logrus.WithField("secret_id", id.String()).Debug("Secret recovered successfully")

	return nil
}

// PurgeSecret permanently removes a soft-deleted secret from the database.
// This should only be called for secrets that have been soft-deleted and have purge protection disabled.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the purge operation fails.
func (r *SecretRepository) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	logrus.WithField("secret_id", id.String()).Debug("Purging secret from database")

	// First check if the secret exists and is soft-deleted without purge protection
	var deletedAt *time.Time
	var purgeProtection bool
	err := r.db.QueryRowContext(ctx,
		"SELECT deleted_at, purge_protection FROM secrets WHERE id = ?", id.String()).
		Scan(&deletedAt, &purgeProtection)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			r.log.LogAuditError("", "purge_secret", "failed", "Secret not found", nil)
			return fmt.Errorf("secret not found")
		}
		r.log.LogAuditError("", "purge_secret", "failed", "Failed to check secret status", err)
		return fmt.Errorf("failed to check secret status: %w", err)
	}

	// Validate that the secret can be purged
	if deletedAt == nil {
		r.log.LogAuditError("", "purge_secret", "failed", "Secret is not soft-deleted", nil)
		return fmt.Errorf("secret is not soft-deleted")
	}
	if purgeProtection {
		r.log.LogAuditError("", "purge_secret", "failed", "Secret has purge protection enabled", nil)
		return fmt.Errorf("secret has purge protection enabled")
	}

	// Perform the purge
	result, err := r.db.ExecContext(ctx, "DELETE FROM secrets WHERE id = ?", id.String())
	if err != nil {
		r.log.LogAuditError("", "purge_secret", "failed", "Failed to purge secret", err)
		return fmt.Errorf("failed to purge secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError("", "purge_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError("", "purge_secret", "failed", "Secret not found for purge", nil)
		return fmt.Errorf("secret not found for purge")
	}

	r.log.LogAuditInfo("", "purge_secret", "success", "Secret purged successfully")
	logrus.WithField("secret_id", id.String()).Debug("Secret purged successfully")

	return nil
}

// ListByUser retrieves all secrets for a specific user with optimized query and monitoring.
// Note: Tag filtering has been moved to the TagService.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user's unique identifier.
//	tags: Tag filter (maintained for interface compatibility but not used).
//
// Returns:
//
//	A slice of secrets (with encrypted values) or an error if retrieval fails.
func (r *SecretRepository) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	var secretList []model.Secret

	err := r.executeWithMetrics("list_secrets_by_user", func() error {
		logrus.WithField("user_id", userID.String()).Debug("Listing secrets for user")

		// Optimized query with proper indexing and ordering - excludes soft-deleted secrets
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE user_id = ? AND deleted_at IS NULL ORDER BY name ASC",
			userID.String(),
		)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to query secrets", err)
			return fmt.Errorf("failed to query secrets: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice with estimated capacity for better memory performance
		secretList = make([]model.Secret, 0, 50) // Assume max 50 secrets per user initially

		for rows.Next() {
			var secret model.Secret
			var idStr, userIDStr string

			var deletedAt *time.Time
			var purgeProtection bool

			err := rows.Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to scan secret", err)
				return fmt.Errorf("failed to scan secret: %w", err)
			}

			secret.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to parse secret ID", err)
				return fmt.Errorf("failed to parse secret ID: %w", err)
			}

			secret.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			// Set soft delete fields (these should be nil/false for active secrets)
			secret.DeletedAt = deletedAt
			secret.PurgeProtection = purgeProtection

			secretList = append(secretList, secret)
		}

		if err := rows.Err(); err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Row iteration error", err)
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id":      userID.String(),
		"secret_count": len(secretList),
	}).Debug("Secrets listed successfully")

	return secretList, nil
}

// ListByUserIncludeDeleted retrieves all secrets for a user including soft-deleted ones.
// This is useful for administrative operations and recovery scenarios.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user's unique identifier.
//	tags: Tag filter (maintained for interface compatibility but not used).
//
// Returns:
//
//	A slice of all secrets including soft-deleted ones, or an error if retrieval fails.
func (r *SecretRepository) ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	var secretList []model.Secret

	err := r.executeWithMetrics("list_secrets_by_user_include_deleted", func() error {
		logrus.WithField("user_id", userID.String()).Debug("Listing all secrets for user including deleted")

		// Query includes soft-deleted secrets
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE user_id = ? ORDER BY name ASC",
			userID.String(),
		)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets_include_deleted", "failed", "Failed to query secrets", err)
			return fmt.Errorf("failed to query secrets: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice with estimated capacity for better memory performance
		secretList = make([]model.Secret, 0, 50) // Assume max 50 secrets per user initially

		for rows.Next() {
			var secret model.Secret
			var idStr, userIDStr string
			var deletedAt *time.Time
			var purgeProtection bool

			err := rows.Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_secrets_include_deleted", "failed", "Failed to scan secret", err)
				return fmt.Errorf("failed to scan secret: %w", err)
			}

			secret.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_secrets_include_deleted", "failed", "Failed to parse secret ID", err)
				return fmt.Errorf("failed to parse secret ID: %w", err)
			}

			secret.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_secrets_include_deleted", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			// Set soft delete fields
			secret.DeletedAt = deletedAt
			secret.PurgeProtection = purgeProtection

			secretList = append(secretList, secret)
		}

		if err := rows.Err(); err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets_include_deleted", "failed", "Row iteration error", err)
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id":      userID.String(),
		"secret_count": len(secretList),
	}).Debug("All secrets listed successfully including deleted")

	return secretList, nil
}

// ExportSecrets is deprecated and should be moved to a dedicated export service.
func (r *SecretRepository) ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error) {
	return nil, fmt.Errorf("export functionality has been moved to export service")
}

// ImportSecrets is deprecated and should be moved to a dedicated import service.
func (r *SecretRepository) ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error) {
	return 0, fmt.Errorf("import functionality has been moved to import service")
}

// GetVersions is deprecated and should use the VersioningService.
func (r *SecretRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// GetVersion is deprecated and should use the VersioningService.
func (r *SecretRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// GetLatestVersion is deprecated and should use the VersioningService.
func (r *SecretRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// ReadInVault retrieves a secret by ID only when it belongs to the given vault.
// It mirrors ReadByOwner but scopes by vault_id instead of user_id.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//	vaultID: The vault the secret must belong to.
//
// Returns:
//
//	The secret entity (with encrypted value) or an error if not found / access denied.
func (r *SecretRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Secret, error) {
	var secret model.Secret
	var idStr, userIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE id = ? AND vault_id = ? AND deleted_at IS NULL",
		id.String(), vaultID.String(),
	).Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("secret not found or access denied")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	var parseErr error
	secret.ID, parseErr = uuid.Parse(idStr)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse secret ID: %w", parseErr)
	}

	secret.UserID, parseErr = uuid.Parse(userIDStr)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", parseErr)
	}

	// Set soft delete fields.
	secret.DeletedAt = deletedAt
	secret.PurgeProtection = purgeProtection

	// The vault scope is known from the query, so populate it for consistency.
	secret.VaultID = vaultID

	return &secret, nil
}

// UpdateInVault updates a secret in the database, scoped to a vault instead
// of an owner. It mirrors Update but the WHERE clause matches vault_id
// instead of user_id, so any vault member's update succeeds.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secret: The secret entity with updated fields; VaultID must be set.
//
// Returns:
//
//	An error if the update fails or no row matches id+vault_id.
func (r *SecretRepository) UpdateInVault(ctx context.Context, secret *model.Secret) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"vault_id":  secret.VaultID.String(),
		"version":   secret.Version,
	}).Debug("Updating secret in database (vault-scoped)")

	result, err := r.db.ExecContext(
		ctx,
		"UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ?, enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND vault_id = ?",
		secret.Name, secret.Value, secret.Version, secret.ContentType, secret.Enabled, secret.ExpiresAt, secret.NotBefore, secret.ID.String(), secret.VaultID.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("secret not found")
	}

	// Audit attribution belongs to the caller (service layer), which knows
	// the acting principal; this pure-CRUD method receives none, and
	// secret.UserID is the row's owner, not necessarily the actor.
	// UpdateSecretInVault already emits its own audit row after calling this.
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"vault_id":  secret.VaultID.String(),
		"version":   secret.Version,
	}).Debug("Secret updated successfully")

	return nil
}

// ListInVault retrieves all active secrets for a specific vault.
// It mirrors ListByUser but scopes by vault_id instead of user_id.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	vaultID: The vault's unique identifier.
//	tags: Tag filter (maintained for interface compatibility but not used).
//
// Returns:
//
//	A slice of secrets (with encrypted values) or an error if retrieval fails.
func (r *SecretRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	var secretList []model.Secret

	err := r.executeWithMetrics("list_secrets_by_vault", func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Listing secrets for vault")

		// Optimized query - excludes soft-deleted secrets.
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE vault_id = ? AND deleted_at IS NULL ORDER BY name ASC",
			vaultID.String(),
		)
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "list_secrets", "failed", "Failed to query secrets", err)
			return fmt.Errorf("failed to query secrets: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice with estimated capacity for better memory performance.
		secretList = make([]model.Secret, 0, 50)

		for rows.Next() {
			var secret model.Secret
			var idStr, userIDStr string

			var deletedAt *time.Time
			var purgeProtection bool

			err := rows.Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_secrets", "failed", "Failed to scan secret", err)
				return fmt.Errorf("failed to scan secret: %w", err)
			}

			secret.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_secrets", "failed", "Failed to parse secret ID", err)
				return fmt.Errorf("failed to parse secret ID: %w", err)
			}

			secret.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_secrets", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			// Set soft delete fields (these should be nil/false for active secrets).
			secret.DeletedAt = deletedAt
			secret.PurgeProtection = purgeProtection

			// Populate VaultID from the queried vault for caller consistency.
			secret.VaultID = vaultID

			secretList = append(secretList, secret)
		}

		if err := rows.Err(); err != nil {
			r.log.LogAuditError(vaultID.String(), "list_secrets", "failed", "Row iteration error", err)
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"vault_id":     vaultID.String(),
		"secret_count": len(secretList),
	}).Debug("Secrets listed successfully")

	return secretList, nil
}

// ListInVaultIncludeDeleted retrieves all secrets for a vault including soft-deleted ones.
// It mirrors ListByUserIncludeDeleted but scopes by vault_id instead of user_id.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	vaultID: The vault's unique identifier.
//	tags: Tag filter (maintained for interface compatibility but not used).
//
// Returns:
//
//	A slice of all secrets including soft-deleted ones, or an error if retrieval fails.
func (r *SecretRepository) ListInVaultIncludeDeleted(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	var secretList []model.Secret

	err := r.executeWithMetrics("list_secrets_by_vault_include_deleted", func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Listing all secrets for vault including deleted")

		// Query includes soft-deleted secrets.
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE vault_id = ? ORDER BY name ASC",
			vaultID.String(),
		)
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "list_secrets_include_deleted", "failed", "Failed to query secrets", err)
			return fmt.Errorf("failed to query secrets: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice with estimated capacity for better memory performance.
		secretList = make([]model.Secret, 0, 50)

		for rows.Next() {
			var secret model.Secret
			var idStr, userIDStr string
			var deletedAt *time.Time
			var purgeProtection bool

			err := rows.Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_secrets_include_deleted", "failed", "Failed to scan secret", err)
				return fmt.Errorf("failed to scan secret: %w", err)
			}

			secret.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_secrets_include_deleted", "failed", "Failed to parse secret ID", err)
				return fmt.Errorf("failed to parse secret ID: %w", err)
			}

			secret.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_secrets_include_deleted", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			// Set soft delete fields.
			secret.DeletedAt = deletedAt
			secret.PurgeProtection = purgeProtection

			// Populate VaultID from the queried vault for caller consistency.
			secret.VaultID = vaultID

			secretList = append(secretList, secret)
		}

		if err := rows.Err(); err != nil {
			r.log.LogAuditError(vaultID.String(), "list_secrets_include_deleted", "failed", "Row iteration error", err)
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"vault_id":     vaultID.String(),
		"secret_count": len(secretList),
	}).Debug("All secrets listed successfully including deleted")

	return secretList, nil
}

// SoftDeleteVaultContents marks every active secret in a vault as soft-deleted.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	vaultID: The vault whose secrets should be soft-deleted.
//	deletedAt: The exact deletion timestamp to stamp on each cascaded row.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *SecretRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.softDeleteVaultContents(ctx, r.db, vaultID, deletedAt)
}

// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
func (r *SecretRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.softDeleteVaultContents(ctx, ex, vaultID, deletedAt)
}

func (r *SecretRepository) softDeleteVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all secrets in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
		deletedAt, vaultID.String())
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "soft_delete_vault_secrets", "failed", "Failed to soft delete vault secrets", err)
		return fmt.Errorf("failed to soft delete vault secrets: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "soft_delete_vault_secrets", "success", "Vault secrets soft deleted successfully")
	return nil
}

// RecoverVaultContents restores every soft-deleted secret in a vault.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	vaultID: The vault whose secrets should be recovered.
//	deletedAt: The cascade deletion timestamp; only rows stamped with it are restored.
//
// Returns:
//
//	An error if the recovery fails.
func (r *SecretRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.recoverVaultContents(ctx, r.db, vaultID, deletedAt)
}

// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
func (r *SecretRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.recoverVaultContents(ctx, ex, vaultID, deletedAt)
}

func (r *SecretRepository) recoverVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted secrets in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
		vaultID.String(), deletedAt)
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "recover_vault_secrets", "failed", "Failed to recover vault secrets", err)
		return fmt.Errorf("failed to recover vault secrets: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "recover_vault_secrets", "success", "Vault secrets recovered successfully")
	return nil
}
