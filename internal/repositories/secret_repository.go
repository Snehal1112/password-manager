package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/db"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
)

// SecretRepositoryInterface defines the interface for secret repository operations.
type SecretRepositoryInterface interface {
	Create(ctx context.Context, secret *domain.Secret) error
	Read(ctx context.Context, id uuid.UUID) (*domain.Secret, error)
	Update(ctx context.Context, secret *domain.Secret) error
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error)
	ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error)
	ExportSecrets(ctx context.Context, options domain.ExportOptions) ([]byte, error)
	ImportSecrets(ctx context.Context, data []byte, options domain.ImportOptions) (int, error)
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]domain.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*domain.SecretVersion, error)
	PurgeSecret(ctx context.Context, id uuid.UUID) error
}

// SecretRepository implements SecretRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like encryption or versioning with performance monitoring.
type SecretRepository struct {
	db  *sql.DB
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
func NewSecretRepository(db *sql.DB, log *logging.Logger) SecretRepositoryInterface {
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
func (r *SecretRepository) Create(ctx context.Context, secret *domain.Secret) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"name":      secret.Name,
	}).Debug("Inserting secret into database")

	// Insert the secret into the database.
	_, err := r.db.ExecContext(
		ctx,
		"INSERT INTO secrets (id, user_id, name, value, version, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		secret.ID.String(), secret.UserID.String(), secret.Name, secret.Value, secret.Version, secret.CreatedAt,
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
func (r *SecretRepository) Read(ctx context.Context, id uuid.UUID) (*domain.Secret, error) {
	var secret domain.Secret
	var idStr, userIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection FROM secrets WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection)

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

	// Set soft delete fields
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
func (r *SecretRepository) Update(ctx context.Context, secret *domain.Secret) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"version":   secret.Version,
	}).Debug("Updating secret in database")

	result, err := r.db.ExecContext(
		ctx,
		"UPDATE secrets SET name = ?, value = ?, version = ? WHERE id = ? AND user_id = ?",
		secret.Name, secret.Value, secret.Version, secret.ID.String(), secret.UserID.String(),
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
		"UPDATE secrets SET deleted_at = ?, purge_protection = FALSE WHERE id = ? AND deleted_at IS NULL",
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
func (r *SecretRepository) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	var secretList []domain.Secret

	err := r.executeWithMetrics("list_secrets_by_user", func() error {
		logrus.WithField("user_id", userID.String()).Debug("Listing secrets for user")

		// Optimized query with proper indexing and ordering - excludes soft-deleted secrets
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection FROM secrets WHERE user_id = ? AND deleted_at IS NULL ORDER BY name ASC",
			userID.String(),
		)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to query secrets", err)
			return fmt.Errorf("failed to query secrets: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice with estimated capacity for better memory performance
		secretList = make([]domain.Secret, 0, 50) // Assume max 50 secrets per user initially

		for rows.Next() {
			var secret domain.Secret
			var idStr, userIDStr string

			var deletedAt *time.Time
			var purgeProtection bool

			err := rows.Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection)
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
func (r *SecretRepository) ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	var secretList []domain.Secret

	err := r.executeWithMetrics("list_secrets_by_user_include_deleted", func() error {
		logrus.WithField("user_id", userID.String()).Debug("Listing all secrets for user including deleted")

		// Query includes soft-deleted secrets
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection FROM secrets WHERE user_id = ? ORDER BY name ASC",
			userID.String(),
		)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets_include_deleted", "failed", "Failed to query secrets", err)
			return fmt.Errorf("failed to query secrets: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice with estimated capacity for better memory performance
		secretList = make([]domain.Secret, 0, 50) // Assume max 50 secrets per user initially

		for rows.Next() {
			var secret domain.Secret
			var idStr, userIDStr string
			var deletedAt *time.Time
			var purgeProtection bool

			err := rows.Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection)
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
func (r *SecretRepository) ExportSecrets(ctx context.Context, options domain.ExportOptions) ([]byte, error) {
	return nil, fmt.Errorf("export functionality has been moved to export service")
}

// ImportSecrets is deprecated and should be moved to a dedicated import service.
func (r *SecretRepository) ImportSecrets(ctx context.Context, data []byte, options domain.ImportOptions) (int, error) {
	return 0, fmt.Errorf("import functionality has been moved to import service")
}

// GetVersions is deprecated and should use the VersioningService.
func (r *SecretRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]domain.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// GetVersion is deprecated and should use the VersioningService.
func (r *SecretRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// GetLatestVersion is deprecated and should use the VersioningService.
func (r *SecretRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*domain.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}
