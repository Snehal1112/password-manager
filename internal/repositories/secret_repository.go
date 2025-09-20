package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/domain"
	"password-manager/internal/logging"
)

// SecretRepositoryInterface defines the interface for secret repository operations.
type SecretRepositoryInterface interface {
	Create(ctx context.Context, secret *domain.Secret) error
	Read(ctx context.Context, id uuid.UUID) (*domain.Secret, error)
	Update(ctx context.Context, secret *domain.Secret) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error)
	ExportSecrets(ctx context.Context, options domain.ExportOptions) ([]byte, error)
	ImportSecrets(ctx context.Context, data []byte, options domain.ImportOptions) (int, error)
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]domain.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*domain.SecretVersion, error)
}

// SecretRepository implements SecretRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like encryption or versioning.
type SecretRepository struct {
	db  *sql.DB
	log *logging.Logger
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

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, version, created_at FROM secrets WHERE id = ?",
		id.String(),
	).Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt)

	if err == sql.ErrNoRows {
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

// ListByUser retrieves all secrets for a specific user.
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
	logrus.WithField("user_id", userID.String()).Debug("Listing secrets for user")

	rows, err := r.db.QueryContext(
		ctx,
		"SELECT id, user_id, name, value, version, created_at FROM secrets WHERE user_id = ? ORDER BY created_at DESC",
		userID.String(),
	)
	if err != nil {
		r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to query secrets", err)
		return nil, fmt.Errorf("failed to query secrets: %w", err)
	}
	defer rows.Close()

	var secretList []domain.Secret
	for rows.Next() {
		var secret domain.Secret
		var idStr, userIDStr string

		err := rows.Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to scan secret", err)
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		secret.ID, err = uuid.Parse(idStr)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to parse secret ID", err)
			return nil, fmt.Errorf("failed to parse secret ID: %w", err)
		}

		secret.UserID, err = uuid.Parse(userIDStr)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to parse user ID", err)
			return nil, fmt.Errorf("failed to parse user ID: %w", err)
		}

		secretList = append(secretList, secret)
	}

	if err := rows.Err(); err != nil {
		r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Row iteration error", err)
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"user_id":      userID.String(),
		"secret_count": len(secretList),
	}).Debug("Secrets listed successfully")

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
