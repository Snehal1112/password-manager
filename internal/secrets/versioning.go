// Package versioning manages secret version tracking and history for the password manager.
// It provides functionality to create, retrieve, and manage historical versions of secrets,
// enabling audit trails and rollback capabilities.
package secrets

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"password-manager/common"
	"password-manager/internal/logging"
)

// SecretVersion represents a historical version of a secret.
type SecretVersion struct {
	ID        uuid.UUID
	SecretID  uuid.UUID
	UserID    uuid.UUID
	Name      string
	Value     string
	Version   int
	CreatedAt time.Time
}

// SecretVersionRepository interface for version operations.
type SecretVersionRepository interface {
	CreateVersion(ctx context.Context, version *SecretVersion) error
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*SecretVersion, error)
	DeleteVersions(ctx context.Context, secretID uuid.UUID) error
}

// secretVersionRepository implements SecretVersionRepository.
type secretVersionRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewSecretVersionRepository creates a new SecretVersionRepository.
func NewSecretVersionRepository(db *sql.DB, log *logging.Logger) SecretVersionRepository {
	return &secretVersionRepository{db: db, log: log}
}

// CreateVersion creates a new version of a secret.
func (r *secretVersionRepository) CreateVersion(ctx context.Context, version *SecretVersion) error {
	// Encrypt the secret value
	encryptedValue, err := common.EncryptSecret(version.Value)
	if err != nil {
		r.log.LogAuditError(version.UserID.String(), "create_version", "failed", "Failed to encrypt secret version", err)
		return fmt.Errorf("failed to encrypt secret version: %w", err)
	}

	// Insert the version into the database
	_, err = r.db.ExecContext(
		ctx,
		`INSERT INTO secret_versions (id, secret_id, user_id, name, value, version, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		version.ID.String(), version.SecretID.String(), version.UserID.String(),
		version.Name, encryptedValue, version.Version, version.CreatedAt,
	)
	if err != nil {
		r.log.LogAuditError(version.UserID.String(), "create_version", "failed", "Failed to create secret version", err)
		return fmt.Errorf("failed to create secret version: %w", err)
	}

	r.log.LogAuditInfo(version.UserID.String(), "create_version", "success",
		fmt.Sprintf("Created version %d for secret %s", version.Version, version.SecretID.String()))
	return nil
}

// GetVersions retrieves all versions of a secret.
func (r *secretVersionRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]SecretVersion, error) {
	rows, err := r.db.QueryContext(
		ctx,
		`SELECT id, secret_id, user_id, name, value, version, created_at
		 FROM secret_versions
		 WHERE secret_id = ?
		 ORDER BY version DESC`,
		secretID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query secret versions: %w", err)
	}
	defer rows.Close()

	var versions []SecretVersion
	for rows.Next() {
		var v SecretVersion
		var encryptedValue string

		err := rows.Scan(&v.ID, &v.SecretID, &v.UserID, &v.Name, &encryptedValue, &v.Version, &v.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan secret version: %w", err)
		}

		// Decrypt the value
		v.Value, err = common.DecryptSecret(encryptedValue)
		if err != nil {
			r.log.LogAuditError(v.UserID.String(), "get_versions", "failed", "Failed to decrypt secret version", err)
			return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
		}

		versions = append(versions, v)
	}

	return versions, nil
}

// GetVersion retrieves a specific version of a secret.
func (r *secretVersionRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*SecretVersion, error) {
	var v SecretVersion
	var encryptedValue string

	err := r.db.QueryRowContext(
		ctx,
		`SELECT id, secret_id, user_id, name, value, version, created_at
		 FROM secret_versions
		 WHERE secret_id = ? AND version = ?`,
		secretID.String(), version,
	).Scan(&v.ID, &v.SecretID, &v.UserID, &v.Name, &encryptedValue, &v.Version, &v.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("version %d not found for secret %s", version, secretID.String())
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret version: %w", err)
	}

	// Decrypt the value
	v.Value, err = common.DecryptSecret(encryptedValue)
	if err != nil {
		r.log.LogAuditError(v.UserID.String(), "get_version", "failed", "Failed to decrypt secret version", err)
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}

	return &v, nil
}

// GetLatestVersion retrieves the latest version of a secret.
func (r *secretVersionRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*SecretVersion, error) {
	var v SecretVersion
	var encryptedValue string

	err := r.db.QueryRowContext(
		ctx,
		`SELECT id, secret_id, user_id, name, value, version, created_at
		 FROM secret_versions
		 WHERE secret_id = ?
		 ORDER BY version DESC
		 LIMIT 1`,
		secretID.String(),
	).Scan(&v.ID, &v.SecretID, &v.UserID, &v.Name, &encryptedValue, &v.Version, &v.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no versions found for secret %s", secretID.String())
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query latest secret version: %w", err)
	}

	// Decrypt the value
	v.Value, err = common.DecryptSecret(encryptedValue)
	if err != nil {
		r.log.LogAuditError(v.UserID.String(), "get_latest_version", "failed", "Failed to decrypt secret version", err)
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}

	return &v, nil
}

// DeleteVersions deletes all versions of a secret.
func (r *secretVersionRepository) DeleteVersions(ctx context.Context, secretID uuid.UUID) error {
	result, err := r.db.ExecContext(
		ctx,
		"DELETE FROM secret_versions WHERE secret_id = ?",
		secretID.String(),
	)
	if err != nil {
		r.log.LogAuditError("", "delete_versions", "failed", "Failed to delete secret versions", err)
		return fmt.Errorf("failed to delete secret versions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.log.LogAuditInfo("", "delete_versions", "success",
		fmt.Sprintf("Deleted %d versions for secret %s", rowsAffected, secretID.String()))
	return nil
}
