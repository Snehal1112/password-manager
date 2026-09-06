// Package repositories provides data access interfaces and implementations following
// the repository pattern with clean separation of concerns.
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// SecretVersionRepositoryInterface defines the data access contract for secret versions.
// It follows the pure repository pattern expecting pre-processed data (encrypted values).
type SecretVersionRepositoryInterface interface {
	// Version operations
	CreateVersion(ctx context.Context, version *model.SecretVersion) error
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error)
	DeleteVersions(ctx context.Context, secretID uuid.UUID) error
	DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int) error
}

// secretVersionRepository implements SecretVersionRepositoryInterface.
type secretVersionRepository struct {
	db  db.DB
	log *logging.Logger
}

// NewSecretVersionRepository creates a new SecretVersionRepository.
func NewSecretVersionRepository(db db.DB, log *logging.Logger) SecretVersionRepositoryInterface {
	return &secretVersionRepository{db: db, log: log}
}

// CreateVersion creates a new version of a secret (expects pre-encrypted value).
func (r *secretVersionRepository) CreateVersion(ctx context.Context, version *model.SecretVersion) error {
	return r.createVersion(ctx, r.db, version)
}

// CreateVersionTx is CreateVersion's Tx-scoped variant, letting a caller run
// it inside an existing transaction. Used by ItemBackupService.RestoreSecret
// for an atomic restore (F3).
func (r *secretVersionRepository) CreateVersionTx(ctx context.Context, ex db.DBTX, version *model.SecretVersion) error {
	return r.createVersion(ctx, ex, version)
}

func (r *secretVersionRepository) createVersion(ctx context.Context, ex db.DBTX, version *model.SecretVersion) error {
	query := `
		INSERT INTO secret_versions (id, secret_id, user_id, name, value, version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := ex.ExecContext(ctx, query,
		version.ID.String(),
		version.SecretID.String(),
		version.UserID.String(),
		version.Name,
		version.Value, // Expected to be pre-encrypted
		version.Version,
		version.CreatedAt,
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to create secret version")
		return fmt.Errorf("failed to create secret version: %w", err)
	}

	r.log.WithFields(map[string]any{
		"version_id": version.ID,
		"secret_id":  version.SecretID,
		"version":    version.Version,
	}).Info("Secret version created")

	return nil
}

// GetVersions retrieves all versions of a secret (returns encrypted values).
func (r *secretVersionRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	query := `
		SELECT id, secret_id, user_id, name, value, version, created_at
		FROM secret_versions
		WHERE secret_id = ?
		ORDER BY version DESC
	`

	rows, err := r.db.QueryContext(ctx, query, secretID.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to query secret versions")
		return nil, fmt.Errorf("failed to query secret versions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var versions []model.SecretVersion
	for rows.Next() {
		var v model.SecretVersion
		var id, secretIDStr, userIDStr string

		err := rows.Scan(&id, &secretIDStr, &userIDStr, &v.Name, &v.Value, &v.Version, &v.CreatedAt)
		if err != nil {
			r.log.WithError(err).Error("Failed to scan secret version")
			return nil, fmt.Errorf("failed to scan secret version: %w", err)
		}

		if v.ID, err = uuid.Parse(id); err != nil {
			return nil, fmt.Errorf("invalid secret version id: %w", err)
		}
		if v.SecretID, err = uuid.Parse(secretIDStr); err != nil {
			return nil, fmt.Errorf("invalid secret id: %w", err)
		}
		if v.UserID, err = uuid.Parse(userIDStr); err != nil {
			return nil, fmt.Errorf("invalid user id: %w", err)
		}
		versions = append(versions, v)
	}

	if err := rows.Err(); err != nil {
		r.log.WithError(err).Error("Failed to iterate secret versions")
		return nil, fmt.Errorf("failed to iterate secret versions: %w", err)
	}

	return versions, nil
}

// GetVersion retrieves a specific version of a secret (returns encrypted value).
func (r *secretVersionRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	query := `
		SELECT id, secret_id, user_id, name, value, version, created_at
		FROM secret_versions
		WHERE secret_id = ? AND version = ?
	`

	var v model.SecretVersion
	var id, secretIDStr, userIDStr string

	err := r.db.QueryRowContext(ctx, query, secretID.String(), version).Scan(
		&id, &secretIDStr, &userIDStr, &v.Name, &v.Value, &v.Version, &v.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("version %d not found for secret %s: %w", version, secretID.String(), ErrNotFound)
	}
	if err != nil {
		r.log.WithError(err).Error("Failed to query secret version")
		return nil, fmt.Errorf("failed to query secret version: %w", err)
	}

	if v.ID, err = uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid secret version id: %w", err)
	}
	if v.SecretID, err = uuid.Parse(secretIDStr); err != nil {
		return nil, fmt.Errorf("invalid secret id: %w", err)
	}
	if v.UserID, err = uuid.Parse(userIDStr); err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	return &v, nil
}

// GetLatestVersion retrieves the latest version of a secret (returns encrypted value).
func (r *secretVersionRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	query := `
		SELECT id, secret_id, user_id, name, value, version, created_at
		FROM secret_versions
		WHERE secret_id = ?
		ORDER BY version DESC
		LIMIT 1
	`

	var v model.SecretVersion
	var id, secretIDStr, userIDStr string

	err := r.db.QueryRowContext(ctx, query, secretID.String()).Scan(
		&id, &secretIDStr, &userIDStr, &v.Name, &v.Value, &v.Version, &v.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("no versions found for secret %s: %w", secretID.String(), ErrNotFound)
	}
	if err != nil {
		r.log.WithError(err).Error("Failed to query latest secret version")
		return nil, fmt.Errorf("failed to query latest secret version: %w", err)
	}

	if v.ID, err = uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid secret version id: %w", err)
	}
	if v.SecretID, err = uuid.Parse(secretIDStr); err != nil {
		return nil, fmt.Errorf("invalid secret id: %w", err)
	}
	if v.UserID, err = uuid.Parse(userIDStr); err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	return &v, nil
}

// DeleteVersions deletes all versions of a secret.
func (r *secretVersionRepository) DeleteVersions(ctx context.Context, secretID uuid.UUID) error {
	query := "DELETE FROM secret_versions WHERE secret_id = ?"

	result, err := r.db.ExecContext(ctx, query, secretID.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to delete secret versions")
		return fmt.Errorf("failed to delete secret versions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.log.WithFields(map[string]any{
		"secret_id":     secretID,
		"rows_affected": rowsAffected,
	}).Info("Secret versions deleted")

	return nil
}

// DeleteSpecificVersion deletes a specific version of a secret.
func (r *secretVersionRepository) DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int) error {
	query := "DELETE FROM secret_versions WHERE secret_id = ? AND version = ?"

	result, err := r.db.ExecContext(ctx, query, secretID.String(), version)
	if err != nil {
		r.log.WithError(err).Error("Failed to delete secret version")
		return fmt.Errorf("failed to delete secret version: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("version %d not found for secret %s", version, secretID.String())
	}

	r.log.WithFields(map[string]any{
		"secret_id": secretID,
		"version":   version,
	}).Info("Secret version deleted")

	return nil
}
