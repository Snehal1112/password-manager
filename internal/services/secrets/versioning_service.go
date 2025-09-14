package secrets

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/logging"
	"password-manager/internal/secrets"
)

// VersioningService handles secret versioning operations.
// It manages the creation and retrieval of secret versions,
// separating versioning logic from secret storage operations.
type VersioningService interface {
	CreateVersion(ctx context.Context, secretID uuid.UUID, name, value string, version int, userID uuid.UUID) error
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]secrets.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*secrets.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*secrets.SecretVersion, error)
}

// versioningService implements VersioningService for database version operations.
type versioningService struct {
	db     *sql.DB
	logger *logging.Logger
}

// NewVersioningService creates a new VersioningService with the given database connection.
// It provides secret versioning functionality.
//
// Parameters:
//   db: The database connection.
//   logger: The logger for audit and error logging.
//
// Returns:
//   A VersioningService implementation for versioning operations.
func NewVersioningService(db *sql.DB, logger *logging.Logger) VersioningService {
	return &versioningService{
		db:     db,
		logger: logger,
	}
}

// CreateVersion creates a new version of a secret before it is updated.
// It stores the previous state of the secret for version history.
//
// Parameters:
//   ctx: The context for the database operation.
//   secretID: The secret's unique identifier.
//   name: The secret's name at this version.
//   value: The secret's value at this version.
//   version: The version number.
//   userID: The user's unique identifier.
//
// Returns:
//   An error if the operation fails.
func (s *versioningService) CreateVersion(ctx context.Context, secretID uuid.UUID, name, value string, version int, userID uuid.UUID) error {
	versionID := uuid.New()

	_, err := s.db.ExecContext(
		ctx,
		"INSERT INTO secret_versions (id, secret_id, user_id, name, value, version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		versionID.String(), secretID.String(), userID.String(), name, value, version, time.Now(),
	)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "create_version", "failed", "Failed to create secret version", err)
		return fmt.Errorf("failed to create secret version: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "create_version", "success",
		fmt.Sprintf("Created version %d for secret %s", version, secretID.String()))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"user_id":   userID.String(),
		"version":   version,
	}).Debug("Secret version created")

	return nil
}

// GetVersions retrieves all versions of a secret.
//
// Parameters:
//   ctx: The context for the database operation.
//   secretID: The secret's unique identifier.
//
// Returns:
//   A slice of secret versions ordered by version number, or an error if the operation fails.
func (s *versioningService) GetVersions(ctx context.Context, secretID uuid.UUID) ([]secrets.SecretVersion, error) {
	rows, err := s.db.QueryContext(
		ctx,
		"SELECT id, secret_id, user_id, name, value, version, created_at FROM secret_versions WHERE secret_id = ? ORDER BY version ASC",
		secretID.String(),
	)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_versions", "failed", "Failed to query secret versions", err)
		return nil, fmt.Errorf("failed to query secret versions: %w", err)
	}
	defer rows.Close()

	var versions []secrets.SecretVersion
	for rows.Next() {
		var version secrets.SecretVersion
		var idStr, secretIDStr, userIDStr string

		err := rows.Scan(
			&idStr, &secretIDStr, &userIDStr,
			&version.Name, &version.Value, &version.Version, &version.CreatedAt,
		)
		if err != nil {
			s.logger.LogAuditError(secretID.String(), "get_versions", "failed", "Failed to scan secret version", err)
			return nil, fmt.Errorf("failed to scan secret version: %w", err)
		}

		// Parse UUIDs
		version.ID, err = uuid.Parse(idStr)
		if err != nil {
			s.logger.LogAuditError(secretID.String(), "get_versions", "failed", "Failed to parse version ID", err)
			return nil, fmt.Errorf("failed to parse version ID: %w", err)
		}

		version.SecretID, err = uuid.Parse(secretIDStr)
		if err != nil {
			s.logger.LogAuditError(secretID.String(), "get_versions", "failed", "Failed to parse secret ID", err)
			return nil, fmt.Errorf("failed to parse secret ID: %w", err)
		}

		version.UserID, err = uuid.Parse(userIDStr)
		if err != nil {
			s.logger.LogAuditError(secretID.String(), "get_versions", "failed", "Failed to parse user ID", err)
			return nil, fmt.Errorf("failed to parse user ID: %w", err)
		}

		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		s.logger.LogAuditError(secretID.String(), "get_versions", "failed", "Row iteration error", err)
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"secret_id":     secretID.String(),
		"version_count": len(versions),
	}).Debug("Retrieved secret versions")

	return versions, nil
}

// GetVersion retrieves a specific version of a secret.
//
// Parameters:
//   ctx: The context for the database operation.
//   secretID: The secret's unique identifier.
//   version: The version number to retrieve.
//
// Returns:
//   The secret version or an error if not found.
func (s *versioningService) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*secrets.SecretVersion, error) {
	var secretVersion secrets.SecretVersion
	var idStr, secretIDStr, userIDStr string

	err := s.db.QueryRowContext(
		ctx,
		"SELECT id, secret_id, user_id, name, value, version, created_at FROM secret_versions WHERE secret_id = ? AND version = ?",
		secretID.String(), version,
	).Scan(
		&idStr, &secretIDStr, &userIDStr,
		&secretVersion.Name, &secretVersion.Value, &secretVersion.Version, &secretVersion.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret version %d not found", version)
	}
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_version", "failed", "Failed to query secret version", err)
		return nil, fmt.Errorf("failed to query secret version: %w", err)
	}

	// Parse UUIDs
	secretVersion.ID, err = uuid.Parse(idStr)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_version", "failed", "Failed to parse version ID", err)
		return nil, fmt.Errorf("failed to parse version ID: %w", err)
	}

	secretVersion.SecretID, err = uuid.Parse(secretIDStr)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_version", "failed", "Failed to parse secret ID", err)
		return nil, fmt.Errorf("failed to parse secret ID: %w", err)
	}

	secretVersion.UserID, err = uuid.Parse(userIDStr)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_version", "failed", "Failed to parse user ID", err)
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"version":   version,
	}).Debug("Retrieved secret version")

	return &secretVersion, nil
}

// GetLatestVersion retrieves the latest version of a secret.
//
// Parameters:
//   ctx: The context for the database operation.
//   secretID: The secret's unique identifier.
//
// Returns:
//   The latest secret version or an error if not found.
func (s *versioningService) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*secrets.SecretVersion, error) {
	var secretVersion secrets.SecretVersion
	var idStr, secretIDStr, userIDStr string

	err := s.db.QueryRowContext(
		ctx,
		"SELECT id, secret_id, user_id, name, value, version, created_at FROM secret_versions WHERE secret_id = ? ORDER BY version DESC LIMIT 1",
		secretID.String(),
	).Scan(
		&idStr, &secretIDStr, &userIDStr,
		&secretVersion.Name, &secretVersion.Value, &secretVersion.Version, &secretVersion.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no versions found for secret")
	}
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_latest_version", "failed", "Failed to query latest secret version", err)
		return nil, fmt.Errorf("failed to query latest secret version: %w", err)
	}

	// Parse UUIDs
	secretVersion.ID, err = uuid.Parse(idStr)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_latest_version", "failed", "Failed to parse version ID", err)
		return nil, fmt.Errorf("failed to parse version ID: %w", err)
	}

	secretVersion.SecretID, err = uuid.Parse(secretIDStr)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_latest_version", "failed", "Failed to parse secret ID", err)
		return nil, fmt.Errorf("failed to parse secret ID: %w", err)
	}

	secretVersion.UserID, err = uuid.Parse(userIDStr)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_latest_version", "failed", "Failed to parse user ID", err)
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"version":   secretVersion.Version,
	}).Debug("Retrieved latest secret version")

	return &secretVersion, nil
}