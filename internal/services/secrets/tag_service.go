package secrets

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/logging"
)

// TagService handles tag management operations for secrets.
// It provides functionality to add, remove, and query tags
// while maintaining separation from secret storage concerns.
type TagService interface {
	AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error
	RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error
	RemoveAllTags(ctx context.Context, secretID uuid.UUID) error
	GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error)
	FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error)
}

// tagService implements TagService for database tag operations.
type tagService struct {
	db     *sql.DB
	logger *logging.Logger
}

// NewTagService creates a new TagService with the given database connection.
// It provides tag management functionality for secrets.
//
// Parameters:
//
//	db: The database connection.
//	logger: The logger for audit and error logging.
//
// Returns:
//
//	A TagService implementation for tag operations.
func NewTagService(db *sql.DB, logger *logging.Logger) TagService {
	return &tagService{
		db:     db,
		logger: logger,
	}
}

// AddTags adds the specified tags to a secret.
// It inserts new tag associations while avoiding duplicates.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//	tags: The tags to add to the secret.
//
// Returns:
//
//	An error if the operation fails.
func (s *tagService) AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	if len(tags) == 0 {
		return nil
	}

	for _, tag := range tags {
		_, err := s.db.ExecContext(
			ctx,
			"INSERT OR IGNORE INTO secret_tags (secret_id, tag) VALUES (?, ?)",
			secretID.String(), tag,
		)
		if err != nil {
			s.logger.LogAuditError(secretID.String(), "add_tags", "failed", "Failed to add tag", err)
			return fmt.Errorf("failed to add tag %s: %w", tag, err)
		}
	}

	s.logger.LogAuditInfo(secretID.String(), "add_tags", "success",
		fmt.Sprintf("Added %d tags to secret", len(tags)))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"tag_count": len(tags),
	}).Debug("Tags added to secret")

	return nil
}

// RemoveTags removes the specified tags from a secret.
// It deletes the tag associations from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//	tags: The tags to remove from the secret.
//
// Returns:
//
//	An error if the operation fails.
func (s *tagService) RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	if len(tags) == 0 {
		return nil
	}

	for _, tag := range tags {
		_, err := s.db.ExecContext(
			ctx,
			"DELETE FROM secret_tags WHERE secret_id = ? AND tag = ?",
			secretID.String(), tag,
		)
		if err != nil {
			s.logger.LogAuditError(secretID.String(), "remove_tags", "failed", "Failed to remove tag", err)
			return fmt.Errorf("failed to remove tag %s: %w", tag, err)
		}
	}

	s.logger.LogAuditInfo(secretID.String(), "remove_tags", "success",
		fmt.Sprintf("Removed %d tags from secret", len(tags)))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"tag_count": len(tags),
	}).Debug("Tags removed from secret")

	return nil
}

// RemoveAllTags removes all tags from a secret.
// It deletes all tag associations for the specified secret.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//
// Returns:
//
//	An error if the operation fails.
func (s *tagService) RemoveAllTags(ctx context.Context, secretID uuid.UUID) error {
	result, err := s.db.ExecContext(
		ctx,
		"DELETE FROM secret_tags WHERE secret_id = ?",
		secretID.String(),
	)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "remove_all_tags", "failed", "Failed to remove all tags", err)
		return fmt.Errorf("failed to remove all tags: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "remove_all_tags", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	s.logger.LogAuditInfo(secretID.String(), "remove_all_tags", "success",
		fmt.Sprintf("Removed %d tags from secret", rowsAffected))
	logrus.WithFields(logrus.Fields{
		"secret_id":    secretID.String(),
		"tags_removed": rowsAffected,
	}).Debug("All tags removed from secret")

	return nil
}

// GetTags retrieves all tags associated with a secret.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//
// Returns:
//
//	A slice of tags associated with the secret, or an error if the operation fails.
func (s *tagService) GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT tag FROM secret_tags WHERE secret_id = ?", secretID.String())
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_tags", "failed", "Failed to query tags", err)
		return nil, fmt.Errorf("failed to query tags: %w", err)
	}
	defer rows.Close()

	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			s.logger.LogAuditError(secretID.String(), "get_tags", "failed", "Failed to scan tag", err)
			return nil, fmt.Errorf("failed to scan tag: %w", err)
		}
		tags = append(tags, tag)
	}

	if err := rows.Err(); err != nil {
		s.logger.LogAuditError(secretID.String(), "get_tags", "failed", "Row iteration error", err)
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return tags, nil
}

// FindSecretsByTags finds all secrets for a user that have any of the specified tags.
// It performs a query to find secrets matching the tag criteria.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user's unique identifier.
//	tags: The tags to search for.
//
// Returns:
//
//	A slice of secret IDs that have any of the specified tags, or an error if the operation fails.
func (s *tagService) FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error) {
	if len(tags) == 0 {
		return []uuid.UUID{}, nil
	}

	// Build query for tag matching
	placeholders := make([]interface{}, 0, len(tags)+1)
	placeholders = append(placeholders, userID.String())

	tagPlaceholders := ""
	for i, tag := range tags {
		if i > 0 {
			tagPlaceholders += ", "
		}
		tagPlaceholders += "?"
		placeholders = append(placeholders, tag)
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT s.id
		FROM secrets s
		INNER JOIN secret_tags st ON s.id = st.secret_id
		WHERE s.user_id = ? AND st.tag IN (%s)
	`, tagPlaceholders)

	rows, err := s.db.QueryContext(ctx, query, placeholders...)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "find_secrets_by_tags", "failed", "Failed to query secrets by tags", err)
		return nil, fmt.Errorf("failed to query secrets by tags: %w", err)
	}
	defer rows.Close()

	var secretIDs []uuid.UUID
	for rows.Next() {
		var secretIDStr string
		if err := rows.Scan(&secretIDStr); err != nil {
			s.logger.LogAuditError(userID.String(), "find_secrets_by_tags", "failed", "Failed to scan secret ID", err)
			return nil, fmt.Errorf("failed to scan secret ID: %w", err)
		}

		secretID, err := uuid.Parse(secretIDStr)
		if err != nil {
			s.logger.LogAuditError(userID.String(), "find_secrets_by_tags", "failed", "Failed to parse secret ID", err)
			return nil, fmt.Errorf("failed to parse secret ID: %w", err)
		}

		secretIDs = append(secretIDs, secretID)
	}

	if err := rows.Err(); err != nil {
		s.logger.LogAuditError(userID.String(), "find_secrets_by_tags", "failed", "Row iteration error", err)
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"user_id":       userID.String(),
		"tags":          tags,
		"secrets_found": len(secretIDs),
	}).Debug("Found secrets by tags")

	return secretIDs, nil
}
