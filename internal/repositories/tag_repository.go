// Package repositories provides data access interfaces and implementations.
package repositories

import (
	"context"
	"fmt"
	"strings"

	"rocketvault/internal/db"

	"github.com/google/uuid"
)

// SecretTagRepositoryInterface defines data access for secret tag operations.
// It provides a pure repository layer that the TagService can depend on.
type SecretTagRepositoryInterface interface {
	AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error
	RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error
	RemoveAllTags(ctx context.Context, secretID uuid.UUID) error
	GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error)
	FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error)
}

// secretTagRepository implements SecretTagRepositoryInterface with direct SQL.
type secretTagRepository struct {
	db db.DB
}

// NewSecretTagRepository creates a SecretTagRepository backed by the given connection.
func NewSecretTagRepository(db db.DB) SecretTagRepositoryInterface {
	return &secretTagRepository{db: db}
}

// AddTags inserts new tag associations for a secret, ignoring duplicates.
func (r *secretTagRepository) AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	query := r.db.Dialect().UpsertIgnore(
		"secret_tags", "secret_id, tag", "?, ?", "secret_id, tag",
	)
	for _, tag := range tags {
		_, err := r.db.ExecContext(ctx, query, secretID.String(), tag)
		if err != nil {
			return fmt.Errorf("add tag %s: %w", tag, err)
		}
	}
	return nil
}

// RemoveTags deletes specific tag associations for a secret.
func (r *secretTagRepository) RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	for _, tag := range tags {
		_, err := r.db.ExecContext(
			ctx,
			"DELETE FROM secret_tags WHERE secret_id = ? AND tag = ?",
			secretID.String(), tag,
		)
		if err != nil {
			return fmt.Errorf("remove tag %s: %w", tag, err)
		}
	}
	return nil
}

// RemoveAllTags deletes all tag associations for a secret.
func (r *secretTagRepository) RemoveAllTags(ctx context.Context, secretID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM secret_tags WHERE secret_id = ?", secretID.String())
	if err != nil {
		return fmt.Errorf("remove all tags: %w", err)
	}
	return nil
}

// GetTags returns all tags associated with a secret.
func (r *secretTagRepository) GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT tag FROM secret_tags WHERE secret_id = ?", secretID.String())
	if err != nil {
		return nil, fmt.Errorf("query tags: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, fmt.Errorf("scan tag: %w", err)
		}
		tags = append(tags, tag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration: %w", err)
	}
	return tags, nil
}

// FindSecretsByTags returns IDs of secrets owned by userID that have any of the given tags.
func (r *secretTagRepository) FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error) {
	if len(tags) == 0 {
		return []uuid.UUID{}, nil
	}

	args := make([]any, 0, len(tags)+1)
	args = append(args, userID.String())
	ph := make([]string, len(tags))
	for i, tag := range tags {
		ph[i] = "?"
		args = append(args, tag)
	}
	placeholders := strings.Join(ph, ", ")

	query := fmt.Sprintf(`
		SELECT DISTINCT s.id
		FROM secrets s
		INNER JOIN secret_tags st ON s.id = st.secret_id
		WHERE s.user_id = ? AND st.tag IN (%s)
	`, placeholders)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("find secrets by tags: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var secretIDs []uuid.UUID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("scan secret id: %w", err)
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("parse secret id: %w", err)
		}
		secretIDs = append(secretIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration: %w", err)
	}
	return secretIDs, nil
}
