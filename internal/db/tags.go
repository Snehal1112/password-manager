// Package db provides tag management operations for the password manager.
package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type TagRepository[T any] interface {
	AddTags(ctx context.Context, id uuid.UUID, tags []string) error
	GetTags(ctx context.Context, id uuid.UUID) ([]string, error)
	// GetTagsForMany retrieves tags for multiple entities in one query,
	// returned as a map from entity ID to its tag list. An ID with no tags
	// simply has no entry. Used by scoped list queries to avoid issuing one
	// GetTags query per row.
	GetTagsForMany(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]string, error)
	ReplaceTags(ctx context.Context, id uuid.UUID, tags []string) error
}

// TagRepository manages tags for a specific entity type.
type tagRepository[T any] struct {
	db       DB
	table    string
	idColumn string
}

// NewTagRepository creates a new TagRepository for the specified entity type.
// It initializes the repository with the provided database connection, table name,
// and ID column name for tag operations.
// Parameters:
// - db: The SQLite database connection.
// - table: The name of the table storing tags (e.g., "key_tags").
// - idColumn: The column name for the entity ID (e.g., "key_id").
// Returns: A pointer to the initialized TagRepository.
func NewTagRepository[T any](db DB, table, idColumn string) *tagRepository[T] {
	return &tagRepository[T]{
		db:       db,
		table:    table,
		idColumn: idColumn,
	}
}

// AddTags adds tags to an entity in the database.
// It inserts the provided tags for the specified entity ID within a transaction.
// If a tag already exists, it is skipped to avoid constraint violations.
// Parameters:
// - ctx: The context for the database operation.
// - id: The ID of the entity to tag.
// - tags: The list of tags to add.
// Returns: An error if the operation fails.
func (r *tagRepository[T]) AddTags(ctx context.Context, id uuid.UUID, tags []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		logrus.Error("Failed to begin transaction for tags: ", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	for _, tag := range tags {
		_, err := tx.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s (%s, tag) VALUES (?, ?)", r.table, r.idColumn),
			id.String(), tag,
		)
		if err != nil {
			// A unique-constraint violation means the tag already exists; skip it.
			// IsConstraintErr handles both SQLite and Postgres error shapes.
			if SQLite.IsConstraintErr(err) {
				logrus.Warnf("Skipping duplicate tag %s for %s %s", tag, r.idColumn, id.String())
				continue
			}
			logrus.Error("Failed to insert tag: ", err)
			return fmt.Errorf("failed to insert tag %s: %w", tag, err)
		}
		logrus.Debugf("Inserted tag %s for %s %s", tag, r.idColumn, id.String())
	}

	if err := tx.Commit(); err != nil {
		logrus.Error("Failed to commit transaction for tags: ", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// GetTags retrieves all tags for an entity from the database.
// It queries the tags associated with the specified entity ID.
// Parameters:
// - ctx: The context for the database operation.
// - id: The ID of the entity to retrieve tags for.
// Returns: A slice of tags and an error if the operation fails.
func (r *tagRepository[T]) GetTags(ctx context.Context, id uuid.UUID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		fmt.Sprintf("SELECT tag FROM %s WHERE %s = ?", r.table, r.idColumn),
		id.String(),
	)
	if err != nil {
		logrus.Error("Failed to query tags: ", err)
		return nil, fmt.Errorf("failed to query tags: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			logrus.Error("Failed to scan tag: ", err)
			return nil, fmt.Errorf("failed to scan tag: %w", err)
		}
		tags = append(tags, tag)
	}

	return tags, nil
}

// GetTagsForMany retrieves tags for multiple entities in one query. Returns
// an empty map for an empty ids slice without querying.
func (r *tagRepository[T]) GetTagsForMany(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]string, error) {
	result := make(map[uuid.UUID][]string, len(ids))
	if len(ids) == 0 {
		return result, nil
	}

	placeholders := strings.Repeat(",?", len(ids))[1:]
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id.String()
	}

	rows, err := r.db.QueryContext(ctx,
		fmt.Sprintf("SELECT %s, tag FROM %s WHERE %s IN (%s)", r.idColumn, r.table, r.idColumn, placeholders),
		args...,
	)
	if err != nil {
		logrus.Error("Failed to query tags: ", err)
		return nil, fmt.Errorf("failed to query tags: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var idStr, tag string
		if err := rows.Scan(&idStr, &tag); err != nil {
			logrus.Error("Failed to scan tag: ", err)
			return nil, fmt.Errorf("failed to scan tag: %w", err)
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tag owner id: %w", err)
		}
		result[id] = append(result[id], tag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}
	return result, nil
}

// ReplaceTags replaces all tags for an entity in the database.
// It first deletes existing tags for the specified entity ID and then adds the new tags.
// Parameters:
// - ctx: The context for the database operation.
// - id: The ID of the entity to update tags for.
// - tags: The new list of tags to set for the entity.
func (r *tagRepository[T]) ReplaceTags(ctx context.Context, id uuid.UUID, tags []string) error {
	// Ensure unique tags
	uniqueTags := make(map[string]struct{})
	var dedupedTags []string
	for _, tag := range tags {
		if tag == "" {
			continue // Skip empty tags
		}
		if _, exists := uniqueTags[tag]; !exists {
			uniqueTags[tag] = struct{}{}
			dedupedTags = append(dedupedTags, tag)
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		logrus.Error("Failed to begin transaction: ", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Delete existing tags
	_, err = tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s = ?", r.table, r.idColumn), id.String())
	if err != nil {
		logrus.Error("Failed to delete tags: ", err)
		return fmt.Errorf("failed to delete tags: %w", err)
	}

	// Insert new tags (if any)
	for _, tag := range dedupedTags {
		_, err = tx.ExecContext(ctx, fmt.Sprintf("INSERT INTO %s (%s, tag) VALUES (?, ?)", r.table, r.idColumn), id.String(), tag)
		if err != nil {
			logrus.Error("Failed to insert tag: ", err)
			return fmt.Errorf("failed to insert tag %s: %w", tag, err)
		}
	}

	if err := tx.Commit(); err != nil {
		logrus.Error("Failed to commit transaction: ", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"id":    id,
		"tags":  dedupedTags,
		"table": r.table,
	}).Debug("Tags replaced successfully")
	return nil
}
