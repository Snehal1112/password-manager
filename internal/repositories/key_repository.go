// Package repositories provides data access layer implementations.
// This package contains repository implementations that focus solely on
// database operations without business logic, following the SRP principle.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/db"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
)

// KeyRepositoryInterface is a generic repository interface for key operations.
// It provides type-safe CRUD operations for the Key type.
type KeyRepositoryInterface interface {
	db.Repository[domain.Key]
	ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]domain.Key, error)
	UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error
}

// KeyRepository implements KeyRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like encryption or key generation.
// All crypto operations (encryption, key generation) are handled by the service layer.
type KeyRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// executeWithMetrics wraps database operations with performance monitoring.
func (r *KeyRepository) executeWithMetrics(operation string, fn func() error) error {
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
			"table":     "keys",
		}).Warn("Slow database query detected")
	}

	return err
}

// NewKeyRepository creates a new KeyRepository instance.
// It provides pure database operations for key entities.
//
// Parameters:
//   - db: The database connection.
//   - log: The logger for database operation logging.
//
// Returns:
//
//	A KeyRepositoryInterface implementation for key database operations.
func NewKeyRepository(db *sql.DB, log *logging.Logger) KeyRepositoryInterface {
	return &KeyRepository{db: db, log: log}
}

// Create inserts a new key into the database.
// It expects the key value to be already encrypted by the service layer.
// NO encryption or key generation happens here - pure data access only.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - key: The key entity to store (with pre-encrypted value).
//
// Returns:
//
//	An error if the insertion fails.
func (r *KeyRepository) Create(ctx context.Context, key *domain.Key) error {
	return r.executeWithMetrics("create_key", func() error {
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
			"type":    key.Type,
		}).Debug("Inserting key into database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback()

		// Insert key with pre-encrypted value
		_, err = tx.ExecContext(
			ctx,
			"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			key.ID.String(), key.UserID.String(), key.Name, key.Value, key.Type, key.Revoked, key.CreatedAt,
		)
		if err != nil {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to insert key", err)
			return fmt.Errorf("failed to insert key: %w", err)
		}

		// Insert tags if provided
		if len(key.Tags) > 0 {
			tagRepo := db.NewTagRepository[domain.Key](r.db, "key_tags", "key_id")
			if err := tagRepo.AddTags(ctx, key.ID, key.Tags); err != nil {
				r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to add tags", err)
				return fmt.Errorf("failed to add tags: %w", err)
			}
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(key.UserID.String(), "create_key", "success", fmt.Sprintf("Key created: %s", key.Name))
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
			"type":    key.Type,
		}).Debug("Key inserted successfully")

		return nil
	})
}

// Read retrieves a key by ID from the database.
// It returns the key with encrypted value - NO decryption happens here.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	The key entity (with encrypted value) or an error if not found.
func (r *KeyRepository) Read(ctx context.Context, id uuid.UUID) (*domain.Key, error) {
	var key domain.Key
	var idStr, userIDStr string

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, type, revoked, created_at FROM keys WHERE id = ?",
		id.String(),
	).Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("key not found")
	}
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_key", "failed", "Failed to query key", err)
		return nil, fmt.Errorf("failed to query key: %w", err)
	}

	key.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	key.UserID, err = uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	// Retrieve tags using TagRepository
	tagRepo := db.NewTagRepository[domain.Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_key", "failed", "Failed to read tags", err)
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}

	return &key, nil
}

// Update updates a key in the database.
// It expects the key value to be already encrypted if changed.
// NO encryption happens here - pure data access only.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - key: The key entity with updated fields (pre-encrypted value).
//
// Returns:
//
//	An error if the update fails.
func (r *KeyRepository) Update(ctx context.Context, key *domain.Key) error {
	return r.executeWithMetrics("update_key", func() error {
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
		}).Debug("Updating key in database")

		result, err := r.db.ExecContext(
			ctx,
			"UPDATE keys SET name = ?, value = ?, revoked = ?, created_at = ? WHERE id = ?",
			key.Name, key.Value, key.Revoked, key.CreatedAt, key.ID.String(),
		)
		if err != nil {
			r.log.LogAuditError(key.UserID.String(), "update_key", "failed", "Failed to update key", err)
			return fmt.Errorf("failed to update key: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(key.UserID.String(), "update_key", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(key.UserID.String(), "update_key", "failed", "Key not found for update", nil)
			return fmt.Errorf("key not found")
		}

		r.log.LogAuditInfo(key.UserID.String(), "update_key", "success", fmt.Sprintf("Key updated: %s", key.Name))
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
		}).Debug("Key updated successfully")

		return nil
	})
}

// Delete removes a key from the database.
// It removes the key and its associated tags within a transaction.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *KeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("delete_key", func() error {
		logrus.WithField("key_id", id.String()).Debug("Deleting key from database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_key", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback()

		// Delete tags first
		_, err = tx.ExecContext(ctx, "DELETE FROM key_tags WHERE key_id = ?", id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_key", "failed", "Failed to delete tags", err)
			return fmt.Errorf("failed to delete tags: %w", err)
		}

		// Delete key
		result, err := tx.ExecContext(ctx, "DELETE FROM keys WHERE id = ?", id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_key", "failed", "Failed to delete key", err)
			return fmt.Errorf("failed to delete key: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_key", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "delete_key", "failed", "Key not found for deletion", nil)
			return fmt.Errorf("key not found")
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_key", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "delete_key", "success", "Key deleted successfully")
		logrus.WithField("key_id", id.String()).Debug("Key deleted successfully")

		return nil
	})
}

// ListByUser retrieves keys for a user, optionally filtered by type and tags.
// It returns keys with encrypted values - NO decryption happens here.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - userID: The ID of the user whose keys to list (nil for all users).
//   - keyType: The key type to filter by (empty for all types).
//   - tags: The tags to filter by (empty for no tag filter).
//
// Returns:
//
//	A slice of keys (with encrypted values) or an error if retrieval fails.
func (r *KeyRepository) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]domain.Key, error) {
	var keyList []domain.Key

	err := r.executeWithMetrics("list_keys_by_user", func() error {
		var args []interface{}
		query := "SELECT id, user_id, name, value, type, revoked, created_at FROM keys"

		// Build WHERE clauses
		var conditions []string
		if userID != nil {
			conditions = append(conditions, "user_id = ?")
			args = append(args, userID.String())
		}

		if keyType != "" {
			conditions = append(conditions, "type = ?")
			args = append(args, keyType)
		}

		if len(tags) > 0 {
			placeholders := strings.Repeat(",?", len(tags))[1:]
			conditions = append(conditions, fmt.Sprintf("id IN (SELECT key_id FROM key_tags WHERE tag IN (%s))", placeholders))
			for _, tag := range tags {
				args = append(args, tag)
			}
		}

		if len(conditions) > 0 {
			query += " WHERE " + strings.Join(conditions, " AND ")
		}

		query += " ORDER BY created_at DESC"

		rows, err := r.db.QueryContext(ctx, query, args...)
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "list_keys", "failed", "Failed to query keys", err)
			return fmt.Errorf("failed to query keys: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice for better memory performance
		keyList = make([]domain.Key, 0, 50)

		for rows.Next() {
			var key domain.Key
			var idStr, userIDStr string

			if err := rows.Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt); err != nil {
				r.log.LogAuditError(uuid.Nil.String(), "list_keys", "failed", "Failed to scan key", err)
				return fmt.Errorf("failed to scan key: %w", err)
			}

			key.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(uuid.Nil.String(), "list_keys", "failed", "Failed to parse key ID", err)
				return fmt.Errorf("failed to parse key ID: %w", err)
			}

			key.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(uuid.Nil.String(), "list_keys", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			// Retrieve tags for each key
			tagRepo := db.NewTagRepository[domain.Key](r.db, "key_tags", "key_id")
			key.Tags, err = tagRepo.GetTags(ctx, key.ID)
			if err != nil {
				r.log.LogAuditError(uuid.Nil.String(), "list_keys", "failed", "Failed to read tags for key", err)
				return fmt.Errorf("failed to read tags for key: %w", err)
			}

			keyList = append(keyList, key)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithField("count", len(keyList)).Debug("Keys listed successfully")
	return keyList, nil
}

// UpdateRevocationStatus updates only the revocation status of a key.
// This is used for key rotation workflows.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//   - revoked: The new revocation status.
//
// Returns:
//
//	An error if the update fails.
func (r *KeyRepository) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return r.executeWithMetrics("update_key_revocation", func() error {
		result, err := r.db.ExecContext(
			ctx,
			"UPDATE keys SET revoked = ? WHERE id = ?",
			revoked, id.String(),
		)
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "update_key_revocation", "failed", "Failed to update revocation status", err)
			return fmt.Errorf("failed to update revocation status: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "update_key_revocation", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "update_key_revocation", "failed", "Key not found", nil)
			return fmt.Errorf("key not found")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "update_key_revocation", "success", fmt.Sprintf("Key revocation status updated to %v", revoked))
		return nil
	})
}
