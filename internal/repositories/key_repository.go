// Package repositories provides data access layer implementations.
// This package contains repository implementations that focus solely on
// database operations without business logic, following the SRP principle.
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// KeyRepositoryInterface is a generic repository interface for key operations.
// It provides type-safe CRUD operations for the Key type.
type KeyRepositoryInterface interface {
	db.Repository[model.Key]
	ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]model.Key, error)
	UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverKey(ctx context.Context, id uuid.UUID) error
	PurgeKey(ctx context.Context, id uuid.UUID) error
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
	ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error)
	// ReadDeleted retrieves a key by ID regardless of soft-deletion state.
	// Used to return deletion metadata after a soft-delete operation.
	ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error)
	// CreateVersion persists a versioned snapshot of a key's raw material.
	CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error
	// ListVersions returns all version records for a key, ordered by version ASC.
	// userID is used to enforce ownership before returning results.
	ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error)
	// ListInVault lists keys scoped to a vault, optionally filtered by type and tags.
	ListInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error)
	// ReadInVault fetches a key only when id and vaultID both match.
	ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Key, error)
	// SoftDeleteVaultContents soft-deletes every active key in a vault.
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContents recovers only the keys the cascade soft-deleted at deletedAt.
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}

// KeyRepository implements KeyRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like encryption or key generation.
// All crypto operations (encryption, key generation) are handled by the service layer.
type KeyRepository struct {
	db  db.DB
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
func NewKeyRepository(db db.DB, log *logging.Logger) KeyRepositoryInterface {
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
func (r *KeyRepository) Create(ctx context.Context, key *model.Key) error {
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

		// Insert key with pre-encrypted value.
		_, err = tx.ExecContext(
			ctx,
			"INSERT INTO keys (id, user_id, vault_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			key.ID.String(), key.UserID.String(), key.VaultID.String(), key.Name, key.Value, key.Type, key.Revoked, key.CreatedAt,
			key.Enabled, key.ExpiresAt, key.NotBefore, key.Bits, key.Curve,
		)
		if err != nil {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to insert key", err)
			return fmt.Errorf("failed to insert key: %w", err)
		}

		// Insert tags if provided (using existing transaction to avoid locks)
		if len(key.Tags) > 0 {
			for _, tag := range key.Tags {
				_, err := tx.ExecContext(ctx,
					"INSERT INTO key_tags (key_id, tag) VALUES (?, ?)",
					key.ID.String(), tag,
				)
				if err != nil {
					r.log.LogAuditError(key.UserID.String(), "create_key", "failed", fmt.Sprintf("Failed to insert tag %s", tag), err)
					return fmt.Errorf("failed to insert tag %s: %w", tag, err)
				}
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
func (r *KeyRepository) Read(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	var key model.Key
	var idStr, userIDStr string

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at FROM keys WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt,
		&key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
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
	tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_key", "failed", "Failed to read tags", err)
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}

	return &key, nil
}

// ReadDeleted retrieves a key by ID regardless of whether it has been soft-deleted.
// This is used after SoftDelete to return deletion metadata to callers.
// It follows the same scan pattern as Read but omits the "deleted_at IS NULL" filter.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	The key entity (including deleted_at/scheduled_purge_at) or an error if not found.
func (r *KeyRepository) ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	var key model.Key
	var idStr, userIDStr string

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at, deleted_at, scheduled_purge_at FROM keys WHERE id = ?",
		id.String(),
	).Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt,
		&key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt,
		&key.DeletedAt, &key.ScheduledPurgeAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("key not found")
	}
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_deleted_key", "failed", "Failed to query key", err)
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

	// Tags are not strictly needed for deletion metadata but kept for consistency.
	tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_deleted_key", "failed", "Failed to read tags", err)
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
func (r *KeyRepository) Update(ctx context.Context, key *model.Key) error {
	return r.executeWithMetrics("update_key", func() error {
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
		}).Debug("Updating key in database")

		now := time.Now().UTC()
		key.UpdatedAt = &now
		result, err := r.db.ExecContext(
			ctx,
			"UPDATE keys SET name = ?, value = ?, revoked = ?, created_at = ?, enabled = ?, expires_at = ?, not_before = ?, bits = ?, curve = ?, updated_at = ? WHERE id = ?",
			key.Name, key.Value, key.Revoked, key.CreatedAt, key.Enabled, key.ExpiresAt, key.NotBefore, key.Bits, key.Curve, now, key.ID.String(),
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
func (r *KeyRepository) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	var keyList []model.Key

	err := r.executeWithMetrics("list_keys_by_user", func() error {
		var args []interface{}
		query := "SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at FROM keys"

		// Build WHERE clauses — always exclude soft-deleted keys.
		conditions := []string{"deleted_at IS NULL"}
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
		keyList = make([]model.Key, 0, 50)

		for rows.Next() {
			var key model.Key
			var idStr, userIDStr string

			if err := rows.Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt,
				&key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt); err != nil {
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
			tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
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

// SoftDelete marks a key as deleted without removing it from the database.
// The key is excluded from normal reads but remains available for recovery.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *KeyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("soft_delete_key", func() error {
		logrus.WithField("key_id", id.String()).Debug("Soft deleting key from database")

		now := time.Now()
		result, err := r.db.ExecContext(ctx,
			"UPDATE keys SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
			now, id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "soft_delete_key", "failed", "Failed to soft delete key", err)
			return fmt.Errorf("failed to soft delete key: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "soft_delete_key", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "soft_delete_key", "failed", "Key not found or already deleted", nil)
			return fmt.Errorf("key not found or already deleted")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "soft_delete_key", "success", "Key soft deleted successfully")
		logrus.WithField("key_id", id.String()).Debug("Key soft deleted successfully")

		return nil
	})
}

// RecoverKey restores a soft-deleted key by clearing its deleted_at timestamp.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the key is not found in a deleted state or the update fails.
func (r *KeyRepository) RecoverKey(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("recover_key", func() error {
		logrus.WithField("key_id", id.String()).Debug("Recovering soft-deleted key")

		result, err := r.db.ExecContext(ctx,
			"UPDATE keys SET deleted_at = NULL, scheduled_purge_at = NULL WHERE id = ? AND deleted_at IS NOT NULL",
			id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "recover_key", "failed", "Failed to recover key", err)
			return fmt.Errorf("failed to recover key: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "recover_key", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "recover_key", "failed", "Key not found in deleted state", nil)
			return fmt.Errorf("key not found in deleted state")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "recover_key", "success", "Key recovered successfully")
		logrus.WithField("key_id", id.String()).Debug("Key recovered successfully")

		return nil
	})
}

// PurgeKey permanently removes a soft-deleted key from the database.
// It fails if the key has purge protection enabled.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the purge operation fails or purge protection is enabled.
func (r *KeyRepository) PurgeKey(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("purge_key", func() error {
		logrus.WithField("key_id", id.String()).Debug("Purging key from database")

		// Check key status before purging.
		var deletedAt *time.Time
		var purgeProtection bool
		err := r.db.QueryRowContext(ctx,
			"SELECT deleted_at, purge_protection FROM keys WHERE id = ?", id.String()).
			Scan(&deletedAt, &purgeProtection)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Key not found", nil)
				return fmt.Errorf("key not found")
			}
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Failed to check key status", err)
			return fmt.Errorf("failed to check key status: %w", err)
		}

		if deletedAt == nil {
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Key is not soft-deleted", nil)
			return fmt.Errorf("key is not soft-deleted")
		}
		if purgeProtection {
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Key has purge protection enabled", nil)
			return fmt.Errorf("key has purge protection enabled")
		}

		result, err := r.db.ExecContext(ctx, "DELETE FROM keys WHERE id = ?", id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Failed to purge key", err)
			return fmt.Errorf("failed to purge key: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Key not found for purge", nil)
			return fmt.Errorf("key not found for purge")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "purge_key", "success", "Key purged successfully")
		logrus.WithField("key_id", id.String()).Debug("Key purged successfully")

		return nil
	})
}

// SetPurgeProtection enables or disables purge protection on a key.
// A key with purge protection cannot be permanently deleted via PurgeKey.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//   - enabled: True to enable purge protection, false to disable it.
//
// Returns:
//
//	An error if the update fails.
func (r *KeyRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return r.executeWithMetrics("set_purge_protection_key", func() error {
		result, err := r.db.ExecContext(ctx,
			"UPDATE keys SET purge_protection = ? WHERE id = ?",
			enabled, id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "set_purge_protection_key", "failed", "Failed to set purge protection", err)
			return fmt.Errorf("failed to set purge protection: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "set_purge_protection_key", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "set_purge_protection_key", "failed", "Key not found", nil)
			return fmt.Errorf("key not found")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "set_purge_protection_key", "success", fmt.Sprintf("Key purge protection set to %v", enabled))
		return nil
	})
}

// ListSoftDeleted retrieves all soft-deleted keys for a given user.
// Only keys with deleted_at set are returned.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - userID: The user's unique identifier.
//
// Returns:
//
//	A slice of soft-deleted key pointers, or an error if retrieval fails.
func (r *KeyRepository) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error) {
	var keyList []*model.Key

	err := r.executeWithMetrics("list_soft_deleted_keys", func() error {
		logrus.WithField("user_id", userID.String()).Debug("Listing soft-deleted keys for user")

		rows, err := r.db.QueryContext(ctx,
			"SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at, deleted_at, purge_protection FROM keys WHERE user_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC",
			userID.String())
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_soft_deleted_keys", "failed", "Failed to query soft-deleted keys", err)
			return fmt.Errorf("failed to query soft-deleted keys: %w", err)
		}
		defer rows.Close()

		keyList = make([]*model.Key, 0)

		for rows.Next() {
			var key model.Key
			var idStr, userIDStr string
			var deletedAt *time.Time
			var purgeProtection bool

			if err := rows.Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt,
				&key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt,
				&deletedAt, &purgeProtection); err != nil {
				r.log.LogAuditError(userID.String(), "list_soft_deleted_keys", "failed", "Failed to scan key", err)
				return fmt.Errorf("failed to scan key: %w", err)
			}

			key.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_soft_deleted_keys", "failed", "Failed to parse key ID", err)
				return fmt.Errorf("failed to parse key ID: %w", err)
			}

			key.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_soft_deleted_keys", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			key.DeletedAt = deletedAt
			key.PurgeProtection = purgeProtection

			keyList = append(keyList, &key)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id":   userID.String(),
		"key_count": len(keyList),
	}).Debug("Soft-deleted keys listed successfully")

	return keyList, nil
}

// CreateVersion inserts a new version row for a key into the key_versions table.
// value is the encrypted key material for this version.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - keyID: The key's unique identifier.
//   - version: The version number (must be unique per key).
//   - value: The encrypted PEM material for this version.
//
// Returns:
//
//	An error if the insertion fails.
func (r *KeyRepository) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO key_versions (key_id, version, value, created_at) VALUES (?, ?, ?, ?)",
		keyID.String(), version, value, time.Now(),
	)
	return err
}

// ListVersions retrieves all version metadata for a key, enforcing ownership via a JOIN.
// Raw key material (value) is not returned; only version number and timestamp are exposed.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - keyID: The key's unique identifier.
//   - userID: The owner's user ID — rows are filtered by joining against the keys table.
//
// Returns:
//
//	An ordered (ASC) slice of KeyVersion records, or an error if retrieval fails.
func (r *KeyRepository) ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT kv.version, kv.created_at
		FROM key_versions kv
		JOIN keys k ON k.id = kv.key_id
		WHERE kv.key_id = ? AND k.user_id = ?
		ORDER BY kv.version ASC`,
		keyID.String(), userID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query key versions: %w", err)
	}
	defer rows.Close()

	var versions []model.KeyVersion
	for rows.Next() {
		var v model.KeyVersion
		v.KeyID = keyID
		if err := rows.Scan(&v.Version, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key version: %w", err)
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// ListInVault retrieves keys for a vault, optionally filtered by type and tags.
// It mirrors ListByUser but scopes by vault_id instead of user_id.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose keys to list.
//   - keyType: The key type to filter by (empty for all types).
//   - tags: The tags to filter by (empty for no tag filter).
//
// Returns:
//
//	A slice of keys (with encrypted values) or an error if retrieval fails.
func (r *KeyRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	var keyList []model.Key

	err := r.executeWithMetrics("list_keys_by_vault", func() error {
		var args []interface{}
		query := "SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at FROM keys"

		// Build WHERE clauses — always exclude soft-deleted keys and scope by vault.
		conditions := []string{"deleted_at IS NULL", "vault_id = ?"}
		args = append(args, vaultID.String())

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

		query += " WHERE " + strings.Join(conditions, " AND ")
		query += " ORDER BY created_at DESC"

		rows, err := r.db.QueryContext(ctx, query, args...)
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "list_keys", "failed", "Failed to query keys", err)
			return fmt.Errorf("failed to query keys: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice for better memory performance.
		keyList = make([]model.Key, 0, 50)

		for rows.Next() {
			var key model.Key
			var idStr, userIDStr string

			if err := rows.Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt,
				&key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt); err != nil {
				r.log.LogAuditError(vaultID.String(), "list_keys", "failed", "Failed to scan key", err)
				return fmt.Errorf("failed to scan key: %w", err)
			}

			key.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_keys", "failed", "Failed to parse key ID", err)
				return fmt.Errorf("failed to parse key ID: %w", err)
			}

			key.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_keys", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			// Retrieve tags for each key.
			tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
			key.Tags, err = tagRepo.GetTags(ctx, key.ID)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_keys", "failed", "Failed to read tags for key", err)
				return fmt.Errorf("failed to read tags for key: %w", err)
			}

			// Populate VaultID from the queried vault for caller consistency.
			key.VaultID = vaultID

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

// ReadInVault retrieves a key by ID only when it belongs to the given vault.
// It mirrors Read but adds a vault_id scope and the same deleted_at filter.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//   - vaultID: The vault the key must belong to.
//
// Returns:
//
//	The key entity (with encrypted value) or an error if not found / access denied.
func (r *KeyRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Key, error) {
	var key model.Key
	var idStr, userIDStr string

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at FROM keys WHERE id = ? AND vault_id = ? AND deleted_at IS NULL",
		id.String(), vaultID.String(),
	).Scan(&idStr, &userIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt,
		&key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("key not found or access denied")
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

	// Retrieve tags using TagRepository.
	tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_key", "failed", "Failed to read tags", err)
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}

	// Populate VaultID from the queried vault for caller consistency.
	key.VaultID = vaultID

	return &key, nil
}

// SoftDeleteVaultContents marks every active key in a vault as soft-deleted.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose keys should be soft-deleted.
//   - deletedAt: The exact deletion timestamp to stamp on each cascaded row.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *KeyRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("soft_delete_vault_keys", func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all keys in vault")

		_, err := r.db.ExecContext(ctx,
			"UPDATE keys SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
			deletedAt, vaultID.String())
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "soft_delete_vault_keys", "failed", "Failed to soft delete vault keys", err)
			return fmt.Errorf("failed to soft delete vault keys: %w", err)
		}

		r.log.LogAuditInfo(vaultID.String(), "soft_delete_vault_keys", "success", "Vault keys soft deleted successfully")
		return nil
	})
}

// RecoverVaultContents restores every soft-deleted key in a vault.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose keys should be recovered.
//   - deletedAt: The cascade deletion timestamp; only rows stamped with it are restored.
//
// Returns:
//
//	An error if the recovery fails.
func (r *KeyRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("recover_vault_keys", func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted keys in vault")

		_, err := r.db.ExecContext(ctx,
			"UPDATE keys SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
			vaultID.String(), deletedAt)
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "recover_vault_keys", "failed", "Failed to recover vault keys", err)
			return fmt.Errorf("failed to recover vault keys: %w", err)
		}

		r.log.LogAuditInfo(vaultID.String(), "recover_vault_keys", "success", "Vault keys recovered successfully")
		return nil
	})
}
