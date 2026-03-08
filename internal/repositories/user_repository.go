// Package repositories provides data access layer implementations.
// This package contains repository implementations that focus solely on
// database operations without business logic, following the SRP principle.
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
)

// UserRepositoryInterface is a generic repository interface for user operations.
// It provides type-safe CRUD operations for the User type.
type UserRepositoryInterface interface {
	db.Repository[domain.User]
	ReadByUsername(ctx context.Context, username string) (domain.User, error)
	List(ctx context.Context) ([]domain.User, error)
	ValidateBootstrapToken(ctx context.Context, token string) (bool, error)
	InvalidateBootstrapToken(ctx context.Context, token string) error
}

// UserRepository implements UserRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic with performance monitoring.
type UserRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// executeWithMetrics wraps database operations with performance monitoring.
func (r *UserRepository) executeWithMetrics(operation string, fn func() error) error {
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

// queryWithMetrics wraps query operations with performance monitoring.
func (r *UserRepository) queryWithMetrics(operation string, fn func() error) error {
	return r.executeWithMetrics(operation, fn)
}

// NewUserRepository creates a new UserRepository instance.
// It provides pure database operations for user entities.
//
// Parameters:
//
//	db: The database connection.
//	log: The logger for database operation logging.
//
// Returns:
//
//	A UserRepository implementation for user database operations.
func NewUserRepository(db *sql.DB, log *logging.Logger) UserRepositoryInterface {
	return &UserRepository{db: db, log: log}
}

// Create inserts a new user into the database.
// It expects all user fields to be properly prepared (password hashed, TOTP secret generated).
//
// Parameters:
//
//	ctx: The context for the database operation.
//	user: The user entity to store (with pre-processed fields).
//
// Returns:
//
//	An error if the insertion fails.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"role":     user.Role,
		"user_id":  user.ID.String(),
	}).Debug("Inserting user into database")

	// Check if username already exists
	var existingUserID string
	err := r.db.QueryRowContext(ctx, "SELECT id FROM users WHERE username = ?", user.Username).Scan(&existingUserID)
	if err == nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Username already exists", nil)
		return fmt.Errorf("username already exists")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to check existing username", err)
		return fmt.Errorf("failed to check existing username: %w", err)
	}

	// Insert user record
	_, err = r.db.ExecContext(
		ctx,
		"INSERT INTO users (id, username, password_hash, totp_secret, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		user.ID.String(), user.Username, user.PasswordHash, user.TOTPSecret, user.Role, user.CreatedAt,
	)
	if err != nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to insert user", err)
		return fmt.Errorf("failed to insert user: %w", err)
	}

	r.log.LogAuditInfo(user.ID.String(), "create_user", "success", fmt.Sprintf("User inserted: %s", user.Username))
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"user_id":  user.ID.String(),
		"role":     user.Role,
	}).Debug("User inserted successfully")

	return nil
}

// Read retrieves a user by ID from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The user's unique identifier.
//
// Returns:
//
//	The user entity or an error if not found.
func (r *UserRepository) Read(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	var user domain.User
	var idStr string

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, created_at FROM users WHERE id = ?",
		id.String(),
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.Role, &user.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	return &user, nil
}

// Update updates a user in the database.
// It expects all fields to be properly prepared (password hashed if changed).
//
// Parameters:
//
//	ctx: The context for the database operation.
//	user: The user entity with updated fields.
//
// Returns:
//
//	An error if the update fails.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	logrus.WithFields(logrus.Fields{
		"user_id":  user.ID.String(),
		"username": user.Username,
	}).Debug("Updating user in database")

	result, err := r.db.ExecContext(
		ctx,
		"UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?",
		user.Username, user.PasswordHash, user.Role, user.ID.String(),
	)
	if err != nil {
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "Failed to update user", err)
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "User not found for update", nil)
		return fmt.Errorf("user not found")
	}

	r.log.LogAuditInfo(user.ID.String(), "update_user", "success", fmt.Sprintf("User updated: %s", user.Username))
	logrus.WithFields(logrus.Fields{
		"user_id":  user.ID.String(),
		"username": user.Username,
	}).Debug("User updated successfully")

	return nil
}

// Delete removes a user and all associated data from the database.
// It handles cascading deletion to maintain referential integrity with optimized batch operations.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The user's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("delete_user", func() error {
		logrus.WithField("user_id", id.String()).Debug("Deleting user from database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback()

		// Optimized cascading deletion using ON DELETE CASCADE constraints
		// The foreign key constraints with ON DELETE CASCADE will handle most cleanup automatically

		// Delete the user - cascading will handle related data
		result, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id.String())
		if err != nil {
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to delete user", err)
			return fmt.Errorf("failed to delete user: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(id.String(), "delete_user", "failed", "User not found for deletion", nil)
			return fmt.Errorf("user not found")
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(id.String(), "delete_user", "success", "User and associated data deleted successfully")
		logrus.WithField("user_id", id.String()).Debug("User deleted successfully")

		return nil
	})
}

// ReadByUsername retrieves a user by username from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	username: The user's username.
//
// Returns:
//
//	The user entity or an error if not found.
func (r *UserRepository) ReadByUsername(ctx context.Context, username string) (domain.User, error) {
	var user domain.User
	var idStr string

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, created_at FROM users WHERE username = ?",
		username,
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.Role, &user.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return user, fmt.Errorf("user not found")
	}
	if err != nil {
		logrus.WithError(err).Error("Failed to query user by username")
		return user, fmt.Errorf("failed to query user by username: %w", err)
	}

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse user ID")
		return user, fmt.Errorf("failed to parse user ID: %w", err)
	}

	return user, nil
}

// Login is deprecated and should not be used.
// Authentication logic has been moved to AuthenticationService.
func (r *UserRepository) Login(ctx context.Context, username, password, totpCode string) (string, error) {
	return "", fmt.Errorf("login method is deprecated, use AuthenticationService instead")
}

// List retrieves all users from the database with optimized query and monitoring.
//
// Parameters:
//
//	ctx: The context for the database operation.
//
// Returns:
//
//	A slice of all users or an error if retrieval fails.
func (r *UserRepository) List(ctx context.Context) ([]domain.User, error) {
	var users []domain.User

	err := r.queryWithMetrics("list_users", func() error {
		// Optimized query with explicit column selection and ordering for better performance
		rows, err := r.db.QueryContext(ctx,
			"SELECT id, username, password_hash, totp_secret, role, created_at FROM users ORDER BY created_at DESC")
		if err != nil {
			logrus.WithError(err).Error("Failed to list users")
			return fmt.Errorf("failed to list users: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice for better memory performance
		users = make([]domain.User, 0, 100) // Assume max 100 users initially

		for rows.Next() {
			var user domain.User
			var idStr string

			if err := rows.Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.Role, &user.CreatedAt); err != nil {
				logrus.WithError(err).Error("Failed to scan user")
				return fmt.Errorf("failed to scan user: %w", err)
			}

			user.ID, err = uuid.Parse(idStr)
			if err != nil {
				logrus.WithError(err).Error("Failed to parse user ID")
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			users = append(users, user)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithField("count", len(users)).Debug("Users listed successfully")
	return users, nil
}

// ValidateBootstrapToken checks if the provided bootstrap token is valid.
// This is a simple implementation and should be replaced with secure token storage.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	token: The bootstrap token to validate.
//
// Returns:
//
//	True if valid, false otherwise, and an error if the operation fails.
func (r *UserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	// Check if users table is empty (bootstrap condition)
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Failed to query user count", err)
		return false, fmt.Errorf("failed to query user count: %w", err)
	}

	// Bootstrap only allowed if no users exist
	if count > 0 {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Bootstrap not allowed: users exist", nil)
		return false, nil
	}

	// Check token in bootstrap_tokens table
	var used bool
	err = r.db.QueryRowContext(ctx, "SELECT used FROM bootstrap_tokens WHERE token = ?", token).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Bootstrap token not found", nil)
		return false, nil
	}
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Failed to query bootstrap token", err)
		return false, fmt.Errorf("failed to query bootstrap token: %w", err)
	}

	if used {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Bootstrap token already used", nil)
		return false, nil
	}

	return true, nil
}

// InvalidateBootstrapToken marks a bootstrap token as used.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	token: The bootstrap token to invalidate.
//
// Returns:
//
//	An error if the operation fails.
func (r *UserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	// Try to update existing token
	result, err := r.db.ExecContext(ctx, "UPDATE bootstrap_tokens SET used = TRUE WHERE token = ?", token)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "invalidate_bootstrap_token", "failed", "Failed to update bootstrap token", err)
		return fmt.Errorf("failed to update bootstrap token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "invalidate_bootstrap_token", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows affected, insert the token as used
	if rowsAffected == 0 {
		_, err = r.db.ExecContext(ctx, "INSERT INTO bootstrap_tokens (token, used) VALUES (?, TRUE)", token)
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "invalidate_bootstrap_token", "failed", "Failed to insert bootstrap token", err)
			return fmt.Errorf("failed to insert bootstrap token: %w", err)
		}
	}

	r.log.LogAuditInfo(uuid.Nil.String(), "invalidate_bootstrap_token", "success", "Bootstrap token invalidated")
	return nil
}
