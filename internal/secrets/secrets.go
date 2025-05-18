// Package secrets manages secret storage and operations for the password manager.
// It provides CRUD operations, AES encryption, versioning, and tagging for secrets,
// using Go Generics for type-safe database interactions.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"password-manager/internal/db"
	"password-manager/internal/logging"
)

// Secret represents a secret in the password manager.
// It includes the secret’s ID, user ID, name, encrypted value, version, tags, and creation time.
type Secret struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Name      string
	Value     string
	Version   int
	Tags      []string
	CreatedAt time.Time
}

// SecretRepository is a generic repository interface for secret operations.
// It provides type-safe CRUD operations for the Secret type.
type SecretRepository interface {
	db.Repository[Secret]
	ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]Secret, error)
}

// secretRepository implements SecretRepository for database operations on secrets.
type secretRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewSecretRepository creates a new SecretRepository with the given database connection.
// It initializes the repository for secret-related database operations.
//
// Parameters:
//
//	db: The database connection.
//
// Returns:
//
//	A SecretRepository for secret operations.
func NewSecretRepository(db *sql.DB, log *logging.Logger) SecretRepository {
	return &secretRepository{db: db, log: log}
}

// Create inserts a new secret into the database.
// It encrypts the secret value and stores it with the specified user ID, name, version, and tags.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secret: The secret to create.
//
// Returns:
//
//	An error if the insertion fails.
func (r *secretRepository) Create(ctx context.Context, secret Secret) error {
	// Encrypt the secret value.
	encryptedValue, err := EncryptSecret(secret.Value)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "create_secret", "failed", "Failed to encrypt secret", err)
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Insert the secret into the database.
	_, err = r.db.ExecContext(
		ctx,
		"INSERT INTO secrets (id, user_id, name, value, version, created_at) VALUES (?,?, ?, ?, ?, ?)",
		secret.ID.String(), secret.UserID.String(), secret.Name, encryptedValue, secret.Version, secret.CreatedAt,
	)

	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "create_secret", "failed", "Failed to create secret", err)
		return fmt.Errorf("failed to create secret: %w", err)
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

	r.log.LogAuditInfo(secret.UserID.String(), "create_secret", "success", "Secret created successfully")
	return nil
}

// Read retrieves a secret by ID from the database.
// It decrypts the secret value and includes associated tags.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret’s ID.
//
// Returns:
//
//	The secret and an error if the retrieval fails.
func (r *secretRepository) Read(ctx context.Context, id uuid.UUID) (Secret, error) {
	var secret Secret
	var encryptedValue string
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, version, created_at FROM secrets WHERE id = ?",
		id,
	).Scan(&secret.ID, &secret.UserID, &secret.Name, &encryptedValue, &secret.Version, &secret.CreatedAt)
	if err == sql.ErrNoRows {
		r.log.LogAuditError(secret.UserID.String(), "get_secret", "failed", "Secret not found", err)
		return secret, fmt.Errorf("secret not found")
	}
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "get_secret", "failed", "Failed to query secret", err)
		return secret, fmt.Errorf("failed to query secret: %w", err)
	}

	// Decrypt the secret value.
	secret.Value, err = DecryptSecret(encryptedValue)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "get_secret", "failed", "Failed to decrypt secret", err)
		return secret, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Retrieve tags.
	rows, err := r.db.QueryContext(ctx, "SELECT tag FROM secret_tags WHERE secret_id = ?", id)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "get_secret", "failed", "Failed to query tags", err)
		return secret, fmt.Errorf("failed to query tags: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			r.log.LogAuditError(secret.UserID.String(), "get_secret", "failed", "Failed to scan tag", err)
			return secret, fmt.Errorf("failed to scan tag: %w", err)
		}
		secret.Tags = append(secret.Tags, tag)
	}

	return secret, nil
}

// Update updates a secret in the database.
// It creates a new version of the secret with the updated value and tags.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secret: The secret to update.
//
// Returns:
//
//	An error if the update fails.
func (r *secretRepository) Update(ctx context.Context, secret Secret) error {
	// Encrypt the updated secret value.
	encryptedValue, err := EncryptSecret(secret.Value)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to encrypt secret", err)
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Insert a new version of the secret.
	_, err = r.db.ExecContext(
		ctx,
		"INSERT INTO secrets (id, user_id, name, value, version, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		secret.ID.String(), secret.UserID.String(), secret.Name, encryptedValue, secret.Version, secret.CreatedAt,
	)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	// Delete existing tags.
	_, err = r.db.ExecContext(ctx, "DELETE FROM secret_tags WHERE secret_id = ?", secret.ID.String())
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to delete existing tags", err)
		return fmt.Errorf("failed to delete existing tags: %w", err)
	}

	// Insert updated tags.
	for _, tag := range secret.Tags {
		_, err = r.db.ExecContext(
			ctx,
			"INSERT INTO secret_tags (secret_id, tag) VALUES (?, ?)",
			secret.ID.String(), tag,
		)
		if err != nil {
			r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to insert tag", err)
			return fmt.Errorf("failed to insert tag: %w", err)
		}
	}

	r.log.LogAuditInfo(secret.UserID.String(), "update_secret", "success", "Secret updated successfully")
	return nil
}

// Delete deletes a secret by ID from the database.
// It also removes associated tags.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret’s ID.
//
// Returns:
//
//	An error if the deletion fails.
func (r *secretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	// Delete associated tags first.
	_, err := r.db.ExecContext(ctx, "DELETE FROM secret_tags WHERE secret_id = ?", id.String())
	if err != nil {
		r.log.LogAuditError("", "delete_secret", "failed", "Failed to delete tags", err)
		return fmt.Errorf("failed to delete tags: %w", err)
	}

	// Delete the secret.
	_, err = r.db.ExecContext(ctx, "DELETE FROM secrets WHERE id = ?", id.String())
	if err != nil {
		r.log.LogAuditError("", "delete_secret", "failed", "Failed to delete secret", err)
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	r.log.LogAuditInfo("", "delete_secret", "success", "Secret deleted successfully")
	logrus.WithFields(logrus.Fields{
		"secret_id": id.String(),
	}).Info("Secret deleted successfully")
	return nil
}

// ListByUser retrieves all secrets for a user, optionally filtered by tags.
// It decrypts secret values and includes associated tags.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//	tags: Optional tags to filter secrets.
//
// Returns:
//
//	A list of secrets and an error if the retrieval fails.
func (r *secretRepository) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]Secret, error) {
	var secrets []Secret
	query := "SELECT id, user_id, name, value, version, created_at FROM secrets WHERE user_id = ?"
	args := []interface{}{userID.String()}

	if len(tags) > 0 {
		query += " AND id IN (SELECT secret_id FROM secret_tags WHERE tag IN (?" + strings.Repeat(",?", len(tags)-1) + "))"
		for _, tag := range tags {
			args = append(args, tag)
		}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to query secrets", err)
		return nil, fmt.Errorf("failed to query secrets: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var secret Secret
		var encryptedValue string

		if err := rows.Scan(&secret.ID, &secret.UserID, &secret.Name, &encryptedValue, &secret.Version, &secret.CreatedAt); err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to scan secret", err)
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		// Decrypt the secret value.
		secret.Value, err = DecryptSecret(encryptedValue)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to decrypt secret", err)
			return nil, fmt.Errorf("failed to decrypt secret: %w", err)
		}

		// Retrieve tags.
		tagRows, err := r.db.QueryContext(ctx, "SELECT tag FROM secret_tags WHERE secret_id = ?", secret.ID.String())
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to query tags", err)
			r.log.LogAuditError(userID.String(), "list_secrets", "failed", fmt.Sprintf("Failed to query tags: %v, context error: %v", err, ctx.Err()), err)
			return nil, fmt.Errorf("failed to query tags: %w", err)
		}

		for tagRows.Next() {
			var tag string
			if err := tagRows.Scan(&tag); err != nil {
				r.log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to scan tag", err)
				return nil, fmt.Errorf("failed to scan tag: %w", err)
			}
			secret.Tags = append(secret.Tags, tag)
		}
		tagRows.Close()

		secrets = append(secrets, secret)
	}

	r.log.LogAuditInfo(userID.String(), "list_secrets", "success", "Secrets listed successfully")
	logrus.WithFields(logrus.Fields{
		"user_id": userID.String(),
		"count":   len(secrets),
	}).Info("Secrets listed successfully")
	return secrets, nil
}

// encryptSecret encrypts a secret value using AES-256-GCM.
// It uses the master key from configuration for encryption.
//
// Parameters:
//
//	value: The plaintext secret value.
//
// Returns:
//
//	The encrypted value (base64-encoded) and an error if encryption fails.
func EncryptSecret(value string) (string, error) {
	masterKey := viper.GetString("master_key")
	if masterKey == "" {
		return "", fmt.Errorf("master key not configured")
	}

	key, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode master key: %w", err)
	}
	if len(key) < 32 {
		return "", fmt.Errorf("master key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptSecret decrypts a secret value encrypted with AES-256-GCM.
// It uses the master key from configuration for decryption.
//
// Parameters:
//
//	encryptedValue: The encrypted value (base64-encoded).
//
// Returns:
//
//	The decrypted plaintext value and an error if decryption fails.
func DecryptSecret(encryptedValue string) (string, error) {
	masterKey := viper.GetString("master_key")
	if masterKey == "" {
		return "", fmt.Errorf("master key not configured")
	}

	key, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode master key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("master key must be 32 bytes")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted value: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
