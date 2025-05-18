// Package keys manages cryptographic key storage and operations for the password manager.
// It supports RSA and ECDSA key generation, storage, rotation, and HSM integration.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/db"
	"password-manager/internal/logging"
	"password-manager/internal/secrets"
)

// Key represents a cryptographic key in the password manager.
type Key struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Name      string
	Type      string // "RSA" or "ECDSA"
	Value     string // Encrypted PEM-encoded private key
	Revoked   bool
	CreatedAt time.Time
	Tags      []string
}

// KeyRepository is a repository interface for key operations.
// It provides CRUD operations and key-specific methods for the Key type.
type KeyRepository interface {
	db.Repository[Key]
	GenerateRSA(ctx context.Context, userID uuid.UUID, name string, bits int, tags []string) (*Key, error)
	GenerateECDSA(ctx context.Context, userID uuid.UUID, name string, curve string, tags []string) (*Key, error)
	Rotate(ctx context.Context, id uuid.UUID) (*Key, error)
	ListByUser(ctx context.Context, userID uuid.UUID, keyType string, tags []string) ([]Key, error)
}

// keyRepository implements KeyRepository for database operations on keys.
type keyRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewKeyRepository creates a new KeyRepository with the given database connection.
// It initializes the repository for key-related database operations.
// Parameters:
// - db: The SQLite database connection.
// - log: The logger for audit and error logging.
// Returns: A KeyRepository implementation.
func NewKeyRepository(db *sql.DB, log *logging.Logger) KeyRepository {
	return &keyRepository{db: db, log: log}
}

// Create inserts a new key into the database.
// It encrypts the key value and stores it with the specified user ID, name, type,
// revocation status, and tags within a transaction.
// Parameters:
// - ctx: The context for the database operation.
// - key: The key to create.
// Returns: An error if the operation fails.
func (r *keyRepository) Create(ctx context.Context, key Key) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		logrus.Error("Failed to begin transaction: ", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Encrypt the key value.
	encryptedValue, err := secrets.EncryptSecret(key.Value)
	if err != nil {
		logrus.Error("Failed to encrypt key: ", err)
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	// Insert the key into the database.
	_, err = tx.ExecContext(
		ctx,
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		key.ID.String(), key.UserID.String(), key.Name, encryptedValue, key.Type, key.Revoked, key.CreatedAt,
	)
	if err != nil {
		logrus.Error("Failed to create key: ", err)
		return fmt.Errorf("failed to create key: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logrus.Error("Failed to commit transaction: ", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Insert tags using TagRepository.
	if len(key.Tags) > 0 {
		logrus.Debugf("Adding tags %v for key ID %d", key.Tags, key.ID)
		tagRepo := db.NewTagRepository[Key](r.db, "key_tags", "key_id")
		if err := tagRepo.AddTags(ctx, key.ID, key.Tags); err != nil {
			logrus.Error("Failed to add tags: ", err)
			return fmt.Errorf("failed to add tags: %w", err)
		}
	} else {
		logrus.Debug("No tags provided for key ID ", key.ID)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":  key.ID.String(),
		"user_id": key.UserID,
		"name":    key.Name,
		"type":    key.Type,
	}).Info("Key created successfully")
	return nil
}

// Read retrieves a key by ID from the database.
// It decrypts the key value and retrieves associated tags.
// Parameters:
// - ctx: The context for the database operation.
// - id: The ID of the key to retrieve.
// Returns: The retrieved key and an error if the operation fails.
func (r *keyRepository) Read(ctx context.Context, id uuid.UUID) (Key, error) {
	var key Key
	var encryptedValue string
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, type, revoked, created_at FROM keys WHERE id = ?",
		id,
	).Scan(&key.ID, &key.UserID, &key.Name, &encryptedValue, &key.Type, &key.Revoked, &key.CreatedAt)
	if err == sql.ErrNoRows {
		return key, fmt.Errorf("key not found")
	}
	if err != nil {
		logrus.Error("Failed to query key: ", err)
		return key, fmt.Errorf("failed to query key: %w", err)
	}

	// Decrypt the key value.
	key.Value, err = secrets.DecryptSecret(encryptedValue)
	if err != nil {
		logrus.Error("Failed to decrypt key: ", err)
		return key, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Retrieve tags using TagRepository.
	tagRepo := db.NewTagRepository[Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		logrus.Error("Failed to read tags: ", err)
		return key, fmt.Errorf("failed to read tags: %w", err)
	}

	return key, nil
}

// Update updates a key in the database.
// It encrypts the updated key value and stores it with the new revocation status.
// Parameters:
// - ctx: The context for the database operation.
// - key: The key to update.
// Returns: An error if the operation fails.
func (r *keyRepository) Update(ctx context.Context, key Key) error {
	// Encrypt the updated key value.
	encryptedValue, err := secrets.EncryptSecret(key.Value)
	if err != nil {
		logrus.Error("Failed to encrypt key: ", err)
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	// Update the key in the database.
	_, err = r.db.ExecContext(
		ctx,
		"UPDATE keys SET value = ?, revoked = ?, created_at = ? WHERE id = ?",
		encryptedValue, key.Revoked, key.CreatedAt, key.ID,
	)
	if err != nil {
		logrus.Error("Failed to update key: ", err)
		return fmt.Errorf("failed to update key: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":  key.ID,
		"user_id": key.UserID,
		"name":    key.Name,
		"type":    key.Type,
	}).Info("Key updated successfully")
	return nil
}

// Delete deletes a key by ID from the database.
// It removes the key and its associated tags within a transaction.
// Parameters:
// - ctx: The context for the database operation.
// - id: The ID of the key to delete.
// Returns: An error if the operation fails.
func (r *keyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		logrus.Error("Failed to begin transaction: ", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete tags.
	_, err = tx.ExecContext(ctx, "DELETE FROM key_tags WHERE key_id = ?", id)
	if err != nil {
		logrus.Error("Failed to delete tags: ", err)
		return fmt.Errorf("failed to delete tags: %w", err)
	}

	// Delete key.
	_, err = tx.ExecContext(ctx, "DELETE FROM keys WHERE id = ?", id)
	if err != nil {
		logrus.Error("Failed to delete key: ", err)
		return fmt.Errorf("failed to delete key: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logrus.Error("Failed to commit transaction: ", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id": id,
	}).Info("Key deleted successfully")
	return nil
}

// GenerateRSA generates a new RSA key pair.
// It creates a private key with the specified bit size and associates the provided tags.
// Parameters:
// - ctx: The context for the operation (unused, for interface consistency).
// - userID: The ID of the user owning the key.
// - name: The name of the key.
// - bits: The bit size for the RSA key (e.g., 2048, 4096).
// - tags: The tags to associate with the key.
// Returns: A pointer to the generated Key and an error if the operation fails.
func (r *keyRepository) GenerateRSA(ctx context.Context, userID uuid.UUID, name string, bits int, tags []string) (*Key, error) {
	// Generate RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		r.log.LogAuditError(userID.String(), "generate_key", "failed", "Failed to generate RSA key", err)
		logrus.Error("Failed to generate RSA key: ", err)
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM.
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Store the key in the database.
	key := &Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      name,
		Type:      "RSA",
		Value:     string(privateKeyPEM),
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      tags,
	}

	if err := r.Create(ctx, *key); err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateECDSA generates a new ECDSA key pair.
// It creates a private key with the specified elliptic curve and associates the provided tags.
// Parameters:
// - ctx: The context for the operation (unused, for interface consistency).
// - userID: The ID of the user owning the key.
// - name: The name of the key.
// - curve: The elliptic curve for the ECDSA key (e.g., "P-256", "P-384", "P-521").
// - tags: The tags to associate with the key.
// Returns: A pointer to the generated Key and an error if the operation fails.
func (r *keyRepository) GenerateECDSA(ctx context.Context, userID uuid.UUID, name string, curve string, tags []string) (*Key, error) {
	var c elliptic.Curve
	switch curve {
	case "P-256":
		c = elliptic.P256()
	case "P-384":
		c = elliptic.P384()
	case "P-521":
		c = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	// Generate ECDSA private key.
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		r.log.LogAuditError(userID.String(), "generate_key", "failed", "Failed to generate ECDSA key", err)
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Encode private key to PEM.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		r.log.LogAuditError(userID.String(), "generate_key", "failed", "Failed to marshal ECDSA key", err)
		return nil, fmt.Errorf("failed to marshal ECDSA key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Store the key in the database.
	key := &Key{
		UserID:    userID,
		Name:      name,
		Type:      "ECDSA",
		Value:     string(privateKeyPEM),
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      tags,
	}

	if err := r.Create(ctx, *key); err != nil {
		return nil, err
	}

	return key, nil
}

// Rotate rotates an existing key by generating a new key pair.
// It marks the old key as revoked and creates a new key with the same name, type,
// and tags, using default parameters (2048 bits for RSA, P-256 for ECDSA).
// Parameters:
// - ctx: The context for the database operation.
// - id: The ID of the key to rotate.
// Returns: A pointer to the new Key and an error if the operation fails.
func (r *keyRepository) Rotate(ctx context.Context, id uuid.UUID) (*Key, error) {
	// Read the existing key.
	key, err := r.Read(ctx, id)
	if err != nil {
		return nil, err
	}

	// Mark the old key as revoked.
	key.Revoked = true
	key.CreatedAt = time.Now()
	if err := r.Update(ctx, key); err != nil {
		r.log.LogAuditError(key.UserID.String(), "rotate_key", "failed", "Failed to revoke old key", err)
		return nil, err
	}

	var newKey *Key
	// Generate a new key based on the type.
	switch key.Type {
	case "RSA":
		newKey, err = r.GenerateRSA(ctx, key.UserID, key.Name, 2048, key.Tags) // Default to 2048 bits for simplicity.
	case "ECDSA":
		newKey, err = r.GenerateECDSA(ctx, key.UserID, key.Name, "P-256", key.Tags) // Default to P-256 curve.
	default:
		err = fmt.Errorf("unsupported key type: %s", key.Type)
	}
	if err != nil {
		r.log.LogAuditError(key.UserID.String(), "rotate_key", "failed", "Failed to rotate key", err)
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}
	newKey.Tags = key.Tags // Copy tags.

	logrus.WithFields(logrus.Fields{
		"key_id": id.String(),
		"name":   key.Name,
		"type":   key.Type,
	}).Info("Key rotated successfully")
	return newKey, nil
}

// ListByUser lists keys for a user, optionally filtered by type and tags.
// It retrieves keys matching the user ID and filters, decrypting their values and
// including associated tags.
// Parameters:
// - ctx: The context for the database operation.
// - userID: The ID of the user whose keys to list.
// - keyType: The key type to filter by (e.g., "RSA", "ECDSA"; empty for all).
// - tags: The tags to filter by (empty for no tag filter).
// Returns: A slice of keys and an error if the operation fails.
func (r *keyRepository) ListByUser(ctx context.Context, userID uuid.UUID, keyType string, tags []string) ([]Key, error) {
	query := "SELECT id, user_id, name, value, type, revoked, created_at FROM keys WHERE user_id = ?"
	args := []interface{}{userID.String()}
	if keyType != "" {
		query += " AND type = ?"
		args = append(args, keyType)
	}
	if len(tags) > 0 {
		query += " AND id IN (SELECT key_id FROM key_tags WHERE tag IN (?" + strings.Repeat(",?", len(tags)-1) + "))"
		for _, tag := range tags {
			args = append(args, tag)
		}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		logrus.Error("Failed to list keys: ", err)
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close()

	var keys []Key
	for rows.Next() {
		var key Key
		var encryptedValue string
		if err := rows.Scan(&key.ID, &key.UserID, &key.Name, &encryptedValue, &key.Type, &key.Revoked, &key.CreatedAt); err != nil {
			logrus.Error("Failed to scan key: ", err)
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		// Decrypt the key value.
		key.Value, err = secrets.DecryptSecret(encryptedValue)
		if err != nil {
			logrus.Error("Failed to decrypt key: ", err)
			return nil, fmt.Errorf("failed to decrypt key: %w", err)
		}

		// Retrieve tags for each key.
		tagRepo := db.NewTagRepository[Key](r.db, "key_tags", "key_id")
		key.Tags, err = tagRepo.GetTags(ctx, key.ID)
		if err != nil {
			logrus.Error("Failed to read tags for key: ", err)
			return nil, fmt.Errorf("failed to read tags for key %d: %w", key.ID, err)
		}
		keys = append(keys, key)
	}

	return keys, nil
}
