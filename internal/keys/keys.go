// Package keys manages cryptographic key storage and operations for the password manager.
// It supports RSA and ECDSA key generation, storage, rotation, and HSM integration,
// using Go Generics for type-safe key handling.
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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/logging"
	"github.com/snehal1112/password-manager/internal/secrets"
)

// Key represents a cryptographic key in the password manager.
// It includes the key’s ID, user ID, name, type, encrypted value, revocation status, and creation time.
type Key struct {
	ID        int
	UserID    int
	Name      string
	Type      string // "RSA" or "ECDSA"
	Value     string // Encrypted PEM-encoded private key
	Revoked   bool
	CreatedAt time.Time
}

// KeyRepository is a generic repository interface for key operations.
// It provides type-safe CRUD operations for the Key type.
type KeyRepository interface {
	db.Repository[Key]
	GenerateRSA(ctx context.Context, userID int, name string, bits int) (*Key, error)
	GenerateECDSA(ctx context.Context, userID int, name string, curve string) (*Key, error)
	Rotate(ctx context.Context, id int) (*Key, error)
}

// keyRepository implements KeyRepository for database operations on keys.
type keyRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewKeyRepository creates a new KeyRepository with the given database connection.
// It initializes the repository for key-related database operations.
//
// Parameters:
//
//	db: The database connection.
//
// Returns:
//
//	A KeyRepository for key operations.
func NewKeyRepository(db *sql.DB, log *logging.Logger) KeyRepository {
	return &keyRepository{db: db, log: log}
}

// Create inserts a new key into the database.
// It stores the encrypted key value with the specified user ID, name, type, and revocation status.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	key: The key to create.
//
// Returns:
//
//	An error if the insertion fails.
func (r *keyRepository) Create(ctx context.Context, key Key) error {
	// Encrypt the key value.
	encryptedValue, err := secrets.EncryptSecret(key.Value)
	if err != nil {
		logrus.Error("Failed to encrypt key: ", err)
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	// Insert the key into the database.
	result, err := r.db.ExecContext(
		ctx,
		"INSERT INTO keys (user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		key.UserID, key.Name, encryptedValue, key.Type, key.Revoked, key.CreatedAt,
	)
	if err != nil {
		logrus.Error("Failed to create key: ", err)
		return fmt.Errorf("failed to create key: %w", err)
	}

	// Retrieve the new key’s ID.
	keyID, _ := result.LastInsertId()

	logrus.WithFields(logrus.Fields{
		"key_id":  keyID,
		"user_id": key.UserID,
		"name":    key.Name,
		"type":    key.Type,
	}).Info("Key created successfully")
	return nil
}

// Read retrieves a key by ID from the database.
// It decrypts the key value and returns the key details.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The key’s ID.
//
// Returns:
//
//	The key and an error if the retrieval fails.
func (r *keyRepository) Read(ctx context.Context, id int) (Key, error) {
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

	return key, nil
}

// Update updates a key in the database.
// It encrypts the updated key value and stores it with the new revocation status.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	key: The key to update.
//
// Returns:
//
//	An error if the update fails.
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
// It removes the key and its associated data.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The key’s ID.
//
// Returns:
//
//	An error if the deletion fails.
func (r *keyRepository) Delete(ctx context.Context, id int) error {
	// Delete the key.
	_, err := r.db.ExecContext(ctx, "DELETE FROM keys WHERE id = ?", id)
	if err != nil {
		logrus.Error("Failed to delete key: ", err)
		return fmt.Errorf("failed to delete key: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id": id,
	}).Info("Key deleted successfully")
	return nil
}

// GenerateRSA generates a new RSA key pair and stores it in the database.
// It creates a private key with the specified bit size and encrypts it.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//	name: The key’s name.
//	bits: The key size in bits (e.g., 2048, 4096).
//
// Returns:
//
//	An error if key generation or storage fails.
func (r *keyRepository) GenerateRSA(ctx context.Context, userID int, name string, bits int) (*Key, error) {
	// Generate RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		r.log.LogAuditError(userID, "generate_key", "failed", "Failed to generate RSA key", err)
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
		UserID:    userID,
		Name:      name,
		Type:      "RSA",
		Value:     string(privateKeyPEM),
		Revoked:   false,
		CreatedAt: time.Now(),
	}

	if err := r.Create(ctx, *key); err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateECDSA generates a new ECDSA key pair and stores it in the database.
// It creates a private key with the specified elliptic curve.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//	name: The key’s name.
//	curve: The elliptic curve (e.g., "P-256", "P-384", "P-521").
//
// Returns:
//
//	The generated key and an error if key generation or storage fails.
func (r *keyRepository) GenerateECDSA(ctx context.Context, userID int, name string, curve string) (*Key, error) {
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
		r.log.LogAuditError(userID, "generate_key", "failed", "Failed to generate ECDSA key", err)
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Encode private key to PEM.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		r.log.LogAuditError(userID, "generate_key", "failed", "Failed to marshal ECDSA key", err)
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
	}

	if err := r.Create(ctx, *key); err != nil {
		return nil, err
	}

	return key, nil
}

// Rotate rotates an existing key by generating a new key pair and updating the database.
// It marks the old key as revoked and creates a new key with the same name and type.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The key’s ID.
//
// Returns:
//
//	The generated key and an error if rotation fails.
func (r *keyRepository) Rotate(ctx context.Context, id int) (*Key, error) {
	// Read the existing key.
	key, err := r.Read(ctx, id)
	if err != nil {
		return nil, err
	}

	// Mark the old key as revoked.
	key.Revoked = true
	key.CreatedAt = time.Now()
	if err := r.Update(ctx, key); err != nil {
		r.log.LogAuditError(key.UserID, "rotate_key", "failed", "Failed to revoke old key", err)
		return nil, err
	}

	var newKey *Key
	// Generate a new key based on the type.
	switch key.Type {
	case "RSA":
		newKey, err = r.GenerateRSA(ctx, key.UserID, key.Name, 2048) // Default to 2048 bits for simplicity.
	case "ECDSA":
		newKey, err = r.GenerateECDSA(ctx, key.UserID, key.Name, "P-256") // Default to P-256 curve.
	default:
		err = fmt.Errorf("unsupported key type: %s", key.Type)
	}
	if err != nil {
		r.log.LogAuditError(key.UserID, "rotate_key", "failed", "Failed to rotate key", err)
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id": id,
		"name":   key.Name,
		"type":   key.Type,
	}).Info("Key rotated successfully")
	return newKey, nil
}
