// Package keys_test contains unit tests for the keys package.
// It verifies key generation, CRUD operations, rotation, and encryption for cryptographic keys.
package keys_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/keys"
	"github.com/snehal1112/password-manager/internal/logging"
	"github.com/snehal1112/password-manager/internal/secrets"
)

// setupTestDB initializes an in-memory SQLite database for testing.
// It sets up the keys table and assigns the connection to db.DB.
//
// Parameters:
//
//	t: The testing context.
//
// Returns:
//
//	A function to clean up the database after the test.
func setupTestDB(t *testing.T) func() {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	assert.NoError(t, err, "opening in-memory database should succeed")

	_, err = sqlDB.Exec(`
		CREATE TABLE keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	assert.NoError(t, err, "creating keys table should succeed")

	db.DB = sqlDB
	return func() {
		db.DB.Close()
		db.DB = nil
	}
}

// generateMasterKey generates a valid 32-byte base64-encoded master key for testing.
//
// Parameters:
//
//	tb: The testing context (supports *testing.T or *testing.B).
//
// Returns:
//
//	A base64-encoded 32-byte key.
func generateMasterKey(tb testing.TB) string {
	tb.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		tb.Fatalf("generating random key failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// TestGenerateRSA tests the GenerateRSA function to ensure it creates an RSA key.
func TestGenerateRSA(t *testing.T) {
	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")

	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(t))

	// Test RSA key generation.
	ctx := context.Background()
	repo := keys.NewKeyRepository(db.DB, log)
	_, err := repo.GenerateRSA(ctx, 1, "test-rsa-key", 2048)
	assert.NoError(t, err, "generating RSA key should succeed")

	// Verify key in database.
	var name, value, keyType string
	var revoked bool
	err = db.DB.QueryRow("SELECT name, value, type, revoked FROM keys WHERE user_id = ?", 1).
		Scan(&name, &value, &keyType, &revoked)
	assert.NoError(t, err, "querying key should succeed")
	assert.Equal(t, "test-rsa-key", name, "key name should match")
	assert.Equal(t, "RSA", keyType, "key type should match")
	assert.False(t, revoked, "key should not be revoked")

	// Decrypt and verify key format.
	decryptedValue, err := secrets.DecryptSecret(value)
	assert.NoError(t, err, "decrypting key should succeed")
	assert.Contains(t, decryptedValue, "-----BEGIN RSA PRIVATE KEY-----", "key should be PEM-encoded RSA")
}

// TestGenerateECDSA tests the GenerateECDSA function to ensure it creates an ECDSA key.
func TestGenerateECDSA(t *testing.T) {
	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")
	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(t))

	// Test ECDSA key generation.
	ctx := context.Background()
	repo := keys.NewKeyRepository(db.DB, log)
	_, err := repo.GenerateECDSA(ctx, 1, "test-ecdsa-key", "P-256")
	assert.NoError(t, err, "generating ECDSA key should succeed")

	// Verify key in database.
	var name, value, keyType string
	var revoked bool
	err = db.DB.QueryRow("SELECT name, value, type, revoked FROM keys WHERE user_id = ?", 1).
		Scan(&name, &value, &keyType, &revoked)
	assert.NoError(t, err, "querying key should succeed")
	assert.Equal(t, "test-ecdsa-key", name, "key name should match")
	assert.Equal(t, "ECDSA", keyType, "key type should match")
	assert.False(t, revoked, "key should not be revoked")

	// Decrypt and verify key format.
	decryptedValue, err := secrets.DecryptSecret(value)
	assert.NoError(t, err, "decrypting key should succeed")
	assert.Contains(t, decryptedValue, "-----BEGIN EC PRIVATE KEY-----", "key should be PEM-encoded ECDSA")
}

// TestRead tests the Read function to ensure it retrieves and decrypts a key.
func TestRead(t *testing.T) {
	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")
	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(t))

	// Insert a test key.
	encryptedValue, err := secrets.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")
	createdAt := time.Now()
	_, err = db.DB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (1, 1, 'test-key', ?, 'RSA', false, ?)",
		encryptedValue, createdAt,
	)
	assert.NoError(t, err, "inserting key should succeed")

	// Test reading.
	ctx := context.Background()
	repo := keys.NewKeyRepository(db.DB, log)
	key, err := repo.Read(ctx, 1)
	assert.NoError(t, err, "reading key should succeed")
	assert.Equal(t, 1, key.ID, "key ID should match")
	assert.Equal(t, 1, key.UserID, "user ID should match")
	assert.Equal(t, "test-key", key.Name, "key name should match")
	assert.Contains(t, key.Value, "-----BEGIN RSA PRIVATE KEY-----", "decrypted value should be PEM-encoded")
	assert.Equal(t, "RSA", key.Type, "key type should match")
	assert.False(t, key.Revoked, "key should not be revoked")
}

// TestRotate tests the Rotate function to ensure it revokes an old key and creates a new one.
func TestRotate(t *testing.T) {
	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")

	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(t))

	// Insert a test key.
	encryptedValue, err := secrets.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")
	createdAt := time.Now()
	_, err = db.DB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (1, 1, 'test-key', ?, 'RSA', false, ?)",
		encryptedValue, createdAt,
	)
	assert.NoError(t, err, "inserting key should succeed")

	// Test rotation.
	ctx := context.Background()
	repo := keys.NewKeyRepository(db.DB, log)
	_, err = repo.Rotate(ctx, 1)
	assert.NoError(t, err, "rotating key should succeed")

	// Verify old key is revoked.
	var revoked bool
	err = db.DB.QueryRow("SELECT revoked FROM keys WHERE id = ?", 1).Scan(&revoked)
	assert.NoError(t, err, "querying old key should succeed")
	assert.True(t, revoked, "old key should be revoked")

	// Verify new key exists.
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM keys WHERE user_id = ? AND name = ? AND id != ?", 1, "test-key", 1).Scan(&count)
	assert.NoError(t, err, "querying new key should succeed")
	assert.Equal(t, 1, count, "new key should exist")
}

// BenchmarkGenerateRSA measures the performance of the GenerateRSA function.
func BenchmarkGenerateRSA(b *testing.B) {
	// Set up mock database.
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		b.Fatalf("creating mock database failed: %v", err)
	}
	defer sqlDB.Close()

	// Mock key insertion.
	mock.ExpectExec("INSERT INTO keys \\(user_id, name, value, type, revoked, created_at\\) VALUES \\(\\?, \\?, \\?, \\?, \\?, \\?\\)").
		WithArgs(1, "test-rsa-key", sqlmock.AnyArg(), "RSA", false, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(b))

	// Set mock database.
	db.DB = sqlDB

	// Run benchmark.
	ctx := context.Background()
	repo := keys.NewKeyRepository(db.DB, logging.InitLogger())
	for i := 0; i < b.N; i++ {
		_, err = repo.GenerateRSA(ctx, 1, "test-rsa-key", 2048)
	}

	// Verify mock expectations.
	if err := mock.ExpectationsWereMet(); err != nil {
		b.Fatalf("mock expectations not met: %v", err)
	}
}
