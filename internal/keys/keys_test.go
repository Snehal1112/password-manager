// Package keys_test contains unit tests for the keys package.
package keys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"password-manager/common"
	"password-manager/internal/db"
	"password-manager/internal/logging"
)

// setupTestDB initializes an in-memory SQLite database for testing.
// It creates the keys and key_tags tables and returns the database connection
// along with a cleanup function.
// Parameters:
// - t: The testing context.
// Returns: The SQLite database connection and a function to close it.
func setupTestDB(t *testing.T) func() {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", "file:memdb1?mode=memory&cache=shared")
	assert.NoError(t, err, "opening in-memory database should succeed")
	// Test database connection.
	_, err = sqlDB.Exec("SELECT 1")
	assert.NoError(t, err, "database connection should be active")

	// Begin transaction for table creation.
	tx, err := sqlDB.Begin()
	assert.NoError(t, err, "beginning transaction should succeed")

	// Create keys table.
	_, err = tx.Exec(`
    CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`)
	assert.NoError(t, err, "creating keys table should succeed")

	// Verify keys table exists.
	var count int
	err = tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='keys'").Scan(&count)
	assert.NoError(t, err, "querying keys table existence should succeed")
	assert.Equal(t, 1, count, "keys table should exist")

	// Create key_tags table.
	_, err = tx.Exec(`
		CREATE TABLE key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		)
	`)
	assert.NoError(t, err, "creating key_tags table should succeed")

	// Verify key_tags table exists.
	err = tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='key_tags'").Scan(&count)
	assert.NoError(t, err, "querying key_tags table existence should succeed")
	assert.Equal(t, 1, count, "key_tags table should exist")

	// Commit transaction.
	err = tx.Commit()
	assert.NoError(t, err, "committing table creation transaction should succeed")

	// Final verification of tables.
	rows, err := sqlDB.Query("SELECT name FROM sqlite_master WHERE type='table'")
	assert.NoError(t, err, "querying final table list should succeed")
	defer rows.Close()
	tables := make(map[string]bool)
	for rows.Next() {
		var name string
		err = rows.Scan(&name)
		assert.NoError(t, err, "scanning table name should succeed")
		tables[name] = true
	}
	assert.True(t, tables["keys"], "keys table should exist")
	assert.True(t, tables["key_tags"], "key_tags table should exist")

	db.DB = sqlDB
	return func() {
		sqlDB.Close()
		db.DB = nil
	}
}

// generateMasterKey generates a valid 32-byte base64-encoded master key for testing.
// Parameters:
// - tb: The testing context.
// Returns: A base64-encoded 32-byte key.
func generateMasterKey(tb testing.TB) string {
	tb.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		tb.Fatalf("generating random key failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// TestGenerateRSA tests the GenerateRSA function to ensure it creates an RSA key with tags.
func TestGenerateRSA(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	sqlDB := db.DB
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	ctx := context.Background()
	repo := NewKeyRepository(sqlDB, log)
	userID := uuid.New()
	key, err := repo.GenerateRSA(ctx, userID, "test-rsa-key", 2048, []string{"prod"})
	assert.NoError(t, err, "generating RSA key should succeed")

	var id string
	var name, value, keyType string
	var revoked bool
	err = sqlDB.QueryRow("SELECT id, name, value, type, revoked FROM keys WHERE user_id = ?", key.UserID.String()).
		Scan(&id, &name, &value, &keyType, &revoked)
	assert.NoError(t, err, "querying key should succeed")
	assert.Equal(t, "test-rsa-key", name, "key name should match")
	assert.Equal(t, "RSA", keyType, "key type should match")
	assert.False(t, revoked, "key should not be revoked")

	decryptedValue, err := common.DecryptSecret(value)
	assert.NoError(t, err, "decrypting key should succeed")
	assert.Contains(t, decryptedValue, "-----BEGIN RSA PRIVATE KEY-----", "key should be PEM-encoded RSA")

	var tag string
	err = sqlDB.QueryRow("SELECT tag FROM key_tags WHERE key_id = ?", id).Scan(&tag)
	assert.NoError(t, err, "querying tag should succeed")
	assert.Equal(t, "prod", tag, "tag should match")
}

// TestGenerateECDSA tests the GenerateECDSA function to ensure it creates an ECDSA key with tags.
func TestGenerateECDSA(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()
	sqlDB := db.DB

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	ctx := context.Background()
	repo := NewKeyRepository(sqlDB, log)
	userID := uuid.New()
	_, err := repo.GenerateECDSA(ctx, userID, "test-ecdsa-key", "P-256", []string{"dev"})
	assert.NoError(t, err, "generating ECDSA key should succeed")

	var id, userId string
	var name, value, keyType string
	var revoked bool
	err = sqlDB.QueryRow("SELECT id,user_id, name, value, type, revoked FROM keys WHERE user_id = ?", userID.String()).
		Scan(&id, &userId, &name, &value, &keyType, &revoked)
	assert.NoError(t, err, "querying key should succeed")
	assert.Equal(t, "test-ecdsa-key", name, "key name should match")
	assert.Equal(t, "ECDSA", keyType, "key type should match")
	assert.False(t, revoked, "key should not be revoked")

	decryptedValue, err := common.DecryptSecret(value)
	assert.NoError(t, err, "decrypting key should succeed")
	assert.Contains(t, decryptedValue, "-----BEGIN EC PRIVATE KEY-----", "key should be PEM-encoded ECDSA")

	var tag string
	err = sqlDB.QueryRow("SELECT tag FROM key_tags WHERE key_id = ?", id).Scan(&tag)
	assert.NoError(t, err, "querying tag should succeed")
	assert.Equal(t, "dev", tag, "tag should match")
}

// TestCreate tests the Create function to ensure it stores a key with tags.
func TestCreate(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()
	sqlDB := db.DB

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	ctx := context.Background()
	repo := NewKeyRepository(sqlDB, log)
	userID := uuid.New()
	keyID := uuid.New()
	key := Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      "RSA",
		Value:     "-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----",
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      []string{"prod", "api"},
	}
	err := repo.Create(ctx, &key)
	assert.NoError(t, err, "creating key should succeed")

	var id string
	var userId string
	var name, value, keyType string
	var revoked bool
	err = sqlDB.QueryRow("SELECT id, user_id, name, value, type, revoked FROM keys WHERE user_id = ?", userID.String()).
		Scan(&id, &userId, &name, &value, &keyType, &revoked)
	assert.NoError(t, err, "querying key should succeed")
	assert.Equal(t, "test-key", name, "key name should match")
	assert.Equal(t, "RSA", keyType, "key type should match")
	assert.False(t, revoked, "key should not be revoked")

	rows, err := sqlDB.Query("SELECT tag FROM key_tags WHERE key_id = ?", id)
	assert.NoError(t, err, "querying tags should succeed")
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var tag string
		err = rows.Scan(&tag)
		assert.NoError(t, err, "scanning tag should succeed")
		tags = append(tags, tag)
	}
	assert.ElementsMatch(t, []string{"prod", "api"}, tags, "tags should match")
}

// TestRead tests the Read function to ensure it retrieves and decrypts a key with tags.
func TestRead(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()
	sqlDB := db.DB

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	encryptedValue, err := common.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")
	createdAt := time.Now()
	userID := uuid.New()
	keyID := uuid.New()

	_, err = sqlDB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		keyID.String(), userID.String(), "test-key", encryptedValue, "RSA", false, createdAt,
	)
	assert.NoError(t, err, "inserting key should succeed")

	_, err = sqlDB.Exec(
		"INSERT INTO key_tags (key_id, tag) VALUES (?, ?), (?, ?)",
		keyID.String(), "prod", keyID.String(), "api",
	)
	assert.NoError(t, err, "inserting tags should succeed")

	ctx := context.Background()
	repo := NewKeyRepository(sqlDB, log)
	key, err := repo.Read(ctx, keyID)
	assert.NoError(t, err, "reading key should succeed")
	assert.Equal(t, keyID, key.ID, "key ID should match")
	assert.Equal(t, userID, key.UserID, "user ID should match")
	assert.Equal(t, "test-key", key.Name, "key name should match")
	assert.Contains(t, key.Value, "-----BEGIN RSA PRIVATE KEY-----", "decrypted value should be PEM-encoded")
	assert.Equal(t, "RSA", key.Type, "key type should match")
	assert.False(t, key.Revoked, "key should not be revoked")
	assert.ElementsMatch(t, []string{"prod", "api"}, key.Tags, "tags should match")
}

// TestListByUser tests the ListByUser function to ensure it lists keys with type and tag filters.
func TestListByUser(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test keys.
	encryptedValue1, err := common.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key1\n-----END RSA PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")
	encryptedValue2, err := common.EncryptSecret("-----BEGIN EC PRIVATE KEY-----\ntest-key2\n-----END EC PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")
	createdAt := time.Now()
	userID1 := uuid.New()
	keyID1 := uuid.New()
	_, err = db.DB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		keyID1.String(), userID1.String(), "test-key1", encryptedValue1, "RSA", false, createdAt,
	)
	assert.NoError(t, err, "inserting key 1 should succeed")
	userID2 := uuid.New()
	keyID2 := uuid.New()
	createdAt = time.Now()
	_, err = db.DB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		keyID2.String(), userID2.String(), "test-key2", encryptedValue2, "ECDSA", false, createdAt,
	)
	assert.NoError(t, err, "inserting key 2 should succeed")

	// Insert tags.
	_, err = db.DB.Exec(
		"INSERT INTO key_tags (key_id, tag) VALUES (?, ?), (?, ?)",
		keyID1.String(), "prod", keyID1.String(), "api",
	)
	assert.NoError(t, err, "inserting tags for key 1 should succeed")
	_, err = db.DB.Exec(
		"INSERT INTO key_tags (key_id, tag) VALUES (?, ?)",
		keyID2.String(), "dev",
	)
	assert.NoError(t, err, "inserting tags for key 2 should succeed")

	ctx := context.Background()
	repo := NewKeyRepository(db.DB, log)
	keysList, err := repo.ListByUser(ctx, userID1, "RSA", []string{"prod"})

	assert.NoError(t, err, "listing keys should succeed")
	assert.Len(t, keysList, 1, "should return one key")
	assert.Equal(t, keyID1, keysList[0].ID, "key ID should match")
	assert.Equal(t, "test-key1", keysList[0].Name, "key name should match")
	assert.Equal(t, "RSA", keysList[0].Type, "key type should match")
	assert.ElementsMatch(t, []string{"prod", "api"}, keysList[0].Tags, "tags should match")
}

// TestRotate tests the Rotate function to ensure it revokes an old key and creates a new one with tags.
func TestRotate(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test key.
	encryptedValue, err := common.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")

	userID := uuid.New()
	keyID := uuid.New()
	_, err = db.DB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		keyID.String(), userID.String(), "test-key", encryptedValue, "RSA", false, time.Now(),
	)
	assert.NoError(t, err, "inserting key should succeed")

	// Insert tags.
	_, err = db.DB.Exec(
		"INSERT INTO key_tags (key_id, tag) VALUES (?, ?)",
		keyID.String(), "prod",
	)
	assert.NoError(t, err, "inserting tags should succeed")

	ctx := context.Background()
	repo := NewKeyRepository(db.DB, log)
	_, err = repo.Rotate(ctx, keyID)

	assert.NoError(t, err, "rotating key should succeed")

	// Verify old key is revoked.
	var revoked bool
	var userId, ID string
	var name, value, types string

	err = db.DB.QueryRow("SELECT id, user_id, name, value, type, revoked FROM keys WHERE id = ?", keyID.String()).Scan(&ID, &userId, &name, &value, &types, &revoked)
	assert.NoError(t, err, "querying old key should succeed")
	assert.True(t, revoked, "old key should be revoked")

	// Verify new key exists with tags.
	var newID string
	var tag string

	err = db.DB.QueryRow("SELECT id FROM keys WHERE user_id = ? AND name = ? AND id != ?", userId, "test-key", 0).Scan(&newID)
	assert.NoError(t, err, "querying new key should succeed")

	err = db.DB.QueryRow("SELECT tag FROM key_tags WHERE key_id = ?", newID).Scan(&tag)

	assert.NoError(t, err, "querying new key tag should succeed")
	assert.Equal(t, "prod", tag, "new key should have copied tag")
}
