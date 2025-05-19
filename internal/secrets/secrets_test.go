// Package secrets_test contains unit tests for the secrets package.
// It verifies CRUD operations, encryption, versioning, and tagging for secrets.
package secrets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"password-manager/internal/db"
	"password-manager/internal/logging"
)

// setupTestDB initializes an in-memory SQLite database for testing.
// It sets up the secrets and secret_tags tables and assigns the connection to db.DB.
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

	// Switch to Shared In-Memory Database (Optional):
	// To avoid per-connection isolation, you can use a
	// named in-memory database, which allows multiple connections
	// to share the same database. Use a connection string like:
	sqlDB, err := sql.Open("sqlite3", "file:memdb1?mode=memory&cache=shared")
	assert.NoError(t, err, "opening in-memory database should succeed")

	// Create secrets table.
	_, err = sqlDB.Exec(`
    CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`)
	assert.NoError(t, err, "creating secrets table should succeed")

	// Create secret_tags table.
	_, err = sqlDB.Exec(`
		CREATE TABLE IF NOT EXISTS secret_tags (
			secret_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag),
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
		)
	`)

	assert.NoError(t, err, "creating secret_tags table should succeed")

	// Verify table creation.
	var count int
	err = sqlDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='secrets'").Scan(&count)
	assert.NoError(t, err, "querying secrets table existence should succeed")
	assert.Equal(t, 1, count, "secrets table should exist")
	err = sqlDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='secret_tags'").Scan(&count)
	assert.NoError(t, err, "querying secret_tags table existence should succeed")
	assert.Equal(t, 1, count, "secret_tags table should exist")

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

// TestCreate tests the Create function to ensure it stores an encrypted secret with tags.
func TestCreate(t *testing.T) {
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

	// Set Viper configuration with a valid 32-byte master key.
	viper.Set("master_key", generateMasterKey(t))

	// Test secret creation.
	ctx := context.Background()
	userID := uuid.New()
	secret := Secret{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "test-secret",
		Value:     "my-secret-value",
		Version:   1,
		Tags:      []string{"prod", "api"},
		CreatedAt: time.Now(),
	}

	repo := NewSecretRepository(db.DB, log)
	err := repo.Create(ctx, secret)
	assert.NoError(t, err, "creating secret should succeed")

	// Verify secret in database.
	var name, value string
	var version int
	var id string
	err = db.DB.QueryRow("SELECT id, user_id, name, value, version FROM secrets WHERE user_id = ?", userID.String()).
		Scan(&id, &userID, &name, &value, &version)

	assert.NoError(t, err, "querying secret should succeed")
	assert.Equal(t, "test-secret", name, "secret name should match")
	assert.Equal(t, 1, version, "secret version should match")

	// Decrypt and verify value.
	decryptedValue, err := DecryptSecret(value)
	assert.NoError(t, err, "decrypting secret should succeed")
	assert.Equal(t, "my-secret-value", decryptedValue, "decrypted value should match")

	// Verify tags.
	rows, err := db.DB.Query("SELECT tag FROM secret_tags WHERE secret_id = ?", id)
	assert.NoError(t, err, "querying tags should succeed")
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var tag string
		assert.NoError(t, rows.Scan(&tag), "scanning tag should succeed")
		tags = append(tags, tag)
	}
	assert.ElementsMatch(t, []string{"prod", "api"}, tags, "tags should match")
}

// TestCreateInvalidKey tests the Create function with an invalid master key length.
func TestCreateInvalidKey(t *testing.T) {
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

	// Generate a valid base64-encoded key that is not 32 bytes (e.g., 16 bytes).
	key := make([]byte, 16)
	_, err := rand.Read(key)
	assert.NoError(t, err, "generating random key should succeed")
	invalidKey := base64.StdEncoding.EncodeToString(key)
	viper.Set("master_key", invalidKey)

	// Test secret creation.
	ctx := context.Background()
	userID := uuid.New()

	secret := Secret{
		UserID:    userID,
		Name:      "test-secret",
		Value:     "my-secret-value",
		Version:   1,
		Tags:      []string{"prod"},
		CreatedAt: time.Now(),
	}
	repo := NewSecretRepository(db.DB, log)
	err = repo.Create(ctx, secret)
	assert.Error(t, err, "creating secret should fail with invalid key")
	assert.Contains(t, err.Error(), "master key must be 32 bytes", "error should indicate invalid key length")
}

// TestRead tests the Read function to ensure it retrieves and decrypts a secret.
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

	// Insert a test secret.
	encryptedValue, err := EncryptSecret("my-secret-value")
	assert.NoError(t, err, "encrypting secret should succeed")
	createdAt := time.Now()
	userID := uuid.New()
	id := uuid.New()
	_, err = db.DB.Exec(
		"INSERT INTO secrets (id, user_id, name, value, version, created_at) VALUES (?, ?, 'test-secret', ?, 1, ?)",
		id.String(), userID.String(), encryptedValue, createdAt,
	)
	assert.NoError(t, err, "inserting secret should succeed")
	_, err = db.DB.Exec("INSERT INTO secret_tags (secret_id, tag) VALUES (?, 'prod'), (?, 'api')", id.String(), id.String())
	assert.NoError(t, err, "inserting tags should succeed")

	// Test reading.
	ctx := context.Background()
	repo := NewSecretRepository(db.DB, log)
	secret, err := repo.Read(ctx, id)
	assert.NoError(t, err, "reading secret should succeed")
	assert.Equal(t, id, secret.ID, "secret ID should match")
	assert.Equal(t, userID, secret.UserID, "user ID should match")
	assert.Equal(t, "test-secret", secret.Name, "secret name should match")
	assert.Equal(t, "my-secret-value", secret.Value, "decrypted value should match")
	assert.Equal(t, 1, secret.Version, "version should match")
	assert.ElementsMatch(t, []string{"prod", "api"}, secret.Tags, "tags should match")
}

// TestUpdate tests the Update function to ensure it creates a new secret version.
func TestUpdate(t *testing.T) {
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

	// Insert a test secret.
	encryptedValue, err := EncryptSecret("old-value")
	assert.NoError(t, err, "encrypting secret should succeed")
	userID := uuid.New()
	id := uuid.New()
	_, err = db.DB.Exec(
		"INSERT INTO secrets (id, user_id, name, value, version, created_at) VALUES (?, ?, 'test-secret', ?, 1, ?)",
		id.String(), userID.String(), encryptedValue, time.Now(),
	)
	assert.NoError(t, err, "inserting secret should succeed")

	// Test updating.
	ctx := context.Background()
	secret := Secret{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "test-secret",
		Value:     "new-value",
		Version:   2,
		Tags:      []string{"dev"},
		CreatedAt: time.Now(),
	}
	repo := NewSecretRepository(db.DB, log)
	err = repo.Update(ctx, secret)
	assert.NoError(t, err, "updating secret should succeed")

	// Verify updated secret.
	var name, value string
	var version int
	err = db.DB.QueryRow("SELECT name, value, version FROM secrets WHERE user_id = ? AND version = 2", userID.String()).
		Scan(&name, &value, &version)

	assert.NoError(t, err, "querying updated secret should succeed")
	assert.Equal(t, "test-secret", name, "secret name should match")
	assert.Equal(t, 2, version, "secret version should match")
	decryptedValue, err := DecryptSecret(value)
	assert.NoError(t, err, "decrypting secret should succeed")
	assert.Equal(t, "new-value", decryptedValue, "decrypted value should match")

	// Verify tags.
	rows, err := db.DB.Query("SELECT tag FROM secret_tags WHERE secret_id = ?", secret.ID.String())
	assert.NoError(t, err, "querying tags should succeed")
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var tag string
		assert.NoError(t, rows.Scan(&tag), "scanning tag should succeed")
		tags = append(tags, tag)
	}
	assert.ElementsMatch(t, []string{"dev"}, tags, "tags should match")
}

// TestDelete tests the Delete function to ensure it removes a secret and its tags.
func TestDelete(t *testing.T) {
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

	id := uuid.New()
	userID := uuid.New()

	// Insert a test secret.
	_, err := db.DB.Exec(
		"INSERT INTO secrets (id, user_id, name, value, version, created_at) VALUES (?, ?, 'test-secret', 'encrypted', 1, ?)",
		id.String(), userID.String(), time.Now(),
	)
	assert.NoError(t, err, "inserting secret should succeed")
	_, err = db.DB.Exec("INSERT INTO secret_tags (secret_id, tag) VALUES (?, 'prod')", id.String())
	assert.NoError(t, err, "inserting tag should succeed")

	// Test deletion.
	ctx := context.Background()
	repo := NewSecretRepository(db.DB, log)
	err = repo.Delete(ctx, id)
	assert.NoError(t, err, "deleting secret should succeed")

	// Verify secret is deleted.
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM secrets WHERE id = ?", id.String()).Scan(&count)
	assert.NoError(t, err, "querying secret count should succeed")
	assert.Equal(t, 0, count, "secret should be deleted")

	// Verify tags are deleted.
	err = db.DB.QueryRow("SELECT COUNT(*) FROM secret_tags WHERE secret_id = ?", id.String()).Scan(&count)
	assert.NoError(t, err, "querying tag count should succeed")
	assert.Equal(t, 0, count, "tags should be deleted")
}

// TestListByUser tests the ListByUser function to ensure it retrieves secrets with optional tag filtering.
func TestListByUser(t *testing.T) {
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

	// Insert test secrets.
	encryptedValue1, err := EncryptSecret("value1")
	assert.NoError(t, err, "encrypting secret should succeed")
	encryptedValue2, err := EncryptSecret("value2")
	assert.NoError(t, err, "encrypting secret should succeed")
	createdAt := time.Now()
	id1 := uuid.New()
	userID1 := uuid.New()

	id2 := uuid.New()
	userID2 := uuid.New()

	_, err = db.DB.Exec(
		"INSERT INTO secrets (id, user_id, name, value, version, created_at) VALUES (?, ?, 'secret1', ?, 1, ?), (?, ?, 'secret2', ?, 1, ?)",
		id1.String(), userID1.String(), encryptedValue1, createdAt, id2.String(), userID2.String(), encryptedValue2, createdAt,
	)
	assert.NoError(t, err, "inserting secrets should succeed")
	_, err = db.DB.Exec("INSERT INTO secret_tags (secret_id, tag) VALUES (?, 'prod'), (?, 'dev')", id1.String(), id2.String())
	assert.NoError(t, err, "inserting tags should succeed")

	// Test listing with tag filter.
	ctx := context.Background()
	repo := NewSecretRepository(db.DB, log)
	secretsList, err := repo.ListByUser(ctx, userID1, []string{"prod"})
	assert.NoError(t, err, "listing secrets should succeed")
	assert.Len(t, secretsList, 1, "should return one secret")
	if len(secretsList) > 0 {
		assert.Equal(t, "secret1", secretsList[0].Name, "secret name should match")
		assert.Equal(t, "value1", secretsList[0].Value, "decrypted value should match")
		assert.ElementsMatch(t, []string{"prod"}, secretsList[0].Tags, "tags should match")
	}
}

// BenchmarkCreate measures the performance of the Create function.
func BenchmarkCreate(b *testing.B) {
	// Set up mock database.
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		b.Fatalf("creating mock database failed: %v", err)
	}
	defer sqlDB.Close()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")

	id := uuid.New()
	userID := uuid.New()
	// Mock secret insertion.
	mock.ExpectExec("INSERT INTO secrets \\(id, user_id, name, value, version, created_at\\) VALUES \\(\\?,\\?, \\?, \\?, \\?, \\?\\)").
		WithArgs(id.String(), userID.String(), "test-secret", sqlmock.AnyArg(), 1, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock tag insertion.
	mock.ExpectExec("INSERT INTO secret_tags \\(secret_id, tag\\) VALUES \\(\\?, \\?\\)").
		WithArgs(id.String(), "prod").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(b))

	// Set mock database.
	db.DB = sqlDB

	// Run benchmark.
	ctx := context.Background()
	repo := NewSecretRepository(db.DB, log)
	secret := Secret{
		ID:        id,
		UserID:    userID,
		Name:      "test-secret",
		Value:     "my-secret-value",
		Version:   1,
		Tags:      []string{"prod"},
		CreatedAt: time.Now(),
	}
	for i := 0; i < b.N; i++ {
		_ = repo.Create(ctx, secret)
	}

	// Verify mock expectations.
	if err := mock.ExpectationsWereMet(); err != nil {
		b.Fatalf("mock expectations not met: %v", err)
	}
}
