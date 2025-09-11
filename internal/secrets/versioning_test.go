// Package secrets_test contains unit tests for the versioning functionality.
// It verifies secret version creation, retrieval, and management operations.
package secrets

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"password-manager/internal/db"
	"password-manager/internal/logging"
)

// setupVersioningTestDB initializes an in-memory SQLite database for versioning tests.
// It sets up all necessary tables including secret_versions.
//
// Parameters:
//
//	t: The testing context.
//
// Returns:
//
//	A function to clean up the database after the test.
func setupVersioningTestDB(t *testing.T) func() {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", "file:memdb_versioning?mode=memory&cache=shared")
	assert.NoError(t, err, "opening in-memory database should succeed")

	// Create all necessary tables
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
		CREATE TABLE IF NOT EXISTS secret_versions (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (secret_id) REFERENCES secrets(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS secret_tags (
			secret_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag),
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
		);
	`)
	assert.NoError(t, err, "creating tables should succeed")

	db.DB = sqlDB
	return func() {
		db.DB.Close()
		db.DB = nil
	}
}

// TestSecretVersionRepositoryCreateVersion tests creating a new secret version.
func TestSecretVersionRepositoryCreateVersion(t *testing.T) {
	cleanup := setupVersioningTestDB(t)
	defer cleanup()

	// Set up configuration
	viper.Set("master_key", generateMasterKey(t))
	viper.Set("log.file", "test_versioning.log")
	log := logging.InitLogger()
	defer os.Remove("test_versioning.log")

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	version := &SecretVersion{
		ID:        uuid.New(),
		SecretID:  secretID,
		UserID:    userID,
		Name:      "test-secret",
		Value:     "test-value-v1",
		Version:   1,
		CreatedAt: time.Now(),
	}

	repo := NewSecretVersionRepository(db.DB, log)
	err := repo.CreateVersion(ctx, version)
	assert.NoError(t, err, "creating version should succeed")

	// Verify version was created
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM secret_versions WHERE secret_id = ?", secretID.String()).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 1, count, "version should be created")
}

// TestSecretVersionRepositoryGetVersions tests retrieving all versions of a secret.
func TestSecretVersionRepositoryGetVersions(t *testing.T) {
	cleanup := setupVersioningTestDB(t)
	defer cleanup()

	// Set up configuration
	viper.Set("master_key", generateMasterKey(t))
	viper.Set("log.file", "test_versioning.log")
	log := logging.InitLogger()
	defer os.Remove("test_versioning.log")

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	repo := NewSecretVersionRepository(db.DB, log)

	// Create multiple versions
	for i := 1; i <= 3; i++ {
		version := &SecretVersion{
			ID:        uuid.New(),
			SecretID:  secretID,
			UserID:    userID,
			Name:      "test-secret",
			Value:     "test-value-v" + string(rune(i+'0')),
			Version:   i,
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		}
		err := repo.CreateVersion(ctx, version)
		assert.NoError(t, err, "creating version %d should succeed", i)
	}

	// Retrieve all versions
	versions, err := repo.GetVersions(ctx, secretID)
	assert.NoError(t, err)
	assert.Len(t, versions, 3, "should retrieve 3 versions")

	// Verify versions are ordered by version DESC
	assert.Equal(t, 3, versions[0].Version)
	assert.Equal(t, 2, versions[1].Version)
	assert.Equal(t, 1, versions[2].Version)

	// Verify values are decrypted correctly
	assert.Equal(t, "test-value-v3", versions[0].Value)
	assert.Equal(t, "test-value-v2", versions[1].Value)
	assert.Equal(t, "test-value-v1", versions[2].Value)
}

// TestSecretVersionRepositoryGetVersion tests retrieving a specific version.
func TestSecretVersionRepositoryGetVersion(t *testing.T) {
	cleanup := setupVersioningTestDB(t)
	defer cleanup()

	// Set up configuration
	viper.Set("master_key", generateMasterKey(t))
	viper.Set("log.file", "test_versioning.log")
	log := logging.InitLogger()
	defer os.Remove("test_versioning.log")

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	repo := NewSecretVersionRepository(db.DB, log)

	// Create versions
	version1 := &SecretVersion{
		ID:        uuid.New(),
		SecretID:  secretID,
		UserID:    userID,
		Name:      "test-secret",
		Value:     "value-v1",
		Version:   1,
		CreatedAt: time.Now(),
	}
	version2 := &SecretVersion{
		ID:        uuid.New(),
		SecretID:  secretID,
		UserID:    userID,
		Name:      "test-secret",
		Value:     "value-v2",
		Version:   2,
		CreatedAt: time.Now().Add(time.Minute),
	}

	err := repo.CreateVersion(ctx, version1)
	assert.NoError(t, err)
	err = repo.CreateVersion(ctx, version2)
	assert.NoError(t, err)

	// Retrieve specific version
	retrieved, err := repo.GetVersion(ctx, secretID, 2)
	assert.NoError(t, err)
	assert.Equal(t, 2, retrieved.Version)
	assert.Equal(t, "value-v2", retrieved.Value)
	assert.Equal(t, secretID, retrieved.SecretID)

	// Test retrieving non-existent version
	_, err = repo.GetVersion(ctx, secretID, 99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version 99 not found")
}

// TestSecretVersionRepositoryGetLatestVersion tests retrieving the latest version.
func TestSecretVersionRepositoryGetLatestVersion(t *testing.T) {
	cleanup := setupVersioningTestDB(t)
	defer cleanup()

	// Set up configuration
	viper.Set("master_key", generateMasterKey(t))
	viper.Set("log.file", "test_versioning.log")
	log := logging.InitLogger()
	defer os.Remove("test_versioning.log")

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	repo := NewSecretVersionRepository(db.DB, log)

	// Create versions out of order
	versions := []*SecretVersion{
		{
			ID:        uuid.New(),
			SecretID:  secretID,
			UserID:    userID,
			Name:      "test-secret",
			Value:     "value-v1",
			Version:   1,
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New(),
			SecretID:  secretID,
			UserID:    userID,
			Name:      "test-secret",
			Value:     "value-v3",
			Version:   3,
			CreatedAt: time.Now().Add(2 * time.Minute),
		},
		{
			ID:        uuid.New(),
			SecretID:  secretID,
			UserID:    userID,
			Name:      "test-secret",
			Value:     "value-v2",
			Version:   2,
			CreatedAt: time.Now().Add(time.Minute),
		},
	}

	for _, v := range versions {
		err := repo.CreateVersion(ctx, v)
		assert.NoError(t, err)
	}

	// Retrieve latest version
	latest, err := repo.GetLatestVersion(ctx, secretID)
	assert.NoError(t, err)
	assert.Equal(t, 3, latest.Version)
	assert.Equal(t, "value-v3", latest.Value)

	// Test with no versions
	emptySecretID := uuid.New()
	_, err = repo.GetLatestVersion(ctx, emptySecretID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no versions found")
}

// TestSecretVersionRepositoryDeleteVersions tests deleting all versions of a secret.
func TestSecretVersionRepositoryDeleteVersions(t *testing.T) {
	cleanup := setupVersioningTestDB(t)
	defer cleanup()

	// Set up configuration
	viper.Set("master_key", generateMasterKey(t))
	viper.Set("log.file", "test_versioning.log")
	log := logging.InitLogger()
	defer os.Remove("test_versioning.log")

	ctx := context.Background()
	userID := uuid.New()
	secretID1 := uuid.New()
	secretID2 := uuid.New()

	repo := NewSecretVersionRepository(db.DB, log)

	// Create versions for two different secrets
	for i := 1; i <= 2; i++ {
		version1 := &SecretVersion{
			ID:        uuid.New(),
			SecretID:  secretID1,
			UserID:    userID,
			Name:      "secret1",
			Value:     "value1-v" + string(rune(i+'0')),
			Version:   i,
			CreatedAt: time.Now(),
		}
		version2 := &SecretVersion{
			ID:        uuid.New(),
			SecretID:  secretID2,
			UserID:    userID,
			Name:      "secret2",
			Value:     "value2-v" + string(rune(i+'0')),
			Version:   i,
			CreatedAt: time.Now(),
		}
		err := repo.CreateVersion(ctx, version1)
		assert.NoError(t, err)
		err = repo.CreateVersion(ctx, version2)
		assert.NoError(t, err)
	}

	// Delete versions for secret1
	err := repo.DeleteVersions(ctx, secretID1)
	assert.NoError(t, err)

	// Verify secret1 versions are deleted
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM secret_versions WHERE secret_id = ?", secretID1.String()).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 0, count, "secret1 versions should be deleted")

	// Verify secret2 versions still exist
	err = db.DB.QueryRow("SELECT COUNT(*) FROM secret_versions WHERE secret_id = ?", secretID2.String()).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 2, count, "secret2 versions should still exist")
}

// TestSecretVersioningIntegration tests the integration between SecretRepository and SecretVersionRepository.
func TestSecretVersioningIntegration(t *testing.T) {
	cleanup := setupVersioningTestDB(t)
	defer cleanup()

	// Set up configuration
	viper.Set("master_key", generateMasterKey(t))
	viper.Set("log.file", "test_versioning.log")
	log := logging.InitLogger()
	defer os.Remove("test_versioning.log")

	ctx := context.Background()
	userID := uuid.New()

	// Create a user first
	_, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, totp_secret, role) VALUES (?, ?, ?, ?, ?)",
		userID.String(), "testuser", "hash", "secret", "user")
	assert.NoError(t, err)

	secretRepo := NewSecretRepository(db.DB, log)
	versionRepo := NewSecretVersionRepository(db.DB, log)

	// Create initial secret
	secret := &Secret{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "integration-test-secret",
		Value:     "initial-value",
		Version:   1,
		Tags:      []string{"test"},
		CreatedAt: time.Now(),
	}

	err = secretRepo.Create(ctx, secret)
	assert.NoError(t, err)

	// Update secret (should create version)
	secret.Value = "updated-value"
	secret.Version = 2
	err = secretRepo.Update(ctx, secret)
	assert.NoError(t, err)

	// Verify version was created
	versions, err := versionRepo.GetVersions(ctx, secret.ID)
	assert.NoError(t, err)
	assert.Len(t, versions, 1, "should have 1 version after update")
	assert.Equal(t, 1, versions[0].Version)
	assert.Equal(t, "initial-value", versions[0].Value)

	// Update again
	secret.Value = "final-value"
	secret.Version = 3
	err = secretRepo.Update(ctx, secret)
	assert.NoError(t, err)

	// Verify versions
	versions, err = versionRepo.GetVersions(ctx, secret.ID)
	assert.NoError(t, err)
	assert.Len(t, versions, 2, "should have 2 versions after second update")
	assert.Equal(t, 2, versions[0].Version) // Latest first
	assert.Equal(t, "updated-value", versions[0].Value)
	assert.Equal(t, 1, versions[1].Version)
	assert.Equal(t, "initial-value", versions[1].Value)

	// Test GetLatestVersion
	latest, err := versionRepo.GetLatestVersion(ctx, secret.ID)
	assert.NoError(t, err)
	assert.Equal(t, 2, latest.Version)
	assert.Equal(t, "updated-value", latest.Value)

	// Delete secret (should delete versions)
	err = secretRepo.Delete(ctx, secret.ID)
	assert.NoError(t, err)

	// Verify versions are deleted
	versions, err = versionRepo.GetVersions(ctx, secret.ID)
	assert.NoError(t, err)
	assert.Len(t, versions, 0, "versions should be deleted when secret is deleted")
}
