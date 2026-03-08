package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// setupTestDB creates an in-memory SQLite database with the keys table.
// The table includes the soft-delete columns added by migrations.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "failed to open in-memory database")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP DEFAULT NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP DEFAULT NULL
		);
		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag)
		);
	`)
	require.NoError(t, err, "failed to create test schema")

	t.Cleanup(func() { db.Close() })

	return db
}

func TestKeySoftDelete(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	key := &domain.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "test-key",
		Type:      "rsa",
		Value:     "encrypted-private-key",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))

	// SoftDelete sets deleted_at, leaves row in table.
	require.NoError(t, repo.SoftDelete(ctx, key.ID))

	// Normal Read should return error (soft-deleted item not visible).
	_, err := repo.Read(ctx, key.ID)
	assert.Error(t, err)

	// ListSoftDeleted should include it.
	deleted, err := repo.ListSoftDeleted(ctx, userID)
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, key.ID, deleted[0].ID)
	assert.NotNil(t, deleted[0].DeletedAt)
}

func TestKeyPurge(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	key := &domain.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "purge-key",
		Type:      "rsa",
		Value:     "encrypted-private-key",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))
	require.NoError(t, repo.SoftDelete(ctx, key.ID))

	// Purge should permanently remove it.
	require.NoError(t, repo.PurgeKey(ctx, key.ID))

	deleted, err := repo.ListSoftDeleted(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, deleted)
}

func TestKeyPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	key := &domain.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "protected-key",
		Type:      "rsa",
		Value:     "encrypted-private-key",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))
	require.NoError(t, repo.SoftDelete(ctx, key.ID))
	require.NoError(t, repo.SetPurgeProtection(ctx, key.ID, true))

	// Purge should fail when purge_protection = true.
	err := repo.PurgeKey(ctx, key.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "purge protection")
}
