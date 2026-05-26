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

	"rocketvault/model"
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
			scheduled_purge_at TIMESTAMP DEFAULT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP NULL,
			not_before TIMESTAMP NULL,
			bits INTEGER NOT NULL DEFAULT 0,
			curve TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NULL
		);
		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag)
		);
		CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version)
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

	key := &model.Key{
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

func TestKeyRepository_UpdateSetsUpdatedAt(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "update-at-test-key",
		Type:      "rsa",
		Value:     "encrypted-private-key",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))

	// UpdatedAt must be nil before the first Update call.
	created, err := repo.Read(ctx, key.ID)
	require.NoError(t, err)
	assert.Nil(t, created.UpdatedAt, "UpdatedAt should be nil before first update")

	// Update the key and verify UpdatedAt is stamped.
	beforeUpdate := time.Now()
	created.Name = "update-at-test-key-renamed"
	require.NoError(t, repo.Update(ctx, created))

	updated, err := repo.Read(ctx, key.ID)
	require.NoError(t, err)
	require.NotNil(t, updated.UpdatedAt, "UpdatedAt must be non-nil after Update")
	assert.True(t, !updated.UpdatedAt.Before(beforeUpdate),
		"UpdatedAt (%v) should be at or after the time Update was called (%v)",
		updated.UpdatedAt, beforeUpdate)
	assert.True(t, !updated.UpdatedAt.Before(updated.CreatedAt),
		"UpdatedAt should not be before CreatedAt")
}

func TestKeyPurge(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	key := &model.Key{
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

	key := &model.Key{
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

// TestKeyLifecycleAttributes_PersistAndLoad verifies that enabled, expires_at,
// and not_before are stored and loaded correctly from the keys table.
func TestKeyLifecycleAttributes_PersistAndLoad(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)

	exp := time.Now().Add(24 * time.Hour)
	k := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		Value:     "encrypted",
		Enabled:   true,
		ExpiresAt: &exp,
	}
	require.NoError(t, repo.Create(context.Background(), k))

	loaded, err := repo.Read(context.Background(), k.ID)
	require.NoError(t, err)
	require.True(t, loaded.Enabled)
	require.NotNil(t, loaded.ExpiresAt)
}

// TestKeySoftDelete_PreservesPurgeProtection verifies that SoftDelete does not
// overwrite a pre-existing purge_protection = TRUE on a key.
func TestKeySoftDelete_PreservesPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "pp-key",
		Type:      "rsa",
		Value:     "encrypted-private-key",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))

	// Enable purge protection before soft-deleting.
	require.NoError(t, repo.SetPurgeProtection(ctx, key.ID, true))

	// SoftDelete must not reset purge_protection to FALSE.
	require.NoError(t, repo.SoftDelete(ctx, key.ID))

	var pp bool
	err := db.QueryRowContext(ctx,
		"SELECT purge_protection FROM keys WHERE id = ?", key.ID.String()).Scan(&pp)
	require.NoError(t, err)
	assert.True(t, pp, "SoftDelete must not overwrite purge_protection")
}
