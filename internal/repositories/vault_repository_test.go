package repositories_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func newTestVaultLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func newVaultTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT);
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT 1,
			purge_protection BOOLEAN NOT NULL DEFAULT 0,
			retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL,
			tags TEXT NOT NULL DEFAULT '{}',
			updated_at TIMESTAMP NULL,
			updated_by TEXT NULL
		);`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestVaultRepository_CreateAndReadByName(t *testing.T) {
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(db, newTestVaultLogger(t))
	ctx := context.Background()

	v := &model.Vault{ID: uuid.New(), Name: "prod", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}
	require.NoError(t, repo.Create(ctx, v))

	got, err := repo.ReadByName(ctx, "prod")
	require.NoError(t, err)
	require.Equal(t, "prod", got.Name)
	require.True(t, got.Enabled)
}

func TestVaultRepository_SoftDeleteHidesFromReadByName(t *testing.T) {
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(db, newTestVaultLogger(t))
	ctx := context.Background()
	id := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Vault{ID: id, Name: "stg", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}))

	require.NoError(t, repo.SoftDelete(ctx, id))
	_, err := repo.ReadByName(ctx, "stg")
	require.Error(t, err)
}

func TestVaultRepository_ListAndListDeleted(t *testing.T) {
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(db, newTestVaultLogger(t))
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Vault{ID: a, Name: "alpha", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}))
	require.NoError(t, repo.Create(ctx, &model.Vault{ID: b, Name: "beta", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}))
	require.NoError(t, repo.SoftDelete(ctx, b))

	active, err := repo.List(ctx)
	require.NoError(t, err)
	require.Len(t, active, 1)
	require.Equal(t, "alpha", active[0].Name)

	deleted, err := repo.ListDeleted(ctx)
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	require.Equal(t, "beta", deleted[0].Name)
}

func TestVaultRepository_RecoverRestoresSoftDeleted(t *testing.T) {
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(db, newTestVaultLogger(t))
	ctx := context.Background()
	id := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Vault{ID: id, Name: "rec", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}))
	require.NoError(t, repo.SoftDelete(ctx, id))
	_, err := repo.ReadByName(ctx, "rec")
	require.Error(t, err) // hidden while soft-deleted

	require.NoError(t, repo.Recover(ctx, id))
	got, err := repo.ReadByName(ctx, "rec")
	require.NoError(t, err) // visible again after recover
	require.Equal(t, "rec", got.Name)
}
