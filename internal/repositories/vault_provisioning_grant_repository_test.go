package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func newGrantTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = database.Exec(`
		CREATE TABLE vault_provisioning_grants (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL UNIQUE,
			quota        INTEGER NOT NULL,
			created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by   TEXT NOT NULL
		);`)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() }) //nolint:errcheck,gosec
	return database
}

func newGrantRepo(t *testing.T) repositories.VaultProvisioningGrantRepositoryInterface {
	t.Helper()
	return repositories.NewVaultProvisioningGrantRepository(rvdb.NewConn(newGrantTestDB(t), rvdb.SQLite))
}

func TestGrantRepository_UpsertAndGet(t *testing.T) {
	repo := newGrantRepo(t)
	ctx := context.Background()
	principal := uuid.New()

	g := &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 5, CreatedBy: uuid.New(),
	}
	require.NoError(t, repo.Upsert(ctx, g))

	got, err := repo.GetByPrincipal(ctx, principal)
	require.NoError(t, err)
	require.Equal(t, 5, got.Quota)
	require.Equal(t, principal, got.PrincipalID)
}

func TestGrantRepository_UpsertReplacesQuota(t *testing.T) {
	repo := newGrantRepo(t)
	ctx := context.Background()
	principal := uuid.New()

	require.NoError(t, repo.Upsert(ctx, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 5, CreatedBy: uuid.New(),
	}))
	require.NoError(t, repo.Upsert(ctx, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 9, CreatedBy: uuid.New(),
	}))

	got, err := repo.GetByPrincipal(ctx, principal)
	require.NoError(t, err)
	require.Equal(t, 9, got.Quota, "second upsert must replace the quota, not insert a duplicate")

	all, err := repo.List(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1, "principal_id is UNIQUE: one row per principal")
}

func TestGrantRepository_GetMissingReturnsNotFound(t *testing.T) {
	repo := newGrantRepo(t)

	_, err := repo.GetByPrincipal(context.Background(), uuid.New())
	require.True(t, errors.Is(err, repositories.ErrNotFound),
		"a principal with no grant must be distinguishable from a lookup failure")
}

func TestGrantRepository_Delete(t *testing.T) {
	repo := newGrantRepo(t)
	ctx := context.Background()
	principal := uuid.New()

	require.NoError(t, repo.Upsert(ctx, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 3, CreatedBy: uuid.New(),
	}))
	require.NoError(t, repo.Delete(ctx, principal))

	_, err := repo.GetByPrincipal(ctx, principal)
	require.True(t, errors.Is(err, repositories.ErrNotFound))
}
