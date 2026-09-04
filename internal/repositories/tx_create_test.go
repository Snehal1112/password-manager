package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestVaultRepository_CreateTx_RollsBack(t *testing.T) {
	database := newVaultTestDB(t) // existing helper
	repo := repositories.NewVaultRepository(rvdb.NewConn(database, rvdb.SQLite), newTestVaultLogger(t))
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	concrete := repo.(*repositories.VaultRepository)
	require.NoError(t, concrete.CreateTx(ctx, tx, &model.Vault{
		ID: uuid.New(), Name: "rolled-back", CreatedBy: uuid.New(), RetentionDays: 90,
	}))
	require.NoError(t, tx.Rollback())

	_, err = repo.ReadByName(ctx, "rolled-back")
	require.Error(t, err, "a rolled-back CreateTx must leave no vault behind")
}

func TestVaultRepository_CreateTx_Commits(t *testing.T) {
	database := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(database, rvdb.SQLite), newTestVaultLogger(t))
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	concrete := repo.(*repositories.VaultRepository)
	require.NoError(t, concrete.CreateTx(ctx, tx, &model.Vault{
		ID: uuid.New(), Name: "committed", CreatedBy: uuid.New(), RetentionDays: 90,
	}))
	require.NoError(t, tx.Commit())

	got, err := repo.ReadByName(ctx, "committed")
	require.NoError(t, err)
	require.Equal(t, "committed", got.Name)
}
