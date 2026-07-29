package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestKeyRepositoryInterfaceExposesScopedMethods(t *testing.T) {
	db := setupFullKeyDB(t)
	var repo repositories.KeyRepositoryInterface = repositories.NewKeyRepository(
		rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID, vaultID := uuid.New(), uuid.New()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      "iface-key",
		Type:      model.KeyTypeRSA,
		Value:     "encrypted",
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
		Bits:      2048,
	}
	require.NoError(t, repo.Create(ctx, key))

	got, err := repo.Read(ctx, key.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)

	got.Name = "iface-key-renamed"
	require.NoError(t, repo.Update(ctx, got, model.NewVaultScope(vaultID, ownerID)))

	list, err := repo.List(ctx, model.NewVaultScope(vaultID, ownerID), repositories.KeyFilter{Type: model.KeyTypeRSA})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "iface-key-renamed", list[0].Name)
}
