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

// TestSecretRepositoryInterfaceExposesScopedMethods pins that service callers
// can reach the scope-aware API through the interface, not just the struct.
func TestSecretRepositoryInterfaceExposesScopedMethods(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	var repo repositories.SecretRepositoryInterface = repositories.NewSecretRepository(
		rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID, vaultID := uuid.New(), uuid.New()
	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      "iface-secret",
		Value:     "encrypted",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	got, err := repo.ReadScoped(ctx, secret.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)

	got.Name = "iface-secret-renamed"
	got.Version = 2
	require.NoError(t, repo.UpdateScoped(ctx, got, model.NewVaultScope(vaultID, ownerID)))

	list, err := repo.ListScoped(ctx, model.NewVaultScope(vaultID, ownerID), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "iface-secret-renamed", list[0].Name)
}
