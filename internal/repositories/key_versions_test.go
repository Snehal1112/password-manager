package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

func TestKeyVersions_CreateAndList(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(db, log)

	keyID := uuid.New()
	userID := uuid.New()

	k := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "versioned",
		Type:      model.KeyTypeRSA,
		Value:     "pem-v1",
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(context.Background(), k))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))

	versions, err := repo.ListVersions(context.Background(), keyID, userID)
	require.NoError(t, err)
	require.Len(t, versions, 2)
	require.Equal(t, 2, versions[1].Version)
}
