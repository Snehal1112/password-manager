package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestKeyVersions_CreateAndList(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

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

func TestKeyVersions_ReadVersionValue_ArchivedVersion(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v2", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))

	value, err := repo.ReadVersionValue(context.Background(), keyID, 1)
	require.NoError(t, err)
	require.Equal(t, "pem-v1", value)
}

func TestKeyVersions_ReadVersionValue_ImplicitVersionOneFallback(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	// Never rotated: zero key_versions rows. Version 1 must fall back to keys.value.
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-original", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	value, err := repo.ReadVersionValue(context.Background(), keyID, 1)
	require.NoError(t, err)
	require.Equal(t, "pem-original", value)
}

func TestKeyVersions_ReadVersionValue_NonexistentVersion(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v1", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	_, err := repo.ReadVersionValue(context.Background(), keyID, 5)
	require.ErrorIs(t, err, repositories.ErrKeyVersionNotFound)
}

func TestKeyVersions_GetVersion_ArchivedAndImplicit(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v1", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	// Implicit version 1 (never rotated) resolves from the key row.
	v, err := repo.GetVersion(context.Background(), keyID, 1, userID)
	require.NoError(t, err)
	require.Equal(t, 1, v.Version)
	require.Equal(t, keyID, v.KeyID)

	// Nonexistent version.
	_, err = repo.GetVersion(context.Background(), keyID, 2, userID)
	require.ErrorIs(t, err, repositories.ErrKeyVersionNotFound)

	// After rotation, version 1 is archived and version 2 exists.
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))
	v, err = repo.GetVersion(context.Background(), keyID, 2, userID)
	require.NoError(t, err)
	require.Equal(t, 2, v.Version)
}

// TestKeyVersions_CurrentVersion covers the LEFT-JOIN aggregate that the
// crypto service calls on every operation: a never-rotated key (zero
// key_versions rows) must resolve to the implicit 1, and a rotated key to
// the real maximum. An INNER JOIN here would return zero rows for the
// never-rotated case and fail instead of falling back to 1.
func TestKeyVersions_CurrentVersion(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v1", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	// Never rotated: zero key_versions rows resolve to the implicit 1.
	current, err := repo.CurrentVersion(context.Background(), keyID, userID)
	require.NoError(t, err)
	require.Equal(t, 1, current)

	// After two rotations the maximum archived version wins.
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 3, "pem-v3"))

	current, err = repo.CurrentVersion(context.Background(), keyID, userID)
	require.NoError(t, err)
	require.Equal(t, 3, current)
}

func TestKeyVersions_ListVersionRecords_IncludesValue(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v2", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	// Never rotated: zero records.
	records, err := repo.ListVersionRecords(context.Background(), keyID)
	require.NoError(t, err)
	require.Empty(t, records)

	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))

	records, err = repo.ListVersionRecords(context.Background(), keyID)
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Equal(t, "pem-v1", records[0].Value)
	require.Equal(t, 1, records[0].Version)
	require.Equal(t, "pem-v2", records[1].Value)
}

// TestVersionQueries_NotFilteredByOwner pins the contract these methods moved
// to: they return a key's versions by key ID alone. Authorization is the
// caller's scoped Read of the parent key, performed before these are reached.
// Before this change the queries joined keys and filtered k.user_id, so a
// lookup keyed on anyone but the owner returned nothing.
func TestVersionQueries_NotFilteredByOwner(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	ctx := context.Background()
	keyID := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: uuid.New(), Name: "rotated",
		Type: model.KeyTypeRSA, Value: "pem-v2", Enabled: true, CreatedAt: time.Now(),
	}))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 1, "pem-v1"))

	value, err := repo.ReadVersionValue(ctx, keyID, 1)
	require.NoError(t, err)
	require.Equal(t, "pem-v1", value)

	records, err := repo.ListVersionRecords(ctx, keyID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "pem-v1", records[0].Value)
}
