package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupSecretTestDB creates an in-memory SQLite database for secret repository tests.
func setupSecretTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id               TEXT PRIMARY KEY,
		user_id          TEXT NOT NULL,
		vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name             TEXT NOT NULL,
		value            TEXT NOT NULL,
		version          INTEGER NOT NULL,
		created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at       TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type     TEXT NOT NULL DEFAULT '',
		enabled          BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at       TIMESTAMP NULL,
		not_before       TIMESTAMP NULL
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestSecretLogger creates a logger suitable for use in repository tests.
func newTestSecretLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func TestSecretRepository_ReadByOwner_WrongUserReturnsError(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	otherID := uuid.New()
	secret := &model.Secret{
		ID:              uuid.New(),
		UserID:          ownerID,
		Name:            "my-secret",
		Value:           "encrypted-data",
		Version:         1,
		CreatedAt:       time.Now().UTC(),
		PurgeProtection: false,
	}
	require.NoError(t, repo.Create(ctx, secret))

	// Owner can read their own secret.
	found, err := repo.ReadByOwner(ctx, secret.ID, ownerID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, found.ID)
	assert.Equal(t, ownerID, found.UserID)

	// Non-owner must receive an error — no data returned.
	_, err = repo.ReadByOwner(ctx, secret.ID, otherID)
	assert.Error(t, err, "ReadByOwner must fail for a wrong user_id")
	assert.Contains(t, err.Error(), "not found")
}

func TestSecretRepository_ReadByOwner_SoftDeletedSecretNotVisible(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	secret := &model.Secret{
		ID:              uuid.New(),
		UserID:          ownerID,
		Name:            "deleted-secret",
		Value:           "encrypted-data",
		Version:         1,
		CreatedAt:       time.Now().UTC(),
		PurgeProtection: false,
	}
	require.NoError(t, repo.Create(ctx, secret))
	require.NoError(t, repo.SoftDelete(ctx, secret.ID))

	// Even the owner cannot read a soft-deleted secret via ReadByOwner.
	_, err := repo.ReadByOwner(ctx, secret.ID, ownerID)
	assert.Error(t, err, "ReadByOwner must not return a soft-deleted secret")
	assert.Contains(t, err.Error(), "not found")
}

// TestSecretLifecycleAttributes_PersistAndLoad verifies that enabled, expires_at,
// and not_before are stored and loaded correctly from the database.
func TestSecretLifecycleAttributes_PersistAndLoad(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestSecretLogger(t))

	now := time.Now()
	exp := now.Add(24 * time.Hour)
	nbf := now.Add(-1 * time.Hour)

	s := &model.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "test-lifecycle",
		Value:     "encrypted-value",
		Version:   1,
		CreatedAt: now,
		Enabled:   true,
		ExpiresAt: &exp,
		NotBefore: &nbf,
	}
	require.NoError(t, repo.Create(context.Background(), s))

	loaded, err := repo.Read(context.Background(), s.ID)
	require.NoError(t, err)
	require.True(t, loaded.Enabled)
	require.NotNil(t, loaded.ExpiresAt)
	require.WithinDuration(t, exp, *loaded.ExpiresAt, time.Second)
	require.NotNil(t, loaded.NotBefore)
}

// TestSecretRepository_ListInVault_ScopesByVault verifies that ListInVault returns
// only secrets belonging to the requested vault.
func TestSecretRepository_ListInVault_ScopesByVault(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestSecretLogger(t))
	ctx := context.Background()
	vaultA, vaultB := uuid.New(), uuid.New()

	mk := func(name string, v uuid.UUID) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: v, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	require.NoError(t, repo.Create(ctx, mk("a", vaultA)))
	require.NoError(t, repo.Create(ctx, mk("b", vaultA)))
	require.NoError(t, repo.Create(ctx, mk("c", vaultB)))

	gotA, err := repo.ListInVault(ctx, vaultA, nil)
	require.NoError(t, err)
	require.Len(t, gotA, 2)
	gotB, err := repo.ListInVault(ctx, vaultB, nil)
	require.NoError(t, err)
	require.Len(t, gotB, 1)
}

// TestSecretRepository_SoftDeleteVaultContents_HidesFromList verifies that after
// soft-deleting a vault's contents, ListInVault returns nothing while
// ListInVaultIncludeDeleted still returns the rows.
func TestSecretRepository_SoftDeleteVaultContents_HidesFromList(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestSecretLogger(t))
	ctx := context.Background()
	vaultA := uuid.New()

	mk := func(name string) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	require.NoError(t, repo.Create(ctx, mk("a")))
	require.NoError(t, repo.Create(ctx, mk("b")))

	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultA, time.Now()))

	active, err := repo.ListInVault(ctx, vaultA, nil)
	require.NoError(t, err)
	require.Len(t, active, 0)

	all, err := repo.ListInVaultIncludeDeleted(ctx, vaultA, nil)
	require.NoError(t, err)
	require.Len(t, all, 2)
}

// TestSecretRepository_RecoverVaultContents_OnlyRestoresCascadeDeleted verifies that
// recovering a vault restores ONLY the rows the vault cascade soft-deleted (matched
// by the cascade timestamp), and does NOT resurrect a secret the user had
// individually soft-deleted earlier.
func TestSecretRepository_RecoverVaultContents_OnlyRestoresCascadeDeleted(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestSecretLogger(t))
	ctx := context.Background()
	vaultA := uuid.New()

	mk := func(name string) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	keep := mk("active")        // stays active
	indiv := mk("user-deleted") // user deletes this one individually, before vault delete
	require.NoError(t, repo.Create(ctx, keep))
	require.NoError(t, repo.Create(ctx, indiv))

	// User individually soft-deletes "user-deleted".
	require.NoError(t, repo.SoftDelete(ctx, indiv.ID))

	// Vault is deleted: cascade soft-deletes the remaining active rows at vaultDeletedAt.
	vaultDeletedAt := time.Now().Add(time.Hour) // distinct from the individual delete time
	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultA, vaultDeletedAt))

	// Vault is recovered: only the cascade-deleted rows should come back.
	require.NoError(t, repo.RecoverVaultContents(ctx, vaultA, vaultDeletedAt))

	active, err := repo.ListInVault(ctx, vaultA, nil)
	require.NoError(t, err)
	// Only "active" should be live again; "user-deleted" must remain soft-deleted.
	require.Len(t, active, 1)
	require.Equal(t, "active", active[0].Name)
}

// TestSoftDelete_PreservesPurgeProtection verifies that SoftDelete does not
// overwrite a pre-existing purge_protection = TRUE on a secret.
func TestSoftDelete_PreservesPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	secret := &model.Secret{
		ID:              uuid.New(),
		UserID:          ownerID,
		Name:            "protected-secret",
		Value:           "encrypted-data",
		Version:         1,
		CreatedAt:       time.Now().UTC(),
		PurgeProtection: false,
	}
	require.NoError(t, repo.Create(ctx, secret))

	// Enable purge protection directly — SecretRepositoryInterface has no SetPurgeProtection.
	_, err := db.ExecContext(ctx,
		"UPDATE secrets SET purge_protection = TRUE WHERE id = ?", secret.ID.String())
	require.NoError(t, err)

	// SoftDelete must not reset purge_protection to FALSE.
	require.NoError(t, repo.SoftDelete(ctx, secret.ID))

	var pp bool
	err = db.QueryRowContext(ctx,
		"SELECT purge_protection FROM secrets WHERE id = ?", secret.ID.String()).Scan(&pp)
	require.NoError(t, err)
	assert.True(t, pp, "SoftDelete must not overwrite purge_protection")
}
