package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupKeyRotationPolicyTestDB creates an in-memory SQLite DB for key rotation
// policy tests.
func setupKeyRotationPolicyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT,
		role TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS key_rotation_policies (
		id                         TEXT PRIMARY KEY,
		key_id                     TEXT NOT NULL UNIQUE,
		user_id                    TEXT NOT NULL,
		vault_id                   TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		rotate_after_days          INTEGER NOT NULL DEFAULT 90,
		notify_before_expiry_days  INTEGER NOT NULL DEFAULT 30,
		expiry_days                INTEGER NOT NULL DEFAULT 365,
		enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
		created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

func newKeyRotationPolicyTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func TestKeyRotationPolicy_UpsertAndGet(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))

	keyID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()

	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 userID,
		VaultID:                vaultID,
		RotateAfterDays:        90,
		NotifyBeforeExpiryDays: 30,
		ExpiryDays:             365,
		Enabled:                true,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
	require.NoError(t, repo.Upsert(context.Background(), policy))

	scope := model.NewVaultScope(vaultID, uuid.New())
	loaded, err := repo.GetByKeyID(context.Background(), keyID, scope)
	require.NoError(t, err)
	require.Equal(t, 90, loaded.RotateAfterDays)
	require.True(t, loaded.Enabled)
}

func TestKeyRotationPolicy_UpsertUpdatesExisting(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))

	keyID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	now := time.Now()

	first := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultID,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(context.Background(), first))

	second := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultID,
		RotateAfterDays: 30, NotifyBeforeExpiryDays: 7, ExpiryDays: 180, Enabled: false,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(context.Background(), second))

	scope := model.NewVaultScope(vaultID, uuid.New())
	loaded, err := repo.GetByKeyID(context.Background(), keyID, scope)
	require.NoError(t, err)
	require.Equal(t, 30, loaded.RotateAfterDays)
	require.Equal(t, 7, loaded.NotifyBeforeExpiryDays)
	require.False(t, loaded.Enabled)
}

func TestKeyRotationPolicy_DeleteByKeyID(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))

	keyID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	now := time.Now()

	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultID,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(context.Background(), policy))

	scope := model.NewVaultScope(vaultID, uuid.New())
	require.NoError(t, repo.DeleteByKeyID(context.Background(), keyID, scope))

	_, err := repo.GetByKeyID(context.Background(), keyID, scope)
	require.Error(t, err)
}

func TestGetByKeyID_CrossVaultDenied(t *testing.T) {
	sqlDB := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	keyID, userID := uuid.New(), uuid.New()
	_, err := sqlDB.Exec(`INSERT INTO keys (id, user_id, vault_id, name, value, type) VALUES (?, ?, ?, 'k', 'v', 'RSA')`,
		keyID.String(), userID.String(), vaultA.String())
	require.NoError(t, err)

	now := time.Now()
	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultA,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	_, err = repo.GetByKeyID(ctx, keyID, model.NewVaultScope(vaultB, uuid.New()))
	require.Error(t, err, "a policy on a vault-A key must not be readable under vault B's scope")

	got, err := repo.GetByKeyID(ctx, keyID, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Equal(t, policy.ID, got.ID)
}

func TestDeleteByKeyID_CrossVaultDenied(t *testing.T) {
	sqlDB := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	keyID, userID := uuid.New(), uuid.New()
	_, err := sqlDB.Exec(`INSERT INTO keys (id, user_id, vault_id, name, value, type) VALUES (?, ?, ?, 'k', 'v', 'RSA')`,
		keyID.String(), userID.String(), vaultA.String())
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, repo.Upsert(ctx, &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultA,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}))

	require.Error(t, repo.DeleteByKeyID(ctx, keyID, model.NewVaultScope(vaultB, uuid.New())))
	require.NoError(t, repo.DeleteByKeyID(ctx, keyID, model.NewVaultScope(vaultA, uuid.New())))
}
