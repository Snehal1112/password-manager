package repositories

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

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// newScopeTestSecretRepo builds a concrete *SecretRepository over an in-memory
// SQLite database carrying the full secrets schema.
func newScopeTestSecretRepo(t *testing.T) *SecretRepository {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

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
	);
	CREATE TABLE IF NOT EXISTS secret_tags (
		secret_id TEXT NOT NULL,
		tag       TEXT NOT NULL,
		PRIMARY KEY (secret_id, tag)
	)`)
	require.NoError(t, err)

	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: &logging.Logger{Logger: l}}
}

func seedScopeSecret(t *testing.T, repo *SecretRepository, ownerID, vaultID uuid.UUID, name string) *model.Secret {
	t.Helper()
	s := &model.Secret{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      name,
		Value:     "encrypted-" + name,
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
	}
	require.NoError(t, repo.Create(context.Background(), s))
	return s
}

func TestSecretReadScoped(t *testing.T) {
	repo := newScopeTestSecretRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	secret := seedScopeSecret(t, repo, ownerID, vaultA, "alpha")

	t.Run("vault scope matches", func(t *testing.T) {
		got, err := repo.ReadScoped(ctx, secret.ID, model.NewVaultScope(vaultA, otherUser))
		require.NoError(t, err)
		assert.Equal(t, secret.ID, got.ID)
		assert.Equal(t, vaultA, got.VaultID)
	})
	t.Run("wrong vault denies", func(t *testing.T) {
		_, err := repo.ReadScoped(ctx, secret.ID, model.NewVaultScope(vaultB, otherUser))
		assert.Error(t, err)
	})
	t.Run("owner scope matches", func(t *testing.T) {
		got, err := repo.ReadScoped(ctx, secret.ID, model.NewOwnerScope(vaultA, ownerID))
		require.NoError(t, err)
		assert.Equal(t, secret.ID, got.ID)
	})
	t.Run("wrong owner denies", func(t *testing.T) {
		_, err := repo.ReadScoped(ctx, secret.ID, model.NewOwnerScope(vaultA, otherUser))
		assert.Error(t, err)
	})
	t.Run("admin scope sees everything", func(t *testing.T) {
		got, err := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(otherUser))
		require.NoError(t, err)
		assert.Equal(t, secret.ID, got.ID)
	})
}

func TestSecretUpdateScoped(t *testing.T) {
	repo := newScopeTestSecretRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	secret := seedScopeSecret(t, repo, ownerID, vaultA, "beta")

	t.Run("vault member may write", func(t *testing.T) {
		updated := *secret
		updated.Name = "beta-renamed"
		updated.Version = 2
		require.NoError(t, repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultA, otherUser)))

		got, err := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
		require.NoError(t, err)
		assert.Equal(t, "beta-renamed", got.Name)
	})
	t.Run("wrong vault write is rejected", func(t *testing.T) {
		updated := *secret
		updated.Name = "should-not-land"
		err := repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultB, otherUser))
		require.Error(t, err)

		got, readErr := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
		require.NoError(t, readErr)
		assert.NotEqual(t, "should-not-land", got.Name)
	})
	t.Run("predicate comes from the scope not the entity", func(t *testing.T) {
		// The entity claims vaultA, but the scope says vaultB: the write must fail.
		updated := *secret
		updated.VaultID = vaultA
		updated.Name = "entity-wins"
		assert.Error(t, repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultB, otherUser)))
	})
}

func TestSecretListScoped(t *testing.T) {
	repo := newScopeTestSecretRepo(t)
	ctx := context.Background()

	ownerA, ownerB := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	live := seedScopeSecret(t, repo, ownerA, vaultA, "live")
	gone := seedScopeSecret(t, repo, ownerA, vaultA, "gone")
	seedScopeSecret(t, repo, ownerB, vaultB, "other-vault")
	require.NoError(t, repo.SoftDelete(ctx, gone.ID))

	t.Run("vault scope excludes deleted by default", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), SecretFilter{})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, live.ID, got[0].ID)
		assert.Equal(t, vaultA, got[0].VaultID)
	})
	t.Run("include deleted", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), SecretFilter{IncludeDeleted: true})
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
	t.Run("only deleted filters in SQL", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), SecretFilter{OnlyDeleted: true})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, gone.ID, got[0].ID)
		assert.NotNil(t, got[0].DeletedAt)
	})
	t.Run("owner scope ignores vault", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewOwnerScope(vaultB, ownerA), SecretFilter{})
		require.NoError(t, err)
		assert.Len(t, got, 1, "owner scope must not constrain vault_id")
	})
	t.Run("admin scope sees every vault", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewAdminScope(uuid.Nil), SecretFilter{})
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
}
