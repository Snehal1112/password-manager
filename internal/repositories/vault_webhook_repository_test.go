package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupWebhookTestDB creates an in-memory SQLite database with just the
// vault_webhook_configs table. A shared-cache DSN keeps every pooled
// connection on the same schema, matching setupTestDB in key_soft_delete_test.go.
func setupWebhookTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:webhooktest_" + uuid.NewString() + "?mode=memory&cache=shared"
	database, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })

	_, err = database.Exec(`
		CREATE TABLE IF NOT EXISTS vault_webhook_configs (
			id                       TEXT PRIMARY KEY,
			vault_id                 TEXT NOT NULL UNIQUE,
			url                      TEXT NOT NULL,
			signing_secret_encrypted TEXT NOT NULL,
			enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
			created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
	require.NoError(t, err)
	return database
}

// newWebhookTestLogger mirrors newKeyRotationPolicyTestLogger in
// key_rotation_policy_repository_test.go: logging.Logger has no bare
// constructor, so tests build one directly around a logrus.Logger.
func newWebhookTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func newWebhookRepo(t *testing.T, database *sql.DB) repositories.VaultWebhookRepositoryInterface {
	t.Helper()
	return repositories.NewVaultWebhookRepository(rvdb.NewConn(database, rvdb.SQLite), newWebhookTestLogger(t))
}

func sampleConfig(vaultID uuid.UUID, url, ciphertext string) *model.VaultWebhookConfig {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.VaultWebhookConfig{
		ID:                     uuid.New(),
		VaultID:                vaultID,
		URL:                    url,
		SigningSecretEncrypted: ciphertext,
		Enabled:                true,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
}

func TestVaultWebhookRepository_Upsert_CreatesThenReplaces(t *testing.T) {
	database := setupWebhookTestDB(t)
	repo := newWebhookRepo(t, database)
	ctx := context.Background()
	vaultID := uuid.New()

	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultID, "https://first.example", "ct-1")))

	got, err := repo.GetByVaultID(ctx, vaultID)
	require.NoError(t, err)
	assert.Equal(t, "https://first.example", got.URL)
	assert.Equal(t, "ct-1", got.SigningSecretEncrypted)

	// A second Upsert for the same vault replaces rather than duplicating.
	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultID, "https://second.example", "ct-2")))

	got, err = repo.GetByVaultID(ctx, vaultID)
	require.NoError(t, err)
	assert.Equal(t, "https://second.example", got.URL)
	assert.Equal(t, "ct-2", got.SigningSecretEncrypted)

	var count int
	require.NoError(t, database.QueryRow(
		"SELECT COUNT(*) FROM vault_webhook_configs WHERE vault_id = ?", vaultID.String(),
	).Scan(&count))
	assert.Equal(t, 1, count, "Upsert must replace, never duplicate")
}

func TestVaultWebhookRepository_GetByVaultID_UnknownReturnsErrNotFound(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))

	_, err := repo.GetByVaultID(context.Background(), uuid.New())
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrNotFound), "expected ErrNotFound, got %v", err)
}

// TestVaultWebhookRepository_GetByVaultID_RealErrorIsNotErrNotFound proves a
// genuine failure is not laundered into a not-found, which would make a
// database outage look like an absent config.
func TestVaultWebhookRepository_GetByVaultID_RealErrorIsNotErrNotFound(t *testing.T) {
	database := setupWebhookTestDB(t)
	repo := newWebhookRepo(t, database)
	require.NoError(t, database.Close())

	_, err := repo.GetByVaultID(context.Background(), uuid.New())
	require.Error(t, err)
	assert.False(t, errors.Is(err, repositories.ErrNotFound), "a closed-DB error must not look like not-found")
}

func TestVaultWebhookRepository_DeleteByVaultID(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))
	ctx := context.Background()
	vaultID := uuid.New()
	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultID, "https://a.example", "ct")))

	require.NoError(t, repo.DeleteByVaultID(ctx, vaultID))

	_, err := repo.GetByVaultID(ctx, vaultID)
	assert.True(t, errors.Is(err, repositories.ErrNotFound))
}

// TestVaultWebhookRepository_DeleteByVaultID_UnknownIsNotAnError keeps delete
// idempotent: the vault-purge cleanup hook calls this for every purged vault,
// including the overwhelming majority that never configured a webhook.
func TestVaultWebhookRepository_DeleteByVaultID_UnknownIsNotAnError(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))
	assert.NoError(t, repo.DeleteByVaultID(context.Background(), uuid.New()))
}

func TestVaultWebhookRepository_Upsert_IsolatesVaults(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))
	ctx := context.Background()
	vaultA, vaultB := uuid.New(), uuid.New()

	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultA, "https://a.example", "ct-a")))
	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultB, "https://b.example", "ct-b")))

	gotA, err := repo.GetByVaultID(ctx, vaultA)
	require.NoError(t, err)
	assert.Equal(t, "https://a.example", gotA.URL)

	gotB, err := repo.GetByVaultID(ctx, vaultB)
	require.NoError(t, err)
	assert.Equal(t, "https://b.example", gotB.URL)
}
