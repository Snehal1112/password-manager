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

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupContentTypeTestDB creates an in-memory SQLite database for content_type tests.
func setupContentTypeTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type TEXT NOT NULL DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secret_tags (
		secret_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (secret_id, tag)
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
	return db
}

// newContentTypeTestLogger creates a logger suitable for content_type repository tests.
func newContentTypeTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func TestSecretRepositoryContentType(t *testing.T) {
	db := setupContentTypeTestDB(t)
	log := newContentTypeTestLogger(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	userID := uuid.New()
	secret := &model.Secret{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        "my-secret",
		Value:       "encrypted-value",
		Version:     1,
		CreatedAt:   time.Now(),
		ContentType: "application/json",
	}

	err := repo.Create(context.Background(), secret)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), secret.ID, model.NewOwnerScope(uuid.Nil, userID))
	require.NoError(t, err)
	assert.Equal(t, "application/json", got.ContentType)
}
