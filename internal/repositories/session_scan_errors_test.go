package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// setupSessionTestDB creates an in-memory SQLite database with the
// user_sessions table. Named distinctly from the package-scope setupTestDB
// and setupRotationTestDB helpers that already exist in this test package.
func setupSessionTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:sessiontest_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE user_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			refresh_token_hash TEXT NOT NULL,
			device_info TEXT NOT NULL DEFAULT '',
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMP NOT NULL,
			last_used_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at TIMESTAMP,
			revoked_reason TEXT
		);
	`)
	require.NoError(t, err, "create user_sessions schema")

	return raw
}

// TestGetActiveSessionsReturnsEveryMatchingRow is regression coverage for the
// F1 fix. It cannot go red before the fix -- see the note in the plan -- so it
// pins the well-formed path instead: every stored active session for the user
// is returned, and revoked/expired ones are not.
func TestGetActiveSessionsReturnsEveryMatchingRow(t *testing.T) {
	raw := setupSessionTestDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{
		DB:     rvdb.NewConn(raw, rvdb.SQLite),
		Logger: logging.InitLogger(),
	})

	userID := uuid.New()
	ctx := context.Background()
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	insert := func(hash string, expiresAt time.Time, revoked bool) {
		t.Helper()
		_, err := raw.ExecContext(ctx,
			`INSERT INTO user_sessions
			 (id, user_id, refresh_token_hash, expires_at, last_used_at, created_at, revoked)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			uuid.New().String(), userID.String(), hash, expiresAt, time.Now(), time.Now(), revoked)
		require.NoError(t, err, "insert session %s", hash)
	}

	insert("hash-active-a", future, false)
	insert("hash-active-b", future, false)
	insert("hash-revoked", future, true)
	insert("hash-expired", past, false)

	sessions, err := repo.GetActiveSessionsByUserID(ctx, userID)
	require.NoError(t, err)
	require.Len(t, sessions, 2, "both active sessions, neither the revoked nor the expired one")
	for _, s := range sessions {
		require.Equal(t, userID, s.UserID, "user id parsed, not left as uuid.Nil")
	}
}
