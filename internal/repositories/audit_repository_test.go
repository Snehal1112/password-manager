package repositories_test

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
)

func openAuditTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_logs (
		id      TEXT PRIMARY KEY,
		user_id TEXT,
		action  TEXT NOT NULL,
		details TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	return db
}

func TestAuditRepository_PersistAudit(t *testing.T) {
	db := openAuditTestDB(t)
	repo := repositories.NewAuditRepository(db)

	err := repo.PersistAudit("user-1", "create_secret", "status=success message=done")
	require.NoError(t, err)

	var count int
	err = db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id = ? AND action = ?",
		"user-1", "create_secret",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify the stored field values, not just the count.
	var storedUserID, storedAction, storedDetails string
	err = db.QueryRowContext(context.Background(),
		"SELECT user_id, action, details FROM audit_logs WHERE user_id = ? AND action = ?",
		"user-1", "create_secret",
	).Scan(&storedUserID, &storedAction, &storedDetails)
	require.NoError(t, err)
	assert.Equal(t, "user-1", storedUserID)
	assert.Equal(t, "create_secret", storedAction)
	assert.Equal(t, "status=success message=done", storedDetails)
}

func TestAuditRepository_PersistAudit_EmptyUserID(t *testing.T) {
	db := openAuditTestDB(t)
	repo := repositories.NewAuditRepository(db)

	// Empty user_id is valid (unauthenticated events like auth failures).
	err := repo.PersistAudit("", "auth", "status=failed message=missing token")
	require.NoError(t, err)

	var count int
	err = db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id IS NULL OR user_id = ''",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestAuditRepository_PersistAudit_MultipleRecords(t *testing.T) {
	db := openAuditTestDB(t)
	repo := repositories.NewAuditRepository(db)

	for i := 0; i < 5; i++ {
		err := repo.PersistAudit("user-2", "get_key", "status=success")
		require.NoError(t, err)
	}

	var count int
	err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id = ?", "user-2",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}
