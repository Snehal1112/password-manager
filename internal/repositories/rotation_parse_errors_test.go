// internal/repositories/rotation_parse_errors_test.go
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
	"rocketvault/model"
)

// setupRotationTestDB creates an in-memory SQLite database with the rotation
// tables. Named distinctly from key_soft_delete_test.go's package-scope
// setupTestDB, which already occupies that name in this test package. Returns
// *sql.DB and lets callers wrap it, matching setupCertLifecycleTestDB.
func setupRotationTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:rotationtest_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			interval_days INTEGER NOT NULL DEFAULT 90,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);
		CREATE TABLE secret_policies (
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			assigned_at TIMESTAMP NOT NULL,
			last_rotated_at TIMESTAMP,
			next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id)
		);
		CREATE TABLE secret_rotation_history (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT,
			rotated_at TIMESTAMP NOT NULL,
			previous_version INTEGER NOT NULL DEFAULT 0,
			new_version INTEGER NOT NULL DEFAULT 0,
			triggered_by TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT ''
		);
	`)
	require.NoError(t, err, "create rotation schema")

	return raw
}

// TestReadRejectsMalformedVaultID pins the F6 fix: a corrupt vault_id column
// must surface as an error, not silently become uuid.Nil. uuid.Nil is a
// meaningful value here -- model.NewAdminScope(uuid.Nil) is a real privileged
// scope -- so substituting it for corrupt data is strictly worse than failing.
func TestReadRejectsMalformedVaultID(t *testing.T) {
	raw := setupRotationTestDB(t)
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	repo := repositories.NewRotationPolicyRepository(conn, logging.InitLogger())

	policyID := uuid.New()
	userID := uuid.New()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO rotation_policies
		 (id, user_id, vault_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		policyID.String(), userID.String(), "not-a-uuid", "nightly", "", 90, true, 7, false,
		time.Now(), time.Now())
	require.NoError(t, err, "insert policy with corrupt vault_id")

	_, err = repo.Read(context.Background(), policyID, model.NewAdminScope(userID))
	require.Error(t, err, "a malformed vault_id must be an error, not uuid.Nil")
	require.Contains(t, err.Error(), "vault id")
}
