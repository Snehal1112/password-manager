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

// TestGetRotationHistoryReportsCorruptRow pins the F1 fix: a row that cannot be
// parsed must surface as an error rather than being dropped from the returned
// slice. Before the fix this returned (1 row, nil error) for two stored rows --
// a silently short list the caller could not distinguish from a complete one.
func TestGetRotationHistoryReportsCorruptRow(t *testing.T) {
	raw := setupRotationTestDB(t)
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	repo := repositories.NewRotationPolicyRepository(conn, logging.InitLogger())

	secretID := uuid.New()
	ctx := context.Background()

	_, err := conn.ExecContext(ctx,
		`INSERT INTO secret_rotation_history
		 (id, secret_id, policy_id, rotated_at, previous_version, new_version, triggered_by, notes)
		 VALUES (?, ?, NULL, ?, 1, 2, 'scheduler', '')`,
		uuid.New().String(), secretID.String(), time.Now())
	require.NoError(t, err, "insert well-formed history row")

	_, err = conn.ExecContext(ctx,
		`INSERT INTO secret_rotation_history
		 (id, secret_id, policy_id, rotated_at, previous_version, new_version, triggered_by, notes)
		 VALUES (?, ?, NULL, ?, 2, 3, 'scheduler', '')`,
		"not-a-uuid", secretID.String(), time.Now())
	require.NoError(t, err, "insert history row with corrupt id")

	_, err = repo.GetRotationHistory(ctx, secretID)
	require.Error(t, err, "a corrupt history row must be reported, not silently dropped")
	require.Contains(t, err.Error(), "invalid rotation history id")
}
