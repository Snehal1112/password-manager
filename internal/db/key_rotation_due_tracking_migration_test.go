// Regression test for the key_rotation_policies.last_rotated_at /
// next_rotation_at migration. Proves migrateSchema adds both columns to an
// old-shape database, that next_rotation_at is backfilled anchored on the
// migration's own run time (not the key's created_at -- a mass-rotation
// hazard, see docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md
// section 4), and that a second run is idempotent.
package db

import (
	"database/sql"
	"io"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func newSilentLogrus() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func TestMigrateSchema_KeyRotationPoliciesDueTracking(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, err = conn.Exec(`
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL);
		CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE certificates (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE audit_logs (id TEXT PRIMARY KEY);
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE, retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL, scheduled_purge_at TIMESTAMP NULL
		);
		CREATE TABLE keys (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			created_at TIMESTAMP NOT NULL
		);
		-- Old-shape rotation_policies (already vault_id-scoped from an earlier
		-- migration in real installs; irrelevant to this test, minimal shape).
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL, description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		-- Old-shape key_rotation_policies: already has vault_id (a later
		-- migration than this one in real installs) but no due-tracking columns.
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO keys (id, name, vault_id, created_at) VALUES
			('11111111-1111-1111-1111-111111111111', 'old-key', '00000000-0000-0000-0000-00000000efa1', '2020-01-01 00:00:00');
		INSERT INTO key_rotation_policies (id, key_id, user_id, rotate_after_days, enabled) VALUES
			('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333', 45, TRUE);
	`)
	require.NoError(t, err)

	repo := &DBRepository{dialect: SQLite}
	logger := &logging.Logger{Logger: newSilentLogrus()}
	repo.log = logger

	beforeMigration := time.Now().UTC()
	require.NoError(t, repo.migrateSchema(conn))
	afterMigration := time.Now().UTC()

	var lastRotatedAt sql.NullTime
	var nextRotationAt time.Time
	err = conn.QueryRow(`SELECT last_rotated_at, next_rotation_at FROM key_rotation_policies WHERE id = ?`,
		"22222222-2222-2222-2222-222222222222").Scan(&lastRotatedAt, &nextRotationAt)
	require.NoError(t, err)

	require.False(t, lastRotatedAt.Valid, "a never-rotated policy must not get a fabricated last_rotated_at")

	// next_rotation_at must be anchored on the migration's own run time (not
	// the key's 2020-01-01 created_at, which would make this policy
	// instantly overdue) plus its own rotate_after_days (45).
	wantEarliest := beforeMigration.AddDate(0, 0, 45).Add(-time.Minute)
	wantLatest := afterMigration.AddDate(0, 0, 45).Add(time.Minute)
	require.True(t, nextRotationAt.After(wantEarliest) && nextRotationAt.Before(wantLatest),
		"next_rotation_at = %v, want between %v and %v", nextRotationAt, wantEarliest, wantLatest)

	// Second run must be idempotent: no error, and next_rotation_at must not
	// be recomputed a second time now that it's already populated.
	require.NoError(t, repo.migrateSchema(conn))
	var nextRotationAtAfterSecondRun time.Time
	err = conn.QueryRow(`SELECT next_rotation_at FROM key_rotation_policies WHERE id = ?`,
		"22222222-2222-2222-2222-222222222222").Scan(&nextRotationAtAfterSecondRun)
	require.NoError(t, err)
	require.True(t, nextRotationAt.Equal(nextRotationAtAfterSecondRun),
		"a second migration run must not recompute an already-populated next_rotation_at")
}
