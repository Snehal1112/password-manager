package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestUserRolesTable_CreatedOnFreshInstall(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	d := &DBRepository{dialect: SQLite}
	d.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, d.createOptimizedSchema(conn))

	var name string
	err = conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='user_roles'`,
	).Scan(&name)
	require.NoError(t, err, "user_roles table must exist after createOptimizedSchema")
	require.Equal(t, "user_roles", name)

	// UNIQUE(user_id, role) must reject an exact duplicate but allow a
	// second, different role for the same user.
	_, err = conn.Exec(`INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'alice', 'h', 'admin')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO user_roles (id, user_id, role) VALUES ('r1', 'u1', 'admin')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO user_roles (id, user_id, role) VALUES ('r2', 'u1', 'admin')`)
	require.Error(t, err, "duplicate (user_id, role) must be rejected")
	_, err = conn.Exec(`INSERT INTO user_roles (id, user_id, role) VALUES ('r3', 'u1', 'secrets_manager')`)
	require.NoError(t, err, "a second, different role for the same user must be allowed")
}

func TestUserRolesBackfill_SplitsLegacyCommaJoinedRoles(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	repo := &DBRepository{dialect: SQLite}
	repo.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, repo.createOptimizedSchema(conn))

	// Seed users the way pre-migration data actually looks: a plain single
	// role, a legacy comma-joined pair (the exact historical shape from the
	// Oct 2025 commit), and a messy-whitespace duplicate-laden variant.
	seed := []struct{ id, username, role string }{
		{"u1", "alice", "admin"},
		{"u2", "bob", "secrets_manager, crypto_manager"},
		{"u3", "carol", "user,  user , admin"},
		{"u4", "dave", ""},
		{"u5", "erin", ",  , "},
	}
	for _, u := range seed {
		_, err := conn.Exec(
			`INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, 'h', ?)`,
			u.id, u.username, u.role,
		)
		require.NoError(t, err)
	}

	require.NoError(t, repo.migrateSchema(conn))

	assertRoles := func(userID string, want []string) {
		rows, err := conn.Query(`SELECT role FROM user_roles WHERE user_id = ? ORDER BY role`, userID)
		require.NoError(t, err)
		defer rows.Close()
		var got []string
		for rows.Next() {
			var r string
			require.NoError(t, rows.Scan(&r))
			got = append(got, r)
		}
		require.ElementsMatch(t, want, got, "user_id=%s", userID)
	}

	assertRoles("u1", []string{"admin"})
	assertRoles("u2", []string{"crypto_manager", "secrets_manager"})
	assertRoles("u3", []string{"admin", "user"}) // deduped

	// Empty / comma-only role columns must not leave a user with zero
	// user_roles rows -- the migration falls back to the least-privilege
	// "user" role rather than silently producing no row at all.
	assertRoles("u4", []string{"user"})
	assertRoles("u5", []string{"user"})

	// Idempotency: running migrateSchema() again must not error or duplicate rows.
	require.NoError(t, repo.migrateSchema(conn))
	assertRoles("u3", []string{"admin", "user"})
	assertRoles("u4", []string{"user"})
	assertRoles("u5", []string{"user"})
}

// TestMigrateSchema_UserRoles_UpgradesLegacyDatabase exercises the true
// migrate-only upgrade path: an old-shape database that has never seen
// createOptimizedSchema's copy of user_roles, with a user already present.
// Both tests above call createOptimizedSchema() first, which already creates
// user_roles via its own "CREATE TABLE IF NOT EXISTS" -- so migrateSchema's
// own "CREATE TABLE IF NOT EXISTS user_roles" is never actually the thing
// under test there. This test hand-rolls the legacy schema, following the
// pattern in certificate_ca_cert_id_migration_test.go, so migrateSchema is
// the only thing that can create the table and backfill the seeded user.
func TestMigrateSchema_UserRoles_UpgradesLegacyDatabase(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// Minimal pre-feature schema: the tables migrateSchema touches, in shapes
	// that predate user_roles. No user_roles table anywhere yet.
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
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL, description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO users (id, username, role) VALUES ('legacy-1', 'legacy-admin', 'admin');
	`)
	require.NoError(t, err)

	// Confirm the fixture really has no user_roles table before migrateSchema runs.
	var beforeName sql.NullString
	err = conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='user_roles'`,
	).Scan(&beforeName)
	require.ErrorIs(t, err, sql.ErrNoRows, "fixture must not have user_roles before migrateSchema runs")

	repo := &DBRepository{dialect: SQLite}
	repo.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, repo.migrateSchema(conn))

	var afterName string
	err = conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='user_roles'`,
	).Scan(&afterName)
	require.NoError(t, err, "migrateSchema must create user_roles on a legacy database")
	require.Equal(t, "user_roles", afterName)

	var role string
	err = conn.QueryRow(`SELECT role FROM user_roles WHERE user_id = ?`, "legacy-1").Scan(&role)
	require.NoError(t, err, "the pre-existing legacy user must be backfilled into user_roles")
	require.Equal(t, "admin", role)

	// A second run must not error and must not duplicate the backfilled row.
	require.NoError(t, repo.migrateSchema(conn))
	var count int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM user_roles WHERE user_id = ?`, "legacy-1").Scan(&count))
	require.Equal(t, 1, count, "a second migrateSchema run must not duplicate the backfilled row")
}
