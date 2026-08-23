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

	d := NewRepository(logging.InitLogger())
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

	repo := NewRepository(logging.InitLogger())
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
