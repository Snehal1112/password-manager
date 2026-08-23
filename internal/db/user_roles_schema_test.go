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
