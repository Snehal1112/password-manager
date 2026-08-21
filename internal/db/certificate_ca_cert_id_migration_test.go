// Regression test for B37. Renewal cannot re-issue through the original CA
// unless the CA link survives creation, and it had nowhere to be stored:
// certificates has no ca_cert_id column. This proves migrateSchema adds it to
// an old-shape database and that a second run is idempotent.
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestMigrateSchema_CertificatesGetCACertID(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// Minimal pre-feature schema: the tables migrateSchema ALTERs, in shapes
	// that predate this column.
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
	`)
	require.NoError(t, err)

	repo := &DBRepository{dialect: SQLite}
	repo.log = &logging.Logger{Logger: newSilentLogrus()}

	require.NoError(t, repo.migrateSchema(conn))

	// The column exists, accepts a value, and reads back.
	_, err = conn.Exec(`INSERT INTO certificates (id, name, ca_cert_id) VALUES (?, ?, ?)`,
		"11111111-1111-1111-1111-111111111111", "leaf",
		"22222222-2222-2222-2222-222222222222")
	require.NoError(t, err)

	var caCertID sql.NullString
	err = conn.QueryRow(`SELECT ca_cert_id FROM certificates WHERE id = ?`,
		"11111111-1111-1111-1111-111111111111").Scan(&caCertID)
	require.NoError(t, err)
	require.True(t, caCertID.Valid)
	require.Equal(t, "22222222-2222-2222-2222-222222222222", caCertID.String)

	// A self-signed certificate leaves it NULL.
	_, err = conn.Exec(`INSERT INTO certificates (id, name) VALUES (?, ?)`,
		"33333333-3333-3333-3333-333333333333", "self-signed")
	require.NoError(t, err)

	var selfSigned sql.NullString
	err = conn.QueryRow(`SELECT ca_cert_id FROM certificates WHERE id = ?`,
		"33333333-3333-3333-3333-333333333333").Scan(&selfSigned)
	require.NoError(t, err)
	require.False(t, selfSigned.Valid, "a self-signed certificate must leave ca_cert_id NULL")

	// A second run must not error on the now-existing column.
	require.NoError(t, repo.migrateSchema(conn))
}
