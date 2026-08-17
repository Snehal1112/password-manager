// Regression test for the rotation_policies / key_rotation_policies vault_id
// migration. Proves migrateSchema adds the column to both tables on an
// old-shape database, that key_rotation_policies is backfilled from its
// parent key's real vault (not blindly defaulted), and that a second run is
// idempotent.
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

const defaultVaultID = "00000000-0000-0000-0000-00000000efa1"
const otherVaultID = "11111111-1111-1111-1111-111111111111"

func TestMigrateSchema_RotationPoliciesVaultID(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, err = conn.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL
		);
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
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, scheduled_purge_at TIMESTAMP NULL
		);
		-- keys pre-dates this migration's ADD COLUMN in real installs, but already
		-- has vault_id from the 2026-07-26 migration, which runs earlier in the
		-- same migrateSchema statement list.
		CREATE TABLE keys (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '`+defaultVaultID+`'
		);
		-- Old-shape rotation_policies: no vault_id column, has existing rows.
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
			description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		-- Old-shape key_rotation_policies: no vault_id column. One row's parent
		-- key (key-in-vault-b) is in a non-default vault.
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO rotation_policies (id, user_id, name, interval_days)
			VALUES ('11111111-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000001', 'p1', 30);
		INSERT INTO keys (id, name, vault_id) VALUES
			('33333333-0000-0000-0000-000000000001', 'key-in-default', '`+defaultVaultID+`'),
			('33333333-0000-0000-0000-000000000002', 'key-in-vault-b', '`+otherVaultID+`');
		INSERT INTO key_rotation_policies (id, key_id, user_id) VALUES
			('44444444-0000-0000-0000-000000000001', '33333333-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000001'),
			('44444444-0000-0000-0000-000000000002', '33333333-0000-0000-0000-000000000002', '22222222-0000-0000-0000-000000000001');
	`)
	require.NoError(t, err)

	require.False(t, columnExists(t, conn, "rotation_policies", "vault_id"))
	require.False(t, columnExists(t, conn, "key_rotation_policies", "vault_id"))

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.migrateSchema(conn), "first migrateSchema run should succeed")
	require.NoError(t, repo.migrateSchema(conn), "second migrateSchema run should be idempotent")

	require.True(t, columnExists(t, conn, "rotation_policies", "vault_id"))
	require.True(t, columnExists(t, conn, "key_rotation_policies", "vault_id"))

	// rotation_policies: blind default-vault backfill.
	var rpVault string
	require.NoError(t, conn.QueryRow(
		`SELECT vault_id FROM rotation_policies WHERE id = '11111111-0000-0000-0000-000000000001'`,
	).Scan(&rpVault))
	require.Equal(t, defaultVaultID, rpVault)

	// key_rotation_policies: JOIN-derived backfill, not blind default.
	var krpDefault, krpOther string
	require.NoError(t, conn.QueryRow(
		`SELECT vault_id FROM key_rotation_policies WHERE id = '44444444-0000-0000-0000-000000000001'`,
	).Scan(&krpDefault))
	require.Equal(t, defaultVaultID, krpDefault, "policy on default-vault key must backfill to the default vault")

	require.NoError(t, conn.QueryRow(
		`SELECT vault_id FROM key_rotation_policies WHERE id = '44444444-0000-0000-0000-000000000002'`,
	).Scan(&krpOther))
	require.Equal(t, otherVaultID, krpOther, "policy on vault-b key must backfill to vault b, not the default vault")
}

func TestMigrateSchema_KeyRotationPoliciesVaultIDIndexes(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(conn, SQLite), "fresh install should create both indexes directly")

	for _, idx := range []string{"idx_rotation_policies_vault_id", "idx_key_rotation_policies_vault_id"} {
		var name string
		row := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx)
		require.NoError(t, row.Scan(&name), "%s missing after fresh SetupSchema", idx)
	}
}
