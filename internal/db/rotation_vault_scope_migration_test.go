// Regression test for the rotation_policies / key_rotation_policies vault_id
// migration. Proves migrateSchema adds the column to both tables on an
// old-shape database, that key_rotation_policies is backfilled from its
// parent key's real vault (not blindly defaulted), and that a second run is
// idempotent.
package db

import (
	"bytes"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
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
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE, retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL, scheduled_purge_at TIMESTAMP NULL
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

// TestSetupSchema_UpgradesOldShapeRotationPoliciesWithoutError reproduces the
// real upgrade path -- SetupSchema (createOptimizedSchema, then
// migrateSchema), not migrateSchema in isolation -- against a database whose
// rotation_policies/key_rotation_policies tables predate vault_id.
//
// This is the regression test that was missing when vault_id was added to
// these two tables: createOptimizedSchema's CREATE TABLE IF NOT EXISTS is a
// safe no-op on an old-shaped table, but it used to be followed, in the same
// batch, by CREATE INDEX ... (vault_id) -- not a no-op, and fatal with "no
// such column: vault_id" on exactly this database shape. Because
// createOptimizedSchema runs before migrateSchema inside SetupSchema, that
// failure aborted the whole call before migrateSchema's correct ALTER TABLE
// ever ran, so no real upgrade could ever self-heal. TestMigrateSchema_Rota-
// tionPoliciesVaultID above calls migrateSchema directly and never exercised
// this ordering; TestMigrateSchema_KeyRotationPoliciesVaultIDIndexes calls
// SetupSchema but only against a fresh database, where the bug can't
// reproduce because the tables don't pre-exist.
func TestSetupSchema_UpgradesOldShapeRotationPoliciesWithoutError(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, err = conn.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
			totp_secret TEXT, role TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		-- Old-shape rotation_policies and key_rotation_policies: no vault_id
		-- column, matching a database created before commit 57bfa2b.
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
			description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	require.False(t, columnExists(t, conn, "rotation_policies", "vault_id"))
	require.False(t, columnExists(t, conn, "key_rotation_policies", "vault_id"))

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(conn, SQLite),
		"SetupSchema must upgrade an old-shape database in place, not fail on 'no such column: vault_id'")

	require.True(t, columnExists(t, conn, "rotation_policies", "vault_id"))
	require.True(t, columnExists(t, conn, "key_rotation_policies", "vault_id"))

	for _, idx := range []string{"idx_rotation_policies_vault_id", "idx_key_rotation_policies_vault_id"} {
		var name string
		row := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx)
		require.NoError(t, row.Scan(&name), "%s missing after upgrading an old-shape database", idx)
	}

	// A second run must remain idempotent, matching every other SetupSchema caller.
	require.NoError(t, repo.SetupSchema(conn, SQLite), "second SetupSchema run should be idempotent")
}

// newCapturingRepo returns a DBRepository whose logger writes to the returned
// buffer, so a test can assert on log output. Warn level keeps the buffer to
// just the diagnostics under test.
func newCapturingRepo(t *testing.T) (*DBRepository, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	l.SetLevel(logrus.WarnLevel)
	return NewRepository(logging.WrapLogrus(l)), &buf
}

// seedRotationPairingSchema creates the minimal secrets/rotation_policies/
// secret_policies shape warnMismatchedRotationPolicyVaults joins across.
func seedRotationPairingSchema(t *testing.T, conn *sql.DB) {
	t.Helper()
	_, err := conn.Exec(`
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '` + defaultVaultID + `'
		);
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '` + defaultVaultID + `',
			name TEXT NOT NULL, interval_days INTEGER NOT NULL
		);
		CREATE TABLE secret_policies (
			secret_id TEXT NOT NULL, policy_id TEXT NOT NULL,
			PRIMARY KEY (secret_id, policy_id)
		);
	`)
	require.NoError(t, err)
}

// TestWarnMismatchedRotationPolicyVaults_ReportsCrossVaultPairing is the
// diagnostic half of this migration: a secret in vault B paired with a policy
// left in the default vault by the blind backfill is a pairing manual rotation
// can no longer act on from either vault, so the operator must be told.
func TestWarnMismatchedRotationPolicyVaults_ReportsCrossVaultPairing(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	seedRotationPairingSchema(t, conn)
	_, err = conn.Exec(`
		INSERT INTO secrets (id, name, vault_id) VALUES
			('55555555-0000-0000-0000-000000000001', 'secret-in-vault-b', '` + otherVaultID + `'),
			('55555555-0000-0000-0000-000000000002', 'secret-in-default', '` + defaultVaultID + `');
		INSERT INTO rotation_policies (id, user_id, vault_id, name, interval_days) VALUES
			('66666666-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000001', '` + defaultVaultID + `', 'p', 30);
		INSERT INTO secret_policies (secret_id, policy_id) VALUES
			('55555555-0000-0000-0000-000000000001', '66666666-0000-0000-0000-000000000001'),
			('55555555-0000-0000-0000-000000000002', '66666666-0000-0000-0000-000000000001');
	`)
	require.NoError(t, err)

	repo, buf := newCapturingRepo(t)
	repo.warnMismatchedRotationPolicyVaults(conn)

	out := buf.String()
	require.Contains(t, out, "Rotation policy assigned across vaults")
	require.Contains(t, out, "55555555-0000-0000-0000-000000000001", "the vault-B secret must be named in the warning")
	require.NotContains(t, out, "55555555-0000-0000-0000-000000000002", "a same-vault pairing must not warn")
}

// TestWarnMismatchedRotationPolicyVaults_SilentWhenConsistent pins the other
// half: a clean database must produce no diagnostic noise on every boot.
func TestWarnMismatchedRotationPolicyVaults_SilentWhenConsistent(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	seedRotationPairingSchema(t, conn)
	_, err = conn.Exec(`
		INSERT INTO secrets (id, name, vault_id) VALUES
			('55555555-0000-0000-0000-000000000003', 'secret-in-default', '` + defaultVaultID + `');
		INSERT INTO rotation_policies (id, user_id, vault_id, name, interval_days) VALUES
			('66666666-0000-0000-0000-000000000002', '22222222-0000-0000-0000-000000000001', '` + defaultVaultID + `', 'p', 30);
		INSERT INTO secret_policies (secret_id, policy_id) VALUES
			('55555555-0000-0000-0000-000000000003', '66666666-0000-0000-0000-000000000002');
	`)
	require.NoError(t, err)

	repo, buf := newCapturingRepo(t)
	repo.warnMismatchedRotationPolicyVaults(conn)
	require.Empty(t, buf.String(), "a consistent database must emit no warning")
}

// TestWarnMismatchedRotationPolicyVaults_ToleratesMissingTables proves the
// diagnostic can never break a migration: on a partially-built schema it warns
// about its own failure and returns instead of panicking or erroring out.
func TestWarnMismatchedRotationPolicyVaults_ToleratesMissingTables(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	repo, buf := newCapturingRepo(t)
	repo.warnMismatchedRotationPolicyVaults(conn)
	require.Contains(t, buf.String(), "Failed to check for cross-vault rotation-policy assignments")
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
