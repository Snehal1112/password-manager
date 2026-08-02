package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// seedPreMigrationDB builds a database in the pre-P2 shape: two vaults, three
// users (one a global admin), and objects owned across both vaults.
func seedPreMigrationDB(t *testing.T) (*sql.DB, map[string]string) {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Exec(`
		CREATE TABLE users (
			id       TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			role     TEXT NOT NULL
		);
		CREATE TABLE vaults (
			id             TEXT PRIMARY KEY,
			name           TEXT NOT NULL,
			enabled        BOOLEAN NOT NULL DEFAULT TRUE,
			retention_days INTEGER NOT NULL DEFAULT 90,
			created_by     TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE secrets (
			id       TEXT PRIMARY KEY,
			user_id  TEXT NOT NULL,
			vault_id TEXT NOT NULL
		);
		CREATE TABLE keys (
			id       TEXT PRIMARY KEY,
			user_id  TEXT NOT NULL,
			vault_id TEXT NOT NULL
		);
		CREATE TABLE certificates (
			id       TEXT PRIMARY KEY,
			user_id  TEXT NOT NULL,
			vault_id TEXT NOT NULL
		);
		CREATE TABLE role_assignments (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			role           TEXT NOT NULL,
			vault_id       TEXT NOT NULL,
			created_by     TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (principal_id, role, vault_id)
		);
	`)
	require.NoError(t, err)

	ids := map[string]string{
		"admin":  "11111111-1111-1111-1111-111111111111",
		"alice":  "22222222-2222-2222-2222-222222222222",
		"bob":    "33333333-3333-3333-3333-333333333333",
		"vaultA": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"vaultB": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
	}

	_, err = conn.Exec(`INSERT INTO users (id, username, role) VALUES (?, 'root', 'admin'), (?, 'alice', 'user'), (?, 'bob', 'user')`,
		ids["admin"], ids["alice"], ids["bob"])
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO vaults (id, name) VALUES (?, 'prod'), (?, 'staging')`,
		ids["vaultA"], ids["vaultB"])
	require.NoError(t, err)

	// Alice owns two secrets in vault A (one principal, one grant) and a key in B.
	_, err = conn.Exec(`INSERT INTO secrets (id, user_id, vault_id) VALUES ('s1', ?, ?), ('s2', ?, ?), ('s3', ?, ?)`,
		ids["alice"], ids["vaultA"], ids["alice"], ids["vaultA"], ids["bob"], ids["vaultB"])
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO keys (id, user_id, vault_id) VALUES ('k1', ?, ?)`,
		ids["alice"], ids["vaultB"])
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO certificates (id, user_id, vault_id) VALUES ('c1', ?, ?)`,
		ids["bob"], ids["vaultA"])
	require.NoError(t, err)

	return conn, ids
}

// TestPlanRoleBackfill asserts the exact derivation: secrets owners become
// Secrets Officer in the owning vault, keys owners Crypto Officer, certificates
// owners Certificates Officer, and every global admin becomes Key Vault
// Administrator in every vault.
func TestPlanRoleBackfill(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)

	type want struct{ principal, vault, role string }
	got := make([]want, 0, len(grants))
	for _, g := range grants {
		got = append(got, want{g.PrincipalID, g.VaultID, g.Role})
	}

	assert.ElementsMatch(t, []want{
		{ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer},
		{ids["bob"], ids["vaultB"], model.RoleKeyVaultSecretsOfficer},
		{ids["alice"], ids["vaultB"], model.RoleKeyVaultCryptoOfficer},
		{ids["bob"], ids["vaultA"], model.RoleKeyVaultCertificatesOfficer},
		{ids["admin"], ids["vaultA"], model.RoleKeyVaultAdministrator},
		{ids["admin"], ids["vaultB"], model.RoleKeyVaultAdministrator},
	}, got)

	// Vault names are resolved for readable preview output and summary logging.
	names := map[string]string{}
	for _, g := range grants {
		names[g.VaultID] = g.VaultName
	}
	assert.Equal(t, "prod", names[ids["vaultA"]])
	assert.Equal(t, "staging", names[ids["vaultB"]])
}

// TestPlanRoleBackfillIsStable asserts the output order is deterministic so a
// preview run and the migration report the same thing in the same sequence.
func TestPlanRoleBackfillIsStable(t *testing.T) {
	conn, _ := seedPreMigrationDB(t)
	first, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	second, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

// TestPlanRoleBackfillSkipsUnknownVault asserts an object whose vault_id has no
// vaults row produces no grant. role_assignments has a foreign key to vaults, so
// such a grant would fail to insert on PostgreSQL.
func TestPlanRoleBackfillSkipsUnknownVault(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	_, err := conn.Exec(`INSERT INTO secrets (id, user_id, vault_id) VALUES ('orphan', ?, 'cccccccc-cccc-cccc-cccc-cccccccccccc')`,
		ids["alice"])
	require.NoError(t, err)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	for _, g := range grants {
		assert.NotEqual(t, "cccccccc-cccc-cccc-cccc-cccccccccccc", g.VaultID)
	}
}

// TestPlanRoleBackfillSkipsMissingColumns asserts a source table lacking the
// ownership columns is skipped rather than failing the whole migration. Old
// databases predate secrets.vault_id.
func TestPlanRoleBackfillSkipsMissingColumns(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Exec(`
		CREATE TABLE vaults (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		INSERT INTO vaults (id, name) VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'prod');
	`)
	require.NoError(t, err)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	assert.Empty(t, grants)
}

// TestPlanRoleBackfillNoVaults returns nothing when the vaults table is empty.
func TestPlanRoleBackfillNoVaults(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Exec(`CREATE TABLE vaults (id TEXT PRIMARY KEY, name TEXT NOT NULL)`)
	require.NoError(t, err)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	assert.Empty(t, grants)
}
