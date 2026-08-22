// Regression tests for B50: a soft-deleted secret, key or certificate used to
// keep holding its (vault_id, name) slot, so a replacement of the same name in
// the same vault failed with a raw "UNIQUE constraint failed" from the driver
// even though the old resource was gone from every list and read path.
//
// finalizeVaultIndexes now builds the three per-vault unique indexes as PARTIAL
// indexes (WHERE deleted_at IS NULL) and drops each one first, because
// CREATE UNIQUE INDEX IF NOT EXISTS matches on the index NAME and would
// silently keep a pre-existing non-partial index of the same name.
//
// These tests use a real in-memory SQLite database and the real SetupSchema /
// finalizeVaultIndexes code -- a mocked database cannot reproduce a constraint
// violation, which is the whole subject here.
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// vaultResourceTables are the three tables carrying a per-vault unique name.
var vaultResourceTables = []string{"secrets", "keys", "certificates"}

// testUserID owns every resource row these tests insert.
const testUserID = "99999999-0000-0000-0000-000000000001"

// newSchemaDB opens an in-memory SQLite database, runs the real SetupSchema on
// it and seeds the owning user plus a second vault, so resource rows can be
// inserted into either vault.
func newSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(conn, SQLite))

	_, err = conn.Exec(
		`INSERT INTO users (id, username, password_hash, role) VALUES (?, 'b50-owner', 'hash', 'admin')`,
		testUserID)
	require.NoError(t, err)

	_, err = conn.Exec(
		`INSERT INTO vaults (id, name, created_by) VALUES (?, 'b50-other-vault', ?)`,
		otherVaultID, testUserID)
	require.NoError(t, err)

	return conn
}

// insertResource inserts one active row into a vault-scoped resource table,
// filling the table's NOT NULL columns with placeholder content. It returns the
// driver error rather than failing, so callers can assert on a constraint
// violation.
func insertResource(conn *sql.DB, table, id, name, vaultID string) error {
	var query string
	switch table {
	case "secrets":
		query = `INSERT INTO secrets (id, user_id, name, vault_id, value, version)
			VALUES (?, ?, ?, ?, 'encrypted-value', 1)`
	case "keys":
		query = `INSERT INTO keys (id, user_id, name, vault_id, value, type)
			VALUES (?, ?, ?, ?, 'encrypted-key', 'RSA')`
	case "certificates":
		query = `INSERT INTO certificates (id, user_id, name, vault_id, certificate, private_key)
			VALUES (?, ?, ?, ?, 'cert-pem', 'key-pem')`
	default:
		panic("unknown vault resource table: " + table)
	}
	_, err := conn.Exec(query, id, testUserID, name, vaultID)
	return err
}

// softDelete stamps deleted_at on one row, exactly as the repositories'
// SoftDelete methods do -- the row and its name stay in the table.
func softDelete(t *testing.T, conn *sql.DB, table, id string) {
	t.Helper()
	res, err := conn.Exec("UPDATE "+table+" SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "soft-delete should have stamped exactly one %s row", table)
}

// indexSQL returns the stored CREATE statement for an index, or "" when the
// index does not exist.
func indexSQL(t *testing.T, conn *sql.DB, name string) string {
	t.Helper()
	var stmt sql.NullString
	err := conn.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&stmt)
	if err == sql.ErrNoRows {
		return ""
	}
	require.NoError(t, err)
	return stmt.String
}

// TestVaultUniqueIndex_SoftDeletedNameIsReusable is the B50 fix itself: after a
// resource is soft-deleted, its name must be free for a replacement in the same
// vault, with no purge required.
func TestVaultUniqueIndex_SoftDeletedNameIsReusable(t *testing.T) {
	for _, table := range vaultResourceTables {
		t.Run(table, func(t *testing.T) {
			conn := newSchemaDB(t)

			require.NoError(t, insertResource(conn, table, "aaaa0000-0000-0000-0000-000000000001",
				"reissue-me", defaultVaultID), "creating the original %s should succeed", table)

			softDelete(t, conn, table, "aaaa0000-0000-0000-0000-000000000001")

			require.NoError(t, insertResource(conn, table, "aaaa0000-0000-0000-0000-000000000002",
				"reissue-me", defaultVaultID),
				"a %s must be creatable under the name of a soft-deleted one (B50)", table)
		})
	}
}

// TestVaultUniqueIndex_ActiveDuplicateStillRejected pins the constraint that
// must survive the fix: two ACTIVE resources still cannot share a name in one
// vault.
func TestVaultUniqueIndex_ActiveDuplicateStillRejected(t *testing.T) {
	for _, table := range vaultResourceTables {
		t.Run(table, func(t *testing.T) {
			conn := newSchemaDB(t)

			require.NoError(t, insertResource(conn, table, "bbbb0000-0000-0000-0000-000000000001",
				"taken", defaultVaultID))

			err := insertResource(conn, table, "bbbb0000-0000-0000-0000-000000000002",
				"taken", defaultVaultID)
			require.Error(t, err, "two active %s rows must not share a name in one vault", table)
			require.True(t, SQLite.IsConstraintErr(err),
				"the duplicate must fail as a unique-constraint violation, got: %v", err)
		})
	}
}

// TestVaultUniqueIndex_CrossVaultNamesAllowed confirms the partial predicate did
// not disturb vault isolation: the same name in two different vaults is fine.
func TestVaultUniqueIndex_CrossVaultNamesAllowed(t *testing.T) {
	for _, table := range vaultResourceTables {
		t.Run(table, func(t *testing.T) {
			conn := newSchemaDB(t)

			require.NoError(t, insertResource(conn, table, "cccc0000-0000-0000-0000-000000000001",
				"shared-name", defaultVaultID))
			require.NoError(t, insertResource(conn, table, "cccc0000-0000-0000-0000-000000000002",
				"shared-name", otherVaultID),
				"the same %s name in a different vault must stay legal", table)
		})
	}
}

// TestVaultUniqueIndex_PartialPredicateIsInSchema asserts the shipped index
// definition itself, not just its behavior, so a future refactor that drops the
// predicate is caught directly.
func TestVaultUniqueIndex_PartialPredicateIsInSchema(t *testing.T) {
	conn := newSchemaDB(t)

	for _, idx := range []string{"idx_secrets_vault_name", "idx_keys_vault_name", "idx_certificates_vault_name"} {
		stmt := indexSQL(t, conn, idx)
		require.NotEmpty(t, stmt, "%s must exist after SetupSchema", idx)
		require.Contains(t, stmt, "WHERE deleted_at IS NULL",
			"%s must be a partial index so soft-deleted rows release their name", idx)
	}
}

// TestFinalizeVaultIndexes_ReplacesLegacyNonPartialIndex is the upgrade-path
// case this bug class keeps reappearing in: a database that already carries the
// OLD, non-partial index under the same name. CREATE UNIQUE INDEX IF NOT EXISTS
// would be a silent no-op there and the old definition would survive the fix
// forever, so finalizeVaultIndexes drops each index first.
//
// The "already upgraded" database is simulated by running the real SetupSchema
// and then replacing all three indexes with their pre-fix, non-partial
// definitions -- the exact shape a deployment created before this fix has on
// disk.
func TestFinalizeVaultIndexes_ReplacesLegacyNonPartialIndex(t *testing.T) {
	conn := newSchemaDB(t)

	legacy := map[string]string{
		"idx_secrets_vault_name":      "secrets",
		"idx_keys_vault_name":         "keys",
		"idx_certificates_vault_name": "certificates",
	}
	for idx, table := range legacy {
		_, err := conn.Exec("DROP INDEX IF EXISTS " + idx)
		require.NoError(t, err)
		_, err = conn.Exec("CREATE UNIQUE INDEX " + idx + " ON " + table + "(vault_id, name)")
		require.NoError(t, err)
		require.NotContains(t, indexSQL(t, conn, idx), "WHERE",
			"fixture setup: %s must start out non-partial", idx)
	}

	// With the old index in force the bug reproduces: the name stays taken.
	for _, table := range vaultResourceTables {
		require.NoError(t, insertResource(conn, table, "dddd0000-0000-0000-0000-000000000001",
			"legacy-name", defaultVaultID))
		softDelete(t, conn, table, "dddd0000-0000-0000-0000-000000000001")
		err := insertResource(conn, table, "dddd0000-0000-0000-0000-000000000002",
			"legacy-name", defaultVaultID)
		require.Error(t, err,
			"fixture setup: the pre-fix %s index must still block name reuse", table)
	}

	// Boot again. finalizeVaultIndexes must replace all three definitions.
	repo := NewRepository(logging.InitLogger())
	repo.dialect = SQLite
	require.NoError(t, repo.finalizeVaultIndexes(conn))

	for idx := range legacy {
		require.Contains(t, indexSQL(t, conn, idx), "WHERE deleted_at IS NULL",
			"%s must have been dropped and recreated as a partial index", idx)
	}

	// And the operation that used to fail now works, on the same database.
	for _, table := range vaultResourceTables {
		require.NoError(t, insertResource(conn, table, "dddd0000-0000-0000-0000-000000000003",
			"legacy-name", defaultVaultID),
			"after the upgrade, a soft-deleted %s name must be reusable", table)
	}

	// The active duplicate must still be rejected by the new index.
	err := insertResource(conn, "secrets", "dddd0000-0000-0000-0000-000000000004",
		"legacy-name", defaultVaultID)
	require.Error(t, err, "the recreated index must still constrain active rows")
}

// TestFinalizeVaultIndexes_RepeatedRunsConverge pins the boot-time guarantee the
// doc comment claims: the DROP/CREATE pair really runs on every startup, so it
// must converge on the same end state without erroring, on a database that
// already holds active, soft-deleted and cross-vault rows.
func TestFinalizeVaultIndexes_RepeatedRunsConverge(t *testing.T) {
	conn := newSchemaDB(t)
	repo := NewRepository(logging.InitLogger())
	repo.dialect = SQLite

	for _, table := range vaultResourceTables {
		require.NoError(t, insertResource(conn, table, "eeee0000-0000-0000-0000-000000000001",
			"active", defaultVaultID))
		require.NoError(t, insertResource(conn, table, "eeee0000-0000-0000-0000-000000000002",
			"retired", defaultVaultID))
		softDelete(t, conn, table, "eeee0000-0000-0000-0000-000000000002")
		require.NoError(t, insertResource(conn, table, "eeee0000-0000-0000-0000-000000000003",
			"active", otherVaultID))
	}

	for i := 0; i < 3; i++ {
		require.NoError(t, repo.finalizeVaultIndexes(conn), "finalizeVaultIndexes run %d", i+1)
	}
	// The whole boot sequence must be repeatable too, not just this one step.
	require.NoError(t, repo.SetupSchema(conn, SQLite), "second SetupSchema run should be idempotent")
	require.NoError(t, repo.SetupSchema(conn, SQLite), "third SetupSchema run should be idempotent")

	// Nothing was renamed by the repeated collision passes.
	for _, table := range vaultResourceTables {
		var name string
		require.NoError(t, conn.QueryRow(
			"SELECT name FROM "+table+" WHERE id = 'eeee0000-0000-0000-0000-000000000001'").Scan(&name))
		require.Equal(t, "active", name, "repeated boots must not rename a legitimate %s row", table)
	}
}
