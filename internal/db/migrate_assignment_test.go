// Regression test for the access_policies.assignment_id migration.
// It proves migrateSchema adds the column to an old-shape database and is
// idempotent (safe to run more than once).
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// TestMigrateSchema_AddsAssignmentIDIdempotent verifies that migrateSchema adds
// the assignment_id column to a pre-existing access_policies table and that a
// second run does not error.
func TestMigrateSchema_AddsAssignmentIDIdempotent(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	// Create the prerequisite tables in their old shape, WITHOUT the columns
	// that migrateSchema adds. The ALTER TABLE statements in migrateSchema only
	// succeed if their target tables already exist, so every table touched by an
	// ALTER must be present here. The access_policies table deliberately omits
	// both vault_id and assignment_id so the migration has work to do.
	_, err = conn.Exec(`
		CREATE TABLE secrets (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE keys (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE certificates (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	// Sanity check: the column must NOT exist before migration.
	require.False(t, columnExists(t, conn, "access_policies", "assignment_id"),
		"assignment_id must not exist before migrateSchema runs")

	repo := NewRepository(logging.InitLogger())

	// First run adds the column.
	require.NoError(t, repo.migrateSchema(conn), "first migrateSchema run should succeed")

	// Second run must be a no-op (idempotent).
	require.NoError(t, repo.migrateSchema(conn), "second migrateSchema run should be idempotent")

	// The column must now exist.
	var name string
	row := conn.QueryRow(
		`SELECT name FROM pragma_table_info('access_policies') WHERE name='assignment_id'`)
	if err := row.Scan(&name); err != nil {
		t.Fatalf("assignment_id column missing after migrate: %v", err)
	}
	require.Equal(t, "assignment_id", name)
}

// TestMigrate_CreatesRoleAssignmentsTable verifies that migrateSchema creates the
// vault-scoped role_assignments table on a pre-existing (old-shape) database.
func TestMigrate_CreatesRoleAssignmentsTable(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	// Create the prerequisite tables in their old shape so the ALTER TABLE
	// statements in migrateSchema have targets to operate on.
	_, err = conn.Exec(`
		CREATE TABLE secrets (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE keys (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE certificates (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	repo := NewRepository(logging.InitLogger())

	// migrateSchema must create the vaults table and then role_assignments.
	require.NoError(t, repo.migrateSchema(conn), "migrateSchema run should succeed")

	// A second run must be idempotent.
	require.NoError(t, repo.migrateSchema(conn), "second migrateSchema run should be idempotent")

	var name string
	row := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='role_assignments'`)
	if err := row.Scan(&name); err != nil {
		t.Fatalf("role_assignments table missing: %v", err)
	}
}

// TestMigrate_CreatesPrincipalVaultIndex verifies that migrateSchema creates the
// composite index backing the per-vault authorization lookup. The index must be
// created in migrateSchema as well as in createOptimizedSchema so that upgraded
// databases get it too.
func TestMigrate_CreatesPrincipalVaultIndex(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Exec(`
		CREATE TABLE secrets (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE keys (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE certificates (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.migrateSchema(conn))
	require.NoError(t, repo.migrateSchema(conn), "second run must be idempotent")

	var name string
	row := conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_role_assignments_principal_vault'`)
	require.NoError(t, row.Scan(&name), "idx_role_assignments_principal_vault missing after migrate")
	require.Equal(t, "idx_role_assignments_principal_vault", name)
}

// columnExists reports whether the named column is present on the given table.
func columnExists(t *testing.T, conn *sql.DB, table, column string) bool {
	t.Helper()
	var name string
	err := conn.QueryRow(
		`SELECT name FROM pragma_table_info(?) WHERE name=?`, table, column).Scan(&name)
	if err == sql.ErrNoRows {
		return false
	}
	require.NoError(t, err)
	return name == column
}
