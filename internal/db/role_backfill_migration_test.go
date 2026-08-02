package db

import (
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// TestBackfillRoleAssignments_CreatesDerivedGrants runs the migration writer
// against a seeded pre-migration database and asserts the exact rows produced.
func TestBackfillRoleAssignments_CreatesDerivedGrants(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	repo := NewRepository(logging.InitLogger())

	require.NoError(t, repo.backfillRoleAssignments(conn))

	type row struct{ principal, vault, role string }
	var got []row
	rows, err := conn.Query(`SELECT principal_id, vault_id, role FROM role_assignments`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.principal, &r.vault, &r.role))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())

	assert.ElementsMatch(t, []row{
		{ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer},
		{ids["bob"], ids["vaultB"], model.RoleKeyVaultSecretsOfficer},
		{ids["alice"], ids["vaultB"], model.RoleKeyVaultCryptoOfficer},
		{ids["bob"], ids["vaultA"], model.RoleKeyVaultCertificatesOfficer},
		{ids["admin"], ids["vaultA"], model.RoleKeyVaultAdministrator},
		{ids["admin"], ids["vaultB"], model.RoleKeyVaultAdministrator},
		// backfillRoleAssignments seeds the default vault before deriving
		// grants (FK from role_assignments to vaults), so the global admin
		// also gets Key Vault Administrator there.
		{ids["admin"], model.DefaultVaultID, model.RoleKeyVaultAdministrator},
	}, got)

	// Every backfilled row is attributed to the system actor and typed as a user.
	var nonSystem int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE created_by <> ? OR principal_type <> ?`,
		"00000000-0000-0000-0000-000000000000", string(model.PrincipalTypeUser),
	).Scan(&nonSystem))
	assert.Zero(t, nonSystem)
}

// TestBackfillRoleAssignments_IsIdempotent asserts re-running creates nothing
// new. backfillRoleAssignments runs from migrateSchema on every startup, but
// the roleBackfillAppliedKey marker in audit_config short-circuits every call
// after the first, so a second or third run must not touch the table at all
// (see TestBackfillRoleAssignments_DoesNotResurrectRevokedGrant for proof it
// is the marker, and not just the per-tuple existence guard, doing the work).
func TestBackfillRoleAssignments_IsIdempotent(t *testing.T) {
	conn, _ := seedPreMigrationDB(t)
	repo := NewRepository(logging.InitLogger())

	require.NoError(t, repo.backfillRoleAssignments(conn))
	var first int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM role_assignments`).Scan(&first))
	// 6 ownership/admin-derived grants across the two seeded vaults, plus the
	// admin's Key Vault Administrator grant in the default vault that
	// backfillRoleAssignments seeds before deriving grants.
	require.Equal(t, 7, first)

	require.NoError(t, repo.backfillRoleAssignments(conn))
	require.NoError(t, repo.backfillRoleAssignments(conn))
	var second int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM role_assignments`).Scan(&second))
	assert.Equal(t, first, second, "re-running the backfill must be a no-op")
}

// TestBackfillRoleAssignments_DoesNotResurrectRevokedGrant proves the actual
// fix: once the marker is set, a revoked backfilled grant is not re-created on
// the next run. Without the marker, backfillRoleAssignments re-derives the
// same grant from ownership data that hasn't changed and silently reinstates
// it, defeating DELETE /api/v1/vaults/{vault}/role-assignments/{id} as an
// upgrade remediation path.
func TestBackfillRoleAssignments_DoesNotResurrectRevokedGrant(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	repo := NewRepository(logging.InitLogger())

	require.NoError(t, repo.backfillRoleAssignments(conn))

	// Simulate an operator revoking one of the derived grants.
	res, err := conn.Exec(
		`DELETE FROM role_assignments WHERE principal_id = ? AND vault_id = ? AND role = ?`,
		ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer)
	require.NoError(t, err)
	affected, err := res.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected, "the revoked grant must have existed before deletion")

	// The ownership data that originally produced the grant is untouched, so a
	// naive re-run would re-derive and reinsert it. The marker must prevent
	// that.
	require.NoError(t, repo.backfillRoleAssignments(conn))

	var n int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE principal_id = ? AND vault_id = ? AND role = ?`,
		ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer).Scan(&n))
	assert.Zero(t, n, "a revoked grant must not be resurrected by a later backfill run")
}

// TestBackfillRoleAssignments_PreservesOperatorGrants asserts a hand-made
// assignment is neither duplicated nor removed.
func TestBackfillRoleAssignments_PreservesOperatorGrants(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	_, err := conn.Exec(
		`INSERT INTO role_assignments (id, principal_id, principal_type, role, vault_id, created_by)
		 VALUES ('operator-grant', ?, 'user', ?, ?, ?)`,
		ids["alice"], model.RoleKeyVaultSecretsOfficer, ids["vaultA"], ids["admin"])
	require.NoError(t, err)

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.backfillRoleAssignments(conn))

	var n int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE principal_id = ? AND vault_id = ? AND role = ?`,
		ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer).Scan(&n))
	assert.Equal(t, 1, n, "the pre-existing grant must not be duplicated")

	var createdBy string
	require.NoError(t, conn.QueryRow(
		`SELECT created_by FROM role_assignments WHERE id = 'operator-grant'`).Scan(&createdBy))
	assert.Equal(t, ids["admin"], createdBy, "the operator grant must be untouched")
}

// TestMigrateSchema_RunsRoleBackfill asserts the backfill is wired into
// migrateSchema, not merely callable, and stays idempotent through it.
func TestMigrateSchema_RunsRoleBackfill(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	// migrateSchema also touches audit_logs and access_policies; provide them.
	_, err := conn.Exec(`
		CREATE TABLE audit_logs (id TEXT PRIMARY KEY);
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
	require.NoError(t, repo.migrateSchema(conn))

	var n int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE principal_id = ? AND vault_id = ? AND role = ?`,
		ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer).Scan(&n))
	assert.Equal(t, 1, n)

	// migrateSchema seeds the default vault before the backfill so the foreign
	// key from role_assignments to vaults is satisfiable.
	var defaults int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM vaults WHERE id = ?`, model.DefaultVaultID).Scan(&defaults))
	assert.Equal(t, 1, defaults)
}
