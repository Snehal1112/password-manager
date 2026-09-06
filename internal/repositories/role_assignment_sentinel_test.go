package repositories_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

// setupRoleAssignmentTestDB creates an in-memory SQLite database with the
// role_assignments table. Named distinctly from the package-scope setupTestDB,
// setupRotationTestDB, setupSessionTestDB, setupCertListAllTestDB and
// setupCertLifecycleTestDB helpers that already exist in this test package.
func setupRoleAssignmentTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:roleassign_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE role_assignments (
			id TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			role TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);
	`)
	require.NoError(t, err, "create role_assignments schema")

	return raw
}

// TestFindByTupleDoesNotCompareErrorStrings pins the F3 fix. FindByTuple's
// "no such assignment" contract used to rest on the literal string
// "role assignment not found": rewording that message in scanRoleAssignment --
// an edit nothing would flag as risky -- silently flipped FindByTuple from
// returning (nil, nil) to returning an error, on an authorization-adjacent
// path. The sentinel makes the coupling explicit and compiler-visible.
func TestFindByTupleDoesNotCompareErrorStrings(t *testing.T) {
	src, err := os.ReadFile("role_assignment_repository.go")
	require.NoError(t, err, "read role_assignment_repository.go")

	require.NotContains(t, string(src), `err.Error() ==`,
		"identify errors with errors.Is against a sentinel, never by message text")
	require.NotContains(t, string(src), `== sql.ErrNoRows`,
		"use errors.Is(err, sql.ErrNoRows) so a wrapped driver error still matches")
}

// TestFindByTupleReportsAbsenceAsNilNil pins the behavior the string
// comparison was protecting, so the switch to a sentinel cannot change it.
func TestFindByTupleReportsAbsenceAsNilNil(t *testing.T) {
	raw := setupRoleAssignmentTestDB(t)
	repo := repositories.NewRoleAssignmentRepository(rvdb.NewConn(raw, rvdb.SQLite))

	ra, err := repo.FindByTuple(context.Background(), uuid.New(), "Key Vault Reader", uuid.New())
	require.NoError(t, err, "an absent assignment is not an error")
	require.Nil(t, ra, "an absent assignment yields a nil assignment")
}

// TestFindByTupleFindsAnExistingAssignment is the positive half: the sentinel
// switch must not turn a real hit into a miss.
func TestFindByTupleFindsAnExistingAssignment(t *testing.T) {
	raw := setupRoleAssignmentTestDB(t)
	repo := repositories.NewRoleAssignmentRepository(rvdb.NewConn(raw, rvdb.SQLite))

	ctx := context.Background()
	principalID, vaultID := uuid.New(), uuid.New()
	_, err := raw.ExecContext(ctx,
		`INSERT INTO role_assignments
		 (id, principal_id, principal_type, role, vault_id, created_by, created_at)
		 VALUES (?, ?, 'user', 'Key Vault Reader', ?, ?, CURRENT_TIMESTAMP)`,
		uuid.New().String(), principalID.String(), vaultID.String(), uuid.New().String())
	require.NoError(t, err, "insert role assignment")

	ra, err := repo.FindByTuple(ctx, principalID, "Key Vault Reader", vaultID)
	require.NoError(t, err)
	require.NotNil(t, ra, "an existing assignment must still be found")
	require.Equal(t, vaultID, ra.VaultID)
}
