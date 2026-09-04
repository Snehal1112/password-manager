package repositories

// CreateTx tests for the access-policy and role-assignment repositories live
// here rather than in tx_create_test.go because their concrete types
// (accessPolicyRepository, roleAssignmentRepository) are unexported -- only
// code inside this package can type-assert down to them. VaultRepository is
// exported, so its CreateTx tests live in the external repositories_test
// package instead (tx_create_test.go), matching how the rest of the vault
// repository is tested.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/model"
)

func newAccessPolicyTxTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = database.Exec(`
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			vault_id       TEXT NULL,
			assignment_id  TEXT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() }) //nolint:errcheck,gosec
	return database
}

func TestAccessPolicyRepository_CreateTx_RollsBack(t *testing.T) {
	database := newAccessPolicyTxTestDB(t)
	repo := NewAccessPolicyRepository(rvdb.NewConn(database, rvdb.SQLite)).(*accessPolicyRepository)
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	policy := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpGet, Effect: model.PolicyEffectAllow,
	}
	require.NoError(t, repo.CreateTx(ctx, tx, policy))
	require.NoError(t, tx.Rollback())

	_, err = repo.GetByID(ctx, policy.ID)
	require.Error(t, err, "a rolled-back CreateTx must leave no access policy behind")
}

func TestAccessPolicyRepository_CreateTx_Commits(t *testing.T) {
	database := newAccessPolicyTxTestDB(t)
	repo := NewAccessPolicyRepository(rvdb.NewConn(database, rvdb.SQLite)).(*accessPolicyRepository)
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	policy := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpGet, Effect: model.PolicyEffectAllow,
	}
	require.NoError(t, repo.CreateTx(ctx, tx, policy))
	require.NoError(t, tx.Commit())

	got, err := repo.GetByID(ctx, policy.ID)
	require.NoError(t, err)
	require.Equal(t, policy.ID, got.ID)
}

func newRoleAssignmentTxTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = database.Exec(`CREATE TABLE role_assignments (
		id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
		role TEXT NOT NULL, vault_id TEXT NOT NULL, created_by TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (principal_id, role, vault_id))`)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() }) //nolint:errcheck,gosec
	return database
}

func TestRoleAssignmentRepository_CreateTx_RollsBack(t *testing.T) {
	database := newRoleAssignmentTxTestDB(t)
	repo := NewRoleAssignmentRepository(rvdb.NewConn(database, rvdb.SQLite)).(*roleAssignmentRepository)
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	ra := &model.RoleAssignment{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	}
	require.NoError(t, repo.CreateTx(ctx, tx, ra))
	require.NoError(t, tx.Rollback())

	_, err = repo.GetByID(ctx, ra.ID)
	require.Error(t, err, "a rolled-back CreateTx must leave no role assignment behind")
}

func TestRoleAssignmentRepository_CreateTx_Commits(t *testing.T) {
	database := newRoleAssignmentTxTestDB(t)
	repo := NewRoleAssignmentRepository(rvdb.NewConn(database, rvdb.SQLite)).(*roleAssignmentRepository)
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	ra := &model.RoleAssignment{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	}
	require.NoError(t, repo.CreateTx(ctx, tx, ra))
	require.NoError(t, tx.Commit())

	got, err := repo.GetByID(ctx, ra.ID)
	require.NoError(t, err)
	require.Equal(t, ra.ID, got.ID)
}
