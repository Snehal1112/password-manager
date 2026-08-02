package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	rvdb "rocketvault/internal/db"
	"rocketvault/model"
)

func newRoleAssignmentRepo(t *testing.T) RoleAssignmentRepositoryInterface {
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(`CREATE TABLE role_assignments (
		id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
		role TEXT NOT NULL, vault_id TEXT NOT NULL, created_by TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (principal_id, role, vault_id))`)
	if err != nil {
		t.Fatal(err)
	}
	return NewRoleAssignmentRepository(rvdb.NewConn(conn, rvdb.SQLite))
}

func TestRoleAssignment_CreateGetListDelete(t *testing.T) {
	repo := newRoleAssignmentRepo(t)
	ctx := context.Background()
	vid := uuid.New()
	ra := &model.RoleAssignment{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: vid, CreatedBy: uuid.New(),
	}
	if err := repo.Create(ctx, ra); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, ra.ID)
	if err != nil || got.Role != "secrets-user" {
		t.Fatalf("get: %v %+v", err, got)
	}
	list, err := repo.ListByVault(ctx, vid)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if err := repo.Delete(ctx, ra.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, ra.ID); err == nil {
		t.Fatal("expected not-found after delete")
	}
}

func TestRoleAssignment_FindDuplicate(t *testing.T) {
	repo := newRoleAssignmentRepo(t)
	ctx := context.Background()
	vid := uuid.New()
	pid := uuid.New()
	ra := &model.RoleAssignment{
		ID: uuid.New(), PrincipalID: pid, PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: vid, CreatedBy: uuid.New(),
	}
	_ = repo.Create(ctx, ra)
	dup, err := repo.FindByTuple(ctx, pid, "secrets-user", vid)
	if err != nil || dup == nil || dup.ID != ra.ID {
		t.Fatalf("FindByTuple should return existing: %v %+v", err, dup)
	}
	none, err := repo.FindByTuple(ctx, uuid.New(), "secrets-user", vid)
	if err != nil {
		t.Fatalf("FindByTuple err: %v", err)
	}
	if none != nil {
		t.Fatal("expected nil for non-existent tuple")
	}
}

// TestRoleAssignment_ListByPrincipalInVault returns only the assignments held by
// the given principal in the given vault. Assignments held by another principal,
// or by the same principal in another vault, must not leak into the result:
// this query is the authorization lookup, so a leak is a privilege escalation.
func TestRoleAssignment_ListByPrincipalInVault(t *testing.T) {
	repo := newRoleAssignmentRepo(t)
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	alice, bob := uuid.New(), uuid.New()

	seed := []*model.RoleAssignment{
		{ID: uuid.New(), PrincipalID: alice, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultSecretsOfficer, VaultID: vaultA, CreatedBy: uuid.New()},
		{ID: uuid.New(), PrincipalID: alice, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultCryptoUser, VaultID: vaultA, CreatedBy: uuid.New()},
		{ID: uuid.New(), PrincipalID: alice, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultAdministrator, VaultID: vaultB, CreatedBy: uuid.New()},
		{ID: uuid.New(), PrincipalID: bob, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultAdministrator, VaultID: vaultA, CreatedBy: uuid.New()},
	}
	for _, ra := range seed {
		if err := repo.Create(ctx, ra); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	got, err := repo.ListByPrincipalInVault(ctx, alice, vaultA)
	if err != nil {
		t.Fatalf("ListByPrincipalInVault: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 assignments, got %d", len(got))
	}
	roles := map[string]bool{}
	for _, ra := range got {
		if ra.PrincipalID != alice || ra.VaultID != vaultA {
			t.Fatalf("leaked assignment: principal=%s vault=%s", ra.PrincipalID, ra.VaultID)
		}
		roles[ra.Role] = true
	}
	if !roles[model.RoleKeyVaultSecretsOfficer] || !roles[model.RoleKeyVaultCryptoUser] {
		t.Fatalf("unexpected roles: %v", roles)
	}

	// A principal with no assignment in the vault gets an empty, non-error result.
	none, err := repo.ListByPrincipalInVault(ctx, uuid.New(), vaultA)
	if err != nil {
		t.Fatalf("ListByPrincipalInVault (absent principal): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("want 0 assignments for an unknown principal, got %d", len(none))
	}
}
