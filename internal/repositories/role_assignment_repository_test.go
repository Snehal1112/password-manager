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
