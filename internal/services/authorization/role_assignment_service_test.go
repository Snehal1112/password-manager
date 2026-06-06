package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

type fakeRoleRepo struct {
	rows    map[uuid.UUID]*model.RoleAssignment
	byTuple *model.RoleAssignment
}

func newFakeRoleRepo() *fakeRoleRepo { return &fakeRoleRepo{rows: map[uuid.UUID]*model.RoleAssignment{}} }
func (f *fakeRoleRepo) Create(_ context.Context, ra *model.RoleAssignment) error {
	f.rows[ra.ID] = ra
	return nil
}
func (f *fakeRoleRepo) GetByID(_ context.Context, id uuid.UUID) (*model.RoleAssignment, error) {
	ra, ok := f.rows[id]
	if !ok {
		return nil, errors.New("role assignment not found")
	}
	return ra, nil
}
func (f *fakeRoleRepo) ListByVault(_ context.Context, v uuid.UUID) ([]*model.RoleAssignment, error) {
	var out []*model.RoleAssignment
	for _, ra := range f.rows {
		if ra.VaultID == v {
			out = append(out, ra)
		}
	}
	return out, nil
}
func (f *fakeRoleRepo) FindByTuple(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*model.RoleAssignment, error) {
	return f.byTuple, nil
}
func (f *fakeRoleRepo) Delete(_ context.Context, id uuid.UUID) error { delete(f.rows, id); return nil }

type fakePolicyRepo struct {
	created   []*model.AccessPolicy
	failWrite bool
	failAfter int // if >0, the Nth Create (1-based) and beyond fail; 0 = use failWrite
	deleted   map[uuid.UUID]bool
}

func newFakePolicyRepo() *fakePolicyRepo { return &fakePolicyRepo{deleted: map[uuid.UUID]bool{}} }
func (f *fakePolicyRepo) Create(_ context.Context, p *model.AccessPolicy) error {
	if f.failWrite {
		return errors.New("boom")
	}
	// failAfter=N makes the Nth Create (1-based) and all later ones fail; earlier ones succeed.
	if f.failAfter > 0 && len(f.created)+1 >= f.failAfter {
		return errors.New("boom-midway")
	}
	f.created = append(f.created, p)
	return nil
}
func (f *fakePolicyRepo) DeleteByAssignmentID(_ context.Context, aid uuid.UUID) error {
	f.deleted[aid] = true
	var keep []*model.AccessPolicy
	for _, p := range f.created {
		if p.AssignmentID == nil || *p.AssignmentID != aid {
			keep = append(keep, p)
		}
	}
	f.created = keep
	return nil
}

type fakeUserLookup struct{ users map[string]model.User }

func (f *fakeUserLookup) ReadByUsername(_ context.Context, name string) (model.User, error) {
	u, ok := f.users[name]
	if !ok {
		return model.User{}, errors.New("not found")
	}
	return u, nil
}

func newSvc(rr *fakeRoleRepo, pr *fakePolicyRepo, ul *fakeUserLookup) RoleAssignmentService {
	return NewRoleAssignmentService(rr, pr, ul, nil)
}

func TestAssignRole_HappyPath(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.PrincipalID != uid {
		t.Fatalf("principal not resolved from username")
	}
	if len(pr.created) != 2 {
		t.Fatalf("expected 2 policy rows, got %d", len(pr.created))
	}
	if len(rr.rows) != 1 {
		t.Fatalf("expected 1 assignment row")
	}
}

func TestAssignRole_UnknownRole(t *testing.T) {
	svc := newSvc(newFakeRoleRepo(), newFakePolicyRepo(),
		&fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}})
	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: "nope", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("expected ErrInvalidRole, got %v", err)
	}
}

func TestAssignRole_UnknownPrincipal(t *testing.T) {
	svc := newSvc(newFakeRoleRepo(), newFakePolicyRepo(), &fakeUserLookup{users: map[string]model.User{}})
	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "ghost", PrincipalType: model.PrincipalTypeUser, Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("expected ErrPrincipalNotFound, got %v", err)
	}
}

func TestAssignRole_Idempotent(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	existing := &model.RoleAssignment{ID: uuid.New(), Role: "secrets-user"}
	rr.byTuple = existing
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.ID != existing.ID {
		t.Fatalf("idempotent assign should return existing")
	}
	if len(pr.created) != 0 {
		t.Fatalf("idempotent assign must not write new policies")
	}
}

func TestAssignRole_RollbackOnPolicyFailure(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	pr.failWrite = true
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err == nil {
		t.Fatal("expected error on policy write failure")
	}
	if len(rr.rows) != 0 {
		t.Fatalf("assignment row must be rolled back, have %d", len(rr.rows))
	}
}

func TestRevokeAssignment_CrossVault(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: uuid.New(), Role: "secrets-user"}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	otherVault := uuid.New()
	err := svc.RevokeAssignment(context.Background(), ra.ID, otherVault)
	if !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("cross-vault revoke should be not-found, got %v", err)
	}
}

func TestRevokeAssignment_HappyPath(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	vid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: vid, CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if len(pr.created) != 2 || len(rr.rows) != 1 {
		t.Fatalf("precondition: expected 2 policies + 1 assignment, got %d/%d", len(pr.created), len(rr.rows))
	}

	if err := svc.RevokeAssignment(context.Background(), ra.ID, vid); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(rr.rows) != 0 {
		t.Fatalf("assignment row should be deleted, have %d", len(rr.rows))
	}
	if len(pr.created) != 0 {
		t.Fatalf("policy rows should be deleted, have %d", len(pr.created))
	}
}

func TestAssignRole_RollbackMidSequence(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	pr.failAfter = 2 // first policy write succeeds, second fails (secrets-user expands to 2)
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err == nil {
		t.Fatal("expected error on mid-sequence policy failure")
	}
	if len(pr.created) != 0 {
		t.Fatalf("already-written policies must be cleaned up, have %d", len(pr.created))
	}
	if len(rr.rows) != 0 {
		t.Fatalf("assignment row must be rolled back, have %d", len(rr.rows))
	}
}
