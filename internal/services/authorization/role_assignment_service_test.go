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

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{rows: map[uuid.UUID]*model.RoleAssignment{}}
}
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
func (f *fakeRoleRepo) ListByPrincipalInVault(_ context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	var out []*model.RoleAssignment
	for _, ra := range f.rows {
		if ra.PrincipalID == principalID && ra.VaultID == vaultID {
			out = append(out, ra)
		}
	}
	return out, nil
}

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

func TestAssignRole_PrincipalIsUUID(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	// Empty users map proves no username lookup happens when a raw UUID is passed.
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})
	pid := uuid.New()
	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: pid.String(), PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.PrincipalID != pid {
		t.Fatalf("uuid principal should be used directly, got %v", ra.PrincipalID)
	}
}

func TestRevokeAssignment_NotFound(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})
	err := svc.RevokeAssignment(context.Background(), uuid.New(), uuid.New())
	if !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("expected ErrAssignmentNotFound, got %v", err)
	}
}

func TestListAssignments_ScopedToVault(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{"a": {ID: uid, Username: "a"}}})
	v1, v2 := uuid.New(), uuid.New()
	_, _ = svc.AssignRole(context.Background(), AssignRoleInput{Principal: "a", PrincipalType: model.PrincipalTypeUser, Role: "secrets-user", VaultID: v1, CreatedBy: uid})

	got, err := svc.ListAssignments(context.Background(), v1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 in v1, got %d", len(got))
	}
	got2, err := svc.ListAssignments(context.Background(), v2)
	if err != nil {
		t.Fatalf("list v2: %v", err)
	}
	if len(got2) != 0 {
		t.Fatalf("expected 0 in v2, got %d", len(got2))
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

// fakeVaultRoleRepo serves a fixed set of assignments keyed by (principal, vault).
type fakeVaultRoleRepo struct {
	byPrincipalVault map[string][]*model.RoleAssignment
	err              error
	calls            int
}

func (f *fakeVaultRoleRepo) Create(context.Context, *model.RoleAssignment) error { return nil }
func (f *fakeVaultRoleRepo) GetByID(context.Context, uuid.UUID) (*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) ListByVault(context.Context, uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) FindByTuple(context.Context, uuid.UUID, string, uuid.UUID) (*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) Delete(context.Context, uuid.UUID) error { return nil }
func (f *fakeVaultRoleRepo) ListByPrincipalInVault(_ context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.byPrincipalVault[principalID.String()+"|"+vaultID.String()], nil
}

// TestHasDataAction covers the grant, the denial, the wrong-vault case, and the
// fail-closed inputs. A principal holding Secrets User in vault A must not be
// able to read a secret in vault B.
func TestHasDataAction(t *testing.T) {
	alice := uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()

	repo := &fakeVaultRoleRepo{byPrincipalVault: map[string][]*model.RoleAssignment{
		alice.String() + "|" + vaultA.String(): {
			{PrincipalID: alice, VaultID: vaultA, Role: model.RoleKeyVaultSecretsUser},
		},
	}}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	ctx := context.Background()

	cases := []struct {
		name      string
		principal uuid.UUID
		vault     uuid.UUID
		action    model.DataAction
		want      bool
	}{
		{"granted action in the right vault", alice, vaultA, model.ActionSecretsGet, true},
		{"action the role does not grant", alice, vaultA, model.ActionSecretsSet, false},
		{"same role, different vault", alice, vaultB, model.ActionSecretsGet, false},
		{"unknown principal", uuid.New(), vaultA, model.ActionSecretsGet, false},
		{"nil principal", uuid.Nil, vaultA, model.ActionSecretsGet, false},
		{"nil vault", alice, uuid.Nil, model.ActionSecretsGet, false},
		{"empty action", alice, vaultA, model.DataAction(""), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := svc.HasDataAction(ctx, c.principal, c.vault, c.action)
			if err != nil {
				t.Fatalf("HasDataAction: %v", err)
			}
			if got != c.want {
				t.Fatalf("HasDataAction = %v, want %v", got, c.want)
			}
		})
	}
}

// TestHasDataActionMultipleRolesUnion asserts the grants of every assignment a
// principal holds in the vault are unioned.
func TestHasDataActionMultipleRolesUnion(t *testing.T) {
	alice := uuid.New()
	vault := uuid.New()
	repo := &fakeVaultRoleRepo{byPrincipalVault: map[string][]*model.RoleAssignment{
		alice.String() + "|" + vault.String(): {
			{PrincipalID: alice, VaultID: vault, Role: model.RoleKeyVaultSecretsUser},
			{PrincipalID: alice, VaultID: vault, Role: model.RoleKeyVaultCryptoUser},
		},
	}}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	ctx := context.Background()

	for _, action := range []model.DataAction{model.ActionSecretsGet, model.ActionKeysSign} {
		ok, err := svc.HasDataAction(ctx, alice, vault, action)
		if err != nil || !ok {
			t.Fatalf("HasDataAction(%s) = %v, %v; want true, nil", action, ok, err)
		}
	}
	ok, err := svc.HasDataAction(ctx, alice, vault, model.ActionKeysCreate)
	if err != nil || ok {
		t.Fatalf("HasDataAction(keys/create) = %v, %v; want false, nil", ok, err)
	}
}

// TestHasDataActionRepositoryErrorPropagates asserts a lookup failure surfaces
// as an error rather than a silent false, so the middleware can answer 500
// instead of masking a database outage as a permission denial.
func TestHasDataActionRepositoryErrorPropagates(t *testing.T) {
	repo := &fakeVaultRoleRepo{err: errors.New("database is locked")}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	got, err := svc.HasDataAction(context.Background(), uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil {
		t.Fatal("want an error when the lookup fails")
	}
	if got {
		t.Fatal("want false alongside the error")
	}
}
