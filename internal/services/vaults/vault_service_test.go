package vaults

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

func nowForTest() time.Time { return time.Unix(1700000000, 0) }

// fakeVaultRepo is a hand-rolled in-memory VaultRepositoryInterface for tests.
type fakeVaultRepo struct {
	byName map[string]*model.Vault
	byID   map[string]*model.Vault
}

func newFakeRepo() *fakeVaultRepo {
	return &fakeVaultRepo{byName: map[string]*model.Vault{}, byID: map[string]*model.Vault{}}
}

var errFakeNotFound = errors.New("not found")

func (f *fakeVaultRepo) Create(_ context.Context, v *model.Vault) error {
	if _, ok := f.byName[v.Name]; ok {
		return errors.New("duplicate")
	}
	cp := *v
	f.byName[v.Name] = &cp
	f.byID[v.ID.String()] = &cp
	return nil
}
func (f *fakeVaultRepo) ReadByName(_ context.Context, n string) (*model.Vault, error) {
	if v, ok := f.byName[n]; ok && v.DeletedAt == nil {
		return v, nil
	}
	return nil, errFakeNotFound
}
func (f *fakeVaultRepo) ReadByID(_ context.Context, id uuid.UUID) (*model.Vault, error) {
	if v, ok := f.byID[id.String()]; ok {
		return v, nil
	}
	return nil, errFakeNotFound
}
func (f *fakeVaultRepo) List(context.Context) ([]model.Vault, error) {
	var out []model.Vault
	for _, v := range f.byName {
		if v.DeletedAt == nil {
			out = append(out, *v)
		}
	}
	return out, nil
}
func (f *fakeVaultRepo) ListDeleted(context.Context) ([]model.Vault, error) {
	var out []model.Vault
	for _, v := range f.byName {
		if v.DeletedAt != nil {
			out = append(out, *v)
		}
	}
	return out, nil
}
func (f *fakeVaultRepo) Update(_ context.Context, v *model.Vault) error {
	f.byName[v.Name] = v
	f.byID[v.ID.String()] = v
	return nil
}
func (f *fakeVaultRepo) SoftDelete(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		now := nowForTest()
		v.DeletedAt = &now
	}
	return nil
}
func (f *fakeVaultRepo) Recover(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		v.DeletedAt = nil
	}
	return nil
}
func (f *fakeVaultRepo) Purge(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		delete(f.byName, v.Name)
		delete(f.byID, id.String())
	}
	return nil
}

type noopCascade struct{ soft, recover int }

func (n *noopCascade) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	n.soft++
	return nil
}
func (n *noopCascade) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	n.recover++
	return nil
}

func TestCreateVault_RejectsInvalidName(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	if _, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "BAD_NAME"}, uuid.New()); err == nil {
		t.Fatal("expected invalid-name error")
	}
}

func TestCreateVault_AppliesDefaultsAndOverrides(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	v, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "prod"}, uuid.New())
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if !v.Enabled || v.RetentionDays != 90 {
		t.Fatalf("expected defaults enabled=true retention=90, got %+v", v)
	}
}

func TestDeleteVault_RefusesDefault(t *testing.T) {
	repo := newFakeRepo()
	defID := uuid.MustParse(model.DefaultVaultID)
	repo.byName["default"] = &model.Vault{ID: defID, Name: "default"}
	repo.byID[defID.String()] = repo.byName["default"]
	svc := NewVaultService(repo, &noopCascade{}, nil)
	if err := svc.DeleteVault(context.Background(), "default"); err == nil {
		t.Fatal("expected refusal to delete the default vault")
	}
}

func TestDeleteVault_CascadesContents(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]
	casc := &noopCascade{}
	svc := NewVaultService(repo, casc, nil)
	if err := svc.DeleteVault(context.Background(), "stg"); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}
	if casc.soft != 1 {
		t.Fatalf("expected cascade soft-delete called once, got %d", casc.soft)
	}
}

func TestPurgeVault_RefusedWhenProtected(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["p"] = &model.Vault{ID: id, Name: "p", PurgeProtection: true}
	repo.byID[id.String()] = repo.byName["p"]
	svc := NewVaultService(repo, &noopCascade{}, nil)
	if err := svc.PurgeVault(context.Background(), "p"); err == nil {
		t.Fatal("expected purge refusal when purge protection is on")
	}
}

func TestRecoverVault_RestoresAndCascades(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["r"] = &model.Vault{ID: id, Name: "r", DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["r"]
	casc := &noopCascade{}
	svc := NewVaultService(repo, casc, nil)
	if err := svc.RecoverVault(context.Background(), "r"); err != nil {
		t.Fatalf("RecoverVault: %v", err)
	}
	if casc.recover != 1 {
		t.Fatalf("expected cascade recover called once, got %d", casc.recover)
	}
}

func TestGetVault_UnknownReturnsSentinel(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	_, err := svc.GetVault(context.Background(), "nope")
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

func TestRecoverVault_UnknownReturnsSentinel(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	err := svc.RecoverVault(context.Background(), "nope")
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func TestListVaults_ActiveOnly(t *testing.T) {
	repo := newFakeRepo()
	a1 := uuid.New()
	a2 := uuid.New()
	repo.byName["a1"] = &model.Vault{ID: a1, Name: "a1", Enabled: true}
	repo.byID[a1.String()] = repo.byName["a1"]
	repo.byName["a2"] = &model.Vault{ID: a2, Name: "a2", Enabled: true}
	repo.byID[a2.String()] = repo.byName["a2"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	vaults, err := svc.ListVaults(context.Background(), false)
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) != 2 {
		t.Fatalf("expected 2 active vaults, got %d", len(vaults))
	}
}

func TestListVaults_IncludeDeleted(t *testing.T) {
	repo := newFakeRepo()
	active := uuid.New()
	deleted := uuid.New()
	now := nowForTest()
	repo.byName["active"] = &model.Vault{ID: active, Name: "active", Enabled: true}
	repo.byID[active.String()] = repo.byName["active"]
	repo.byName["gone"] = &model.Vault{ID: deleted, Name: "gone", DeletedAt: &now}
	repo.byID[deleted.String()] = repo.byName["gone"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	vaults, err := svc.ListVaults(context.Background(), true)
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) != 2 {
		t.Fatalf("expected active + deleted = 2 vaults, got %d", len(vaults))
	}
	names := map[string]bool{}
	for _, v := range vaults {
		names[v.Name] = true
	}
	if !names["active"] || !names["gone"] {
		t.Fatalf("expected both active and gone, got %v", names)
	}
}

func TestUpdateVault_AppliesNonNilFields(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	created, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "upd"}, uuid.New())
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if !created.Enabled || created.PurgeProtection {
		t.Fatalf("unexpected initial state: %+v", created)
	}

	updated, err := svc.UpdateVault(context.Background(), "upd", model.UpdateVaultRequest{
		Enabled:       boolPtr(false),
		RetentionDays: intPtr(30),
		// PurgeProtection left nil so it must remain unchanged.
	}, uuid.New())
	if err != nil {
		t.Fatalf("UpdateVault: %v", err)
	}
	if updated.Enabled {
		t.Fatalf("expected Enabled=false")
	}
	if updated.RetentionDays != 30 {
		t.Fatalf("expected RetentionDays=30, got %d", updated.RetentionDays)
	}
	if updated.PurgeProtection {
		t.Fatalf("expected PurgeProtection unchanged (false)")
	}
}

func TestUpdateVault_ReplacesTagsAndSetsUpdatedBy(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	if _, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "tagged"}, uuid.New()); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	updater := uuid.New()
	tags := map[string]string{"env": "prod"}
	got, err := svc.UpdateVault(context.Background(), "tagged",
		model.UpdateVaultRequest{Tags: &tags}, updater)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Tags["env"] != "prod" {
		t.Fatalf("tags not applied: %v", got.Tags)
	}
	if got.UpdatedBy == nil || *got.UpdatedBy != updater {
		t.Fatalf("updated_by not set: %v", got.UpdatedBy)
	}
}

func TestUpdateVault_NotFound(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	_, err := svc.UpdateVault(context.Background(), "missing", model.UpdateVaultRequest{Enabled: boolPtr(true)}, uuid.New())
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

func TestCreateVault_AppliesAllOverrides(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	v, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{
		Name:            "over",
		Enabled:         boolPtr(false),
		PurgeProtection: boolPtr(true),
		RetentionDays:   intPtr(7),
	}, uuid.New())
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if v.Enabled {
		t.Fatalf("expected Enabled=false override")
	}
	if !v.PurgeProtection {
		t.Fatalf("expected PurgeProtection=true override")
	}
	if v.RetentionDays != 7 {
		t.Fatalf("expected RetentionDays=7 override, got %d", v.RetentionDays)
	}
}

func TestPurgeVault_DeletedVaultSucceeds(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["d"] = &model.Vault{ID: id, Name: "d", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["d"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	if err := svc.PurgeVault(context.Background(), "d"); err != nil {
		t.Fatalf("PurgeVault: %v", err)
	}
	if _, ok := repo.byID[id.String()]; ok {
		t.Fatal("expected purged vault to be removed from the repo")
	}
}

func TestRecoverVault_RestoresFromDeleted(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["rec"] = &model.Vault{ID: id, Name: "rec", DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["rec"]
	casc := &noopCascade{}
	svc := NewVaultService(repo, casc, nil)

	if err := svc.RecoverVault(context.Background(), "rec"); err != nil {
		t.Fatalf("RecoverVault: %v", err)
	}
	if repo.byID[id.String()].DeletedAt != nil {
		t.Fatal("expected recovered vault to have DeletedAt cleared")
	}
	if casc.recover != 1 {
		t.Fatalf("expected cascade recover called once, got %d", casc.recover)
	}
}

func TestDeleteVault_NotFound(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	err := svc.DeleteVault(context.Background(), "missing")
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}
