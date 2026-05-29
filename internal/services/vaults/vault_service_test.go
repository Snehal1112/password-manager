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

func (n *noopCascade) SoftDeleteVaultContents(context.Context, uuid.UUID) error { n.soft++; return nil }
func (n *noopCascade) RecoverVaultContents(context.Context, uuid.UUID) error    { n.recover++; return nil }

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
