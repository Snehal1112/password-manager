// Package api — B6 regression tests (design spec 2026-07-26, section 4.1).
// B6 is the temporary invariant that crypto operations on a key remain
// gated by ownership even on vault-scoped routes, where listing/get/update
// already grant vault-wide "members see all" visibility. These tests pin
// that invariant so the P1 mechanical refactor cannot silently widen it.
// They are deliberately deleted (not adapted) in P2, in the same commit as
// the policy change that retires ownership as an authorization input.
package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/app"
	keyServices "rocketvault/internal/services/keys"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// TestB6_CryptoOps_NonOwnerVaultMember_Returns403 asserts that a vault
// member who does not own a key is forbidden from using it for sign,
// verify, encrypt, decrypt, wrap, and unwrap, even via the vault-scoped
// route that grants vault-wide visibility for listing and get.
func TestB6_CryptoOps_NonOwnerVaultMember_Returns403(t *testing.T) {
	tests := []struct {
		name string
		path string
		body []byte
	}{
		{"sign", "/sign", []byte(`{"value":"aGVsbG8="}`)},
		{"verify", "/verify", []byte(`{"value":"aGVsbG8=","signature":"c2ln"}`)},
		{"encrypt", "/encrypt", []byte(`{"value":"aGVsbG8="}`)},
		{"decrypt", "/decrypt", []byte(`{"value":"Y3Q="}`)},
		{"wrap", "/wrap", []byte(`{"plaintext_key":"a2V5"}`)},
		{"unwrap", "/unwrap", []byte(`{"wrapped_key":"d3JhcHBlZA=="}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newB6FakeKeyRepo()
			ownerID := uuid.New()
			vaultID := uuid.New()
			keyID := uuid.New()
			repo.keys[keyID] = &model.Key{
				ID: keyID, UserID: ownerID, VaultID: vaultID,
				Name: "k1", Type: "RSA", Value: "irrelevant-before-authz-check",
				Enabled: true,
			}

			api, vrepo := newB6TestAPI(repo)
			vrepo.byName["prod"] = &model.Vault{ID: vaultID, Name: "prod", Enabled: true}
			vrepo.byID[vaultID.String()] = vrepo.byName["prod"]

			w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/keys/"+keyID.String()+tt.path, tt.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s via vault route for non-owner key: expected 403, got %d (%s)", tt.name, w.Code, w.Body.String())
			}
		})
	}
}

// b6FakeKeyRepo is a minimal, deterministic KeyRepositoryInterface backed by
// an in-memory map. B6 tests need real ownership/vault data on the key
// (UserID, VaultID) rather than per-call expectations, so a plain map fits
// better here than a testify mock.
type b6FakeKeyRepo struct {
	keys map[uuid.UUID]*model.Key
}

func newB6FakeKeyRepo() *b6FakeKeyRepo {
	return &b6FakeKeyRepo{keys: map[uuid.UUID]*model.Key{}}
}

func (f *b6FakeKeyRepo) Create(ctx context.Context, k *model.Key) error {
	f.keys[k.ID] = k
	return nil
}
func (f *b6FakeKeyRepo) Read(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	if k, ok := f.keys[id]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}
func (f *b6FakeKeyRepo) Update(ctx context.Context, k *model.Key) error {
	f.keys[k.ID] = k
	return nil
}
func (f *b6FakeKeyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	delete(f.keys, id)
	return nil
}
func (f *b6FakeKeyRepo) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return nil
}
func (f *b6FakeKeyRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if k, ok := f.keys[id]; ok {
		now := time.Now()
		k.DeletedAt = &now
	}
	return nil
}
func (f *b6FakeKeyRepo) RecoverKey(ctx context.Context, id uuid.UUID) error { return nil }
func (f *b6FakeKeyRepo) PurgeKey(ctx context.Context, id uuid.UUID) error   { return nil }
func (f *b6FakeKeyRepo) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return nil
}
func (f *b6FakeKeyRepo) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	if k, ok := f.keys[id]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}
func (f *b6FakeKeyRepo) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	return nil
}
func (f *b6FakeKeyRepo) ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) ListInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Key, error) {
	k, ok := f.keys[id]
	if !ok || k.VaultID != vaultID {
		return nil, errors.New("key not found in vault")
	}
	return k, nil
}
func (f *b6FakeKeyRepo) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (f *b6FakeKeyRepo) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}

// newB6TestAPI wires the vault-scoped key routes onto a real KeyService and
// real CryptoService backed by repo, so B6 tests exercise the actual
// loadAndAuthorize / DeleteKeyInVault ownership checks rather than a
// recording fake that always succeeds.
func newB6TestAPI(repo *b6FakeKeyRepo) (*API, *vaultFakeRepo) {
	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	keySvc := keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository: repo,
		Logger:        userTestLog(),
	})
	cryptoSvc := keyServices.NewCryptoService(keyServices.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        userTestLog(),
	})
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{
		vaultSvc: vsvc, keySvc: keySvc, cryptoSvc: cryptoSvc, logger: userTestLog(),
	}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	api.InitVault()
	api.InitKeys()
	return api, vrepo
}
