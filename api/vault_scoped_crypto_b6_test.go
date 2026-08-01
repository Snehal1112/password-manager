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
	"rocketvault/internal/repositories"
	keyServices "rocketvault/internal/services/keys"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// TestB6_CryptoOps_NonOwnerVaultMember_Returns404 asserts that a vault
// member who does not own a key cannot use it for sign, verify, encrypt,
// decrypt, wrap, and unwrap, even via the vault-scoped route that grants
// vault-wide visibility for listing and get.
//
// Renamed from TestB6_CryptoOps_NonOwnerVaultMember_Returns403 (P1 scope
// refactor, Task 20). CryptoService.loadAndAuthorize now authorizes through
// KeyRepository.Read with an owner scope (model.NewOwnerScope) instead
// of an unscoped Read followed by a Go-level UserID comparison. A cross-user
// key never matches the owner-id predicate in Read's scoped SQL, so it comes
// back as "not found", the same as it already does for the non-crypto
// scoped key paths (see TestB6_KeyDelete_NonOwnerVaultMember_Returns404
// below, from Task 19). Task 20 additionally wraps the exported
// ErrKeyNotFound sentinel in loadAndAuthorize's not-found branch — a small,
// deliberate deviation from the task brief's literal code — specifically so
// this case reports 404 through the handlers' existing errors.Is(err,
// ErrKeyNotFound) branch instead of falling through to a generic 500;
// without that wrap, Read's plain "key not found or access denied"
// error satisfies none of the handlers' typed error checks. The cross-vault
// case (B6's actual, still-live conjunction) continues to return 403 via
// ErrKeyForbidden; that path is unchanged and not covered by this test.
func TestB6_CryptoOps_NonOwnerVaultMember_Returns404(t *testing.T) {
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
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s via vault route for non-owner key: expected 404, got %d (%s)", tt.name, w.Code, w.Body.String())
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
func (f *b6FakeKeyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	delete(f.keys, id)
	return nil
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
func (f *b6FakeKeyRepo) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (f *b6FakeKeyRepo) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (f *b6FakeKeyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	k, ok := f.keys[id]
	if !ok {
		return nil, errors.New("key not found")
	}
	switch scope.Kind() {
	case model.ScopeVault:
		if k.VaultID != scope.VaultID() {
			return nil, errors.New("key not found or access denied")
		}
	case model.ScopeOwner:
		ownerID, _ := scope.OwnerID()
		if k.UserID != ownerID {
			return nil, errors.New("key not found or access denied")
		}
	case model.ScopeAdmin:
		// No predicate.
	default:
		return nil, errors.New("key not found or access denied")
	}
	return k, nil
}
func (f *b6FakeKeyRepo) Update(ctx context.Context, k *model.Key, scope model.Scope) error {
	f.keys[k.ID] = k
	return nil
}
func (f *b6FakeKeyRepo) List(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	return nil, nil
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

// TestB6_KeyDelete_NonOwnerVaultMember_Returns404 asserts that DELETE on the
// vault-scoped key route is not found for a non-owner vault member.
// KeyService.DeleteKey authorizes through KeyRepository.Read: a non-owner's
// owner scope simply fails to resolve the key, so the handler's existing
// ErrKeyNotFound mapping reports 404 rather than 403. This is the spec's
// intentional "404, not 403" decision for the delete path (P1 scope
// refactor, Task 19). The crypto operations above now authorize through the
// same Read-based mechanism (Task 20) and land on the identical 404 outcome for a non-owner
// vault member; see TestB6_CryptoOps_NonOwnerVaultMember_Returns404's comment
// for that path's specifics.
func TestB6_KeyDelete_NonOwnerVaultMember_Returns404(t *testing.T) {
	repo := newB6FakeKeyRepo()
	ownerID := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()
	repo.keys[keyID] = &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID,
		Name: "k1", Type: "RSA", Value: "irrelevant", Enabled: true,
	}

	api, vrepo := newB6TestAPI(repo)
	vrepo.byName["prod"] = &model.Vault{ID: vaultID, Name: "prod", Enabled: true}
	vrepo.byID[vaultID.String()] = vrepo.byName["prod"]

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/keys/"+keyID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("DELETE non-owner key via vault route: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}
