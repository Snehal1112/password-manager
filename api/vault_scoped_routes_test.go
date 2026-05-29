// Package api — tests that vault-scoped resource routes coexist with vault
// management routes and dispatch to the correct handlers.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/app"
	"rocketvault/common"
	secretServices "rocketvault/internal/services/secrets"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// doScopedRequest issues an authed request carrying both user id and an admin
// role so RBAC endpoint checks on resource routes pass.
func doScopedRequest(api *API, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(r.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, string(model.RoleAdmin))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)
	return w
}

// recordingSecretService records the vault id its list call receives and
// returns an empty list. All other methods panic since they are unused here.
type recordingSecretService struct {
	listVaultID uuid.UUID
	listCalled  bool
}

func (s *recordingSecretService) CreateSecret(context.Context, secretServices.CreateSecretRequest) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) UpdateSecret(context.Context, secretServices.UpdateSecretRequest) error {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecret(context.Context, uuid.UUID, uuid.UUID) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ListSecrets(context.Context, uuid.UUID, []string) ([]model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) DeleteSecret(context.Context, uuid.UUID, uuid.UUID) error {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecretInVault(context.Context, uuid.UUID, uuid.UUID) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ListSecretsInVault(_ context.Context, vaultID uuid.UUID, _ []string) ([]model.Secret, error) {
	s.listCalled = true
	s.listVaultID = vaultID
	return []model.Secret{}, nil
}
func (s *recordingSecretService) DeleteSecretInVault(context.Context, uuid.UUID, uuid.UUID) error {
	panic("unexpected")
}
func (s *recordingSecretService) GenerateSecret(context.Context, secretServices.GenerateSecretRequest) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ExportSecrets(context.Context, secretServices.ExportSecretsRequest) ([]byte, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ImportSecrets(context.Context, secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecretVersions(context.Context, uuid.UUID, uuid.UUID) ([]model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecretVersion(context.Context, uuid.UUID, int, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetLatestSecretVersion(context.Context, uuid.UUID, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}

// newVaultScopedTestAPI wires both the vault management routes and the
// vault-scoped resource routes onto one router, backed by an in-memory vault
// repo and a recording secret service.
func newVaultScopedTestAPI(secretSvc secretServices.SecretService) (*API, *vaultFakeRepo) {
	repo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, secretSvc: secretSvc}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	api.InitVault()
	api.InitSecrets()
	return api, repo
}

// TestVaultScopedRoutes_CoexistWithManagement verifies that the deeper
// /vaults/{vault_name}/secrets route reaches the secret handler while the
// single-segment /vaults/{name} management route still reaches getVault.
func TestVaultScopedRoutes_CoexistWithManagement(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	// Seed a vault named "prod".
	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	// Management route: GET /vaults/prod must reach getVault (returns the vault).
	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("management GET /vaults/prod: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if rec.listCalled {
		t.Fatalf("management route incorrectly dispatched to the secret list handler")
	}

	// Vault-scoped resource route: GET /vaults/prod/secrets must reach listSecrets.
	w = doScopedRequest(api, http.MethodGet, "/api/v1/vaults/prod/secrets")
	if w.Code != http.StatusOK {
		t.Fatalf("resource GET /vaults/prod/secrets: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("resource route did not dispatch to the secret list handler")
	}
}

// TestLegacyFlatRoute_UsesDefaultVault verifies that the legacy flat
// /secrets route still works and resolves to the default vault id when no
// vault is set in context (as in this middleware-free test).
func TestLegacyFlatRoute_UsesDefaultVault(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/secrets")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /secrets: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the secret list handler")
	}
	if rec.listVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy route resolved vault %s, want default %s", rec.listVaultID, model.DefaultVaultID)
	}
}
