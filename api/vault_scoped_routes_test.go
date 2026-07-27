// Package api — tests that vault-scoped resource routes coexist with vault
// management routes and dispatch to the correct handlers.
package api

import (
	"bytes"
	"context"
	"mime/multipart"
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

// recordingSecretService records which list method was called and with what
// scope. The legacy flat route must call the user-scoped ListSecrets; the
// vault-scoped route must call ListSecretsInVault. Unused methods panic.
type recordingSecretService struct {
	listVaultID         uuid.UUID
	listCalled          bool
	listUserScoped      bool
	listUserID          uuid.UUID
	updateCalled        bool
	updateVaultScoped   bool
	updateVaultID       uuid.UUID
	updateUserID        uuid.UUID
	versionsCalled      bool
	versionsVaultScoped bool
	versionsVaultID     uuid.UUID
	exportCalled        bool
	exportVaultID       uuid.UUID
	importCalled        bool
	importVaultID       uuid.UUID
}

func (s *recordingSecretService) CreateSecret(context.Context, secretServices.CreateSecretRequest) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) UpdateSecretScoped(_ context.Context, req secretServices.UpdateSecretRequest) error {
	s.updateCalled = true
	if vaultID := req.Scope.VaultID(); vaultID != uuid.Nil {
		s.updateVaultScoped = true
		s.updateVaultID = vaultID
		return nil
	}
	s.updateVaultScoped = false
	s.updateUserID = req.Scope.ActorID()
	return nil
}
func (s *recordingSecretService) UpdateSecret(_ context.Context, req secretServices.UpdateSecretRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = false
	s.updateUserID = req.UserID
	return nil
}
func (s *recordingSecretService) GetSecret(_ context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	return &model.Secret{ID: secretID, UserID: userID, Name: "existing", Value: "plain-value", Version: 1}, nil
}
func (s *recordingSecretService) GetSecretScoped(context.Context, uuid.UUID, model.Scope) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ListSecretsScoped(context.Context, model.Scope, []string) ([]model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) DeleteSecretScoped(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingSecretService) ListDeletedSecretsScoped(context.Context, model.Scope) ([]model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ListSecrets(_ context.Context, userID uuid.UUID, _ []string) ([]model.Secret, error) {
	s.listCalled = true
	s.listUserScoped = true
	s.listUserID = userID
	return []model.Secret{}, nil
}
func (s *recordingSecretService) DeleteSecret(context.Context, uuid.UUID, uuid.UUID) error {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecretInVault(_ context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	return &model.Secret{ID: secretID, VaultID: vaultID, Name: "existing", Value: "plain-value", Version: 1}, nil
}
func (s *recordingSecretService) UpdateSecretInVault(_ context.Context, req secretServices.UpdateSecretRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = true
	s.updateVaultID = req.VaultID
	return nil
}
func (s *recordingSecretService) ListSecretsInVault(_ context.Context, vaultID uuid.UUID, _ []string) ([]model.Secret, error) {
	s.listCalled = true
	s.listUserScoped = false
	s.listVaultID = vaultID
	return []model.Secret{}, nil
}
func (s *recordingSecretService) DeleteSecretInVault(context.Context, uuid.UUID, uuid.UUID) error {
	panic("unexpected")
}
func (s *recordingSecretService) GenerateSecret(context.Context, secretServices.GenerateSecretRequest) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ExportSecrets(_ context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
	s.exportCalled = true
	s.exportVaultID = req.VaultID
	return []byte("[]"), nil
}
func (s *recordingSecretService) ImportSecrets(_ context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	s.importCalled = true
	s.importVaultID = req.VaultID
	return &secretServices.ImportResult{}, nil
}
func (s *recordingSecretService) GetSecretVersions(_ context.Context, secretID, userID uuid.UUID) ([]model.SecretVersion, error) {
	s.versionsCalled = true
	s.versionsVaultScoped = false
	return []model.SecretVersion{}, nil
}
func (s *recordingSecretService) GetSecretVersionsInVault(_ context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	s.versionsCalled = true
	s.versionsVaultScoped = true
	s.versionsVaultID = vaultID
	return []model.SecretVersion{}, nil
}
func (s *recordingSecretService) GetSecretVersion(context.Context, uuid.UUID, int, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetLatestSecretVersion(context.Context, uuid.UUID, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecretVersionInVault(context.Context, uuid.UUID, int, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetLatestSecretVersionInVault(context.Context, uuid.UUID, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecretVersionsScoped(context.Context, uuid.UUID, model.Scope) ([]model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetSecretVersionScoped(context.Context, uuid.UUID, int, model.Scope) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetLatestSecretVersionScoped(context.Context, uuid.UUID, model.Scope) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) RecoverSecretScoped(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingSecretService) PurgeSecretScoped(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}

// vaultResolutionTestMiddleware mimics middleware.VaultResolutionMiddleware
// for this lightweight test harness, which does not wire the full
// service-container-backed middleware chain. It resolves the {vault_name}
// path variable against the fake vault repo and injects the vault ID into
// the request context the same way the real middleware does, so handlers
// exercising vaultIDFromRequest see the actual seeded vault's ID rather than
// always falling back to the default vault.
func vaultResolutionTestMiddleware(repo *vaultFakeRepo) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := mux.Vars(r)["vault_name"]
			vault, ok := repo.byName[name]
			if !ok {
				http.Error(w, `{"error":"vault not found"}`, http.StatusNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), common.VaultIDKey, vault.ID.String())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
	r.VaultScoped.Use(vaultResolutionTestMiddleware(repo))
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

	// Vault-scoped resource route: GET /vaults/prod/secrets must reach listSecrets
	// and use vault-scoped visibility (ListSecretsInVault).
	w = doScopedRequest(api, http.MethodGet, "/api/v1/vaults/prod/secrets")
	if w.Code != http.StatusOK {
		t.Fatalf("resource GET /vaults/prod/secrets: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("resource route did not dispatch to the secret list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("vault-scoped route must use vault-scoped (not user-scoped) listing")
	}
}

// TestLegacyFlatRoute_UsesUserScopedListing verifies that the legacy flat
// /secrets route uses per-user visibility (ListSecrets scoped to the caller),
// preserving pre-multi-vault behavior. Vault-level "members see all" visibility
// applies only to the explicit /vaults/{name}/... routes.
func TestLegacyFlatRoute_UsesUserScopedListing(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/secrets")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /secrets: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the secret list handler")
	}
	if !rec.listUserScoped {
		t.Fatalf("legacy route must use user-scoped listing (ListSecrets), not vault-scoped")
	}
	if rec.listUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route scoped to user %s, want caller %s", rec.listUserID, vaultTestUserID)
	}
}

// TestVaultScopedRoute_UsesVaultScopedUpdate verifies that PUT on the
// explicit /vaults/{name}/secrets/{id} route dispatches to
// UpdateSecretInVault, not the owner-scoped UpdateSecret.
func TestVaultScopedRoute_UsesVaultScopedUpdate(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	secretID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/secrets/"+secretID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped PUT /vaults/prod/secrets/%s: expected 200, got %d (%s)", secretID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("vault-scoped route did not dispatch to the secret update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("vault-scoped /secrets/{id} PUT must use vault-scoped update (UpdateSecretInVault)")
	}
	if rec.updateVaultID != id {
		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateVaultID, id)
	}
}

// TestLegacyFlatRoute_UsesUserScopedUpdate verifies that PUT on the legacy
// flat /secrets/{id} route still dispatches to the owner-scoped UpdateSecret.
func TestLegacyFlatRoute_UsesUserScopedUpdate(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	secretID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/secrets/"+secretID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy PUT /secrets/%s: expected 200, got %d (%s)", secretID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("legacy route did not dispatch to the secret update handler")
	}
	if rec.updateVaultScoped {
		t.Fatalf("legacy /secrets/{id} PUT must use owner-scoped update (UpdateSecret), not vault-scoped")
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route scoped update to user %s, want caller %s", rec.updateUserID, vaultTestUserID)
	}
}

// TestVaultScopedRoute_UsesVaultScopedVersionsList verifies that GET on the
// explicit /vaults/{name}/secrets/{id}/versions route dispatches to
// GetSecretVersionsInVault, not the owner-scoped GetSecretVersions.
func TestVaultScopedRoute_UsesVaultScopedVersionsList(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	secretID := uuid.New()
	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod/secrets/"+secretID.String()+"/versions", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET .../versions: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.versionsCalled {
		t.Fatalf("vault-scoped route did not dispatch to the versions list handler")
	}
	if !rec.versionsVaultScoped {
		t.Fatalf("vault-scoped .../versions GET must use vault-scoped lookup (GetSecretVersionsInVault)")
	}
	if rec.versionsVaultID != id {
		t.Fatalf("versions lookup dispatched with vault ID %s, want %s", rec.versionsVaultID, id)
	}
}

// TestLegacyFlatRoute_UsesUserScopedVersionsList verifies that GET on the
// legacy flat /secrets/{id}/versions route still dispatches to the
// owner-scoped GetSecretVersions.
func TestLegacyFlatRoute_UsesUserScopedVersionsList(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	secretID := uuid.New()
	w := doVaultRequest(api, http.MethodGet, "/api/v1/secrets/"+secretID.String()+"/versions", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET .../versions: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.versionsCalled {
		t.Fatalf("legacy route did not dispatch to the versions list handler")
	}
	if rec.versionsVaultScoped {
		t.Fatalf("legacy .../versions GET must use owner-scoped lookup (GetSecretVersions), not vault-scoped")
	}
}

// TestVaultScopedRoute_UsesVaultScopedExport verifies that POST on the
// explicit /vaults/{name}/secrets/export route threads the resolved vault's
// ID into ExportSecretsRequest.
func TestVaultScopedRoute_UsesVaultScopedExport(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	body := []byte(`{"format":"json"}`)
	w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/secrets/export", body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped POST .../export: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.exportCalled {
		t.Fatalf("vault-scoped route did not dispatch to the export handler")
	}
	if rec.exportVaultID != id {
		t.Fatalf("export dispatched with vault ID %s, want %s", rec.exportVaultID, id)
	}
}

// TestLegacyFlatRoute_ExportOmitsVaultID verifies that POST on the legacy
// flat /secrets/export route leaves VaultID unset (owner-scoped export).
func TestLegacyFlatRoute_ExportOmitsVaultID(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	body := []byte(`{"format":"json"}`)
	w := doVaultRequest(api, http.MethodPost, "/api/v1/secrets/export", body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy POST /secrets/export: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.exportCalled {
		t.Fatalf("legacy route did not dispatch to the export handler")
	}
	if rec.exportVaultID != uuid.Nil {
		t.Fatalf("legacy /secrets/export must not set VaultID, got %s", rec.exportVaultID)
	}
}

// TestVaultScopedRoute_UsesVaultScopedImport verifies that POST on the
// explicit /vaults/{name}/secrets/import route threads the resolved vault's
// ID into ImportSecretsRequest.
func TestVaultScopedRoute_UsesVaultScopedImport(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "secrets.json")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	fw.Write([]byte(`[{"name":"n1","value":"v1"}]`))
	mw.WriteField("format", "json")
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/secrets/import", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	ctx := context.WithValue(r.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, string(model.RoleAdmin))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped POST .../import: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.importCalled {
		t.Fatalf("vault-scoped route did not dispatch to the import handler")
	}
	if rec.importVaultID != id {
		t.Fatalf("import dispatched with vault ID %s, want %s", rec.importVaultID, id)
	}
}
