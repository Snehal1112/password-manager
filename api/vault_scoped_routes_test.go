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
	ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleAdmin)})
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)
	return w
}

// recordingSecretService records which scope a handler built for each
// operation. The legacy flat route must yield an owner scope; the
// vault-scoped route must yield a vault scope carrying the resolved vault's
// ID. Unused methods panic.
type recordingSecretService struct {
	listScope      model.Scope
	listCalled     bool
	updateScope    model.Scope
	updateCalled   bool
	versionsScope  model.Scope
	versionsCalled bool
	exportScope    model.Scope
	exportCalled   bool
	importScope    model.Scope
	importCalled   bool
}

func (s *recordingSecretService) CreateSecret(context.Context, secretServices.CreateSecretRequest) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) UpdateSecret(_ context.Context, req secretServices.UpdateSecretRequest) error {
	s.updateCalled = true
	s.updateScope = req.Scope
	return nil
}
func (s *recordingSecretService) GetSecret(_ context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	return &model.Secret{ID: secretID, UserID: scope.ActorID(), Name: "existing", Value: "plain-value", Version: 1}, nil
}
func (s *recordingSecretService) ListSecrets(_ context.Context, scope model.Scope, _ []string, _, _ int) ([]model.Secret, error) {
	s.listCalled = true
	s.listScope = scope
	return []model.Secret{}, nil
}
func (s *recordingSecretService) DeleteSecret(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingSecretService) ListDeletedSecrets(context.Context, model.Scope) ([]model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GenerateSecret(context.Context, secretServices.GenerateSecretRequest) (*model.Secret, error) {
	panic("unexpected")
}
func (s *recordingSecretService) ExportSecrets(_ context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
	s.exportCalled = true
	s.exportScope = req.Scope
	return []byte("[]"), nil
}
func (s *recordingSecretService) ImportSecrets(_ context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	s.importCalled = true
	s.importScope = req.Scope
	return &secretServices.ImportResult{}, nil
}

// GetSecretVersions panics: the versions route must reach the metadata path,
// never the value-bearing one. Calling this from a handler is the § B30
// regression, so the double fails loudly rather than quietly returning.
func (s *recordingSecretService) GetSecretVersions(context.Context, uuid.UUID, model.Scope) ([]model.SecretVersion, error) {
	panic("listSecretVersionsHandler must call GetSecretVersionsMetadata, not GetSecretVersions (B30)")
}
func (s *recordingSecretService) GetSecretVersionsMetadata(_ context.Context, _ uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error) {
	s.versionsCalled = true
	s.versionsScope = scope
	return []model.SecretVersionMetadata{}, nil
}
func (s *recordingSecretService) GetSecretVersion(context.Context, uuid.UUID, int, model.Scope) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetLatestSecretVersion(context.Context, uuid.UUID, model.Scope) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) RecoverSecret(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingSecretService) PurgeSecret(context.Context, uuid.UUID, model.Scope) error {
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
// repo and a recording secret service. All requests issued via
// doVaultRequest/doScopedRequest carry model.RoleAdmin, so getVault's
// authorization check short-circuits on the account role before ever calling
// CheckAccess; policySvc only needs to exist (not be stubbed) because
// CanManageVault's caller fetches it via an eagerly evaluated function
// argument regardless of role (see newVaultTestAPI's comment in
// vault_test.go for the same pattern).
func newVaultScopedTestAPI(secretSvc secretServices.SecretService) (*API, *vaultFakeRepo) {
	repo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, secretSvc: secretSvc, policySvc: &mockAccessPolicyService{}}}
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
	// and use vault-scoped visibility (ListSecrets with a vault scope).
	w = doScopedRequest(api, http.MethodGet, "/api/v1/vaults/prod/secrets")
	if w.Code != http.StatusOK {
		t.Fatalf("resource GET /vaults/prod/secrets: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("resource route did not dispatch to the secret list handler")
	}
	if rec.listScope.Kind() != model.ScopeVault {
		t.Fatalf("vault-scoped route must use vault-scoped (not user-scoped) listing")
	}
}

// TestLegacyFlatRoute_UsesDefaultVaultScopedListing verifies that the legacy
// flat /secrets route lists the default vault, not the caller's rows across
// every vault. Vault-level "members see all" visibility now applies to both
// route shapes; only the targeted vault differs.
func TestLegacyFlatRoute_UsesDefaultVaultScopedListing(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/secrets")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /secrets: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the secret list handler")
	}
	if rec.listScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy route must use a vault scope, got %s", rec.listScope.String())
	}
	if rec.listScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy route scoped to vault %s, want the default vault", rec.listScope.VaultID())
	}
	if rec.listScope.ActorID() != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.listScope.ActorID(), vaultTestUserID)
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
	if rec.updateScope.Kind() != model.ScopeVault {
		t.Fatalf("vault-scoped /secrets/{id} PUT must use vault-scoped update (UpdateSecret with a vault scope)")
	}
	if rec.updateScope.VaultID() != id {
		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateScope.VaultID(), id)
	}
}

// TestLegacyFlatRoute_UsesDefaultVaultScopedUpdate verifies that PUT on the
// legacy flat /secrets/{id} route updates within the default vault, not by
// ownership across every vault.
func TestLegacyFlatRoute_UsesDefaultVaultScopedUpdate(t *testing.T) {
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
	if rec.updateScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy /secrets/{id} PUT must use a vault scope, got %s", rec.updateScope.String())
	}
	if rec.updateScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy update scoped to vault %s, want the default vault", rec.updateScope.VaultID())
	}
	if rec.updateScope.ActorID() != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.updateScope.ActorID(), vaultTestUserID)
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
	if rec.versionsScope.Kind() != model.ScopeVault {
		t.Fatalf("vault-scoped .../versions GET must use vault-scoped lookup (GetSecretVersions with a vault scope)")
	}
	if rec.versionsScope.VaultID() != id {
		t.Fatalf("versions lookup dispatched with vault ID %s, want %s", rec.versionsScope.VaultID(), id)
	}
}

// TestLegacyFlatRoute_UsesDefaultVaultScopedVersionsList verifies that GET on
// the legacy flat /secrets/{id}/versions route looks the secret up in the
// default vault rather than by ownership across every vault.
func TestLegacyFlatRoute_UsesDefaultVaultScopedVersionsList(t *testing.T) {
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
	if rec.versionsScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy .../versions GET must use a vault scope, got %s", rec.versionsScope.String())
	}
	if rec.versionsScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy .../versions scoped to vault %s, want the default vault", rec.versionsScope.VaultID())
	}
}

// TestVaultScopedRoute_UsesVaultScopedExport verifies that POST on the
// explicit /vaults/{name}/secrets/export route threads a vault scope carrying
// the resolved vault's ID into ExportSecretsRequest.
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
	if rec.exportScope.Kind() != model.ScopeVault {
		t.Fatalf("vault-scoped /secrets/export must use a vault scope")
	}
	if rec.exportScope.VaultID() != id {
		t.Fatalf("export dispatched with vault ID %s, want %s", rec.exportScope.VaultID(), id)
	}
}

// TestLegacyFlatRoute_ExportUsesDefaultVaultScope verifies that POST on the
// legacy flat /secrets/export route exports the default vault, not the
// caller's rows across every vault.
func TestLegacyFlatRoute_ExportUsesDefaultVaultScope(t *testing.T) {
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
	if rec.exportScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy /secrets/export must use a vault scope, got %s", rec.exportScope.String())
	}
	if rec.exportScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy export scoped to vault %s, want the default vault", rec.exportScope.VaultID())
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
	fw.Write([]byte(`[{"name":"n1","value":"v1"}]`)) //nolint:errcheck,gosec
	mw.WriteField("format", "json")                  //nolint:errcheck,gosec
	mw.Close()                                       //nolint:errcheck,gosec

	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/secrets/import", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	ctx := context.WithValue(r.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, []string{string(model.RoleAdmin)})
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped POST .../import: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.importCalled {
		t.Fatalf("vault-scoped route did not dispatch to the import handler")
	}
	if rec.importScope.Kind() != model.ScopeVault {
		t.Fatalf("vault-scoped /secrets/import must use a vault scope")
	}
	if rec.importScope.VaultID() != id {
		t.Fatalf("import dispatched with vault ID %s, want %s", rec.importScope.VaultID(), id)
	}
}
