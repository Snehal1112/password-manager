// Package api — tests that legacy flat key/certificate routes use per-user
// visibility while explicit vault-scoped routes use vault-level visibility.
package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/app"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// recordingKeyService records which list/get method was called and with what
// scope. The legacy flat route must call the user-scoped ListKeys/GetKey; the
// vault-scoped route must call ListKeysInVault/GetKeyInVault. Unused methods
// panic so an accidental call surfaces immediately.
type recordingKeyService struct {
	listCalled     bool
	listUserScoped bool
	listUserID     uuid.UUID
	listVaultID    uuid.UUID
	getCalled      bool
	getUserScoped  bool
}

func (s *recordingKeyService) CreateRSAKey(context.Context, keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) CreateECDSAKey(context.Context, keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) GetKey(_ context.Context, _, userID uuid.UUID) (*model.Key, error) {
	s.getCalled = true
	s.getUserScoped = true
	s.listUserID = userID
	return &model.Key{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, UserID: userID}, nil
}
func (s *recordingKeyService) ListKeys(_ context.Context, userID uuid.UUID) ([]model.Key, error) {
	s.listCalled = true
	s.listUserScoped = true
	s.listUserID = userID
	return []model.Key{}, nil
}
func (s *recordingKeyService) ListKeysWithFilters(context.Context, *uuid.UUID, string, []string, bool) ([]model.Key, error) {
	panic("unexpected")
}
func (s *recordingKeyService) UpdateKey(context.Context, keyServices.UpdateKeyRequest) error {
	panic("unexpected")
}
func (s *recordingKeyService) DeleteKey(context.Context, uuid.UUID, uuid.UUID) (*model.Key, error) {
	panic("unexpected")
}
func (s *recordingKeyService) GetKeyInVault(_ context.Context, _, vaultID uuid.UUID) (*model.Key, error) {
	s.getCalled = true
	s.getUserScoped = false
	s.listVaultID = vaultID
	return &model.Key{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA}, nil
}
func (s *recordingKeyService) ListKeysInVault(_ context.Context, vaultID uuid.UUID, _ string, _ []string) ([]model.Key, error) {
	s.listCalled = true
	s.listUserScoped = false
	s.listVaultID = vaultID
	return []model.Key{}, nil
}
func (s *recordingKeyService) DeleteKeyInVault(context.Context, uuid.UUID, uuid.UUID) (*model.Key, error) {
	panic("unexpected")
}
func (s *recordingKeyService) RotateKey(context.Context, uuid.UUID, uuid.UUID) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) ValidateKeyAccess(context.Context, uuid.UUID, uuid.UUID, string) error {
	panic("unexpected")
}

// recordingCertService records which list/get method was called and with what
// scope, mirroring recordingKeyService for certificates.
type recordingCertService struct {
	listCalled     bool
	listUserScoped bool
	listUserID     uuid.UUID
	listVaultID    uuid.UUID
	getCalled      bool
	getUserScoped  bool
}

func (s *recordingCertService) CreateSelfSignedCertificate(context.Context, certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	panic("unexpected")
}
func (s *recordingCertService) CreateCASignedCertificate(context.Context, certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	panic("unexpected")
}
func (s *recordingCertService) GetCertificate(_ context.Context, _, userID uuid.UUID) (*model.Certificate, error) {
	s.getCalled = true
	s.getUserScoped = true
	s.listUserID = userID
	return &model.Certificate{ID: uuid.New(), Name: "c", UserID: userID}, nil
}
func (s *recordingCertService) ListCertificates(_ context.Context, userID uuid.UUID) ([]model.Certificate, error) {
	s.listCalled = true
	s.listUserScoped = true
	s.listUserID = userID
	return []model.Certificate{}, nil
}
func (s *recordingCertService) UpdateCertificate(context.Context, certServices.UpdateCertificateRequest) error {
	panic("unexpected")
}
func (s *recordingCertService) DeleteCertificate(context.Context, uuid.UUID, uuid.UUID) error {
	panic("unexpected")
}
func (s *recordingCertService) GetCertificateInVault(_ context.Context, _, vaultID uuid.UUID) (*model.Certificate, error) {
	s.getCalled = true
	s.getUserScoped = false
	s.listVaultID = vaultID
	return &model.Certificate{ID: uuid.New(), Name: "c"}, nil
}
func (s *recordingCertService) ListCertificatesInVault(_ context.Context, vaultID uuid.UUID) ([]model.Certificate, error) {
	s.listCalled = true
	s.listUserScoped = false
	s.listVaultID = vaultID
	return []model.Certificate{}, nil
}
func (s *recordingCertService) DeleteCertificateInVault(context.Context, uuid.UUID, uuid.UUID) error {
	panic("unexpected")
}
func (s *recordingCertService) RenewCertificate(context.Context, uuid.UUID, uuid.UUID, int) (*certServices.CreateCertificateResult, error) {
	panic("unexpected")
}
func (s *recordingCertService) ValidateCertificateAccess(context.Context, uuid.UUID, uuid.UUID, string) error {
	panic("unexpected")
}
func (s *recordingCertService) ValidateKeyOwnership(context.Context, uuid.UUID, uuid.UUID, string) error {
	panic("unexpected")
}

// newVaultScopedKeyCertTestAPI wires both the legacy flat key/certificate routes
// and the vault-scoped resource routes onto one router, backed by recording
// services so each test can assert which scope was used.
func newVaultScopedKeyCertTestAPI(keySvc keyServices.KeyService, certSvc certServices.CertificateService) (*API, *vaultFakeRepo) {
	repo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, keySvc: keySvc, certSvc: certSvc}}
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
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitKeys()
	api.InitCertificates()
	return api, repo
}

// TestLegacyFlatKeyRoute_UsesUserScopedListing verifies the legacy flat /keys
// route uses per-user visibility (ListKeys scoped to the caller).
func TestLegacyFlatKeyRoute_UsesUserScopedListing(t *testing.T) {
	rec := &recordingKeyService{}
	api, _ := newVaultScopedKeyCertTestAPI(rec, nil)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/keys")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /keys: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the key list handler")
	}
	if !rec.listUserScoped {
		t.Fatalf("legacy /keys must use user-scoped listing (ListKeys), not ListKeysInVault")
	}
	if rec.listUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy /keys scoped to user %s, want caller %s", rec.listUserID, vaultTestUserID)
	}
}

// TestVaultScopedKeyRoute_UsesVaultScopedListing verifies the vault-scoped
// /vaults/{name}/keys route uses vault-level visibility (ListKeysInVault).
func TestVaultScopedKeyRoute_UsesVaultScopedListing(t *testing.T) {
	rec := &recordingKeyService{}
	api, repo := newVaultScopedKeyCertTestAPI(rec, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	w := doScopedRequest(api, http.MethodGet, "/api/v1/vaults/prod/keys")
	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET /vaults/prod/keys: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("vault-scoped route did not dispatch to the key list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("vault-scoped /keys must use vault-scoped listing (ListKeysInVault)")
	}
}

// TestLegacyFlatCertRoute_UsesUserScopedListing verifies the legacy flat
// /certificates route uses per-user visibility (ListCertificates).
func TestLegacyFlatCertRoute_UsesUserScopedListing(t *testing.T) {
	rec := &recordingCertService{}
	api, _ := newVaultScopedKeyCertTestAPI(nil, rec)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/certificates")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /certificates: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the certificate list handler")
	}
	if !rec.listUserScoped {
		t.Fatalf("legacy /certificates must use user-scoped listing (ListCertificates), not ListCertificatesInVault")
	}
	if rec.listUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy /certificates scoped to user %s, want caller %s", rec.listUserID, vaultTestUserID)
	}
}

// TestVaultScopedCertRoute_UsesVaultScopedListing verifies the vault-scoped
// /vaults/{name}/certificates route uses vault-level visibility.
func TestVaultScopedCertRoute_UsesVaultScopedListing(t *testing.T) {
	rec := &recordingCertService{}
	api, repo := newVaultScopedKeyCertTestAPI(nil, rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	w := doScopedRequest(api, http.MethodGet, "/api/v1/vaults/prod/certificates")
	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET /vaults/prod/certificates: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("vault-scoped route did not dispatch to the certificate list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("vault-scoped /certificates must use vault-scoped listing (ListCertificatesInVault)")
	}
}
