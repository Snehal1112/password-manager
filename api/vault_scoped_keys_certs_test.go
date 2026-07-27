// Package api — tests that legacy flat key/certificate routes use per-user
// visibility while explicit vault-scoped routes use vault-level visibility.
package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	"rocketvault/internal/repositories"
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

	updateCalled      bool
	updateVaultScoped bool
	updateVaultID     uuid.UUID
	updateUserID      uuid.UUID
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
func (s *recordingKeyService) UpdateKey(_ context.Context, req keyServices.UpdateKeyRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = false
	s.updateUserID = req.UserID
	return nil
}
func (s *recordingKeyService) UpdateKeyInVault(_ context.Context, req keyServices.UpdateKeyRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = true
	s.updateVaultID = req.VaultID
	return nil
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
func (s *recordingKeyService) DeleteKeyInVault(_ context.Context, _, _, _ uuid.UUID) (*model.Key, error) {
	panic("unexpected")
}
func (s *recordingKeyService) RotateKey(context.Context, uuid.UUID, uuid.UUID) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) ValidateKeyAccess(context.Context, uuid.UUID, uuid.UUID, string) error {
	panic("unexpected")
}
func (s *recordingKeyService) GetKeyScoped(context.Context, uuid.UUID, model.Scope) (*model.Key, error) {
	panic("unexpected")
}
func (s *recordingKeyService) ListKeysScoped(context.Context, model.Scope, repositories.KeyFilter) ([]model.Key, error) {
	panic("unexpected")
}
func (s *recordingKeyService) UpdateKeyScoped(context.Context, keyServices.UpdateKeyRequest) error {
	panic("unexpected")
}
func (s *recordingKeyService) DeleteKeyScoped(context.Context, uuid.UUID, model.Scope) (*model.Key, error) {
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

	// getInVaultErr, when set, is returned by GetCertificateInVault instead of
	// a synthetic certificate -- simulates the vault-membership pre-check
	// failing (e.g. the certificate does not belong to the resolved vault).
	getInVaultErr error
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
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
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
	r.VaultScoped.Use(vaultResolutionTestMiddleware(repo))
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitKeys()
	api.InitCertificates()
	return api, repo
}

// newVaultScopedCertPolicyTestAPI wires vault management and vault-scoped
// certificate routes (including the policy sub-resource) onto one router,
// backed by a recording cert service and a certificate policy repository.
func newVaultScopedCertPolicyTestAPI(certSvc certServices.CertificateService, policyRepo repositories.CertificatePolicyRepositoryInterface) (*API, *vaultFakeRepo) {
	repo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, certSvc: certSvc, certPolicyRepo: policyRepo}}
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
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitCertificates()
	return api, repo
}

// TestGetCertificatePolicy_VaultScopedRoute_UsesGetByCertificateIDAny verifies
// that GET on the explicit /vaults/{name}/certificates/{id}/policy route
// succeeds even when the stored policy's owner differs from the caller,
// proving vault-wide access rather than ownership-gated access.
func TestGetCertificatePolicy_VaultScopedRoute_UsesGetByCertificateIDAny(t *testing.T) {
	certSvc := &recordingCertService{}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	otherOwnerID := uuid.New() // different from the caller (vaultTestUserID)
	stored := &model.CertificatePolicy{ID: uuid.New(), CertificateID: certID, UserID: otherOwnerID, ValidityMonths: 12}
	policyRepo.On("GetByCertificateIDAny", mock.Anything, certID).Return(stored, nil)

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET .../policy: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if certSvc.listVaultID != id {
		t.Fatalf("policy operation dispatched with vault ID %s, want %s", certSvc.listVaultID, id)
	}
	policyRepo.AssertExpectations(t)
}

// TestUpsertCertificatePolicy_VaultScopedRoute_VerifiesCertInVaultFirst
// verifies that PUT on the vault-scoped policy route 404s (and never calls
// Upsert) when the certificate does not belong to the resolved vault.
func TestUpsertCertificatePolicy_VaultScopedRoute_VerifiesCertInVaultFirst(t *testing.T) {
	certSvc := &recordingCertService{getInVaultErr: fmt.Errorf("%w: not in vault", certServices.ErrCertNotFound)}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	body := []byte(`{"validity_months":12,"key_type":"RSA","key_size":2048}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", body)

	if w.Code != http.StatusNotFound {
		t.Fatalf("vault-scoped PUT .../policy for cert not in vault: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
	if certSvc.listVaultID != id {
		t.Fatalf("policy operation dispatched with vault ID %s, want %s", certSvc.listVaultID, id)
	}
	policyRepo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
}

// TestDeleteCertificatePolicy_VaultScopedRoute_UsesDeleteByCertificateIDAny verifies
// that DELETE on the explicit vault-scoped policy route succeeds even when
// the stored policy's owner differs from the caller.
func TestDeleteCertificatePolicy_VaultScopedRoute_UsesDeleteByCertificateIDAny(t *testing.T) {
	certSvc := &recordingCertService{}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	policyRepo.On("DeleteByCertificateIDAny", mock.Anything, certID).Return(nil)

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped DELETE .../policy: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if certSvc.listVaultID != id {
		t.Fatalf("policy operation dispatched with vault ID %s, want %s", certSvc.listVaultID, id)
	}
	policyRepo.AssertExpectations(t)
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

// TestVaultScopedKeyRoute_UsesVaultScopedUpdate verifies that PUT on the
// explicit /vaults/{name}/keys/{id} route dispatches to UpdateKeyInVault,
// not the owner-scoped UpdateKey.
func TestVaultScopedKeyRoute_UsesVaultScopedUpdate(t *testing.T) {
	rec := &recordingKeyService{}
	api, repo := newVaultScopedKeyCertTestAPI(rec, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	keyID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/keys/"+keyID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped PUT /vaults/prod/keys/%s: expected 200, got %d (%s)", keyID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("vault-scoped route did not dispatch to the key update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("vault-scoped /keys/{id} PUT must use vault-scoped update (UpdateKeyInVault)")
	}
	if rec.updateVaultID != id {
		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateVaultID, id)
	}
}

// TestLegacyFlatKeyRoute_UsesUserScopedUpdate verifies that PUT on the legacy
// flat /keys/{id} route still dispatches to the owner-scoped UpdateKey.
func TestLegacyFlatKeyRoute_UsesUserScopedUpdate(t *testing.T) {
	rec := &recordingKeyService{}
	api, _ := newVaultScopedKeyCertTestAPI(rec, nil)

	keyID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/keys/"+keyID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy PUT /keys/%s: expected 200, got %d (%s)", keyID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("legacy route did not dispatch to the key update handler")
	}
	if rec.updateVaultScoped {
		t.Fatalf("legacy /keys/{id} PUT must use owner-scoped update (UpdateKey), not vault-scoped")
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route scoped update to user %s, want caller %s", rec.updateUserID, vaultTestUserID)
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
