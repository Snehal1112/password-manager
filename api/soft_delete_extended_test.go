// Package api — additional tests for soft-delete handlers (secrets, keys, certificates).
package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/common"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// errTest is a sentinel error used by stub repositories in soft-delete tests.
var errTest = errors.New("test error")

// ============================================================
// helpers
// ============================================================

const sdExtUserID = "c3d4e5f6-a7b8-9012-cdef-123456789012"

// ============================================================
// userIDFromClaims
// ============================================================

func TestUserIDFromClaims_MissingClaim_ReturnsFalse(t *testing.T) {
	c := &Context{Claims: RequestClaims{}, Params: &ApiParams{}}
	id, ok := userIDFromClaims(c)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
}

func TestUserIDFromClaims_InvalidUUID_ReturnsFalse(t *testing.T) {
	c := &Context{Claims: RequestClaims{UserID: "not-uuid"}, Params: &ApiParams{}}
	id, ok := userIDFromClaims(c)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
}

func TestUserIDFromClaims_ValidUUID_ReturnsTrue(t *testing.T) {
	c := &Context{Claims: RequestClaims{UserID: sdExtUserID}, Params: &ApiParams{}}
	id, ok := userIDFromClaims(c)
	assert.True(t, ok)
	assert.Equal(t, uuid.MustParse(sdExtUserID), id)
}

// ============================================================
// listDeletedSecrets
//
// These handlers now delegate entirely to the SecretService (see
// soft_delete_scope_test.go for the scope-routing proof, and
// secret_scope_service_test.go for the authorization-branch coverage that
// used to live here against a stub repository). What remains here is the
// equivalence proof that the handler still wires status codes correctly
// through the SecretService, mirroring secrets_handlers_test.go's pattern.
// ============================================================

func TestListDeletedSecrets_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ListDeletedSecrets", mock.Anything, mock.Anything).Return(nil, errTest)
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil)

	listDeletedSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedSecrets_EmptyList_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ListDeletedSecrets", mock.Anything, mock.Anything).Return([]model.Secret{}, nil)
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil)

	listDeletedSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedSecrets_WithDeletedItems_Returns200(t *testing.T) {
	now := time.Now()
	svc := &mockSecretService{}
	svc.On("ListDeletedSecrets", mock.Anything, mock.Anything).Return([]model.Secret{
		{ID: uuid.New(), Name: "deleted-secret", DeletedAt: &now},
	}, nil)
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil)

	listDeletedSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// recoverSecret
// ============================================================

func TestRecoverSecret_InvalidID_Returns400(t *testing.T) {
	c := newSecretCtx(&mockSecretService{})
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/secrets/bad/restore", nil)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("RecoverSecret", mock.Anything, secretID, mock.Anything).Return(secretServices.ErrSecretNotFound)
	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/secrets/"+secretID.String()+"/restore", nil)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("RecoverSecret", mock.Anything, secretID, mock.Anything).Return(nil)
	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/secrets/"+secretID.String()+"/restore", nil)

	recoverSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// purgeSecret
// ============================================================

func TestPurgeSecret_InvalidID_Returns400(t *testing.T) {
	c := newSecretCtx(&mockSecretService{})
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/secrets/bad/purge", nil)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("PurgeSecret", mock.Anything, secretID, mock.Anything).Return(secretServices.ErrSecretNotFound)
	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/secrets/"+secretID.String()+"/purge", nil)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("PurgeSecret", mock.Anything, secretID, mock.Anything).Return(nil)
	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/secrets/"+secretID.String()+"/purge", nil)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listDeletedKeys
//
// These handlers now delegate entirely to the KeyService (see
// key_soft_delete_test.go for the scope-authorization branch coverage).
// What remains here is the equivalence proof that the handler still wires
// status codes correctly, mirroring listDeletedSecrets's tests above.
// ============================================================

func TestListDeletedKeys_ServiceError_Returns500(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return(nil, errTest)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys", nil)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedKeys_Success_Returns200(t *testing.T) {
	now := time.Now()
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{
		{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now},
	}, nil)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys", nil)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// recoverKey
// ============================================================

func TestRecoverKey_InvalidID_Returns400(t *testing.T) {
	c := newKeyCtx(&mockKeyService{})
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/bad/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.Anything).Return(keyServices.ErrKeyNotFound)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.Anything).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// purgeKey
// ============================================================

func TestPurgeKey_InvalidID_Returns400(t *testing.T) {
	c := newKeyCtx(&mockKeyService{})
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/bad/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("PurgeKey", mock.Anything, keyID, mock.Anything).Return(keyServices.ErrKeyNotFound)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/"+keyID.String()+"/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("PurgeKey", mock.Anything, keyID, mock.Anything).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/"+keyID.String()+"/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listDeletedCertificates
//
// These handlers now delegate entirely to the CertificateService — see the
// comment above the keys section for why the coverage shape changed.
// ============================================================

func TestListDeletedCertificates_ServiceError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.Anything).Return(nil, errTest)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedCertificates_Success_Returns200(t *testing.T) {
	now := time.Now()
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.Anything).Return([]model.Certificate{
		{ID: uuid.New(), Name: "cert", DeletedAt: &now},
	}, nil)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// recoverCertificate
// ============================================================

func TestRecoverCertificate_InvalidID_Returns400(t *testing.T) {
	c := newCertCtx(&mockCertService{}, certAdminClaims())
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/bad/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverCertificate_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.Anything).Return(certServices.ErrCertNotFound)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverCertificate_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.Anything).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// purgeCertificate
// ============================================================

func TestPurgeCertificate_InvalidID_Returns400(t *testing.T) {
	c := newCertCtx(&mockCertService{}, certAdminClaims())
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/bad/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeCertificate_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("PurgeCertificate", mock.Anything, certID, mock.Anything).Return(certServices.ErrCertNotFound)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeCertificate_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("PurgeCertificate", mock.Anything, certID, mock.Anything).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// vault-scope routing proof — keys and certificates
//
// Mirrors soft_delete_scope_test.go's secrets coverage: proves the flat
// route builds an owner scope and the vault-scoped route builds a vault
// scope, now that keys/certs go through the same scopeFromRequest path.
//
// Each matcher checks both Kind() and the carried vault/owner id (not just
// Kind()) — a resolved-vault-id bug that kept the right Kind but the wrong
// id would otherwise slip through. The vault-scoped requests inject a
// distinct resolved vault id via common.VaultIDKey, exactly as
// VaultResolutionMiddleware does in the real router, so the id under test
// is never just the DefaultVaultID fallback.
// ============================================================

// vaultScopedRequest builds a request carrying both the vault_name route var
// and a resolved vault id in context, as VaultResolutionMiddleware would.
func vaultScopedRequest(method, path string, vaultID uuid.UUID) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	return mux.SetURLVars(r, map[string]string{"vault_name": "team-a"})
}

func TestRecoverKey_FlatRoute_UsesOwnerScope(t *testing.T) {
	keyID := uuid.New()
	wantOwnerID := uuid.MustParse(keyTestUserID)
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		ownerID, ok := s.OwnerID()
		return s.Kind() == model.ScopeOwner && ok && ownerID == wantOwnerID
	})).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverKey_VaultScopedRoute_UsesVaultScope(t *testing.T) {
	keyID := uuid.New()
	wantVaultID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := vaultScopedRequest(http.MethodPost, "/vaults/team-a/deleted/keys/"+keyID.String()+"/restore", wantVaultID)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeKey_FlatRoute_UsesOwnerScope(t *testing.T) {
	keyID := uuid.New()
	wantOwnerID := uuid.MustParse(keyTestUserID)
	svc := &mockKeyService{}
	svc.On("PurgeKey", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		ownerID, ok := s.OwnerID()
		return s.Kind() == model.ScopeOwner && ok && ownerID == wantOwnerID
	})).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/"+keyID.String()+"/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeKey_VaultScopedRoute_UsesVaultScope(t *testing.T) {
	keyID := uuid.New()
	wantVaultID := uuid.New()
	svc := &mockKeyService{}
	svc.On("PurgeKey", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := vaultScopedRequest(http.MethodDelete, "/vaults/team-a/deleted/keys/"+keyID.String()+"/purge", wantVaultID)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// listDeletedKeys never calls scopeFromRequest — it always builds a vault
// scope directly from vaultIDFromRequest/userIDFromClaims (see api/soft_delete.go),
// so any authorized vault member sees the full listing. These tests prove
// that stays true, and that the resolved vault id still varies with the
// route, unlike recover/purge's owner/vault split.
func TestListDeletedKeys_FlatRoute_UsesDefaultVaultScope(t *testing.T) {
	wantVaultID := uuid.MustParse(model.DefaultVaultID)
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return([]model.Key{}, nil)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys", nil)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedKeys_VaultScopedRoute_UsesResolvedVaultScope(t *testing.T) {
	wantVaultID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return([]model.Key{}, nil)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := vaultScopedRequest(http.MethodGet, "/vaults/team-a/deleted/keys", wantVaultID)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverCertificate_FlatRoute_UsesOwnerScope(t *testing.T) {
	certID := uuid.New()
	wantOwnerID := uuid.MustParse(certTestUserID)
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.MatchedBy(func(s model.Scope) bool {
		ownerID, ok := s.OwnerID()
		return s.Kind() == model.ScopeOwner && ok && ownerID == wantOwnerID
	})).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverCertificate_VaultScopedRoute_UsesVaultScope(t *testing.T) {
	certID := uuid.New()
	wantVaultID := uuid.New()
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := vaultScopedRequest(http.MethodPost, "/vaults/team-a/deleted/certificates/"+certID.String()+"/restore", wantVaultID)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeCertificate_FlatRoute_UsesOwnerScope(t *testing.T) {
	certID := uuid.New()
	wantOwnerID := uuid.MustParse(certTestUserID)
	svc := &mockCertService{}
	svc.On("PurgeCertificate", mock.Anything, certID, mock.MatchedBy(func(s model.Scope) bool {
		ownerID, ok := s.OwnerID()
		return s.Kind() == model.ScopeOwner && ok && ownerID == wantOwnerID
	})).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeCertificate_VaultScopedRoute_UsesVaultScope(t *testing.T) {
	certID := uuid.New()
	wantVaultID := uuid.New()
	svc := &mockCertService{}
	svc.On("PurgeCertificate", mock.Anything, certID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := vaultScopedRequest(http.MethodDelete, "/vaults/team-a/deleted/certificates/"+certID.String()+"/purge", wantVaultID)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedCertificates_FlatRoute_UsesDefaultVaultScope(t *testing.T) {
	wantVaultID := uuid.MustParse(model.DefaultVaultID)
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return([]model.Certificate{}, nil)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedCertificates_VaultScopedRoute_UsesResolvedVaultScope(t *testing.T) {
	wantVaultID := uuid.New()
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == wantVaultID
	})).Return([]model.Certificate{}, nil)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := vaultScopedRequest(http.MethodGet, "/vaults/team-a/deleted/certificates", wantVaultID)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}
