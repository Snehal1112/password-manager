// Package api — regression tests for the flat-route vault-scope fix
// (docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md).
//
// These reuse the real-SQLite harnesses from vault_cross_denial_test.go, so
// denial is enforced by the repository's own SQL predicate rather than by a
// fake. Each test reproduces the pentest precondition exactly: the caller OWNS
// the resource (user_id == caller) but it lives in a vault other than the one
// the flat route resolves to. Before the fix these all succeeded.
package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// TestFlatRoute_CannotReachSecretInAnotherVault seeds a secret owned by the
// caller in vault B and requests its versions through the flat route, which
// resolves to the default vault. The scoped read must miss.
func TestFlatRoute_CannotReachSecretInAnotherVault(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretVersionsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.MustParse(vaultTestUserID), VaultID: vaultBID,
		Name: "db-password", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/secrets/"+secretID.String()+"/versions", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("flat GET .../versions for a secret in another vault: expected 404, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_ReachesSecretInTheDefaultVault is the positive control: the
// same request against a secret that IS in the flat route's resolved vault
// still succeeds, so the test above proves denial rather than breakage.
func TestFlatRoute_ReachesSecretInTheDefaultVault(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretVersionsTestAPI(t)
	seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.MustParse(vaultTestUserID),
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "db-password", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in the default vault: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/secrets/"+secretID.String()+"/versions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("flat GET .../versions in the default vault: expected 200, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_CannotReachKeyInAnotherVault mirrors the secret case for keys.
func TestFlatRoute_CannotReachKeyInAnotherVault(t *testing.T) {
	api, vrepo, keyRepo := newCrossVaultKeysTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	keyID := uuid.New()
	if err := keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: uuid.MustParse(vaultTestUserID), VaultID: vaultBID,
		Name: "signing-key", Type: model.KeyTypeRSA, Value: "encrypted-pem", Enabled: true,
	}); err != nil {
		t.Fatalf("seed key in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/keys/"+keyID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("flat GET key in another vault: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestFlatRoute_ReachesKeyInTheDefaultVault is the key positive control.
func TestFlatRoute_ReachesKeyInTheDefaultVault(t *testing.T) {
	api, vrepo, keyRepo := newCrossVaultKeysTestAPI(t)
	seedCrossVaultPair(vrepo)

	keyID := uuid.New()
	if err := keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: uuid.MustParse(vaultTestUserID),
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "signing-key", Type: model.KeyTypeRSA, Value: "encrypted-pem", Enabled: true,
	}); err != nil {
		t.Fatalf("seed key in the default vault: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/keys/"+keyID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("flat GET key in the default vault: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestFlatRoute_CannotReachCertificateInAnotherVault mirrors the secret case
// for certificates.
func TestFlatRoute_CannotReachCertificateInAnotherVault(t *testing.T) {
	api, vrepo, certRepo := newCrossVaultCertsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.MustParse(vaultTestUserID), VaultID: vaultBID,
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		Enabled:     true,
	}); err != nil {
		t.Fatalf("seed certificate in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/certificates/"+certID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("flat GET certificate in another vault: expected 404, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_ReachesCertificateInTheDefaultVault is the certificate
// positive control.
func TestFlatRoute_ReachesCertificateInTheDefaultVault(t *testing.T) {
	api, vrepo, certRepo := newCrossVaultCertsTestAPI(t)
	seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.MustParse(vaultTestUserID),
		VaultID:     uuid.MustParse(model.DefaultVaultID),
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		Enabled:     true,
	}); err != nil {
		t.Fatalf("seed certificate in the default vault: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/certificates/"+certID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("flat GET certificate in the default vault: expected 200, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_CryptoOperationCarriesTheResolvedVault covers the crypto
// handlers, whose denial happens inside CryptoService rather than at the HTTP
// layer: the scope they hand the service must pin the resolved vault and carry
// no owner predicate, so loadAndAuthorize's vault_id check applies.
func TestFlatRoute_CryptoOperationCarriesTheResolvedVault(t *testing.T) {
	var got model.Scope
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
			got = req.Scope
			return &keyServices.SignResult{Signature: []byte("sig"), Algorithm: "RS256"}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := newScopeRequest(t, uuid.MustParse(model.DefaultVaultID), "")
	r.Body = jsonBody(t, map[string]string{"value": base64.StdEncoding.EncodeToString([]byte("hello"))})

	signKey(c, w, r)

	if c.Err != nil {
		t.Fatalf("flat POST /keys/{id}/sign: unexpected error %v", c.Err)
	}
	if got.Kind() != model.ScopeVault {
		t.Fatalf("crypto scope kind %v, want a vault scope", got.Kind())
	}
	if got.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("crypto scope vault %s, want the default vault", got.VaultID())
	}
	if _, ownerScoped := got.OwnerID(); ownerScoped {
		t.Fatalf("crypto scope must carry no owner predicate")
	}
}
