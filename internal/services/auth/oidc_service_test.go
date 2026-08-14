package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestOIDCProvider starts an httptest server serving a minimal OIDC
// discovery document and JWKS so OIDCService can be constructed against it
// without any real network access.
func newTestOIDCProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": jwtBase64URLEncode(key.N.Bytes()),
				"e": jwtBase64URLEncode([]byte{1, 0, 1}),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv, key
}

func jwtBase64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// caCertPathFromServer writes srv's own leaf certificate to a temp PEM file
// and returns the path. httptest.NewTLSServer's certificate is self-signed,
// so it is its own trust anchor for these tests — exactly analogous to a
// private CA's root certificate in production.
func caCertPathFromServer(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

// newTestOIDCTLSProvider is newTestOIDCProvider's TLS counterpart, needed to
// test CA trust — a plain-HTTP test server can't exercise TLS verification
// at all. Duplicated rather than parameterizing newTestOIDCProvider because
// httptest.NewServer and httptest.NewTLSServer return incompatible startup
// sequences (TLS needs the server started before its URL is known, to read
// back its own certificate).
func newTestOIDCTLSProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                               issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": jwtBase64URLEncode(key.N.Bytes()),
				"e": jwtBase64URLEncode([]byte{1, 0, 1}),
			}},
		})
	})
	srv := httptest.NewTLSServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv, key
}

func TestOIDCService_AuthCodeURL_IncludesStateAndNonce(t *testing.T) {
	srv, _ := newTestOIDCProvider(t)

	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.NoError(t, err)

	url := svc.AuthCodeURL("state-123", "nonce-456")
	require.Contains(t, url, "state=state-123")
	require.Contains(t, url, "nonce=nonce-456")
	require.Contains(t, url, "client_id=client-1")
}

func TestNewOIDCService_UnreachableIssuer_ReturnsError(t *testing.T) {
	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: "http://127.0.0.1:1", ClientID: "x", ClientSecret: "y",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.Error(t, err)
}

func TestNewOIDCService_CustomCACert_TrustsSelfSignedIssuer(t *testing.T) {
	srv, _ := newTestOIDCTLSProvider(t)
	caPath := caCertPathFromServer(t, srv)

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		CACertPath: caPath,
	})
	require.NoError(t, err)
}

func TestNewOIDCService_WithoutCACertPath_RejectsUntrustedTLSIssuer(t *testing.T) {
	srv, _ := newTestOIDCTLSProvider(t)

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		// CACertPath deliberately empty.
	})
	require.Error(t, err, "a self-signed issuer must be rejected without an explicit CACertPath")
}

func TestNewOIDCService_InvalidCACertPath_ReturnsClearError(t *testing.T) {
	srv, _ := newTestOIDCProvider(t) // plain HTTP is fine here; discovery never happens

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		CACertPath: "/nonexistent/path/does-not-exist.pem",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca_cert_path")
}
