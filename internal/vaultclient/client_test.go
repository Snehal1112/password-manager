package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultclient"
)

func newTestServer(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != "test-id" || r.FormValue("client_secret") != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"value": secret})
	})
	return httptest.NewServer(mux)
}

func TestGet_ReturnSecretValue(t *testing.T) {
	srv := newTestServer(t, "supersecret")
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "test-id", ClientSecret: "test-secret",
	})
	require.NoError(t, err)
	val, err := client.Get(context.Background(), "some-uuid")
	require.NoError(t, err)
	assert.Equal(t, "supersecret", val)
}

func TestGet_ReturnsErrAuthFailed_On401(t *testing.T) {
	srv := newTestServer(t, "irrelevant")
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "wrong-id", ClientSecret: "wrong-secret",
	})
	require.NoError(t, err)
	_, err = client.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrAuthFailed)
}

func TestGet_ReturnsErrSecretNotFound_On404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-token", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "secret"})
	require.NoError(t, err)
	_, err = client.Get(context.Background(), "missing-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrSecretNotFound)
}

func TestGetMany_ReturnsMappedSecrets(t *testing.T) {
	srv := newTestServer(t, "value1")
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "test-id", ClientSecret: "test-secret",
		Secrets: []vaultclient.SecretMapping{{Name: "MY_SECRET", UUID: "uuid-1"}},
	})
	require.NoError(t, err)
	results, err := client.GetMany(context.Background(), []string{"MY_SECRET"})
	require.NoError(t, err)
	assert.Equal(t, "value1", results["MY_SECRET"])
}

func TestGetByName_ResolvesFromMapping(t *testing.T) {
	srv := newTestServer(t, "resolved-value")
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "test-id", ClientSecret: "test-secret",
		Secrets: []vaultclient.SecretMapping{{Name: "DB_PASSWORD", UUID: "uuid-db"}},
	})
	require.NoError(t, err)
	val, err := client.GetByName(context.Background(), "DB_PASSWORD")
	require.NoError(t, err)
	assert.Equal(t, "resolved-value", val)
}

func TestTokenCached_OnlyFetchedOnce(t *testing.T) {
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		json.NewEncoder(w).Encode(map[string]any{"access_token": "cached-token", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"value": "v"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)
	client.Get(context.Background(), "uuid-1") //nolint:errcheck
	client.Get(context.Background(), "uuid-2") //nolint:errcheck
	assert.Equal(t, 1, tokenCalls, "token should be fetched only once")
}

func TestNew_ReturnsError_WhenURLMissing(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{ClientID: "id", ClientSecret: "s"})
	assert.Error(t, err)
}

func TestTokenExpiry_RefetchedAfterExpiry(t *testing.T) {
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"value": "v"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)
	client.Get(context.Background(), "uuid-1") //nolint:errcheck
	// Force the cached token to appear expired without relying on wall-clock sleep.
	client.ExpireTokenForTest()
	client.Get(context.Background(), "uuid-2") //nolint:errcheck
	assert.Equal(t, 2, tokenCalls, "token should be re-fetched after expiry")
}

func TestTokenFloor_ZeroExpiresIn_DoesNotRefetch(t *testing.T) {
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		// Server returns expires_in: 0; floor must kick in and prevent re-fetch.
		json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 0})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"value": "v"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)
	client.Get(context.Background(), "uuid-1") //nolint:errcheck
	client.Get(context.Background(), "uuid-2") //nolint:errcheck
	assert.Equal(t, 1, tokenCalls, "token with expires_in:0 should not be re-fetched on every call")
}
