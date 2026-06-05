package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultclient"
)

// TestNewFromEnv_Success ensures NewFromEnv reads VAULT_* env vars correctly.
func TestNewFromEnv_Success(t *testing.T) {
	t.Setenv("VAULT_URL", "http://vault.local")
	t.Setenv("VAULT_CLIENT_ID", "env-id")
	t.Setenv("VAULT_CLIENT_SECRET", "env-secret")

	c, err := vaultclient.NewFromEnv()
	require.NoError(t, err)
	require.NotNil(t, c)
}

// TestNewFromEnv_MissingURL checks that an empty VAULT_URL causes an error.
func TestNewFromEnv_MissingURL(t *testing.T) {
	os.Unsetenv("VAULT_URL")
	os.Unsetenv("VAULT_CLIENT_ID")
	os.Unsetenv("VAULT_CLIENT_SECRET")

	_, err := vaultclient.NewFromEnv()
	require.Error(t, err)
}

// TestNewFromViper_Success tests that NewFromViper reads viper config correctly.
func TestNewFromViper_Success(t *testing.T) {
	viper.Set("vault_client.url", "http://vault.local")
	viper.Set("vault_client.client_id", "viper-id")
	viper.Set("vault_client.client_secret", "viper-secret")

	c, err := vaultclient.NewFromViper()
	require.NoError(t, err)
	require.NotNil(t, c)
}

// TestNewFromViper_SecretFromEnv tests that client_secret falls back to env var.
func TestNewFromViper_SecretFromEnv(t *testing.T) {
	viper.Set("vault_client.url", "http://vault.local")
	viper.Set("vault_client.client_id", "viper-id")
	viper.Set("vault_client.client_secret", "")
	t.Setenv("VAULT_CLIENT_SECRET", "env-fallback")

	c, err := vaultclient.NewFromViper()
	require.NoError(t, err)
	require.NotNil(t, c)
}

// TestNew_MissingClientID verifies validation rejects a missing client_id.
func TestNew_MissingClientID(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{URL: "http://vault.local", ClientSecret: "s"})
	require.Error(t, err)
}

// TestNew_MissingClientSecret verifies validation rejects a missing client_secret.
func TestNew_MissingClientSecret(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{URL: "http://vault.local", ClientID: "id"})
	require.Error(t, err)
}

// TestGetByName_UnknownName verifies an error when name has no UUID mapping.
func TestGetByName_UnknownName(t *testing.T) {
	c, err := vaultclient.New(vaultclient.Config{
		URL: "http://vault.local", ClientID: "id", ClientSecret: "s",
	})
	require.NoError(t, err)
	_, err = c.GetByName(context.Background(), "unknown-name")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no UUID mapping")
}

// TestGetMany_ErrorPropagation checks that GetMany returns the first Get error.
func TestGetMany_ErrorPropagation(t *testing.T) {
	// Server that always returns 404.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "id", ClientSecret: "s",
		Secrets: []vaultclient.SecretMapping{{Name: "A", UUID: "uuid-a"}},
	})
	require.NoError(t, err)

	_, err = c.GetMany(context.Background(), []string{"A"})
	require.ErrorIs(t, err, vaultclient.ErrSecretNotFound)
}

// TestGet_UnexpectedStatus verifies that unexpected status codes are retried then fail.
func TestGet_UnexpectedStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
}

// TestFetchToken_NonOKStatus covers the branch where the token endpoint returns non-200/401.
func TestFetchToken_NonOKStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
}

// TestFetchToken_EmptyAccessToken covers the branch where access_token is blank.
func TestFetchToken_EmptyAccessToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		// Return 200 but with no access_token field.
		json.NewEncoder(w).Encode(map[string]any{"access_token": "", "expires_in": 3600})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrAuthFailed)
}

// TestGet_SecretUnauthorized covers the 401 branch inside the Get secret request.
func TestGet_SecretUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "stale", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		// Always reject the secret request.
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrAuthFailed)
}
