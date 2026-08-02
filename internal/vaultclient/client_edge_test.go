package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
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
	t.Setenv("VAULT_ALLOW_INSECURE_HTTP", "true")

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
	viper.Set("vault_client.allow_insecure_http", true)

	c, err := vaultclient.NewFromViper()
	require.NoError(t, err)
	require.NotNil(t, c)
}

// TestNewFromViper_SecretFromEnv tests that client_secret falls back to env var.
func TestNewFromViper_SecretFromEnv(t *testing.T) {
	viper.Set("vault_client.url", "http://vault.local")
	viper.Set("vault_client.client_id", "viper-id")
	viper.Set("vault_client.client_secret", "")
	viper.Set("vault_client.allow_insecure_http", true)
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
		URL: "http://vault.local", ClientID: "id", ClientSecret: "s", AllowInsecureHTTP: true,
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
	assert.ErrorIs(t, err, vaultclient.ErrUnexpectedStatus)
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
	assert.ErrorIs(t, err, vaultclient.ErrUnexpectedStatus)
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

// TestGet_NetworkError_ReturnsErrNetwork verifies a connection failure is
// identifiable via errors.Is(err, ErrNetwork) even after retries are exhausted.
func TestGet_NetworkError_ReturnsErrNetwork(t *testing.T) {
	// Point at a server that's already closed — connection refused on every attempt.
	closedSrv := httptest.NewServer(http.NewServeMux())
	deadURL := closedSrv.URL
	closedSrv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: deadURL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrNetwork)
}

// TestGet_MalformedJSON_ReturnsErrDecodeFailed verifies a 200 response with
// unparseable JSON is treated as terminal (not retried) and identifiable via
// errors.Is(err, ErrDecodeFailed).
func TestGet_MalformedJSON_ReturnsErrDecodeFailed(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not valid json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrDecodeFailed)
	assert.Equal(t, 1, calls, "malformed JSON should be terminal, not retried")
}

// TestGet_ContextCanceled_ReturnsContextError verifies a canceled context is
// surfaced as ctx.Err(), not masked as a generic retries-exhausted error.
func TestGet_ContextCanceled_ReturnsContextError(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before the call

	_, err = c.Get(ctx, "some-uuid")
	assert.ErrorIs(t, err, context.Canceled)
}

// fakeLogger captures Warn calls for assertions. Safe for concurrent use since
// Client may call it from a retry loop driven by a single goroutine, but tests
// should not assume single-threaded access.
type fakeLogger struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeLogger) Warn(msg string, _ ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, msg)
}

func (f *fakeLogger) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestGet_NoLogger_DoesNotPanicOnFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		_, _ = c.Get(context.Background(), "missing")
	})
}

func TestGet_WithLogger_WarnsOnRetryableFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	logger := &fakeLogger{}
	c, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "id", ClientSecret: "s", Logger: logger,
	})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
	assert.Positive(t, logger.callCount(), "expected at least one Warn call across the retried attempts")
}

func TestGet_WithLogger_SilentOnFirstTrySuccess(t *testing.T) {
	srv := newTestServer(t, "value")
	defer srv.Close()

	logger := &fakeLogger{}
	c, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "test-id", ClientSecret: "test-secret", Logger: logger,
	})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	require.NoError(t, err)
	assert.Equal(t, 0, logger.callCount())
}

// TestNew_RejectsPlainHTTPForNonLoopbackHost verifies a production-style
// plaintext URL is rejected by default.
func TestNew_RejectsPlainHTTPForNonLoopbackHost(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{
		URL: "http://vault.internal.example.com", ClientID: "id", ClientSecret: "s",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestNew_AllowInsecureHTTP_PermitsPlainHTTP verifies the explicit opt-out works.
func TestNew_AllowInsecureHTTP_PermitsPlainHTTP(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{
		URL: "http://vault.internal.example.com", ClientID: "id", ClientSecret: "s",
		AllowInsecureHTTP: true,
	})
	require.NoError(t, err)
}

// TestNew_AcceptsHTTPSWithoutOptOut verifies a proper https:// URL never needs the flag.
func TestNew_AcceptsHTTPSWithoutOptOut(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{
		URL: "https://vault.internal.example.com", ClientID: "id", ClientSecret: "s",
	})
	require.NoError(t, err)
}

// TestNew_AllowsPlainHTTPOnLoopback verifies loopback hosts never need the flag —
// this is what every httptest.NewServer-backed test in this package relies on.
func TestNew_AllowsPlainHTTPOnLoopback(t *testing.T) {
	for _, host := range []string{"http://127.0.0.1:9999", "http://localhost:9999", "http://[::1]:9999"} {
		_, err := vaultclient.New(vaultclient.Config{URL: host, ClientID: "id", ClientSecret: "s"})
		require.NoError(t, err, "loopback URL %q should not require AllowInsecureHTTP", host)
	}
}
