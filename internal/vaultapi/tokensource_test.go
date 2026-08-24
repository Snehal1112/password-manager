package vaultapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// tokenServer returns a server that issues sequentially-numbered tokens with
// the given lifetime, plus a counter of how many times it was called.
func tokenServer(t *testing.T, expiresIn int) (*httptest.Server, *int32, *string) {
	t.Helper()
	var calls int32
	var lastAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		lastAuthHeader = r.Header.Get("Authorization")

		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/oauth2/token", r.URL.Path)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		require.NoError(t, r.ParseForm())
		require.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		require.Empty(t, r.PostForm.Get("client_secret"), "secret must travel in the Basic header, not the body")

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"Bearer","expires_in":%d}`, n, expiresIn)
	}))
	return srv, &calls, &lastAuthHeader
}

func TestServiceAccountSource_FetchesTokenWithHTTPBasic(t *testing.T) {
	srv, calls, authHeader := tokenServer(t, 3600)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "mcp-agent", ClientSecret: "s3cr3t", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok)
	require.EqualValues(t, 1, atomic.LoadInt32(calls))

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("mcp-agent:s3cr3t"))
	require.Equal(t, want, *authHeader)
}

func TestServiceAccountSource_CachesUntilNearExpiry(t *testing.T) {
	srv, calls, _ := tokenServer(t, 3600)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		tok, err := src.Token(context.Background())
		require.NoError(t, err)
		require.Equal(t, "tok-1", tok)
	}
	require.EqualValues(t, 1, atomic.LoadInt32(calls), "a live token must not be re-fetched")
}

func TestServiceAccountSource_RefetchesOnceInsideSkewWindow(t *testing.T) {
	// A 30s lifetime with a 60s skew means the token is already considered
	// expired the moment it is issued, so every call re-fetches.
	srv, calls, _ := tokenServer(t, 30)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec",
		HTTPClient: srv.Client(), Skew: 60 * time.Second,
	})
	require.NoError(t, err)

	first, err := src.Token(context.Background())
	require.NoError(t, err)
	second, err := src.Token(context.Background())
	require.NoError(t, err)

	require.Equal(t, "tok-1", first)
	require.Equal(t, "tok-2", second)
	require.EqualValues(t, 2, atomic.LoadInt32(calls))
}

func TestServiceAccountSource_InvalidCredentialsErrorOmitsSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"invalid client credentials"}`))
	}))
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "mcp-agent", ClientSecret: "hunter2-do-not-leak", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid_client")
	require.NotContains(t, err.Error(), "hunter2-do-not-leak")
}

func TestServiceAccountSource_RequiresAllCredentials(t *testing.T) {
	_, err := NewServiceAccountSource(ServiceAccountConfig{ClientID: "id", ClientSecret: "s", HTTPClient: http.DefaultClient})
	require.ErrorContains(t, err, "BaseURL")

	_, err = NewServiceAccountSource(ServiceAccountConfig{BaseURL: "https://v", ClientSecret: "s", HTTPClient: http.DefaultClient})
	require.ErrorContains(t, err, "ClientID")

	_, err = NewServiceAccountSource(ServiceAccountConfig{BaseURL: "https://v", ClientID: "id", HTTPClient: http.DefaultClient})
	require.ErrorContains(t, err, "ClientSecret")
}

func TestServiceAccountSource_SatisfiesTokenSource(t *testing.T) {
	var _ TokenSource = (*ServiceAccountSource)(nil)
}

func TestServiceAccountSource_TrimsTrailingSlashFromBaseURL(t *testing.T) {
	srv, _, _ := tokenServer(t, 3600)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL + "/", ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err, "a trailing slash must not produce a doubled path")
	require.False(t, strings.Contains(srv.URL+"//api", "///"))
}
