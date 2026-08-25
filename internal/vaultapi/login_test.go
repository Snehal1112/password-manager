package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func loginServer(t *testing.T, respond func(w http.ResponseWriter, body map[string]string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		respond(w, body)
	}))
}

func newTestClient(t *testing.T, baseURL string, httpClient *http.Client) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURL: baseURL, HTTPClient: httpClient,
		Tokens: stubTokenSource{token: "unused"}, DisableRetry: true,
	})
	require.NoError(t, err)
	return c
}

func TestClientLogin_Success(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, body map[string]string) {
		require.Equal(t, "admin", body["username"])
		require.Equal(t, "hunter2", body["password"])
		require.Equal(t, "123456", body["totp_code"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"access-1","refresh_token":"refresh-1","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	source, identity, err := c.Login(context.Background(), "admin", "hunter2", "123456", time.Hour)
	require.NoError(t, err)
	require.Equal(t, "admin", identity.Username)
	require.Equal(t, []string{"admin"}, identity.Roles)
	require.WithinDuration(t, time.Now().Add(time.Hour), identity.ExpiresAt, time.Second)

	tok, err := source.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-1", tok)
}

func TestClientLogin_RejectionDoesNotEchoBody(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, _ map[string]string) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"authentication failed"}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "wrong", "000000", time.Hour)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "authentication failed")
	require.Contains(t, err.Error(), "401")
}

func TestClientLogin_MissingTokenInResponseIsAnError(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, _ map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"admin","roles":["admin"]}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "hunter2", "123456", time.Hour)
	require.ErrorContains(t, err, "missing a token")
}

func TestClientLogin_SendsNoAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"access-1","refresh_token":"refresh-1","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "hunter2", "123456", time.Hour)
	require.NoError(t, err)
	require.Empty(t, gotAuth, "login is unauthenticated -- it must not send whatever c.tokens holds")
}
