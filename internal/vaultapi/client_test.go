package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDo_SendsBearerTokenAndCorrelationID(t *testing.T) {
	var gotAuth, gotCorrelation, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCorrelation = r.Header.Get(CorrelationHeader)
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"db-password"}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("tok-123")})
	require.NoError(t, err)

	var out struct {
		Name string `json:"name"`
	}
	ctx := WithCorrelationID(context.Background(), "corr-abc")
	err = c.Do(ctx, http.MethodGet, "/api/v1/vaults/default/secrets", nil, &out)
	require.NoError(t, err)

	require.Equal(t, "Bearer tok-123", gotAuth)
	require.Equal(t, "corr-abc", gotCorrelation)
	require.Equal(t, "application/json", gotAccept)
	require.Equal(t, "db-password", out.Name)
}

func TestDo_EncodesRequestBodyAndSetsContentType(t *testing.T) {
	var gotBody, gotContentType, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		gotContentType = r.Header.Get("Content-Type")
		gotMethod = r.Method
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	payload := map[string]string{"name": "api-key"}
	err = c.Do(context.Background(), http.MethodPost, "/api/v1/vaults/prod/secrets", payload, nil)
	require.NoError(t, err)

	require.JSONEq(t, `{"name":"api-key"}`, gotBody)
	require.Equal(t, "application/json", gotContentType)
	require.Equal(t, http.MethodPost, gotMethod)
}

func TestDo_OmitsCorrelationHeaderWhenAbsent(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header[http.CanonicalHeaderKey(CorrelationHeader)]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	require.NoError(t, c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, nil))
	require.False(t, present, "correlation header must be absent when no ID is set")
}

func TestNew_RequiresBaseURLTokensAndHTTPClient(t *testing.T) {
	_, err := New(Config{HTTPClient: http.DefaultClient, Tokens: staticToken("t")})
	require.ErrorContains(t, err, "BaseURL")

	_, err = New(Config{BaseURL: "https://vault.example", HTTPClient: http.DefaultClient})
	require.ErrorContains(t, err, "Tokens")

	_, err = New(Config{BaseURL: "https://vault.example", Tokens: staticToken("t")})
	require.ErrorContains(t, err, "HTTPClient")
}
