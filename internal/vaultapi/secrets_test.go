package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newClientForTest(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)
	return c
}

func TestListSecrets_UsesVaultScopedRoute(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password","version":3,"tags":["prod"],"created_at":"2026-08-01T00:00:00Z"}
		],"total":1}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/secrets", gotPath,
		"the flat route resolves to the default vault and must never be used")
	require.False(t, truncated)
	require.Len(t, got, 1)
	require.Equal(t, "db-password", got[0].Name)
	require.Equal(t, uuid.MustParse(dbSecretID), got[0].ID)
	require.Equal(t, 3, got[0].Version)
	require.Equal(t, []string{"prod"}, got[0].Tags)
}

func TestListSecrets_TruncatesAtLimitAndReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[
			{"id":"` + dbSecretID + `","name":"a"},
			{"id":"` + apiSecretID + `","name":"b"},
			{"id":"` + signKeyID + `","name":"c"}
		],"total":3}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, truncated, "the caller must be able to tell the model the list was cut short")
}

func TestListSecrets_ZeroLimitReturnsEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[
			{"id":"` + dbSecretID + `","name":"a"},
			{"id":"` + apiSecretID + `","name":"b"}
		],"total":2}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.False(t, truncated)
}

func TestListSecrets_EmptyVaultIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[],"total":0}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Empty(t, got)
	require.False(t, truncated)
}

func TestListSecrets_RequiresVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListSecrets(context.Background(), "", 50)
	require.ErrorContains(t, err, "vault is required")
}

func TestGetSecret_ResolvesNameThenFetchesByID(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/vaults/prod/secrets":
			_, _ = w.Write([]byte(`{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`))
		case "/api/v1/vaults/prod/secrets/" + dbSecretID:
			_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","name":"db-password","value":"` + plaintext + `",
				"version":3,"content_type":"text/plain","enabled":true,"created_at":"2026-08-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", "db-password")
	require.NoError(t, err)
	require.Equal(t, []string{"/api/v1/vaults/prod/secrets", "/api/v1/vaults/prod/secrets/" + dbSecretID}, paths)
	require.Equal(t, "db-password", got.Name)
	require.Equal(t, 3, got.Version)
	require.Equal(t, "text/plain", got.ContentType)
	require.True(t, got.Enabled)
}

func TestGetSecret_CapturesValueAsSecretValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","name":"db-password","value":"` + plaintext + `"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", dbSecretID)
	require.NoError(t, err)
	require.Equal(t, plaintext, got.Value.Reveal(), "the value must be readable when deliberately revealed")
	require.Equal(t, "[REDACTED]", got.Value.String())
}

func TestGetSecret_MarshallingTheResultNeverLeaksTheValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","name":"db-password","value":"` + plaintext + `"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", dbSecretID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), plaintext,
		"marshalling a Secret must never disclose its value")
}

func TestGetSecret_UnknownNameReportsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[],"total":0}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", "nope")
	require.ErrorContains(t, err, "no secrets named")
}
