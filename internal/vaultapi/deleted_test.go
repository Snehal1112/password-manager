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

func TestListDeleted_UsesThePerKindWrapperKey(t *testing.T) {
	cases := []struct {
		kind    Kind
		path    string
		body    string
		wantHit string
	}{
		{
			kind: KindSecrets,
			path: "/api/v1/vaults/prod/deleted/secrets",
			body: `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old-password","version":2,
				"deleted_at":"2026-08-10T00:00:00Z","created_at":"2026-06-01T00:00:00Z"}],"total":1}`,
			wantHit: "old-password",
		},
		{
			kind: KindKeys,
			path: "/api/v1/vaults/prod/deleted/keys",
			body: `{"deleted_keys":[{"id":"` + rsaKeyID + `","name":"old-key",
				"deleted_at":"2026-08-10T00:00:00Z"}],"total":1}`,
			wantHit: "old-key",
		},
		{
			kind: KindCertificates,
			path: "/api/v1/vaults/prod/deleted/certificates",
			body: `{"deleted_certificates":[{"id":"` + tlsCertID + `","name":"old-cert",
				"deleted_at":"2026-08-10T00:00:00Z"}],"total":1}`,
			wantHit: "old-cert",
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			got, truncated, err := newClientForTest(t, srv).ListDeleted(context.Background(), "prod", tc.kind, 50)
			require.NoError(t, err)
			require.Equal(t, tc.path, gotPath)
			require.False(t, truncated)
			require.Len(t, got, 1)
			require.Equal(t, tc.wantHit, got[0].Name)
			require.NotEmpty(t, got[0].DeletedAt)
		})
	}
}

func TestListDeleted_ParsesIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old"}],"total":1}`))
	}))
	defer srv.Close()

	got, _, err := newClientForTest(t, srv).ListDeleted(context.Background(), "prod", KindSecrets, 50)
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got[0].ID)
}

func TestListDeleted_TruncatesAtLimitAndReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted_secrets":[
			{"id":"` + dbSecretID + `","name":"a"},
			{"id":"` + apiSecretID + `","name":"b"},
			{"id":"` + signKeyID + `","name":"c"}
		],"total":3}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListDeleted(context.Background(), "prod", KindSecrets, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, truncated)
}

func TestListDeleted_EmptyIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted_secrets":[],"total":0}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListDeleted(context.Background(), "prod", KindSecrets, 50)
	require.NoError(t, err)
	require.Empty(t, got)
	require.False(t, truncated)
}

func TestListDeleted_RequiresVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListDeleted(context.Background(), "", KindSecrets, 50)
	require.ErrorContains(t, err, "vault is required")
}

func TestListDeleted_RejectsAnUnknownKind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListDeleted(context.Background(), "prod", Kind("vaults"), 50)
	require.ErrorContains(t, err, "unsupported")
}

func TestListDeleted_CarriesNoValueField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old","value":"` + plaintext + `"}],"total":1}`))
	}))
	defer srv.Close()

	got, _, err := newClientForTest(t, srv).ListDeleted(context.Background(), "prod", KindSecrets, 50)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), plaintext,
		"DeletedItem has no value field, so a stray server value is dropped")
}
