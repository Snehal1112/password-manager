package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// deletedListServer serves a deleted-items listing and counts requests.
func deletedListServer(t *testing.T, path, body string) (*httptest.Server, *int32) {
	t.Helper()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestResolveDeleted_FindsASoftDeletedItem(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets",
		`{"deleted_secrets":[{"id":"`+dbSecretID+`","name":"old-password"}],"total":1}`)

	got, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "old-password")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
}

func TestResolveDeleted_UsesTheDeletedRouteNotTheLiveOne(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old"}],"total":1}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "old")
	require.NoError(t, err)
	require.Equal(t, []string{"/api/v1/vaults/prod/deleted/secrets"}, paths,
		"a soft-deleted item is absent from the live listing, so that route cannot find it")
}

func TestResolveDeleted_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind Kind
		path string
		body string
	}{
		{KindSecrets, "/api/v1/vaults/prod/deleted/secrets",
			`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`},
		{KindKeys, "/api/v1/vaults/prod/deleted/keys",
			`{"deleted_keys":[{"id":"` + rsaKeyID + `","name":"gone"}],"total":1}`},
		{KindCertificates, "/api/v1/vaults/prod/deleted/certificates",
			`{"deleted_certificates":[{"id":"` + tlsCertID + `","name":"gone"}],"total":1}`},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			srv, _ := deletedListServer(t, tc.path, tc.body)
			got, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", tc.kind, "gone")
			require.NoError(t, err)
			require.NotEqual(t, uuid.Nil, got)
		})
	}
}

func TestResolveDeleted_AcceptsAUUIDWithoutListing(t *testing.T) {
	srv, calls := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets", `{"deleted_secrets":[],"total":0}`)

	got, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, dbSecretID)
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
	require.EqualValues(t, 0, atomic.LoadInt32(calls))
}

func TestResolveDeleted_MissIsErrResourceNotFound(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets", `{"deleted_secrets":[],"total":0}`)

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Contains(t, err.Error(), "deleted",
		"the message must say it searched the deleted items, not the live ones")
}

func TestResolveDeleted_AmbiguousNamesEveryCandidate(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets",
		`{"deleted_secrets":[{"id":"`+dbSecretID+`","name":"dup"},
		  {"id":"`+apiSecretID+`","name":"dup"}],"total":2}`)

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "dup")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrResourceNotFound)
	require.Contains(t, err.Error(), dbSecretID)
	require.Contains(t, err.Error(), apiSecretID,
		"purging the wrong item is irreversible, so ambiguity must never be guessed")
}

func TestResolveDeleted_RequiresVaultAndName(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets", `{"deleted_secrets":[],"total":0}`)
	c := newClientForTest(t, srv)

	_, err := c.ResolveDeleted(context.Background(), "", KindSecrets, "x")
	require.ErrorContains(t, err, "vault is required")

	_, err = c.ResolveDeleted(context.Background(), "prod", KindSecrets, "")
	require.ErrorContains(t, err, "name is required")
}

func TestResolveDeleted_ForbiddenIsNotAMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "x")
	require.NotErrorIs(t, err, ErrResourceNotFound)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindForbidden, apiErr.Kind)
}
