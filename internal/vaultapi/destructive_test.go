package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// mutationProbe records a destructive call and the paths leading to it.
type mutationProbe struct {
	paths  []string
	method string
	target string
	calls  int
}

// destructiveServer serves listings and records the non-GET call.
func destructiveServer(t *testing.T, routes map[string]string, status int) (*httptest.Server, *mutationProbe) {
	t.Helper()

	probe := &mutationProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probe.paths = append(probe.paths, r.URL.Path)

		if r.Method == http.MethodGet {
			body, ok := routes[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}

		probe.calls++
		probe.method, probe.target = r.Method, r.URL.Path

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, probe
}

func TestDeleteItem_ResolvesAgainstTheLiveListing(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", KindSecrets, "db-password")
	require.NoError(t, err)

	require.Equal(t, http.MethodDelete, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/secrets/"+dbSecretID, probe.target)
	require.Contains(t, probe.paths, "/api/v1/vaults/prod/secrets",
		"a live item is resolved through the live listing")
}

func TestDeleteItem_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind     Kind
		listPath string
		listBody string
		id       string
	}{
		{KindSecrets, "/api/v1/vaults/prod/secrets",
			`{"secrets":[{"id":"` + dbSecretID + `","name":"doomed"}],"total":1}`, dbSecretID},
		{KindKeys, "/api/v1/vaults/prod/keys",
			`{"keys":[{"id":"` + rsaKeyID + `","name":"doomed"}]}`, rsaKeyID},
		{KindCertificates, "/api/v1/vaults/prod/certificates",
			`{"certificates":[{"id":"` + tlsCertID + `","name":"doomed"}]}`, tlsCertID},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			srv, probe := destructiveServer(t, map[string]string{tc.listPath: tc.listBody}, http.StatusOK)

			err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", tc.kind, "doomed")
			require.NoError(t, err)
			require.Equal(t, "/api/v1/vaults/prod/"+string(tc.kind)+"/"+tc.id, probe.target)
		})
	}
}

func TestDeleteItem_UnknownNameMakesNoCall(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[],"total":0}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", KindSecrets, "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls)
}

func TestDeleteItem_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
	}, http.StatusInternalServerError)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", KindSecrets, "db-password")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestDeleteItem_RejectsAnUnknownKind(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{}, http.StatusOK)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", Kind("vaults"), "x")
	require.ErrorContains(t, err, "unsupported")
	require.Zero(t, probe.calls)
}

func TestRecoverDeleted_ResolvesAgainstTheDeletedListing(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old-password"}],"total":1}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", KindSecrets, "old-password")
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/deleted/secrets/"+dbSecretID+"/restore", probe.target)
	require.Contains(t, probe.paths, "/api/v1/vaults/prod/deleted/secrets",
		"a deleted item is invisible to the live listing, so recovery must resolve against the deleted one")
	require.NotContains(t, probe.paths, "/api/v1/vaults/prod/secrets")
}

func TestRecoverDeleted_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind Kind
		path string
		body string
		id   string
	}{
		{KindSecrets, "/api/v1/vaults/prod/deleted/secrets",
			`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`, dbSecretID},
		{KindKeys, "/api/v1/vaults/prod/deleted/keys",
			`{"deleted_keys":[{"id":"` + rsaKeyID + `","name":"gone"}],"total":1}`, rsaKeyID},
		{KindCertificates, "/api/v1/vaults/prod/deleted/certificates",
			`{"deleted_certificates":[{"id":"` + tlsCertID + `","name":"gone"}],"total":1}`, tlsCertID},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			srv, probe := destructiveServer(t, map[string]string{tc.path: tc.body}, http.StatusOK)

			err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", tc.kind, "gone")
			require.NoError(t, err)
			require.Equal(t,
				"/api/v1/vaults/prod/deleted/"+string(tc.kind)+"/"+tc.id+"/restore", probe.target)
		})
	}
}

func TestRecoverDeleted_UnknownNamePointsAtListDeleted(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[],"total":0}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", KindSecrets, "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Contains(t, err.Error(), "list_deleted")
	require.Zero(t, probe.calls)
}

func TestRecoverDeleted_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`,
	}, http.StatusInternalServerError)

	err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", KindSecrets, "gone")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}
