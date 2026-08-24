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

const (
	dbSecretID  = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	apiSecretID = "3f2504e0-4f89-11d3-9a0c-0305e82c3302"
	signKeyID   = "3f2504e0-4f89-11d3-9a0c-0305e82c3303"
)

// listServer serves canned list responses per path and counts requests.
func listServer(t *testing.T, bodies map[string]string) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	return srv, &calls
}

func newResolverForTest(t *testing.T, srv *httptest.Server) *Resolver {
	t.Helper()
	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)
	return c.Resolver()
}

func TestResolver_ResolvesSecretNameToID(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password","version":3},
			{"id":"` + apiSecretID + `","name":"api-key","version":1}
		],"total":2}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
}

func TestResolver_ResolvesKeyFromItsOwnWrapperKey(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/keys": `{"keys":[{"id":"` + signKeyID + `","name":"signing-key","type":"RSA"}]}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindKeys, "signing-key")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(signKeyID), got)
}

func TestResolver_ResolvesCertificateFromItsOwnWrapperKey(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/certificates": `{"certificates":[{"id":"` + signKeyID + `","name":"tls-cert"}]}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindCertificates, "tls-cert")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(signKeyID), got)
}

func TestResolver_CachesListPerVaultAndKind(t *testing.T) {
	srv, calls := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password"},
			{"id":"` + apiSecretID + `","name":"api-key"}
		],"total":2}`,
	})
	defer srv.Close()

	r := newResolverForTest(t, srv)
	for i := 0; i < 4; i++ {
		_, err := r.Resolve(context.Background(), "prod", KindSecrets, "db-password")
		require.NoError(t, err)
		_, err = r.Resolve(context.Background(), "prod", KindSecrets, "api-key")
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, atomic.LoadInt32(calls), "one list call should serve every lookup")
}

func TestResolver_SeparateVaultsAreCachedSeparately(t *testing.T) {
	srv, calls := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets":    `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
		"/api/v1/vaults/staging/secrets": `{"secrets":[{"id":"` + apiSecretID + `","name":"db-password"}],"total":1}`,
	})
	defer srv.Close()

	r := newResolverForTest(t, srv)
	prod, err := r.Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.NoError(t, err)
	staging, err := r.Resolve(context.Background(), "staging", KindSecrets, "db-password")
	require.NoError(t, err)

	require.NotEqual(t, prod, staging, "the same name in two vaults must resolve independently")
	require.EqualValues(t, 2, atomic.LoadInt32(calls))
}

func TestResolver_AcceptsAUUIDWithoutListing(t *testing.T) {
	srv, calls := listServer(t, map[string]string{})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, dbSecretID)
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
	require.EqualValues(t, 0, atomic.LoadInt32(calls), "a UUID needs no list call")
}

func TestResolver_RejectsEmptyName(t *testing.T) {
	srv, _ := listServer(t, map[string]string{})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "")
	require.ErrorContains(t, err, "name is required")
}

func TestResolver_RejectsEmptyVault(t *testing.T) {
	srv, _ := listServer(t, map[string]string{})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "", KindSecrets, "db-password")
	require.ErrorContains(t, err, "vault is required")
}

func TestResolver_PropagatesListFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	_, err = c.Resolver().Resolve(context.Background(), "prod", KindSecrets, "db-password")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindForbidden, apiErr.Kind)
}
