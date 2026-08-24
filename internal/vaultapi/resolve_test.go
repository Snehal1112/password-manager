package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestResolver_AmbiguousNameNamesEveryCandidate(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password"},
			{"id":"` + apiSecretID + `","name":"db-password"}
		],"total":2}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.Error(t, err)
	require.Contains(t, err.Error(), dbSecretID)
	require.Contains(t, err.Error(), apiSecretID)
	require.Contains(t, err.Error(), "address one by id")
}

func TestResolver_AmbiguityIsNeverSilentlyResolved(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/keys": `{"keys":[
			{"id":"` + dbSecretID + `","name":"signing-key"},
			{"id":"` + apiSecretID + `","name":"signing-key"}
		]}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindKeys, "signing-key")
	require.Error(t, err, "a duplicate name must never resolve to an arbitrary pick")
	require.Equal(t, uuid.Nil, got)
}

func TestResolver_NotFoundSuggestsNearMisses(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password"},
			{"id":"` + apiSecretID + `","name":"db-password-legacy"}
		],"total":2}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-passw")
	require.Error(t, err)
	require.Contains(t, err.Error(), "did you mean")
	require.Contains(t, err.Error(), "db-password")
}

func TestResolver_NotFoundIsCaseInsensitiveWhenSuggesting(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"DB-Password"}],"total":1}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.Error(t, err, "matching is exact, so a case difference is still not found")
	require.Contains(t, err.Error(), "DB-Password", "but the suggestion should surface the real name")
}

func TestResolver_NotFoundWithNoNearMissOmitsSuggestion(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "totally-unrelated")
	require.Error(t, err)
	require.Contains(t, err.Error(), `no secrets named "totally-unrelated"`)
	require.NotContains(t, err.Error(), "did you mean")
}

func TestResolver_NotFoundCapsSuggestionsAtThree(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-a"},
			{"id":"` + apiSecretID + `","name":"db-b"},
			{"id":"` + signKeyID + `","name":"db-c"},
			{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3304","name":"db-d"},
			{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3305","name":"db-e"}
		],"total":5}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db")
	require.Error(t, err)
	require.Equal(t, 3, strings.Count(err.Error(), `"db-`),
		"suggestions must be capped so an error stays readable in a model's context")
}

func TestResolver_ErrorNamesTheVault(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/staging/secrets": `{"secrets":[],"total":0}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "staging", KindSecrets, "db-password")
	require.ErrorContains(t, err, `vault "staging"`,
		"the vault must be named so an agent working across vaults can tell where it looked")
}

func TestResolver_EmptyListIsNotFoundNotAnError(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[],"total":0}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.ErrorContains(t, err, "no secrets named")

	var apiErr *APIError
	require.NotErrorAs(t, err, &apiErr, "an empty vault is not an API failure")
}
