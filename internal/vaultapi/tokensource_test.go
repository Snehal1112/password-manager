package vaultapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestServiceAccountSource_ConcurrentCallersShareOneFetch(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		<-release // Hold the request open so all callers pile up.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-shared","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	const callers = 20
	results := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := src.Token(context.Background())
			if err != nil {
				errs <- err
				return
			}
			results <- tok
		}()
	}

	// Give every goroutine time to arrive at the fetch, then let it complete.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	close(errs)

	require.Empty(t, errs)
	require.Len(t, results, callers)
	for tok := range results {
		require.Equal(t, "tok-shared", tok)
	}
	require.EqualValues(t, 1, atomic.LoadInt32(&calls),
		"concurrent callers must share one in-flight token fetch")
}

func TestServiceAccountSource_FetchFailurePropagatesToAllWaiters(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	const callers = 10
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := src.Token(context.Background())
			errs <- err
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	require.Len(t, errs, callers)
	for err := range errs {
		require.Error(t, err, "every waiter must observe the failure")
		require.Contains(t, err.Error(), "invalid_client")
	}
}

func TestServiceAccountSource_RecoversAfterFailedFetch(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-ok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.Error(t, err, "first attempt fails")

	tok, err := src.Token(context.Background())
	require.NoError(t, err, "a failed fetch must not poison the source")
	require.Equal(t, "tok-ok", tok)
}

func TestServiceAccountSource_CloseClearsCachedToken(t *testing.T) {
	srv, _, _ := tokenServer(t, 3600)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, tok)
	require.NotEmpty(t, src.cachedTokenForTest())

	src.Close()
	require.Empty(t, src.cachedTokenForTest(), "Close must drop the cached token")
	require.True(t, src.expiryForTest().IsZero(), "Close must reset expiry so a stale token is never served")
}

func TestServiceAccountSource_TokenAfterCloseFetchesFresh(t *testing.T) {
	srv, calls, _ := tokenServer(t, 3600)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err)
	src.Close()

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-2", tok)
	require.EqualValues(t, 2, atomic.LoadInt32(calls))
}

func TestServiceAccountSource_RefreshDropsPreviousToken(t *testing.T) {
	srv, _, _ := tokenServer(t, 30)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec",
		HTTPClient: srv.Client(), Skew: 60 * time.Second,
	})
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err)
	_, err = src.Token(context.Background())
	require.NoError(t, err)

	require.Equal(t, "tok-2", src.cachedTokenForTest(),
		"the replaced token must not still be the cached one")
}

func TestServiceAccountSource_CloseIsIdempotent(t *testing.T) {
	srv, _, _ := tokenServer(t, 3600)
	defer srv.Close()

	src, err := NewServiceAccountSource(ServiceAccountConfig{
		BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec", HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err)

	require.NotPanics(t, func() {
		src.Close()
		src.Close()
	})
}
