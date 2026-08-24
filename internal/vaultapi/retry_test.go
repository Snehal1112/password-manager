package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/retry"
)

// fastPolicy is ExternalServicePolicy's shape with millisecond delays, so
// retry tests finish in milliseconds instead of the ~15s the real policy
// would take to exhaust.
func fastPolicy() retry.Policy {
	p := retry.ExternalServicePolicy()
	p.MaxAttempts = 3
	p.InitialDelay = time.Millisecond
	p.MaxDelay = 5 * time.Millisecond
	return p
}

func TestDo_RetriesIdempotentGetOnServerError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t"), RetryPolicy: fastPolicy()})
	require.NoError(t, err)

	var out struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, &out))
	require.True(t, out.OK)
	require.EqualValues(t, 3, atomic.LoadInt32(&attempts))
}

func TestDo_DoesNotRetryMutations(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	err = c.Do(context.Background(), http.MethodPost, "/api/v1/vaults/prod/secrets",
		map[string]string{"name": "api-key"}, nil)
	require.Error(t, err)
	require.EqualValues(t, 1, atomic.LoadInt32(&attempts),
		"a mutation must be attempted exactly once: retrying could duplicate the resource")
}

func TestDo_MutationBodySurvivesBecauseItIsNotRetried(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	require.NoError(t, c.Do(context.Background(), http.MethodPost, "/api/v1/vaults/prod/secrets",
		map[string]string{"name": "api-key"}, nil))
	require.JSONEq(t, `{"name":"api-key"}`, gotBody)
}

func TestDo_GivesUpAfterMaxAttempts(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t"), RetryPolicy: fastPolicy()})
	require.NoError(t, err)

	err = c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, nil)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindServer, apiErr.Kind)
	require.Greater(t, atomic.LoadInt32(&attempts), int32(1))
}

func TestDo_DisableRetryMakesGetSingleAttempt(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t"), DisableRetry: true})
	require.NoError(t, err)

	require.Error(t, c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, nil))
	require.EqualValues(t, 1, atomic.LoadInt32(&attempts))
}
