# Service-Account TokenSource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `ServiceAccountSource`, a `TokenSource` that obtains bearer tokens from `POST /api/v1/oauth2/token` using the client-credentials grant, caches them until just before expiry, refreshes single-flight under concurrency, and zeroizes tokens it discards.

**Architecture:** One `TokenSource` implementation with an internal cache guarded by a mutex. Concurrent callers arriving during a refresh wait on a shared in-flight fetch rather than each issuing their own — MCP hosts dispatch tool calls concurrently, so without this, N calls stampede the token endpoint the moment a token expires.

**Tech Stack:** Go 1.25, `net/http`, `net/url`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Authentication", and "Production hardening > Concurrency" and "> Memory hygiene".

**Plan-of-plans:** This is plan 02 of 31. Requires plan 01 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- Credentials go in the **HTTP Basic** header, never the form body. The endpoint accepts both but prefers Basic per RFC 6749 §2.3.1 (`extractClientCredentials`, `api/oauth2.go:143`), and Basic keeps the secret out of request bodies and anything that logs them.
- The token endpoint requires `Content-Type: application/x-www-form-urlencoded` (`api/oauth2.go:63`).
- **A client secret must never appear in an error message or log line.**
- `vaultapi` must not import the MCP SDK or `internal/mcpserver`.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified endpoint contract

- `POST /api/v1/oauth2/token`, form-encoded, `grant_type=client_credentials` (`api/oauth2.go:72`).
- Success body: `{"access_token": "...", "token_type": "Bearer", "expires_in": <seconds>}` (`api/oauth2.go:54`).
- Failure: RFC 6749 §5.2 JSON, e.g. `{"error":"invalid_client", ...}` with 401 (`api/oauth2.go:98,163`).

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/tokensource.go` (new) | `ServiceAccountSource`, its config, cache, and single-flight fetch |
| `internal/vaultapi/tokensource_test.go` (new) | Acquisition, caching, expiry, single-flight, error paths |

---

### Task 1: Acquire and cache a token via client credentials

**Files:**
- Create: `internal/vaultapi/tokensource.go`
- Create: `internal/vaultapi/tokensource_test.go`

**Interfaces:**
- Consumes: `TokenSource` interface from plan 01 (`internal/vaultapi/client.go`).
- Produces — plan 16 (`cmd/mcp.go`) constructs this:
  - `type ServiceAccountConfig struct { BaseURL, ClientID, ClientSecret string; HTTPClient *http.Client; Skew time.Duration }`
  - `func NewServiceAccountSource(cfg ServiceAccountConfig) (*ServiceAccountSource, error)`
  - `func (s *ServiceAccountSource) Token(ctx context.Context) (string, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/tokensource_test.go`:

```go
package vaultapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestServiceAccountSource_ -v`
Expected: FAIL — `undefined: NewServiceAccountSource`, `undefined: ServiceAccountConfig`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/tokensource.go`:

```go
package vaultapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// defaultTokenSkew is how far before real expiry a cached token is treated as
// expired, so a request never races the boundary.
const defaultTokenSkew = 30 * time.Second

// ServiceAccountConfig configures token acquisition for a service account.
type ServiceAccountConfig struct {
	// BaseURL is the server root, e.g. "https://vault.example.com".
	BaseURL string
	// ClientID and ClientSecret are the service-account credentials. They are
	// sent as HTTP Basic, never in the form body.
	ClientID     string
	ClientSecret string
	// HTTPClient is the transport. Required.
	HTTPClient *http.Client
	// Skew overrides how early a token is considered expired. Zero uses
	// defaultTokenSkew.
	Skew time.Duration
}

// ServiceAccountSource obtains bearer tokens with the client-credentials
// grant and caches them until shortly before they expire.
type ServiceAccountSource struct {
	cfg  ServiceAccountConfig
	skew time.Duration

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewServiceAccountSource validates cfg and returns a source.
func NewServiceAccountSource(cfg ServiceAccountConfig) (*ServiceAccountSource, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.BaseURL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.ClientSecret is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.HTTPClient is required")
	}

	skew := cfg.Skew
	if skew == 0 {
		skew = defaultTokenSkew
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &ServiceAccountSource{cfg: cfg, skew: skew}, nil
}

// Token returns a cached token when one is still valid, otherwise fetches a
// new one.
func (s *ServiceAccountSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expiresAt.Add(-s.skew)) {
		return s.token, nil
	}

	token, expiresIn, err := s.fetch(ctx)
	if err != nil {
		return "", err
	}
	s.token = token
	s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return s.token, nil
}

// tokenResponse mirrors the success body documented at api/oauth2.go:54.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// tokenErrorResponse mirrors the RFC 6749 section 5.2 error body.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// fetch performs one client-credentials request.
//
// The client secret travels only in the Authorization header. It is never
// placed in the form body and never included in a returned error.
func (s *ServiceAccountSource) fetch(ctx context.Context) (string, int, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.BaseURL+"/api/v1/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("vaultapi: build token request: %w", err)
	}
	req.SetBasicAuth(s.cfg.ClientID, s.cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vaultapi: token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var apiErr tokenErrorResponse
		// A decode failure is not itself interesting; the status still is.
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return "", 0, fmt.Errorf("vaultapi: token request rejected (HTTP %d): %s", resp.StatusCode, apiErr.Error)
		}
		return "", 0, fmt.Errorf("vaultapi: token request rejected (HTTP %d)", resp.StatusCode)
	}

	var decoded tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", 0, fmt.Errorf("vaultapi: decode token response: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", 0, fmt.Errorf("vaultapi: token response contained no access_token")
	}
	return decoded.AccessToken, decoded.ExpiresIn, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestServiceAccountSource_ -v`
Expected: PASS — all seven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/tokensource.go internal/vaultapi/tokensource_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add service-account TokenSource

Obtains bearer tokens with the client-credentials grant and caches them until
shortly before expiry. Credentials travel as HTTP Basic rather than form
fields, which the endpoint prefers per RFC 6749 2.3.1 and which keeps the
secret out of request bodies. The secret never appears in a returned error."
```

---

### Task 2: Single-flight refresh under concurrency

**Files:**
- Modify: `internal/vaultapi/tokensource.go`
- Modify: `internal/vaultapi/tokensource_test.go` (append)

**Interfaces:**
- Consumes: `ServiceAccountSource` from Task 1.
- Produces: no new exported surface. `Token` gains the guarantee that concurrent callers trigger at most one in-flight fetch.

**Why:** MCP hosts dispatch tool calls concurrently. Task 1 holds `s.mu` across the network call, which does serialize callers — but it serializes them into a queue where each waiter then re-checks and, in the worst case, the queue drains slowly behind one slow fetch. Worse, holding a mutex across a network round trip blocks every unrelated `Token` caller for the full request duration. This task releases the lock during the fetch and shares one in-flight result.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/tokensource_test.go`:

```go
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
```

Add `"sync"` to the test file's import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestServiceAccountSource_Concurrent|TestServiceAccountSource_FetchFailure|TestServiceAccountSource_Recovers' -race -v`
Expected: FAIL — `TestServiceAccountSource_ConcurrentCallersShareOneFetch` reports more than 1 call, because Task 1's implementation lets each queued caller re-fetch after the first token is already stale-checked, and it blocks all callers on one mutex across the network call.

- [ ] **Step 3: Write minimal implementation**

In `internal/vaultapi/tokensource.go`, add an in-flight field to the struct:

```go
	// inflight is non-nil while a fetch is running. Callers arriving during
	// a fetch wait on it rather than issuing their own request.
	inflight *tokenFetch
```

Add the fetch-sharing type:

```go
// tokenFetch is one in-flight token acquisition shared by every caller that
// arrives while it runs.
type tokenFetch struct {
	done  chan struct{}
	token string
	err   error
}
```

Replace `Token` with:

```go
// Token returns a cached token when one is still valid, otherwise fetches a
// new one. Concurrent callers arriving during a fetch share its result rather
// than each issuing a request, so an expiry does not stampede the token
// endpoint.
func (s *ServiceAccountSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()

	if s.token != "" && time.Now().Before(s.expiresAt.Add(-s.skew)) {
		token := s.token
		s.mu.Unlock()
		return token, nil
	}

	// Join a fetch already in progress.
	if s.inflight != nil {
		fetch := s.inflight
		s.mu.Unlock()
		select {
		case <-fetch.done:
			return fetch.token, fetch.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	// Become the fetcher for everyone else.
	fetch := &tokenFetch{done: make(chan struct{})}
	s.inflight = fetch
	s.mu.Unlock()

	token, expiresIn, err := s.fetch(ctx)

	s.mu.Lock()
	if err == nil {
		s.zeroToken()
		s.token = token
		s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	s.inflight = nil
	s.mu.Unlock()

	fetch.token, fetch.err = token, err
	close(fetch.done)
	return token, err
}
```

Add a placeholder for the zeroization introduced in Task 3, so this task compiles on its own:

```go
// zeroToken clears the cached token. Task 3 gives it a real body.
func (s *ServiceAccountSource) zeroToken() {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean. The concurrency test must report exactly 1 call.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/tokensource.go internal/vaultapi/tokensource_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): share one in-flight token fetch across concurrent callers

MCP hosts dispatch tool calls concurrently, so an expiring token would
otherwise stampede the token endpoint. Callers arriving during a fetch now
wait on its result, and the mutex is no longer held across the network call."
```

---

### Task 3: Zeroize discarded tokens

**Files:**
- Modify: `internal/vaultapi/tokensource.go`
- Modify: `internal/vaultapi/tokensource_test.go` (append)

**Interfaces:**
- Consumes: `ServiceAccountSource` from Tasks 1 and 2.
- Produces: `func (s *ServiceAccountSource) Close()` — plan 16 calls it during graceful shutdown.

**Scope note, stated honestly:** Go strings are immutable and may be copied by the runtime, so this cannot guarantee no copy of a token survives in memory. What it does guarantee is that the source's own long-lived reference is dropped on replacement and shutdown, so a heap dump taken after shutdown does not find the token still reachable through this struct. That is the same bound `cachekit.Zeroable` operates under (`internal/cachekit/cachekit.go:32`); the goal is bounded lifetime, not erasure.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/tokensource_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestServiceAccountSource_Close|TestServiceAccountSource_TokenAfterClose|TestServiceAccountSource_RefreshDrops' -v`
Expected: FAIL — `src.Close undefined`, `src.cachedTokenForTest undefined`, `src.expiryForTest undefined`.

- [ ] **Step 3: Write minimal implementation**

In `internal/vaultapi/tokensource.go`, replace the Task 2 placeholder `zeroToken` with a real body and add `Close`:

```go
// zeroToken drops the cached token and its expiry.
//
// Go strings are immutable and the runtime may have copied this value, so
// this cannot erase every copy. What it does guarantee is that the source
// stops holding a live reference, bounding how long the token stays reachable
// through this struct. That is the same bound cachekit.Zeroable operates
// under. Callers must hold s.mu.
func (s *ServiceAccountSource) zeroToken() {
	s.token = ""
	s.expiresAt = time.Time{}
}

// Close drops any cached token. It is safe to call more than once, and the
// source remains usable afterwards — the next Token call fetches a fresh one.
func (s *ServiceAccountSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zeroToken()
}
```

Create `internal/vaultapi/export_test.go`:

```go
package vaultapi

import "time"

// cachedTokenForTest exposes the cached token to same-package tests.
func (s *ServiceAccountSource) cachedTokenForTest() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

// expiryForTest exposes the cached expiry to same-package tests.
func (s *ServiceAccountSource) expiryForTest() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiresAt
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/tokensource.go internal/vaultapi/tokensource_test.go internal/vaultapi/export_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): drop cached tokens on refresh and shutdown

Close() clears the cached token so it is not reachable through the source
after shutdown, and a refresh drops its predecessor. Go strings cannot be
erased in place, so this bounds a token's lifetime rather than erasing it --
the same guarantee cachekit.Zeroable provides."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

The concurrency test is the one that matters most here. Confirm it reports
exactly one token fetch for twenty callers; if it reports more, the
single-flight path is not being taken.

```bash
go test ./internal/vaultapi/ -run TestServiceAccountSource_ConcurrentCallersShareOneFetch -race -count=5 -v
```

`-count=5` is deliberate: a single pass can hide a race that only shows under
repetition.

## Notes for the next plan

Plan 03 implements the session-based `TokenSource`. It reuses the `TokenSource`
interface from plan 01 and does not modify anything created here.
