# Session TokenSource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `SessionSource`, a `TokenSource` backed by the CLI's cached session (`~/.rocketvault/sessions/`), which refreshes an expired access token via `POST /api/v1/users/refresh` and persists **both** rotated tokens back to the cache.

**Architecture:** `SessionSource` wraps the session cache behind two injected function fields, so tests never touch the real home directory. It reads the cached session once at construction, serves its access token while live, and refreshes single-flight when expired — the same concurrency guarantee plan 02 established, for the same reason.

**Tech Stack:** Go 1.25, `net/http`, `common` (session cache), `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Authentication", including the "Refresh tokens rotate" note.

**Plan-of-plans:** This is plan 03 of 31. Requires plans 01 and 02 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **This is the local-development identity path.** Production uses plan 02's service account, because a session makes the agent act as the human and its actions become indistinguishable from theirs in the audit log. Plan 16 enforces that with `require_service_account`.
- **Tests must be hermetic** — no reads or writes under the real `~/.rocketvault`. The codebase already fixed this class of problem once (commit `086914b`, "hermetic session tests").
- A refresh token must never appear in an error message or log line.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified contracts

- `common.SessionCache{Token, RefreshToken string; UserID uuid.UUID; Username, Role string; ExpiresAt time.Time; ServerKey string}` (`common/session.go:34`).
- `common.LoadCurrentSession() (*SessionCache, error)` returns **`(nil, nil)` when there is no session** — absence is not an error (`common/session.go:243`).
- `common.SaveSession(*SessionCache) error` writes the session file *and* updates the current-session pointer (`common/session.go:176`).
- `POST /api/v1/users/refresh` takes `{"refresh_token": "..."}` (`model.RefreshTokenRequest`, `model/user.go:125`) and returns `model.RefreshTokenResponse{Token, RefreshToken, UserID, Username, Role, ExpiresAt}` (`model/user.go:134`). **The returned `refresh_token` is new** (`api/users.go:501`).
- On failure the handler calls `c.SetPermissionError`, so the status is 403, not 401 (`api/users.go:496`).

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/sessionsource.go` (new) | `SessionSource`, construction from the cache, refresh, persistence |
| `internal/vaultapi/sessionsource_test.go` (new) | Live token, expiry refresh, rotation persistence, absence and error paths |

---

### Task 1: Serve the cached access token while it is live

**Files:**
- Create: `internal/vaultapi/sessionsource.go`
- Create: `internal/vaultapi/sessionsource_test.go`

**Interfaces:**
- Consumes: `TokenSource` interface from plan 01.
- Produces — plan 16 constructs this:
  - `type SessionConfig struct { BaseURL string; HTTPClient *http.Client; Skew time.Duration; LoadSession func() (*common.SessionCache, error); SaveSession func(*common.SessionCache) error }`
  - `func NewSessionSource(cfg SessionConfig) (*SessionSource, error)`
  - `func (s *SessionSource) Token(ctx context.Context) (string, error)`
  - `func (s *SessionSource) Username() string` — plan 16 prints it in `--check`.
  - `var ErrNoSession = errors.New(...)` — plan 16 turns this into the "run `rocketvault users login`" startup message.

**Why the loader is injected:** `common.LoadCurrentSession` reads `~/.rocketvault/sessions/current`. A test that exercised it directly would read or clobber the developer's real session. The two function fields default to the real implementations and are overridden in tests.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/sessionsource_test.go`:

```go
package vaultapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

// sessionFixture returns a session whose access token expires at the given
// offset from now.
func sessionFixture(expiresIn time.Duration) *common.SessionCache {
	return &common.SessionCache{
		Token:        "access-original",
		RefreshToken: "refresh-original",
		UserID:       uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Username:     "admin",
		Role:         "admin",
		ExpiresAt:    time.Now().Add(expiresIn),
		ServerKey:    "vault.example.com",
	}
}

// stubStore is an in-memory stand-in for the on-disk session cache, so no
// test touches the real ~/.rocketvault directory.
type stubStore struct {
	session *common.SessionCache
	saved   []*common.SessionCache
	loadErr error
}

func (s *stubStore) load() (*common.SessionCache, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.session, nil
}

func (s *stubStore) save(sc *common.SessionCache) error {
	copied := *sc
	s.saved = append(s.saved, &copied)
	s.session = &copied
	return nil
}

func newSessionSourceForTest(t *testing.T, store *stubStore, baseURL string, client *http.Client) *SessionSource {
	t.Helper()
	src, err := NewSessionSource(SessionConfig{
		BaseURL:     baseURL,
		HTTPClient:  client,
		LoadSession: store.load,
		SaveSession: store.save,
	})
	require.NoError(t, err)
	return src
}

func TestSessionSource_ServesLiveCachedToken(t *testing.T) {
	store := &stubStore{session: sessionFixture(time.Hour)}
	src := newSessionSourceForTest(t, store, "https://vault.example.com", http.DefaultClient)

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-original", tok)
	require.Empty(t, store.saved, "a live token must not trigger a save")
}

func TestSessionSource_ExposesUsername(t *testing.T) {
	store := &stubStore{session: sessionFixture(time.Hour)}
	src := newSessionSourceForTest(t, store, "https://vault.example.com", http.DefaultClient)
	require.Equal(t, "admin", src.Username())
}

func TestSessionSource_NoCachedSessionIsErrNoSession(t *testing.T) {
	// common.LoadCurrentSession returns (nil, nil) when nothing is cached.
	store := &stubStore{session: nil}
	_, err := NewSessionSource(SessionConfig{
		BaseURL:     "https://vault.example.com",
		HTTPClient:  http.DefaultClient,
		LoadSession: store.load,
		SaveSession: store.save,
	})
	require.ErrorIs(t, err, ErrNoSession)
}

func TestSessionSource_LoaderErrorPropagates(t *testing.T) {
	store := &stubStore{loadErr: errors.New("permission denied reading pointer")}
	_, err := NewSessionSource(SessionConfig{
		BaseURL:     "https://vault.example.com",
		HTTPClient:  http.DefaultClient,
		LoadSession: store.load,
		SaveSession: store.save,
	})
	require.ErrorContains(t, err, "permission denied reading pointer")
	require.NotErrorIs(t, err, ErrNoSession, "a real read failure is not the same as no session")
}

func TestSessionSource_RequiresBaseURLAndHTTPClient(t *testing.T) {
	store := &stubStore{session: sessionFixture(time.Hour)}

	_, err := NewSessionSource(SessionConfig{HTTPClient: http.DefaultClient, LoadSession: store.load, SaveSession: store.save})
	require.ErrorContains(t, err, "BaseURL")

	_, err = NewSessionSource(SessionConfig{BaseURL: "https://v", LoadSession: store.load, SaveSession: store.save})
	require.ErrorContains(t, err, "HTTPClient")
}

func TestSessionSource_SatisfiesTokenSource(t *testing.T) {
	var _ TokenSource = (*SessionSource)(nil)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestSessionSource_ -v`
Expected: FAIL — `undefined: NewSessionSource`, `undefined: SessionConfig`, `undefined: ErrNoSession`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/sessionsource.go`:

```go
package vaultapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"rocketvault/common"
)

// ErrNoSession reports that no CLI session is cached. Callers turn this into
// an instruction to run `rocketvault users login`.
var ErrNoSession = errors.New("vaultapi: no cached session")

// SessionConfig configures a TokenSource backed by the CLI session cache.
type SessionConfig struct {
	// BaseURL is the server root, e.g. "https://vault.example.com".
	BaseURL string
	// HTTPClient is the transport used for refreshes. Required.
	HTTPClient *http.Client
	// Skew overrides how early the access token is considered expired. Zero
	// uses defaultTokenSkew.
	Skew time.Duration
	// LoadSession reads the cached session. Nil uses
	// common.LoadCurrentSession. Tests inject a stub so they never touch the
	// real ~/.rocketvault directory.
	LoadSession func() (*common.SessionCache, error)
	// SaveSession persists a refreshed session. Nil uses common.SaveSession.
	SaveSession func(*common.SessionCache) error
}

// SessionSource serves the cached CLI session's access token, refreshing it
// when it expires.
//
// This is the local-development identity path. Under it the agent acts as the
// logged-in human, so its actions are indistinguishable from theirs in the
// audit log. Production should use ServiceAccountSource instead.
type SessionSource struct {
	cfg  SessionConfig
	skew time.Duration
	save func(*common.SessionCache) error

	mu      sync.Mutex
	session *common.SessionCache
}

// NewSessionSource loads the cached session and returns a source. It returns
// ErrNoSession when nothing is cached.
func NewSessionSource(cfg SessionConfig) (*SessionSource, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultapi: SessionConfig.BaseURL is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vaultapi: SessionConfig.HTTPClient is required")
	}

	load := cfg.LoadSession
	if load == nil {
		load = common.LoadCurrentSession
	}
	save := cfg.SaveSession
	if save == nil {
		save = common.SaveSession
	}

	session, err := load()
	if err != nil {
		return nil, fmt.Errorf("vaultapi: read cached session: %w", err)
	}
	// A nil session with a nil error means "nothing cached", which is the
	// documented contract of common.LoadCurrentSession.
	if session == nil {
		return nil, ErrNoSession
	}

	skew := cfg.Skew
	if skew == 0 {
		skew = defaultTokenSkew
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	return &SessionSource{cfg: cfg, skew: skew, save: save, session: session}, nil
}

// Username reports who this source acts as.
func (s *SessionSource) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.Username
}

// Token returns the cached access token while it is live. Task 2 adds
// refresh.
func (s *SessionSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Now().Before(s.session.ExpiresAt.Add(-s.skew)) {
		return s.session.Token, nil
	}
	return "", fmt.Errorf("vaultapi: cached session expired")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestSessionSource_ -v`
Expected: PASS — all six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/sessionsource.go internal/vaultapi/sessionsource_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add session-backed TokenSource

Serves the CLI session cache's access token while it is live. The cache
accessors are injected so tests never read or clobber the developer's real
~/.rocketvault session. A missing session is ErrNoSession, distinct from a
read failure, so the caller can tell the operator to log in."
```

---

### Task 2: Refresh on expiry and persist the rotated refresh token

**Files:**
- Modify: `internal/vaultapi/sessionsource.go`
- Modify: `internal/vaultapi/sessionsource_test.go` (append)

**Interfaces:**
- Consumes: `SessionSource` from Task 1.
- Produces: no new exported surface. `Token` gains refresh-on-expiry.

**The trap this task exists to avoid:** `POST /api/v1/users/refresh` returns a **new** `refresh_token` alongside the access token (`api/users.go:501-503`). Persisting only the access token leaves a stale refresh token on disk, and the *next* refresh fails with a permission error — an hour later, far from its cause. `TestSessionSource_PersistsRotatedRefreshToken` is the regression guard.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/sessionsource_test.go`:

```go
// refreshServer replies to POST /api/v1/users/refresh with a rotated pair,
// and records the refresh token it was sent.
func refreshServer(t *testing.T, newAccess, newRefresh string, expiresIn time.Duration) (*httptest.Server, *string) {
	t.Helper()
	var gotRefresh string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/users/refresh", r.URL.Path)

		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotRefresh = body.RefreshToken

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":%q,"refresh_token":%q,"user_id":"11111111-1111-1111-1111-111111111111","username":"admin","role":"admin","expires_at":%q}`,
			newAccess, newRefresh, time.Now().Add(expiresIn).Format(time.RFC3339Nano))
	}))
	return srv, &gotRefresh
}

func TestSessionSource_RefreshesExpiredToken(t *testing.T) {
	srv, sentRefresh := refreshServer(t, "access-new", "refresh-new", time.Hour)
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)} // already expired
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-new", tok)
	require.Equal(t, "refresh-original", *sentRefresh, "the cached refresh token is what gets sent")
}

func TestSessionSource_PersistsRotatedRefreshToken(t *testing.T) {
	srv, _ := refreshServer(t, "access-new", "refresh-ROTATED", time.Hour)
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.NoError(t, err)

	require.Len(t, store.saved, 1, "a refresh must persist the session")
	saved := store.saved[0]
	require.Equal(t, "access-new", saved.Token)
	require.Equal(t, "refresh-ROTATED", saved.RefreshToken,
		"the rotated refresh token must be persisted, or the next refresh fails with a stale token")
	require.Equal(t, "vault.example.com", saved.ServerKey, "the server key must survive a refresh")
	require.Equal(t, "admin", saved.Username)
}

func TestSessionSource_SecondRefreshUsesTheRotatedToken(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		seen = append(seen, body.RefreshToken)

		w.Header().Set("Content-Type", "application/json")
		// Always hand back an already-expired access token, so the next
		// Token call refreshes again.
		_, _ = fmt.Fprintf(w, `{"token":"access-%d","refresh_token":"refresh-%d","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","role":"admin","expires_at":%q}`,
			len(seen), len(seen), time.Now().Add(-time.Minute).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.NoError(t, err)
	_, err = src.Token(context.Background())
	require.NoError(t, err)

	require.Equal(t, []string{"refresh-original", "refresh-1"}, seen,
		"the second refresh must use the token the first one returned")
}

func TestSessionSource_RefreshRejectionIsActionable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// api/users.go:496 calls SetPermissionError, so this is 403.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"token refresh failed"}`))
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "rocketvault users login")
	require.NotContains(t, err.Error(), "refresh-original", "the refresh token must not appear in the error")
	require.Empty(t, store.saved, "a failed refresh must not persist anything")
}

func TestSessionSource_ConcurrentCallersShareOneRefresh(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"access-shared","refresh_token":"refresh-shared","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","role":"admin","expires_at":%q}`,
			time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	const callers = 15
	results := make(chan string, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := src.Token(context.Background())
			require.NoError(t, err)
			results <- tok
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	for tok := range results {
		require.Equal(t, "access-shared", tok)
	}
	require.EqualValues(t, 1, atomic.LoadInt32(&calls),
		"concurrent callers must share one refresh, not stampede the endpoint")
}
```

Extend the test file's import block with `"encoding/json"`, `"sync"`, and `"sync/atomic"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestSessionSource_Refresh|TestSessionSource_Persists|TestSessionSource_Second|TestSessionSource_Concurrent' -race -v`
Expected: FAIL — every one of these fails with "cached session expired", because Task 1's `Token` has no refresh path.

- [ ] **Step 3: Write minimal implementation**

In `internal/vaultapi/sessionsource.go`, add imports `"encoding/json"` and `"bytes"`, add an in-flight field to the struct:

```go
	// inflight is non-nil while a refresh is running, so concurrent callers
	// share it rather than each calling the refresh endpoint.
	inflight *tokenFetch
```

Replace `Token` with:

```go
// Token returns the cached access token, refreshing it first when it has
// expired. Concurrent callers share one in-flight refresh.
func (s *SessionSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()

	if time.Now().Before(s.session.ExpiresAt.Add(-s.skew)) {
		token := s.session.Token
		s.mu.Unlock()
		return token, nil
	}

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

	fetch := &tokenFetch{done: make(chan struct{})}
	s.inflight = fetch
	refreshToken := s.session.RefreshToken
	s.mu.Unlock()

	refreshed, err := s.refresh(ctx, refreshToken)

	s.mu.Lock()
	if err == nil {
		s.session = refreshed
	}
	s.inflight = nil
	s.mu.Unlock()

	if err == nil {
		fetch.token = refreshed.Token
	}
	fetch.err = err
	close(fetch.done)

	if err != nil {
		return "", err
	}
	return fetch.token, nil
}

// refresh exchanges refreshToken for a new pair and persists the result.
//
// The endpoint rotates the refresh token, so the new one must be written back
// or the next refresh fails with a stale token.
func (s *SessionSource) refresh(ctx context.Context, refreshToken string) (*common.SessionCache, error) {
	payload, err := json.Marshal(map[string]string{"refresh_token": refreshToken})
	if err != nil {
		return nil, fmt.Errorf("vaultapi: encode refresh request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.BaseURL+"/api/v1/users/refresh", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("vaultapi: build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: refresh request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// The body is not surfaced: it can echo the request, which carries
		// the refresh token.
		return nil, fmt.Errorf(
			"vaultapi: session refresh rejected (HTTP %d) — run `rocketvault users login` to sign in again",
			resp.StatusCode)
	}

	var decoded struct {
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		Username     string    `json:"username"`
		Role         string    `json:"role"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("vaultapi: decode refresh response: %w", err)
	}
	if decoded.Token == "" || decoded.RefreshToken == "" {
		return nil, fmt.Errorf("vaultapi: refresh response was missing a token")
	}

	// Copy the existing session so fields the endpoint does not return, such
	// as ServerKey and UserID, survive the refresh.
	s.mu.Lock()
	updated := *s.session
	s.mu.Unlock()

	updated.Token = decoded.Token
	updated.RefreshToken = decoded.RefreshToken
	updated.ExpiresAt = decoded.ExpiresAt
	if decoded.Username != "" {
		updated.Username = decoded.Username
	}
	if decoded.Role != "" {
		updated.Role = decoded.Role
	}

	if err := s.save(&updated); err != nil {
		return nil, fmt.Errorf("vaultapi: persist refreshed session: %w", err)
	}
	return &updated, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/sessionsource.go internal/vaultapi/sessionsource_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): refresh expired sessions and persist the rotated token

POST /api/v1/users/refresh returns a new refresh_token alongside the access
token, so both are written back. Persisting only the access token would leave
a stale refresh token on disk and fail the next refresh an hour later, far
from its cause. Concurrent callers share one in-flight refresh."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

Confirm the tests are hermetic — this must pass with no `~/.rocketvault`
present at all:

```bash
HOME=$(mktemp -d) go test ./internal/vaultapi/ -run TestSessionSource_ -v
```

If any test fails under a fresh `HOME`, it is reaching the real session cache
and must be fixed before commit.

## Notes for the next plan

Plan 04 adds name-to-UUID resolution. It uses `Client.Do` from plan 01 and is
independent of both token sources.

Plan 16 is where the two sources meet: service account first, session second,
fail fast if neither resolves, and refuse the session entirely when
`require_service_account` is set.
