# MCP Interactive Login — Part 1: vaultapi Identity Primitives

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Before starting:** create one Task (via the TaskCreate tool) per task
> below, so progress is visible in Claude Code's own task list. Set a task
> `in_progress` before starting it and `completed` immediately after its
> commit step. Run TaskList at any checkpoint to see where this plan stands.

**Goal:** Add the runtime-identity-swap primitive and fix the stale-refresh-token failure mode in `vaultapi`, with no consumer wiring yet.

**Architecture:** Three additive, independently testable pieces in `internal/vaultapi`: a `TokenSource` wrapper whose backing source can be swapped at runtime, a fix so `SessionSource` recovers when its in-memory refresh token is stale relative to disk, and a constructor that seeds a `SessionSource` from an already-known session instead of loading one from disk.

**Tech Stack:** Go, `testify/require`, `net/http/httptest`.

**Spec:** `docs/superpowers/specs/2026-08-25-mcp-interactive-login-design.md`

## Global Constraints

- No consumer code (`cmd/mcp.go`, `internal/mcpserver`) changes in this plan — that's Part 3 and Part 4.
- Every new/changed function keeps the existing package's error-wrapping convention: `fmt.Errorf("vaultapi: <what>: %w", err)`.
- No new external dependencies.

## Plan Chain

**This is Part 1 of 5.** Next plan: `docs/superpowers/plans/2026-08-25-mcp-interactive-login-part2-vaultapi-login-and-config.md`

---

### Task 1: SwappableSource

**Files:**
- Create: `internal/vaultapi/swappablesource.go`
- Test: `internal/vaultapi/swappablesource_test.go`

**Interfaces:**
- Consumes: `vaultapi.TokenSource` (existing interface, `internal/vaultapi/client.go:39`).
- Produces: `vaultapi.SwappableSource` struct, `NewSwappableSource(initial TokenSource) *SwappableSource`, `(*SwappableSource).Token(ctx) (string, error)`, `(*SwappableSource).Set(next TokenSource)`. Part 2 and Part 3 construct one of these and call `.Set` from the login tool handler.

- [ ] **Step 1: Write the failing tests**

```go
// internal/vaultapi/swappablesource_test.go
package vaultapi

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubTokenSource struct {
	token string
	err   error
}

func (s stubTokenSource) Token(ctx context.Context) (string, error) { return s.token, s.err }

func TestSwappableSource_DelegatesToInitial(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{token: "one"})
	tok, err := s.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "one", tok)
}

func TestSwappableSource_SetSwitchesImmediately(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{token: "one"})
	s.Set(stubTokenSource{token: "two"})

	tok, err := s.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "two", tok)
}

func TestSwappableSource_PropagatesCurrentSourceError(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{err: errors.New("boom")})
	_, err := s.Token(context.Background())
	require.ErrorContains(t, err, "boom")
}

func TestSwappableSource_ConcurrentSetAndTokenIsRace(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{token: "initial"})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			s.Set(stubTokenSource{token: "swapped"})
		}(i)
		go func() {
			defer wg.Done()
			_, _ = s.Token(context.Background())
		}()
	}
	wg.Wait()

	tok, err := s.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "swapped", tok)
}

func TestSwappableSource_SatisfiesTokenSource(t *testing.T) {
	var _ TokenSource = (*SwappableSource)(nil)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vaultapi/... -run TestSwappableSource -v`
Expected: FAIL with `undefined: NewSwappableSource` (the type doesn't exist yet).

- [ ] **Step 3: Write the implementation**

```go
// internal/vaultapi/swappablesource.go
package vaultapi

import (
	"context"
	"sync"
)

// SwappableSource is a TokenSource whose backing source can be replaced at
// runtime -- e.g. an in-chat login swapping a server's identity without
// restarting the process. Token calls always delegate to whatever source is
// current at the time of the call.
type SwappableSource struct {
	mu      sync.RWMutex
	current TokenSource
}

// NewSwappableSource wraps initial so it can be replaced later via Set.
func NewSwappableSource(initial TokenSource) *SwappableSource {
	return &SwappableSource{current: initial}
}

// Token delegates to whatever source is current.
func (s *SwappableSource) Token(ctx context.Context) (string, error) {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	return current.Token(ctx)
}

// Set replaces the current source. Every Token call after this returns uses
// next; a call already in flight when Set runs still completes against
// whichever source it read.
func (s *SwappableSource) Set(next TokenSource) {
	s.mu.Lock()
	s.current = next
	s.mu.Unlock()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/vaultapi/... -run TestSwappableSource -v -race`
Expected: PASS, including under `-race`.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/swappablesource.go internal/vaultapi/swappablesource_test.go
git commit -m "$(cat <<'EOF'
feat(vaultapi): add SwappableSource for runtime identity swaps

Wraps a TokenSource so it can be replaced while the process is running,
without touching Client. Nothing consumes this yet -- wiring lands in
a later plan.
EOF
)"
```

---

### Task 2: Stale-session auto-reload on refresh rejection

**Files:**
- Modify: `internal/vaultapi/sessionsource.go` (struct, `NewSessionSource`, `Token`)
- Test: `internal/vaultapi/sessionsource_test.go` (append)

**Interfaces:**
- Consumes: existing `SessionSource` struct and `stubStore`/`sessionFixture`/`newSessionSourceForTest` test helpers already in `sessionsource_test.go`.
- Produces: a new unexported `load func() (*common.SessionCache, error)` field on `SessionSource`, populated by `NewSessionSource`. Task 3 (this same plan) reads and sets this field too.

- [ ] **Step 1: Write the failing tests**

Append to `internal/vaultapi/sessionsource_test.go`:

```go
func TestSessionSource_StaleRefreshTokenRecoversFromDisk(t *testing.T) {
	var seenTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		seenTokens = append(seenTokens, body.RefreshToken)

		if body.RefreshToken == "refresh-stale" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"access-fresh","refresh_token":"refresh-fresh-2","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"],"expires_at":%q}`,
			time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	stale := sessionFixture(-time.Minute)
	stale.RefreshToken = "refresh-stale"
	store := &stubStore{session: stale}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	// Simulate a newer `rocketvault users login` landing on disk, in a
	// different process, after src was constructed.
	fresh := sessionFixture(-time.Minute)
	fresh.RefreshToken = "refresh-fresh"
	store.session = fresh

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-fresh", tok)
	require.Equal(t, []string{"refresh-stale", "refresh-fresh"}, seenTokens,
		"the stale in-memory token is tried first, then the freshly loaded one")
}

func TestSessionSource_UnchangedDiskSessionDoesNotRetry(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.Error(t, err)
	require.Equal(t, 1, calls, "no newer session on disk means no retry, and no infinite loop")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vaultapi/... -run TestSessionSource_StaleRefreshTokenRecoversFromDisk -v`
Expected: FAIL — `TestSessionSource_StaleRefreshTokenRecoversFromDisk` gets a 403 with no retry, so `err` is non-nil where the test expects success.

- [ ] **Step 3: Implement the reload-and-retry**

In `internal/vaultapi/sessionsource.go`, add a field to the struct:

```go
type SessionSource struct {
	cfg  SessionConfig
	skew time.Duration
	save func(*common.SessionCache) error
	load func() (*common.SessionCache, error)

	mu      sync.Mutex
	session *common.SessionCache

	inflight *tokenFetch
}
```

In `NewSessionSource`, pass the already-resolved `load` into the returned struct (it is currently computed and used once, then discarded):

```go
	return &SessionSource{cfg: cfg, skew: skew, save: save, load: load, session: session}, nil
```

In `Token`, change:

```go
	refreshed, err := s.refresh(ctx, refreshToken)

	s.mu.Lock()
	if err == nil {
		s.session = refreshed
	}
```

to:

```go
	refreshed, err := s.refresh(ctx, refreshToken)
	if err != nil {
		// The cached refresh token can be stale if a newer CLI login
		// happened, in a different process, after this source was
		// constructed. Reload once and retry with whatever is actually on
		// disk before giving up -- this is what lets a running MCP
		// subprocess pick up a fresh `rocketvault users login` without a
		// restart.
		if reloaded, loadErr := s.load(); loadErr == nil && reloaded != nil && reloaded.RefreshToken != refreshToken {
			s.mu.Lock()
			s.session = reloaded
			s.mu.Unlock()
			refreshed, err = s.refresh(ctx, reloaded.RefreshToken)
		}
	}

	s.mu.Lock()
	if err == nil {
		s.session = refreshed
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/vaultapi/... -run TestSessionSource -v -race`
Expected: PASS for all `TestSessionSource_*` tests, including the two new ones and every pre-existing one (`TestSessionSource_RefreshRejectionIsActionable` in particular must still pass unchanged).

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/sessionsource.go internal/vaultapi/sessionsource_test.go
git commit -m "$(cat <<'EOF'
fix(vaultapi): recover from a stale refresh token via disk reload

A SessionSource built before a newer `rocketvault users login` ran in a
different process held a refresh token the server no longer recognized,
and every call failed with "session not found or expired" until the
process was restarted. Token() now reloads the session cache once on
refresh rejection and retries with whatever is actually on disk.
EOF
)"
```

---

### Task 3: NewSessionSourceFromCache

**Files:**
- Modify: `internal/vaultapi/sessionsource.go` (new constructor)
- Test: `internal/vaultapi/sessionsource_test.go` (append)

**Interfaces:**
- Consumes: `common.SessionCache` (existing, `common/session.go:33`), the `load`/`save` fields added in Task 2.
- Produces: `NewSessionSourceFromCache(cfg SessionConfig, session *common.SessionCache) (*SessionSource, error)`. Part 2's `Client.Login` calls this to seed an in-memory-only identity.

- [ ] **Step 1: Write the failing tests**

Append to `internal/vaultapi/sessionsource_test.go`:

```go
func TestNewSessionSourceFromCache_SkipsDiskLoad(t *testing.T) {
	session := sessionFixture(time.Hour)
	src, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:    "https://vault.example.com",
		HTTPClient: http.DefaultClient,
	}, session)
	require.NoError(t, err)

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-original", tok)
}

func TestNewSessionSourceFromCache_RequiresSession(t *testing.T) {
	_, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:    "https://vault.example.com",
		HTTPClient: http.DefaultClient,
	}, nil)
	require.ErrorContains(t, err, "requires a session")
}

func TestNewSessionSourceFromCache_SaveDefaultsToNoOp(t *testing.T) {
	srv, _ := refreshServer(t, "access-new", "refresh-new", time.Hour)
	defer srv.Close()

	src, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	}, sessionFixture(-time.Minute))
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err, "a refresh must not fail merely because no SaveSession was supplied")
}

func TestNewSessionSourceFromCache_HonorsExplicitSaveSession(t *testing.T) {
	srv, _ := refreshServer(t, "access-new", "refresh-new", time.Hour)
	defer srv.Close()

	var saved *common.SessionCache
	src, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		SaveSession: func(sc *common.SessionCache) error { saved = sc; return nil },
	}, sessionFixture(-time.Minute))
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err)
	require.NotNil(t, saved, "an explicitly supplied SaveSession must still be honored")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vaultapi/... -run TestNewSessionSourceFromCache -v`
Expected: FAIL with `undefined: NewSessionSourceFromCache`.

- [ ] **Step 3: Write the implementation**

Add to `internal/vaultapi/sessionsource.go`:

```go
// NewSessionSourceFromCache builds a SessionSource seeded with an
// already-known session, skipping the on-disk load NewSessionSource
// performs. SaveSession defaults to a no-op rather than common.SaveSession,
// so a source built this way never writes to ~/.rocketvault/sessions/ --
// used for an in-chat login, which is deliberately in-memory only. Callers
// that do want persistence may still supply cfg.SaveSession explicitly.
func NewSessionSourceFromCache(cfg SessionConfig, session *common.SessionCache) (*SessionSource, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultapi: SessionConfig.BaseURL is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vaultapi: SessionConfig.HTTPClient is required")
	}
	if session == nil {
		return nil, fmt.Errorf("vaultapi: NewSessionSourceFromCache requires a session")
	}

	load := cfg.LoadSession
	if load == nil {
		// No disk backing: a stale-token retry (see Token) simply finds
		// nothing newer and falls through to the existing error path.
		load = func() (*common.SessionCache, error) { return nil, ErrNoSession }
	}
	save := cfg.SaveSession
	if save == nil {
		save = func(*common.SessionCache) error { return nil }
	}

	skew := cfg.Skew
	if skew == 0 {
		skew = defaultTokenSkew
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	return &SessionSource{cfg: cfg, skew: skew, save: save, load: load, session: session}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/vaultapi/... -v -race`
Expected: PASS for the entire package, including every test from Task 1, Task 2, and Task 3.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/sessionsource.go internal/vaultapi/sessionsource_test.go
git commit -m "$(cat <<'EOF'
feat(vaultapi): add NewSessionSourceFromCache

Seeds a SessionSource from an already-known session instead of loading
one from disk, with SaveSession defaulting to a no-op. This is what will
let an in-chat login stay in-memory-only. Nothing calls it yet.
EOF
)"
```

---

## After this plan

Run the full package check before moving on:

```bash
go build ./internal/vaultapi/...
go vet ./internal/vaultapi/...
go test ./internal/vaultapi/... -race
```

All three must be clean. Then proceed to **Part 2**:
`docs/superpowers/plans/2026-08-25-mcp-interactive-login-part2-vaultapi-login-and-config.md`
