# CLI Login for OIDC Users Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an OIDC-provisioned RocketVault user (who has no local password by design) obtain a CLI session via `rocketvault users login --oidc`, and give both OIDC and local password users a session cache so the CLI stops re-authenticating on every single command.

**Architecture:** A new `POST /oidc/cli/exchange` endpoint plus a `cli_redirect_uri` extension to the existing `/oidc/login`/`/oidc/callback` handlers let the CLI's own local loopback HTTP listener receive a one-time exchange code (never the token itself) after the user completes login in their browser via the provider-registered, unchanged redirect URI. The CLI redeems that code for a session and caches it per-user under `~/.rocketvault/sessions/`; `persistentPreRun` learns to fall back to that cache (with transparent refresh) when `--username`/`--password` aren't given.

**Tech Stack:** Go 1.25, Cobra/Viper (CLI), Gorilla Mux (HTTP), `net/http` loopback server, `crypto/rand`, `testify`/`mock` for tests.

**Spec:** `docs/superpowers/specs/2026-08-15-cli-oidc-login-design.md`

## Global Constraints

- `cli_redirect_uri` must be validated against an allow-list: scheme `http`, host exactly `127.0.0.1` or `localhost`, port required. Reject everything else with `400`.
- Exchange codes: `crypto/rand`, 32 bytes hex-encoded, single-use (deleted on first read), 60-second TTL, never logged.
- The access/refresh token must never appear in a URL or query string — only the opaque exchange code does.
- The CLI's loopback listener binds `127.0.0.1` only, never `0.0.0.0`.
- Session cache files: directory `0700`, file `0600`, explicit `os.WriteFile`/`os.MkdirAll` mode (not umask-dependent).
- `logout` is local-cache-only — no server-side session revocation (out of scope; see spec Non-goals).
- `login` and `logout` must be exempt from `persistentPreRun`'s credential requirement (see Task 4) — they are how a session is bootstrapped or cleared, so they cannot themselves require one.

---

### Task 1: Per-user session cache (`common/session.go`)

**Files:**
- Create: `common/session.go`
- Test: `common/session_test.go`

**Interfaces:**
- Produces: `common.SessionCache{ Token, RefreshToken string; UserID uuid.UUID; Username, Role string; ExpiresAt time.Time }`, `common.SessionBaseDir` (var, string, default `~/.rocketvault/sessions`, override in tests), `common.SaveSession(*SessionCache) error`, `common.LoadSession(username string) (*SessionCache, error)`, `common.LoadCurrentSession() (*SessionCache, error)`, `common.DeleteSession(username string) error`.

- [ ] **Step 1: Write the failing tests**

Create `common/session_test.go`:

```go
package common

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadSession_RoundTrip(t *testing.T) {
	SessionBaseDir = t.TempDir()

	session := &SessionCache{
		Token:        "access-tok",
		RefreshToken: "refresh-tok",
		UserID:       uuid.New(),
		Username:     "user14@exchange4all.local",
		Role:         "user",
		ExpiresAt:    time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second),
	}

	require.NoError(t, SaveSession(session))

	loaded, err := LoadSession("user14@exchange4all.local")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, session.Token, loaded.Token)
	assert.Equal(t, session.RefreshToken, loaded.RefreshToken)
	assert.Equal(t, session.UserID, loaded.UserID)
	assert.Equal(t, session.Username, loaded.Username)
	assert.Equal(t, session.Role, loaded.Role)
	assert.True(t, session.ExpiresAt.Equal(loaded.ExpiresAt))
}

func TestSaveSession_SanitizesFilename(t *testing.T) {
	SessionBaseDir = t.TempDir()

	require.NoError(t, SaveSession(&SessionCache{Username: "user14@exchange4all.local", Token: "t"}))

	_, err := os.Stat(filepath.Join(SessionBaseDir, "user14_exchange4all.local.json"))
	assert.NoError(t, err)
}

func TestLoadSession_MissingFile_ReturnsNilNoError(t *testing.T) {
	SessionBaseDir = t.TempDir()

	loaded, err := LoadSession("nobody")
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestLoadSession_CorruptFile_ReturnsNilNoError(t *testing.T) {
	SessionBaseDir = t.TempDir()
	require.NoError(t, os.MkdirAll(SessionBaseDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(SessionBaseDir, "admin.json"), []byte("not json"), 0600))

	loaded, err := LoadSession("admin")
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestLoadCurrentSession_FollowsPointer(t *testing.T) {
	SessionBaseDir = t.TempDir()

	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))

	loaded, err := LoadCurrentSession()
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "admin", loaded.Username)
}

func TestLoadCurrentSession_NoPointer_ReturnsNilNoError(t *testing.T) {
	SessionBaseDir = t.TempDir()

	loaded, err := LoadCurrentSession()
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestSaveSession_SecondUserDoesNotOverwriteFirst(t *testing.T) {
	SessionBaseDir = t.TempDir()

	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))
	require.NoError(t, SaveSession(&SessionCache{Username: "user14@exchange4all.local", Token: "oidc-tok"}))

	adminSession, err := LoadSession("admin")
	require.NoError(t, err)
	require.NotNil(t, adminSession)
	assert.Equal(t, "admin-tok", adminSession.Token)

	oidcSession, err := LoadSession("user14@exchange4all.local")
	require.NoError(t, err)
	require.NotNil(t, oidcSession)
	assert.Equal(t, "oidc-tok", oidcSession.Token)

	current, err := LoadCurrentSession()
	require.NoError(t, err)
	assert.Equal(t, "user14@exchange4all.local", current.Username)
}

func TestDeleteSession_RemovesFileAndClearsPointerIfCurrent(t *testing.T) {
	SessionBaseDir = t.TempDir()
	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))

	require.NoError(t, DeleteSession("admin"))

	loaded, err := LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, loaded)

	current, err := LoadCurrentSession()
	require.NoError(t, err)
	assert.Nil(t, current)
}

func TestDeleteSession_NonCurrentUser_LeavesPointerAlone(t *testing.T) {
	SessionBaseDir = t.TempDir()
	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))
	require.NoError(t, SaveSession(&SessionCache{Username: "user14", Token: "oidc-tok"}))

	require.NoError(t, DeleteSession("admin"))

	current, err := LoadCurrentSession()
	require.NoError(t, err)
	require.NotNil(t, current)
	assert.Equal(t, "user14", current.Username)
}

func TestDeleteSession_NonExistent_NoError(t *testing.T) {
	SessionBaseDir = t.TempDir()
	assert.NoError(t, DeleteSession("nobody"))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./common/... -run TestSaveAndLoadSession -v`
Expected: FAIL — `SessionBaseDir`, `SessionCache`, `SaveSession`, etc. undefined (file doesn't exist yet).

- [ ] **Step 3: Write the implementation**

Create `common/session.go`:

```go
package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// SessionBaseDir is the directory holding per-user CLI session cache files.
// Overridable in tests.
var SessionBaseDir = defaultSessionBaseDir()

func defaultSessionBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".rocketvault", "sessions")
	}
	return filepath.Join(home, ".rocketvault", "sessions")
}

// SessionCache is the on-disk representation of a CLI-authenticated session.
type SessionCache struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       uuid.UUID `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
}

var usernameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._@-]`)

// sanitizeUsername converts an arbitrary username into a safe filename
// component. Usernames in this codebase are typically emails
// (user14@exchange4all.local) or simple local names (admin) — both pass
// through unchanged; anything else is replaced with "_".
func sanitizeUsername(username string) string {
	return usernameSanitizer.ReplaceAllString(username, "_")
}

func sessionFilePath(username string) string {
	return filepath.Join(SessionBaseDir, sanitizeUsername(username)+".json")
}

func currentPointerPath() string {
	return filepath.Join(SessionBaseDir, "current")
}

// SaveSession writes session to disk and marks it as the current user —
// the one commands run without --username fall back to.
func SaveSession(session *SessionCache) error {
	if err := os.MkdirAll(SessionBaseDir, 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.WriteFile(sessionFilePath(session.Username), data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	if err := os.WriteFile(currentPointerPath(), []byte(session.Username), 0600); err != nil {
		return fmt.Errorf("failed to update current-session pointer: %w", err)
	}

	return nil
}

// LoadSession loads a specific user's cached session. A missing file
// returns (nil, nil) — "no session" is not an error.
func LoadSession(username string) (*SessionCache, error) {
	data, err := os.ReadFile(sessionFilePath(username))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var session SessionCache
	if err := json.Unmarshal(data, &session); err != nil {
		// A corrupt cache file is treated as "no session", not a hard error.
		return nil, nil
	}

	return &session, nil
}

// LoadCurrentSession loads whichever user's session the pointer file
// currently references. Returns (nil, nil) if there is no pointer or no
// matching session file.
func LoadCurrentSession() (*SessionCache, error) {
	data, err := os.ReadFile(currentPointerPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read current-session pointer: %w", err)
	}

	return LoadSession(string(data))
}

// DeleteSession removes username's cached session file. If username is the
// current pointer's target, the pointer is cleared too. Deleting a
// non-existent session is not an error.
func DeleteSession(username string) error {
	if err := os.Remove(sessionFilePath(username)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete session file: %w", err)
	}

	current, err := os.ReadFile(currentPointerPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read current-session pointer: %w", err)
	}
	if string(current) == username {
		if err := os.Remove(currentPointerPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to clear current-session pointer: %w", err)
		}
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./common/... -run 'TestSaveAndLoadSession|TestSaveSession|TestLoadSession|TestLoadCurrentSession|TestDeleteSession' -v`
Expected: PASS (all 10 tests)

- [ ] **Step 5: Commit**

```bash
git add common/session.go common/session_test.go
git commit -m "feat(common): add per-user CLI session cache"
```

---

### Task 2: Browser opener (`common/browser.go`)

**Files:**
- Create: `common/browser.go`
- Test: `common/browser_test.go`

**Interfaces:**
- Produces: `common.OpenBrowser(url string) error`

- [ ] **Step 1: Write the failing tests**

Create `common/browser_test.go`:

```go
package common

import (
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenBrowser_UsesPlatformCommand(t *testing.T) {
	var gotName string
	var gotArgs []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = args
		// Re-exec the current test binary with a flag that matches no test —
		// a real, always-present executable so Start() succeeds on every OS.
		return exec.Command(os.Args[0], "-test.run=TestOpenBrowser_NoSuchTest")
	}
	t.Cleanup(func() { execCommand = exec.Command })

	err := OpenBrowser("http://127.0.0.1:9999/callback")
	assert.NoError(t, err)

	switch runtime.GOOS {
	case "darwin":
		assert.Equal(t, "open", gotName)
		assert.Equal(t, []string{"http://127.0.0.1:9999/callback"}, gotArgs)
	case "windows":
		assert.Equal(t, "rundll32", gotName)
		assert.Equal(t, []string{"url.dll,FileProtocolHandler", "http://127.0.0.1:9999/callback"}, gotArgs)
	default:
		assert.Equal(t, "xdg-open", gotName)
		assert.Equal(t, []string{"http://127.0.0.1:9999/callback"}, gotArgs)
	}
}

func TestOpenBrowser_StartFailure_ReturnsError(t *testing.T) {
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("/nonexistent/binary-that-does-not-exist")
	}
	t.Cleanup(func() { execCommand = exec.Command })

	err := OpenBrowser("http://127.0.0.1:9999/callback")
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./common/... -run TestOpenBrowser -v`
Expected: FAIL — `execCommand`, `OpenBrowser` undefined.

- [ ] **Step 3: Write the implementation**

Create `common/browser.go`:

```go
package common

import (
	"fmt"
	"os/exec"
	"runtime"
)

// execCommand is exec.Command by default; overridable in tests.
var execCommand = exec.Command

// OpenBrowser attempts to open url in the user's default system browser.
// A failure to open (e.g. a headless environment with no display) is
// returned to the caller so it can fall back to printing the URL instead —
// no caller in this codebase treats it as fatal.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = execCommand("open", url)
	case "windows":
		cmd = execCommand("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = execCommand("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./common/... -run TestOpenBrowser -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add common/browser.go common/browser_test.go
git commit -m "feat(common): add cross-platform OpenBrowser helper"
```

---

### Task 3: Server-side CLI relay (`api/oidc.go`, new `api/oidc_cli.go`)

**Files:**
- Create: `api/oidc_cli.go`
- Modify: `api/oidc.go` (both handlers), `api/api.go` (add `cliExchange` field to `API` struct)
- Test: `api/oidc_cli_test.go` (new), `api/oidc_test.go` (extend existing tests' helper + add CLI-redirect cases)

**Interfaces:**
- Consumes: `model.LoginResponse` (`model/user.go:112-118`, unchanged), `authServices.AuthenticationResult` (Task-independent, already exists).
- Produces: `validateCLIRedirectURI(raw string) (string, error)`, `cliExchangeStore` (`newCLIExchangeStore()`, `.put(model.LoginResponse) (string, error)`, `.consume(code string) (model.LoginResponse, bool)`), `(*API).cliExchangeHandler(w, r)`, route `POST /oidc/cli/exchange`, cookie name `oidcCLIRedirectCookie = "oidc_cli_redirect"`.

- [ ] **Step 1: Write the failing tests**

Create `api/oidc_cli_test.go`:

```go
// Package api — tests for the CLI loopback relay added to the OIDC flow.
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestValidateCLIRedirectURI(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"empty is valid no-op", "", false},
		{"loopback IP with port", "http://127.0.0.1:54321/callback", false},
		{"localhost with port", "http://localhost:9999/callback", false},
		{"https rejected", "https://127.0.0.1:1234/callback", true},
		{"non-loopback host rejected", "http://evil.example.com:1234/callback", true},
		{"missing port rejected", "http://127.0.0.1/callback", true},
		{"malformed URL rejected", "://not a url", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCLIRedirectURI(tc.raw)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCLIExchangeStore_PutThenConsume_SingleUse(t *testing.T) {
	store := newCLIExchangeStore()
	response := model.LoginResponse{Token: "tok", RefreshToken: "rtok", UserID: "u1", Username: "jdoe", Role: "user"}

	code, err := store.put(response)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	got, ok := store.consume(code)
	require.True(t, ok)
	assert.Equal(t, response, got)

	_, ok = store.consume(code)
	assert.False(t, ok, "a code must not be redeemable twice")
}

func TestCLIExchangeStore_UnknownCode_NotOK(t *testing.T) {
	store := newCLIExchangeStore()
	_, ok := store.consume("does-not-exist")
	assert.False(t, ok)
}

func TestCLIExchangeStore_ExpiredCode_NotOK(t *testing.T) {
	store := newCLIExchangeStore()
	code, err := store.put(model.LoginResponse{Token: "tok"})
	require.NoError(t, err)

	// Force expiry directly — same package, unexported field access.
	entry := store.entries[code]
	entry.expiresAt = time.Now().Add(-1 * time.Second)
	store.entries[code] = entry

	_, ok := store.consume(code)
	assert.False(t, ok)
}

func TestCLIExchangeHandler_ValidCode_ReturnsLoginResponse(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil)
	response := model.LoginResponse{Token: "tok", RefreshToken: "rtok", UserID: "u1", Username: "jdoe", Role: "user"}
	code, err := api.cliExchange.put(response)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"code": code})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/cli/exchange", bytes.NewReader(body))

	api.cliExchangeHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var got model.LoginResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, response, got)
}

func TestCLIExchangeHandler_MissingCode_Returns400(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil)
	body, _ := json.Marshal(map[string]string{"code": ""})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/cli/exchange", bytes.NewReader(body))

	api.cliExchangeHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCLIExchangeHandler_UnknownCode_Returns410(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil)
	body, _ := json.Marshal(map[string]string{"code": "unknown"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/cli/exchange", bytes.NewReader(body))

	api.cliExchangeHandler(w, r)

	assert.Equal(t, http.StatusGone, w.Code)
}
```

Now extend `api/oidc_test.go`:

1. Update `newOIDCHAPI` to also initialize the exchange store, so every existing test in this file keeps working:

```go
func newOIDCHAPI(oidcSvc authServices.OIDCService, userSvc userServices.UserService, authSvc authServices.AuthenticationService) *API {
	a := &app.App{ServiceContainer: &oidcHTestContainer{oidcSvc: oidcSvc, userSvc: userSvc, authSvc: authSvc}}
	return &API{App: a, Logger: userTestLog(), cliExchange: newCLIExchangeStore()}
}
```

2. Add new test cases at the end of `api/oidc_test.go`:

```go
func TestOIDCLogin_InvalidCLIRedirectURI_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login?cli_redirect_uri=https://evil.example.com/callback", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	oidcSvc.AssertNotCalled(t, "AuthCodeURL", mock.Anything, mock.Anything)
}

func TestOIDCLogin_ValidCLIRedirectURI_SetsCookie(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("AuthCodeURL", mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("https://idp.example.com/authorize?state=x")
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login?cli_redirect_uri=http://127.0.0.1:54321/callback", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	var sawCLIRedirect bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "oidc_cli_redirect" {
			sawCLIRedirect = true
			assert.Equal(t, "http://127.0.0.1:54321/callback", ck.Value)
		}
	}
	assert.True(t, sawCLIRedirect, "oidc_cli_redirect cookie must be set")
}

func TestOIDCCallback_WithCLIRedirect_RedirectsWithExchangeCode(t *testing.T) {
	identity := &authServices.OIDCIdentity{Subject: "sub-1", PreferredUsername: "jdoe"}
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1").Return(identity, nil)

	userSvc := &mockUserServiceForOIDC{}
	user := &model.User{ID: uuid.New(), Username: "jdoe", Role: model.RoleUser}
	userSvc.On("FindOrCreateExternalUser", mock.Anything, mock.Anything).Return(user, nil)

	authSvc := &mockAuthServiceForOIDC{}
	authSvc.On("IssueSessionForUser", mock.Anything, user).Return(&authServices.AuthenticationResult{
		Token: "access-token", RefreshToken: "refresh-token", UserID: user.ID, Username: user.Username, Role: user.Role,
	}, nil)

	api := newOIDCHAPI(oidcSvc, userSvc, authSvc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_cli_redirect", Value: "http://127.0.0.1:54321/callback"})

	api.oidcCallbackHandler(w, r)

	require.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "http://127.0.0.1:54321/callback?code=")

	code := strings.TrimPrefix(location, "http://127.0.0.1:54321/callback?code=")
	got, ok := api.cliExchange.consume(code)
	require.True(t, ok)
	assert.Equal(t, "access-token", got.Token)
	assert.Equal(t, user.ID.String(), got.UserID)
}

func TestOIDCCallback_InvalidCLIRedirectCookie_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1").
		Return(&authServices.OIDCIdentity{Subject: "sub-1"}, nil)
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_cli_redirect", Value: "https://evil.example.com/callback"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

Add `"strings"` and `"github.com/stretchr/testify/require"` to `api/oidc_test.go`'s import block (both new, `require` is not currently imported there).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run 'TestValidateCLIRedirectURI|TestCLIExchangeStore|TestCLIExchangeHandler|TestOIDCLogin_InvalidCLIRedirectURI|TestOIDCLogin_ValidCLIRedirectURI|TestOIDCCallback_WithCLIRedirect|TestOIDCCallback_InvalidCLIRedirectCookie' -v`
Expected: FAIL to compile — `validateCLIRedirectURI`, `newCLIExchangeStore`, `api.cliExchange`, `api.cliExchangeHandler` undefined.

- [ ] **Step 3: Write the implementation**

Create `api/oidc_cli.go`:

```go
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"rocketvault/model"
)

const cliExchangeCodeTTL = 60 * time.Second

// validateCLIRedirectURI restricts cli_redirect_uri to
// http://127.0.0.1:<port> or http://localhost:<port>, with no other
// scheme or host accepted. This is the one new externally reachable input
// on the OIDC login route, so it is intentionally an allow-list.
// An empty raw value is treated as "no CLI redirect requested" and is not
// an error — that is the existing browser-login behavior.
func validateCLIRedirectURI(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid cli_redirect_uri")
	}
	if u.Scheme != "http" {
		return "", fmt.Errorf("cli_redirect_uri must use http")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" {
		return "", fmt.Errorf("cli_redirect_uri must target 127.0.0.1 or localhost")
	}
	if u.Port() == "" {
		return "", fmt.Errorf("cli_redirect_uri must include a port")
	}
	return raw, nil
}

// cliExchangeStore holds short-lived, single-use exchange codes that stand
// in for a LoginResponse during the CLI loopback flow, so the access/
// refresh token itself never appears in a URL. Pure in-memory — losing the
// map on server restart just means the user retries
// `rocketvault users login --oidc`.
type cliExchangeStore struct {
	mu      sync.Mutex
	entries map[string]cliExchangeEntry
}

type cliExchangeEntry struct {
	response  model.LoginResponse
	expiresAt time.Time
}

func newCLIExchangeStore() *cliExchangeStore {
	return &cliExchangeStore{entries: make(map[string]cliExchangeEntry)}
}

// put stores response under a newly generated code and returns the code.
func (s *cliExchangeStore) put(response model.LoginResponse) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[code] = cliExchangeEntry{response: response, expiresAt: time.Now().Add(cliExchangeCodeTTL)}
	return code, nil
}

// consume returns and deletes the entry for code — single use. The second
// return value is false for an unknown, expired, or already-consumed code.
func (s *cliExchangeStore) consume(code string) (model.LoginResponse, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[code]
	if !ok {
		return model.LoginResponse{}, false
	}
	delete(s.entries, code)

	if time.Now().After(entry.expiresAt) {
		return model.LoginResponse{}, false
	}
	return entry.response, true
}

// cliExchangeRequest is the POST /oidc/cli/exchange request body.
type cliExchangeRequest struct {
	Code string `json:"code"`
}

// cliExchangeHandler handles POST /oidc/cli/exchange: redeems a one-time
// code minted by oidcCallbackHandler for the LoginResponse it stands in for.
func (api *API) cliExchangeHandler(w http.ResponseWriter, r *http.Request) {
	var req cliExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	response, ok := api.cliExchange.consume(req.Code)
	if !ok {
		http.Error(w, "unknown or expired code", http.StatusGone)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response) //nolint:errcheck,gosec
}
```

Modify `api/api.go`: add the `cliExchange` field to the `API` struct (around line 46-53):

```go
type API struct {
	App            *app.App
	BaseRoutes     *Routes
	basePath       string
	rootRouter     *mux.Router
	Logger         *logging.Logger
	metricsEnabled bool
	cliExchange    *cliExchangeStore
}
```

Modify `api/oidc.go`:

```go
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

const (
	oidcStateCookie       = "oidc_state"
	oidcNonceCookie       = "oidc_nonce"
	oidcCLIRedirectCookie = "oidc_cli_redirect"
	oidcCookieMaxAge      = 5 * time.Minute
)

// InitOIDC registers the public OIDC login/callback routes, plus the CLI
// exchange endpoint, on the same unauthenticated router that already
// serves POST /oauth2/token.
//
// Routes:
//   - GET  /oidc/login       — redirects to the configured provider's authorization endpoint
//   - GET  /oidc/callback    — completes the authorization code flow and issues a session
//   - POST /oidc/cli/exchange — redeems a one-time code from the CLI loopback flow for a session
func (api *API) InitOIDC() {
	api.cliExchange = newCLIExchangeStore()
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/login", api.oidcLoginHandler).Methods("GET")
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/callback", api.oidcCallbackHandler).Methods("GET")
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/cli/exchange", api.cliExchangeHandler).Methods("POST")
	api.Logger.Infoln("OIDC login/callback/cli-exchange routes initialized")
}

// oidcLoginHandler redirects the caller to the configured OIDC provider's
// authorization endpoint, having first stashed a random state and nonce
// (and, for the CLI loopback flow, a validated cli_redirect_uri) in
// short-lived cookies for oidcCallbackHandler to verify.
func (api *API) oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	svc := api.App.ServiceContainer.GetOIDCService()
	if svc == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}

	cliRedirectURI, err := validateCLIRedirectURI(r.URL.Query().Get("cli_redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state, err := randomOIDCToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomOIDCToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	setOIDCCookie(w, oidcStateCookie, state)
	setOIDCCookie(w, oidcNonceCookie, nonce)
	if cliRedirectURI != "" {
		setOIDCCookie(w, oidcCLIRedirectCookie, cliRedirectURI)
	}

	http.Redirect(w, r, svc.AuthCodeURL(state, nonce), http.StatusFound)
}

// oidcCallbackHandler completes the authorization code flow: verifies
// state, exchanges the code, verifies the ID token (including nonce),
// finds or creates the corresponding local user, and issues a session
// exactly as POST /users/login does. If the login was started with a
// cli_redirect_uri, the session is handed off via a one-time exchange
// code instead of being returned directly (see api/oidc_cli.go).
func (api *API) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	svc := api.App.ServiceContainer.GetOIDCService()
	if svc == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		http.Error(w, "missing or expired oidc_state cookie", http.StatusBadRequest)
		return
	}
	nonceCookie, err := r.Cookie(oidcNonceCookie)
	if err != nil {
		http.Error(w, "missing or expired oidc_nonce cookie", http.StatusBadRequest)
		return
	}

	cliRedirectURI := ""
	if cliCookie, err := r.Cookie(oidcCLIRedirectCookie); err == nil {
		validated, err := validateCLIRedirectURI(cliCookie.Value)
		if err != nil {
			http.Error(w, "invalid cli redirect", http.StatusBadRequest)
			return
		}
		cliRedirectURI = validated
	}

	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code parameter", http.StatusBadRequest)
		return
	}

	identity, err := svc.HandleCallback(r.Context(), code, nonceCookie.Value)
	if err != nil {
		http.Error(w, "oidc callback failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	userSvc := api.App.ServiceContainer.GetUserService()
	if userSvc == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user, err := userSvc.FindOrCreateExternalUser(r.Context(), userServices.FindOrCreateExternalUserRequest{
		Provider:          model.AuthProviderOIDC,
		Subject:           identity.Subject,
		PreferredUsername: identity.PreferredUsername,
	})
	if err != nil {
		http.Error(w, "failed to resolve user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	authSvc := api.App.ServiceContainer.GetAuthenticationService()
	if authSvc == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result, err := authSvc.IssueSessionForUser(r.Context(), user)
	if err != nil {
		http.Error(w, "failed to issue session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	clearOIDCCookie(w, oidcStateCookie)
	clearOIDCCookie(w, oidcNonceCookie)
	clearOIDCCookie(w, oidcCLIRedirectCookie)

	response := model.LoginResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Role:         result.Role,
	}

	if cliRedirectURI != "" {
		exchangeCode, err := api.cliExchange.put(response)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, cliRedirectURI+"?code="+exchangeCode, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response) //nolint:errcheck,gosec
}

// randomOIDCToken returns a 32-byte, hex-encoded random token suitable for
// state/nonce values.
func randomOIDCToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func setOIDCCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(oidcCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearOIDCCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./api/... -run 'TestValidateCLIRedirectURI|TestCLIExchangeStore|TestCLIExchangeHandler|TestOIDCLogin|TestOIDCCallback' -v`
Expected: PASS (all cases, including the pre-existing `TestOIDCLogin_*`/`TestOIDCCallback_*` tests, which must still pass unchanged).

- [ ] **Step 5: Commit**

```bash
git add api/oidc_cli.go api/oidc.go api/api.go api/oidc_cli_test.go api/oidc_test.go
git commit -m "feat(api): relay OIDC login to a CLI loopback listener via one-time exchange code"
```

---

### Task 4: `persistentPreRun` session-cache fallback (`cmd/root.go`)

**Files:**
- Modify: `cmd/root.go`
- Test: Create `cmd/root_test.go`

**Interfaces:**
- Consumes: `common.SessionCache`, `common.SessionBaseDir`, `common.SaveSession`, `common.LoadSession`, `common.LoadCurrentSession` (Task 1); `authServices.AuthenticationService`, `authServices.AuthenticationResult`, `authServices.RefreshTokenResult` (existing); `cmd/testutils.MockAuthenticationService` (existing, for tests).
- Produces: `resolveAuthentication(cmd *cobra.Command, authSvc authServices.AuthenticationService) (*authServices.AuthenticationResult, error)` — used by `persistentPreRun` and directly testable.

- [ ] **Step 1: Write the failing tests**

Create `cmd/root_test.go`:

```go
package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	authServices "rocketvault/internal/services/auth"
)

func newAuthTestCmd(username, password, totpCode string) *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.Flags().String("username", "", "")
	c.Flags().String("password", "", "")
	c.Flags().String("totp-code", "", "")
	_ = c.Flags().Set("username", username)
	_ = c.Flags().Set("password", password)
	_ = c.Flags().Set("totp-code", totpCode)
	c.SetContext(context.Background())
	return c
}

func TestResolveAuthentication_UsernamePassword_Success(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "admin123", "123456").
		Return(&authServices.AuthenticationResult{
			Token: "access-tok", RefreshToken: "refresh-tok", UserID: userID, Username: "admin", Role: "admin",
		}, nil)

	c := newAuthTestCmd("admin", "admin123", "123456")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "access-tok", result.Token)

	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "access-tok", cached.Token)
	assert.True(t, cached.ExpiresAt.After(time.Now()))
}

func TestResolveAuthentication_UsernamePassword_AuthFails_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, assert.AnError)

	c := newAuthTestCmd("admin", "wrong", "123456")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached, "a failed login must not cache a session")
}

func TestResolveAuthentication_UsernameOnly_LoadsNamedCachedSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))

	c := newAuthTestCmd("user14", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
	tc.MockAuthService.AssertNotCalled(t, "AuthenticateUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestResolveAuthentication_NoFlags_UsesCurrentPointer(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
}

func TestResolveAuthentication_NoFlagsNoCache_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)

	c := newAuthTestCmd("", "", "")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
}

func TestResolveAuthentication_ExpiredCache_RefreshesTransparently(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "old-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(-time.Minute),
	}))
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(&authServices.RefreshTokenResult{
			Token: "new-tok", RefreshToken: "new-refresh", UserID: userID, Username: "user14", Role: "user",
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "new-tok", result.Token)

	cached, err := common.LoadSession("user14")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "new-tok", cached.Token, "the refreshed token must be re-cached")
}

func TestResolveAuthentication_ExpiredCacheRefreshFails_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "old-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(-time.Minute),
	}))
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(nil, assert.AnError)

	c := newAuthTestCmd("", "", "")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/... -run TestResolveAuthentication -v`
Expected: FAIL to compile — `resolveAuthentication` undefined.

- [ ] **Step 3: Write the implementation**

In `cmd/root.go`, add to the import block:

```go
import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/db"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)
```

Add two entries to the `systemCmds` map inside `persistentPreRun` (existing code, `cmd/root.go` around line 140-149) — `login` and `logout` bootstrap or clear the very session `persistentPreRun` would otherwise demand, so they cannot be gated behind it:

```go
	systemCmds := map[string]bool{
		"health":            true,
		"serve":             true, // Server startup doesn't require prior authentication
		"admin":             true, // Allow admin registration without prior authentication
		"migrate":           true, // Database migrations don't require authentication
		"migrate:status":    true, // Migration status check
		"migrate:to":        true, // Targeted migrations
		"migrate:create":    true, // Migration file creation
		"roles":             true, // Lists built-in vault roles; pure client-side, no auth needed
		"preview-migration": true, // Reads ownership to plan role assignments; no auth, no writes
		"login":             true, // Bootstraps a session (password or --oidc); cannot itself require one
		"logout":            true, // Clears a cached session; must work even if that session is broken
	}
```

Add `resolveAuthentication` as a new function in `cmd/root.go` (near `persistentPreRun`):

```go
// resolveAuthentication determines the CLI caller's identity for a command
// that requires authentication. It tries, in order:
//  1. --username + --password (+ --totp-code): fresh password/TOTP login,
//     cached to disk on success.
//  2. --username alone (no --password): load that user's cached session.
//  3. no flags at all: load whichever session ~/.rocketvault/sessions/current
//     currently points at.
// A cached session past its ExpiresAt is refreshed transparently via its
// refresh token (and the cache updated) before being returned.
func resolveAuthentication(cmd *cobra.Command, authSvc authServices.AuthenticationService) (*authServices.AuthenticationResult, error) {
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	totpCode, _ := cmd.Flags().GetString("totp-code")

	if username != "" && password != "" {
		result, err := authSvc.AuthenticateUser(cmd.Context(), username, password, totpCode)
		if err != nil {
			return nil, err
		}
		if saveErr := common.SaveSession(&common.SessionCache{
			Token:        result.Token,
			RefreshToken: result.RefreshToken,
			UserID:       result.UserID,
			Username:     result.Username,
			Role:         result.Role,
			ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
		}); saveErr != nil {
			logrus.WithError(saveErr).Warn("failed to cache CLI session")
		}
		return result, nil
	}

	var cached *common.SessionCache
	var err error
	if username != "" {
		cached, err = common.LoadSession(username)
	} else {
		cached, err = common.LoadCurrentSession()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read cached session: %w", err)
	}
	if cached == nil {
		return nil, errors.New("no credentials provided and no cached session found")
	}

	if time.Now().Before(cached.ExpiresAt) {
		return &authServices.AuthenticationResult{
			Token:        cached.Token,
			RefreshToken: cached.RefreshToken,
			UserID:       cached.UserID,
			Username:     cached.Username,
			Role:         cached.Role,
		}, nil
	}

	refreshed, err := authSvc.RefreshAccessToken(cmd.Context(), cached.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("cached session expired and refresh failed: %w", err)
	}

	if saveErr := common.SaveSession(&common.SessionCache{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Role:         refreshed.Role,
		ExpiresAt:    refreshed.ExpiresAt,
	}); saveErr != nil {
		logrus.WithError(saveErr).Warn("failed to cache refreshed CLI session")
	}

	return &authServices.AuthenticationResult{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Role:         refreshed.Role,
	}, nil
}
```

Replace the credential block inside `persistentPreRun` (existing code, currently):

```go
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	totpCode, _ := cmd.Flags().GetString("totp-code")

	if username == "" || password == "" {
		log.LogAuditError("", "secrets", "failed", "Username and password are required for authentication", errors.New("missing credentials"))
		cmd.PrintErrln("Error: Username and password are required for authentication")
		return errors.New("authentication failed")
	}

	// Use authentication service for login
	authService := serviceContainer.GetAuthenticationService()
	authResult, err := authService.AuthenticateUser(ctx, username, password, totpCode)
	if err != nil {
		log.LogAuditError("", "secrets", "failed", "Authentication failed", err)
		cmd.PrintErrln("Error: Authentication failed -", err.Error())
		return errors.New("authentication failed")
	}
```

with:

```go
	authService := serviceContainer.GetAuthenticationService()
	authResult, err := resolveAuthentication(cmd, authService)
	if err != nil {
		log.LogAuditError("", "secrets", "failed", "Authentication failed", err)
		cmd.PrintErrln("Error: Authentication failed -", err.Error())
		cmd.PrintErrln("Run 'rocketvault users login' or 'rocketvault users login --oidc' first, or pass --username/--password/--totp-code.")
		return errors.New("authentication failed")
	}
```

(Everything after this block — building `claims`, setting `common.TokenKey`/`common.UserIDKey`/`common.ClaimsKey` on `ctx` — is unchanged; it already only reads fields off `authResult` that `resolveAuthentication` still populates identically.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/... -run TestResolveAuthentication -v`
Expected: PASS (all 6 tests)

Run also: `go build ./...` (root.go must still compile cleanly with the new imports and the `systemCmds` map).

- [ ] **Step 5: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -m "feat(cmd): fall back to a cached CLI session when no credentials are given"
```

---

### Task 5: `rocketvault users login --oidc` (`cmd/users/login.go`, new `cmd/users/login_oidc.go`)

**Files:**
- Modify: `cmd/users/login.go`
- Create: `cmd/users/login_oidc.go`
- Test: Create `cmd/users/login_password_test.go`, `cmd/users/login_oidc_test.go`

**Interfaces:**
- Consumes: `common.SessionCache`, `common.SaveSession`, `common.OpenBrowser` (Tasks 1-2); `authServices.AuthenticationService` (existing); server routes `GET /oidc/login?cli_redirect_uri=`, `POST /oidc/cli/exchange` (Task 3).
- Produces: `performPasswordLogin(ctx, authSvc, username, password, totpCode string) (*common.SessionCache, error)`, `startLoopbackListener() (redirectURI string, wait func(timeout time.Duration) (string, error), err error)`, `exchangeOIDCCode(ctx, baseURL, code string) (*common.SessionCache, error)`, `runOIDCLogin(cmd *cobra.Command, serviceContainer container.ServiceContainerInterface) error`, `--oidc` bool flag on `loginCmd`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/users/login_password_test.go`:

```go
package users

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	authServices "rocketvault/internal/services/auth"
)

func TestPerformPasswordLogin_Success_SavesSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "admin123", "123456").
		Return(&authServices.AuthenticationResult{
			Token: "access-tok", RefreshToken: "refresh-tok", UserID: userID, Username: "admin", Role: "admin",
		}, nil)

	session, err := performPasswordLogin(context.Background(), tc.MockAuthService, "admin", "admin123", "123456")

	require.NoError(t, err)
	assert.Equal(t, "access-tok", session.Token)

	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "access-tok", cached.Token)
	assert.True(t, cached.ExpiresAt.After(time.Now()))
}

func TestPerformPasswordLogin_AuthFails_NoSessionSaved(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, assert.AnError)

	_, err := performPasswordLogin(context.Background(), tc.MockAuthService, "admin", "wrong", "123456")

	assert.Error(t, err)
	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached)
}
```

Create `cmd/users/login_oidc_test.go`:

```go
package users

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartLoopbackListener_ReceivesCode(t *testing.T) {
	redirectURI, wait, err := startLoopbackListener()
	require.NoError(t, err)

	go func() {
		resp, getErr := http.Get(redirectURI + "?code=abc123") //nolint:noctx
		if getErr == nil {
			resp.Body.Close()
		}
	}()

	code, err := wait(2 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "abc123", code)
}

func TestStartLoopbackListener_MissingCode_ReturnsError(t *testing.T) {
	redirectURI, wait, err := startLoopbackListener()
	require.NoError(t, err)

	go func() {
		resp, getErr := http.Get(redirectURI) //nolint:noctx
		if getErr == nil {
			resp.Body.Close()
		}
	}()

	_, err = wait(2 * time.Second)
	assert.Error(t, err)
}

func TestStartLoopbackListener_Timeout(t *testing.T) {
	_, wait, err := startLoopbackListener()
	require.NoError(t, err)

	_, err = wait(50 * time.Millisecond)
	assert.Error(t, err)
}

func TestExchangeOIDCCode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/oidc/cli/exchange", r.URL.Path)
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "code123", body["code"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"token": "access-tok", "refresh_token": "refresh-tok",
			"user_id": "11111111-1111-1111-1111-111111111111",
			"username": "user14@exchange4all.local", "role": "user",
		})
	}))
	defer server.Close()

	session, err := exchangeOIDCCode(context.Background(), server.URL, "code123")

	require.NoError(t, err)
	assert.Equal(t, "access-tok", session.Token)
	assert.Equal(t, "user14@exchange4all.local", session.Username)
	assert.True(t, session.ExpiresAt.After(time.Now()))
}

func TestExchangeOIDCCode_NonOKStatus_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer server.Close()

	_, err := exchangeOIDCCode(context.Background(), server.URL, "expired-code")
	assert.Error(t, err)
}

func TestExchangeOIDCCode_InvalidUserID_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"user_id": "not-a-uuid"}) //nolint:errcheck
	}))
	defer server.Close()

	_, err := exchangeOIDCCode(context.Background(), server.URL, "code123")
	assert.Error(t, err)
}
```

Add one flag-registration test at the bottom of `cmd/users/login_password_test.go` (this is the only test in the package allowed to call `InitUsersLogin`, since it mutates the package-level `loginCmd` singleton's flag set, which panics if registered twice in one test binary run):

```go
func TestInitUsersLogin_RegistersOIDCFlag(t *testing.T) {
	parent := &cobra.Command{Use: "users"}
	InitUsersLogin(parent)

	flag := loginCmd.Flags().Lookup("oidc")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}
```

(add `"github.com/spf13/cobra"` to that file's imports)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/users/... -run 'TestPerformPasswordLogin|TestStartLoopbackListener|TestExchangeOIDCCode|TestInitUsersLogin_RegistersOIDCFlag' -v`
Expected: FAIL to compile — `performPasswordLogin`, `startLoopbackListener`, `exchangeOIDCCode`, the `oidc` flag undefined.

- [ ] **Step 3: Write the implementation**

Replace `cmd/users/login.go` in full:

```go
/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package users

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	authServices "rocketvault/internal/services/auth"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate a user",
	Long: `Authenticate a user with their username, password, and TOTP code (local
users), or via the configured OIDC provider through a browser (--oidc).
Either way, the resulting session is cached to disk so subsequent commands
don't need credentials repeated.`,
	Example: `  # Log in with a local username/password/TOTP account
  rocketvault users login \
    --username admin --password admin123 --totp-code <code>

  # Log in via the configured OIDC provider (opens a browser)
  rocketvault users login --oidc`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		logger := serviceContainer.GetLogger()

		oidc, _ := cmd.Flags().GetBool("oidc")
		if oidc {
			return runOIDCLogin(cmd, serviceContainer)
		}

		username := viper.GetString("username")
		password := viper.GetString("password")
		totpCode := viper.GetString("totp-code")

		if username == "" || password == "" || totpCode == "" {
			logger.LogAuditError(uuid.Nil.String(), "login", "failed", "username, password, and totp-code are required", nil)
			return fmt.Errorf("username, password, and totp-code are required")
		}

		session, err := performPasswordLogin(ctx, serviceContainer.GetAuthenticationService(), username, password, totpCode)
		if err != nil {
			logger.LogAuditError(uuid.Nil.String(), "login", "failed", fmt.Sprintf("failed to login: %s", err), err)
			return fmt.Errorf("failed to login: %w", err)
		}

		logger.LogAuditInfo(session.UserID.String(), "login", "success", fmt.Sprintf("user logged in: %s", username))
		fmt.Printf("Login successful, JWT token: %s\n", session.Token)
		return nil
	},
}

// performPasswordLogin authenticates via username/password/TOTP and caches
// the resulting session to disk. Extracted from loginCmd's RunE so it is
// unit testable without driving cobra/viper flag parsing.
func performPasswordLogin(ctx context.Context, authSvc authServices.AuthenticationService, username, password, totpCode string) (*common.SessionCache, error) {
	result, err := authSvc.AuthenticateUser(ctx, username, password, totpCode)
	if err != nil {
		return nil, err
	}

	session := &common.SessionCache{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID,
		Username:     result.Username,
		Role:         result.Role,
		ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
	}
	if err := common.SaveSession(session); err != nil {
		return nil, fmt.Errorf("authenticated but failed to cache session: %w", err)
	}
	return session, nil
}

// InitUsersLogin initializes the login command for user-related operations.
// It adds the login command to the users command and sets up flags for
// authentication. The command does not require prior authentication.
//
// Parameters:
// - usersCmd: The parent Cobra command to which the login command will be added.
// Returns: The updated parent Cobra command with the login subcommand attached.
func InitUsersLogin(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(loginCmd)

	loginCmd.Flags().String("username", "", "Username for authentication")
	loginCmd.Flags().String("password", "", "Password for authentication")
	loginCmd.Flags().String("totp-code", "", "TOTP code for MFA")
	loginCmd.Flags().Bool("oidc", false, "Log in via the configured OIDC provider using a browser, instead of username/password/TOTP")
	viper.BindPFlag("username", loginCmd.Flags().Lookup("username"))   //nolint:errcheck,gosec
	viper.BindPFlag("password", loginCmd.Flags().Lookup("password"))   //nolint:errcheck,gosec
	viper.BindPFlag("totp-code", loginCmd.Flags().Lookup("totp-code")) //nolint:errcheck,gosec

	return usersCmd
}
```

Create `cmd/users/login_oidc.go`:

```go
/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package users

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
)

const (
	oidcLoginTimeout = 5 * time.Minute
	oidcBasePath     = "/api/v1"
)

// oidcExchangeResponse mirrors model.LoginResponse's JSON shape, returned
// by POST /oidc/cli/exchange. Duplicated rather than importing the api
// package (an HTTP server package) into the CLI's dependency graph for one
// struct shape.
type oidcExchangeResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
}

// startLoopbackListener starts an HTTP server on 127.0.0.1:<random port>
// that waits for exactly one GET /callback?code=... request. It returns
// the listener's redirect URI and a function that blocks until the
// callback arrives (or the given timeout elapses), shutting the server
// down either way.
func startLoopbackListener() (redirectURI string, wait func(timeout time.Duration) (string, error), err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("failed to start local callback listener: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	handler := http.NewServeMux()
	handler.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Login failed: missing code parameter.")
			errCh <- fmt.Errorf("callback missing code parameter")
			return
		}
		fmt.Fprint(w, "Login successful — you can close this tab.")
		codeCh <- code
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener) //nolint:errcheck

	wait = func(timeout time.Duration) (string, error) {
		defer server.Close() //nolint:errcheck
		select {
		case code := <-codeCh:
			return code, nil
		case err := <-errCh:
			return "", err
		case <-time.After(timeout):
			return "", fmt.Errorf("timed out waiting for OIDC login to complete in the browser")
		}
	}
	return redirectURI, wait, nil
}

// exchangeOIDCCode redeems a one-time code from the loopback callback for a
// full session via POST {baseURL}/api/v1/oidc/cli/exchange.
func exchangeOIDCCode(ctx context.Context, baseURL, code string) (*common.SessionCache, error) {
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+oidcBasePath+"/oidc/cli/exchange", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exchange endpoint returned %s", resp.Status)
	}

	var exchanged oidcExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&exchanged); err != nil {
		return nil, fmt.Errorf("failed to decode exchange response: %w", err)
	}

	userID, err := uuid.Parse(exchanged.UserID)
	if err != nil {
		return nil, fmt.Errorf("exchange response has an invalid user_id: %w", err)
	}

	return &common.SessionCache{
		Token:        exchanged.Token,
		RefreshToken: exchanged.RefreshToken,
		UserID:       userID,
		Username:     exchanged.Username,
		Role:         exchanged.Role,
		ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
	}, nil
}

// runOIDCLogin performs the browser-based OIDC login flow: starts a
// loopback HTTP listener, opens the system browser to the server's
// /oidc/login with a cli_redirect_uri pointing back at that listener,
// waits for the resulting one-time exchange code, redeems it for a
// session, and caches the session to disk.
func runOIDCLogin(cmd *cobra.Command, serviceContainer container.ServiceContainerInterface) error {
	baseURL := viper.GetString("frontend.public_api_url")
	if baseURL == "" {
		return fmt.Errorf("frontend.public_api_url is not configured — required for OIDC CLI login")
	}

	redirectURI, wait, err := startLoopbackListener()
	if err != nil {
		return err
	}

	loginURL := fmt.Sprintf("%s%s/oidc/login?cli_redirect_uri=%s", baseURL, oidcBasePath, redirectURI)
	if err := common.OpenBrowser(loginURL); err != nil {
		fmt.Printf("Could not open a browser automatically. Open this URL to log in:\n%s\n", loginURL)
	} else {
		fmt.Println("Opening browser to complete OIDC login...")
	}

	code, err := wait(oidcLoginTimeout)
	if err != nil {
		return err
	}

	session, err := exchangeOIDCCode(cmd.Context(), baseURL, code)
	if err != nil {
		return fmt.Errorf("login exchange failed, please try again: %w", err)
	}

	if err := common.SaveSession(session); err != nil {
		serviceContainer.GetLogger().WithError(err).Warn("failed to cache CLI session")
	}

	serviceContainer.GetLogger().LogAuditInfo(session.UserID.String(), "login", "success",
		fmt.Sprintf("user logged in via OIDC: %s", session.Username))
	fmt.Printf("Login successful as %s\n", session.Username)
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/users/... -run 'TestPerformPasswordLogin|TestStartLoopbackListener|TestExchangeOIDCCode|TestInitUsersLogin_RegistersOIDCFlag' -v`
Expected: PASS (all cases)

Run also: `go build ./...`

- [ ] **Step 5: Commit**

```bash
git add cmd/users/login.go cmd/users/login_oidc.go cmd/users/login_password_test.go cmd/users/login_oidc_test.go
git commit -m "feat(cmd): add 'rocketvault users login --oidc' browser loopback flow"
```

---

### Task 6: `rocketvault users logout` (`cmd/users/logout.go`)

**Files:**
- Create: `cmd/users/logout.go`
- Modify: `cmd/users.go` (register the command)
- Test: Create `cmd/users/logout_test.go`

**Interfaces:**
- Consumes: `common.LoadCurrentSession`, `common.DeleteSession` (Task 1).
- Produces: `runLogout(username string) error`, `rocketvault users logout` command with a `--username` flag bound to viper key `logout-username`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/users/logout_test.go`:

```go
package users

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

func TestRunLogout_ExplicitUsername_DeletesThatSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	require.NoError(t, common.SaveSession(&common.SessionCache{Username: "admin", Token: "tok", ExpiresAt: time.Now().Add(time.Hour)}))

	require.NoError(t, runLogout("admin"))

	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached)
}

func TestRunLogout_NoUsername_DeletesCurrentSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	require.NoError(t, common.SaveSession(&common.SessionCache{Username: "user14", Token: "tok", ExpiresAt: time.Now().Add(time.Hour)}))

	require.NoError(t, runLogout(""))

	cached, err := common.LoadSession("user14")
	require.NoError(t, err)
	assert.Nil(t, cached)
}

func TestRunLogout_NoUsernameNoCurrentSession_NoError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()

	assert.NoError(t, runLogout(""))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/users/... -run TestRunLogout -v`
Expected: FAIL to compile — `runLogout` undefined.

- [ ] **Step 3: Write the implementation**

Create `cmd/users/logout.go`:

```go
/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package users

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
)

// logoutCmd represents the logout command.
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear a cached CLI session",
	Long: `Removes the session cache written by 'rocketvault users login' (with or
without --oidc). This does not revoke the session server-side — the
underlying JWT simply expires naturally. Without --username, clears
whichever session is currently active (the one commands use when run
without --username/--password).`,
	Example: `  # Log out of whichever session is currently active
  rocketvault users logout

  # Log out a specific cached user without affecting others
  rocketvault users logout --username user14@exchange4all.local`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLogout(viper.GetString("logout-username"))
	},
}

// runLogout resolves which cached session to remove — an explicit
// username, or whichever the current-session pointer references — and
// deletes it. Extracted from logoutCmd's RunE so it is unit testable
// without driving cobra/viper flag parsing.
func runLogout(username string) error {
	if username == "" {
		current, err := common.LoadCurrentSession()
		if err != nil {
			return fmt.Errorf("failed to read current session: %w", err)
		}
		if current == nil {
			fmt.Println("No cached session to log out of.")
			return nil
		}
		username = current.Username
	}

	if err := common.DeleteSession(username); err != nil {
		return fmt.Errorf("failed to log out: %w", err)
	}

	fmt.Printf("Logged out %s.\n", username)
	return nil
}

// InitUsersLogout registers the logout command under usersCmd.
func InitUsersLogout(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(logoutCmd)

	logoutCmd.Flags().String("username", "", "Log out this specific cached user instead of the current one")
	viper.BindPFlag("logout-username", logoutCmd.Flags().Lookup("username")) //nolint:errcheck,gosec

	return usersCmd
}
```

Modify `cmd/users.go`: add `users.InitUsersLogout(usersCmd)` to `init()`, right after the existing `users.InitUsersLogin(usersCmd)` line, and mention `logout` in the command group's `Long` help text:

```go
func init() {
	rootCmd.AddCommand(usersCmd)

	users.InitUsersCreate(usersCmd)
	users.InitUsersDelete(usersCmd)
	users.InitUsersGet(usersCmd)
	users.InitUsersUpdate(usersCmd)
	users.InitUsersList(usersCmd)
	users.InitUsersRegisterAdmin(usersCmd)
	users.InitUsersLogin(usersCmd)
	users.InitUsersLogout(usersCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// usersCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// usersCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/users/... -run TestRunLogout -v`
Expected: PASS (all 3 tests)

Run also: `go build ./...`

- [ ] **Step 5: Commit**

```bash
git add cmd/users/logout.go cmd/users/logout_test.go cmd/users.go
git commit -m "feat(cmd): add 'rocketvault users logout'"
```

---

### Task 7: Full verification, manual end-to-end check, and doc touch-ups

**Files:**
- Modify: `CLAUDE.md` (CLI Authorization section)
- No new source files — this task is verification plus a small doc update.

- [ ] **Step 1: Full build and static checks**

Run, in order, and fix anything that fails before proceeding:

```bash
go build ./...
go vet ./...
gofmt -l $(git diff --name-only --diff-filter=ACM -- '*.go') $(git diff --cached --name-only --diff-filter=ACM -- '*.go')
```
Expected: no build errors, no vet warnings, `gofmt -l` prints nothing (no unformatted files).

- [ ] **Step 2: Full test suite**

Run: `go test ./...`
Expected: PASS, including every test added in Tasks 1-6 and every pre-existing test (in particular `api/oidc_test.go`'s original `TestOIDCLogin_*`/`TestOIDCCallback_*` cases, which must still pass unchanged after Task 3's edits).

- [ ] **Step 3: Manual end-to-end verification against the configured test issuer**

This repo's `.rocketvault.yaml` already points `oidc.issuer_url` at `https://exchange4all.local:8443/` with a real `client_id`/`ca_cert_path`. With `rocketvault serve` running against this config:

```bash
./rocketvault users login --oidc
```

Confirm: a browser opens (or the URL is printed), login at the provider succeeds, the terminal prints `Login successful as <username>`, and `~/.rocketvault/sessions/<username>.json` exists with `0600` permissions. Then confirm the original failing scenario from the bug report now works with zero extra flags:

```bash
./rocketvault secrets list
```

Also verify:
- `rocketvault users login --username admin --password admin123 --totp-code <code>` still works and also populates `~/.rocketvault/sessions/admin.json`.
- `rocketvault secrets list --username admin` (no `--password`) uses the cached admin session.
- `rocketvault users logout` clears the current session; a subsequent `rocketvault secrets list` with no flags fails with the "no credentials provided and no cached session found" message.

- [ ] **Step 4: Update CLAUDE.md**

In the "### CLI Authorization" section of `CLAUDE.md`, add a short paragraph after the existing bullet list documenting the new session cache and `--oidc` login, e.g.:

```markdown
CLI commands no longer require `--username`/`--password`/`--totp-code` on every invocation. `rocketvault users login` (password/TOTP) or `rocketvault users login --oidc` (browser-based, for OIDC-provisioned users who have no local password) cache the resulting session under `~/.rocketvault/sessions/<username>.json`; a bare command with no credential flags reuses whichever session `~/.rocketvault/sessions/current` points at, refreshing it transparently via its refresh token if expired. `rocketvault users logout` clears the cache (client-side only — no server-side revocation). See `docs/superpowers/specs/2026-08-15-cli-oidc-login-design.md` for the full design.
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document CLI session cache and OIDC login in CLAUDE.md"
```
