# MCP Interactive Login — Part 2: Client.Login, Config Flag, Server Fields

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Before starting:** create one Task (via the TaskCreate tool) per task
> below. Set a task `in_progress` before starting it and `completed`
> immediately after its commit step. Run TaskList at any checkpoint to see
> where this plan stands.

**Goal:** Add the HTTP login call, the `mcp.allow_interactive_login` config flag, and the `mcpserver.Server`/`Deps` fields the login tool will need — still with no tool and no `cmd/mcp.go` wiring.

**Architecture:** `Client.Login` is a new unauthenticated method on the existing `vaultapi.Client`, following the same pattern `SessionSource.refresh` already uses for `/users/refresh`. The config flag follows the exact pattern of the three existing `allow_*` flags. The `Server`/`Deps` additions are inert plumbing — real fields, real accessor, but nothing calls `.Set` on the identity yet.

**Tech Stack:** Go, `testify/require`, `net/http/httptest`, Viper.

**Spec:** `docs/superpowers/specs/2026-08-25-mcp-interactive-login-design.md`

## Global Constraints

- Depends on Part 1 (`SwappableSource`, `NewSessionSourceFromCache`, the `load` field on `SessionSource`) — do not start this plan until Part 1's tests pass.
- No `login` tool and no `cmd/mcp.go` changes in this plan — that's Part 3 and Part 4.
- Error messages from `Client.Login` never echo the HTTP response body (it can carry request-derived text) — same rule `SessionSource.refresh` already follows.

## Plan Chain

**This is Part 2 of 5.** Previous: `2026-08-25-mcp-interactive-login-part1-vaultapi-primitives.md`. Next plan: `docs/superpowers/plans/2026-08-25-mcp-interactive-login-part3-mcpserver-login-tool.md`

---

### Task 1: Client.Login

**Files:**
- Create: `internal/vaultapi/login.go`
- Test: `internal/vaultapi/login_test.go`

**Interfaces:**
- Consumes: `Client.baseURL`, `Client.http` (existing unexported fields, `internal/vaultapi/client.go`), `NewSessionSourceFromCache` (Part 1, Task 3).
- Produces: `LoginIdentity` struct `{Username string; Roles []string; ExpiresAt time.Time}`; `(*Client).Login(ctx, username, password, totpCode string, expiry time.Duration) (TokenSource, LoginIdentity, error)`. Part 3's `login` tool handler calls this.

- [ ] **Step 1: Write the failing tests**

```go
// internal/vaultapi/login_test.go
package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func loginServer(t *testing.T, respond func(w http.ResponseWriter, body map[string]string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		respond(w, body)
	}))
}

func newTestClient(t *testing.T, baseURL string, httpClient *http.Client) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURL: baseURL, HTTPClient: httpClient,
		Tokens: stubTokenSource{token: "unused"}, DisableRetry: true,
	})
	require.NoError(t, err)
	return c
}

func TestClientLogin_Success(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, body map[string]string) {
		require.Equal(t, "admin", body["username"])
		require.Equal(t, "hunter2", body["password"])
		require.Equal(t, "123456", body["totp_code"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"access-1","refresh_token":"refresh-1","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	source, identity, err := c.Login(context.Background(), "admin", "hunter2", "123456", time.Hour)
	require.NoError(t, err)
	require.Equal(t, "admin", identity.Username)
	require.Equal(t, []string{"admin"}, identity.Roles)
	require.WithinDuration(t, time.Now().Add(time.Hour), identity.ExpiresAt, time.Second)

	tok, err := source.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-1", tok)
}

func TestClientLogin_RejectionDoesNotEchoBody(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, _ map[string]string) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"authentication failed"}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "wrong", "000000", time.Hour)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "authentication failed")
	require.Contains(t, err.Error(), "401")
}

func TestClientLogin_MissingTokenInResponseIsAnError(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, _ map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"admin","roles":["admin"]}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "hunter2", "123456", time.Hour)
	require.ErrorContains(t, err, "missing a token")
}

func TestClientLogin_SendsNoAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"access-1","refresh_token":"refresh-1","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "hunter2", "123456", time.Hour)
	require.NoError(t, err)
	require.Empty(t, gotAuth, "login is unauthenticated -- it must not send whatever c.tokens holds")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vaultapi/... -run TestClientLogin -v`
Expected: FAIL with `c.Login undefined (type *Client has no field or method Login)`.

- [ ] **Step 3: Write the implementation**

```go
// internal/vaultapi/login.go
package vaultapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
)

// LoginIdentity describes who Login authenticated as. It never carries the
// token itself -- a caller that needs to act as this identity uses the
// TokenSource Login also returns.
type LoginIdentity struct {
	Username  string
	Roles     []string
	ExpiresAt time.Time
}

// Login exchanges a username, password and TOTP code for a session, and
// returns a TokenSource seeded with it plus display information.
//
// Unlike every other Client method, it sends no bearer token: the endpoint
// is unauthenticated by design, the same way the refresh endpoint
// SessionSource.refresh calls is. expiry is the access-token lifetime
// (jwt.expiry), used to compute ExpiresAt the same way the CLI's own login
// command does in cmd/root.go -- the login response itself carries no
// expiry.
func (c *Client) Login(ctx context.Context, username, password, totpCode string, expiry time.Duration) (TokenSource, LoginIdentity, error) {
	payload, err := json.Marshal(map[string]string{
		"username": username, "password": password, "totp_code": totpCode,
	})
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: encode login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/users/login", bytes.NewReader(payload))
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: login request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// The body is not surfaced: a generic message avoids leaking
		// whether the username exists or which factor was wrong.
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: login failed (HTTP %d)", resp.StatusCode)
	}

	var decoded struct {
		Token        string   `json:"token"`
		RefreshToken string   `json:"refresh_token"`
		UserID       string   `json:"user_id"`
		Username     string   `json:"username"`
		Roles        []string `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: decode login response: %w", err)
	}
	if decoded.Token == "" || decoded.RefreshToken == "" {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: login response was missing a token")
	}

	// UserID is display-only here -- Token()/refresh() never use it -- so a
	// malformed value falls back to the zero UUID rather than failing login.
	userID, _ := uuid.Parse(decoded.UserID)
	session := &common.SessionCache{
		Token:        decoded.Token,
		RefreshToken: decoded.RefreshToken,
		UserID:       userID,
		Username:     decoded.Username,
		Roles:        decoded.Roles,
		ExpiresAt:    time.Now().Add(expiry),
	}

	source, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:    c.baseURL,
		HTTPClient: c.http,
	}, session)
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: seed session from login: %w", err)
	}

	return source, LoginIdentity{
		Username:  session.Username,
		Roles:     session.Roles,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/vaultapi/... -v -race`
Expected: PASS for the whole package, including every Part 1 test plus the four new `TestClientLogin_*` tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/login.go internal/vaultapi/login_test.go
git commit -m "$(cat <<'EOF'
feat(vaultapi): add Client.Login

Unauthenticated POST to /users/login, seeding a SessionSource via
NewSessionSourceFromCache on success. Nothing calls this yet.
EOF
)"
```

---

### Task 2: mcp.allow_interactive_login config flag

**Files:**
- Modify: `config/config.go` (`MCPConfig` struct, `LoadMCPConfig`)
- Modify: `.rocketvault.yaml.example` (`mcp:` section)
- Test: `config/mcp_config_test.go` (append)

**Interfaces:**
- Produces: `MCPConfig.AllowInteractiveLogin bool` (`mapstructure:"allow_interactive_login"`, default `false`). Part 3's `TierLogin` gating reads this field.

- [ ] **Step 1: Write the failing tests**

Append to `config/mcp_config_test.go`:

```go
func TestLoadMCPConfig_AllowInteractiveLoginDefaultsFalse(t *testing.T) {
	resetViper(t)
	cfg, err := LoadMCPConfig()
	require.NoError(t, err)
	require.False(t, cfg.AllowInteractiveLogin, "interactive login must be off by default")
}

func TestLoadMCPConfig_ReadsAllowInteractiveLogin(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.allow_interactive_login", true)
	cfg, err := LoadMCPConfig()
	require.NoError(t, err)
	require.True(t, cfg.AllowInteractiveLogin)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/... -run TestLoadMCPConfig_.*InteractiveLogin -v`
Expected: FAIL with `cfg.AllowInteractiveLogin undefined`.

- [ ] **Step 3: Add the field and the loader line**

In `config/config.go`, add to `MCPConfig` (next to the other three `Allow*` flags):

```go
	AllowWrite            bool `mapstructure:"allow_write"`
	AllowDestructive      bool `mapstructure:"allow_destructive"`
	AllowCrypto           bool `mapstructure:"allow_crypto"`
	AllowSecretValues     bool `mapstructure:"allow_secret_values"`
	// AllowInteractiveLogin gates the login tool, which lets a chat message
	// re-authenticate this server's identity at runtime. It is meaningless
	// (and never registered, see mcpserver.TierLogin) under a service
	// account -- a service account's whole point is that the agent cannot
	// act as a human.
	AllowInteractiveLogin bool `mapstructure:"allow_interactive_login"`
```

In `LoadMCPConfig`, add next to the `allow_secret_values` block:

```go
	if viper.IsSet("mcp.allow_interactive_login") {
		cfg.AllowInteractiveLogin = viper.GetBool("mcp.allow_interactive_login")
	}
```

In `.rocketvault.yaml.example`, add a line after `allow_secret_values` in the `mcp:` section:

```yaml
  allow_secret_values: false  # let get_secret return plaintext
  allow_interactive_login: false  # let a chat message log in as a different user
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/... -v`
Expected: PASS for the whole package.

- [ ] **Step 5: Commit**

```bash
git add config/config.go .rocketvault.yaml.example config/mcp_config_test.go
git commit -m "$(cat <<'EOF'
feat(config): add mcp.allow_interactive_login flag

Off by default, following the same pattern as the three existing
allow_* capability tiers. Nothing reads it yet.
EOF
)"
```

---

### Task 3: mcpserver.Server identity fields

**Files:**
- Modify: `internal/mcpserver/server.go` (`Deps`, `Server`, `New`)
- Test: `internal/mcpserver/server_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.SwappableSource` (Part 1, Task 1).
- Produces: `Deps.Identity *vaultapi.SwappableSource`, `Deps.IsServiceAccountIdentity bool`, `Deps.JWTExpiry time.Duration`; `(*Server).IsServiceAccountIdentity() bool`. Part 3's `TierLogin` and `login` tool handler read these.

- [ ] **Step 1: Write the failing tests**

Append to `internal/mcpserver/server_test.go`:

```go
func TestNew_ExposesIsServiceAccountIdentity(t *testing.T) {
	s, err := New(Deps{
		Config: testConfig(), Logger: discardLogger(), Version: "test",
		IsServiceAccountIdentity: true,
	})
	require.NoError(t, err)
	require.True(t, s.IsServiceAccountIdentity())
}

func TestNew_DefaultsToNotServiceAccountIdentity(t *testing.T) {
	s, err := New(Deps{Config: testConfig(), Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)
	require.False(t, s.IsServiceAccountIdentity())
}
```

(If `internal/mcpserver/server_test.go` does not yet exist, create it with `package mcpserver` and `import ("testing"; "github.com/stretchr/testify/require")`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run TestNew_.*ServiceAccountIdentity -v`
Expected: FAIL — `Deps` has no field `IsServiceAccountIdentity`, and `*Server` has no method `IsServiceAccountIdentity`.

- [ ] **Step 3: Add the fields, wiring, and accessor**

In `internal/mcpserver/server.go`, add to `Deps`:

```go
	// Identity is the swappable token source backing Client's
	// authentication. Only cmd/mcp.go constructs one; a nil Identity means
	// no tool can ever change this server's identity at runtime.
	Identity *vaultapi.SwappableSource
	// IsServiceAccountIdentity reports whether this server started under a
	// service account rather than a cached session. TierLogin uses this to
	// disable the login tool entirely when true, regardless of
	// allow_interactive_login.
	IsServiceAccountIdentity bool
	// JWTExpiry is the access-token lifetime (jwt.expiry), used to compute
	// a login-tool session's expiry the same way the CLI does.
	JWTExpiry time.Duration
```

Add to `Server`:

```go
	identity                 *vaultapi.SwappableSource
	isServiceAccountIdentity bool
	jwtExpiry                time.Duration
```

In `New`, extend the returned struct literal:

```go
	return &Server{
		cfg:                      deps.Config,
		client:                   deps.Client,
		logger:                   logger,
		baseURL:                  deps.BaseURL,
		mcpServer:                mcpServer,
		limits:                   newLimiter(deps.Config.RateLimit),
		identity:                 deps.Identity,
		isServiceAccountIdentity: deps.IsServiceAccountIdentity,
		jwtExpiry:                deps.JWTExpiry,
	}, nil
```

Add the accessor near `EnabledTiers`:

```go
// IsServiceAccountIdentity reports whether this server started under a
// service account rather than a cached session.
func (s *Server) IsServiceAccountIdentity() bool { return s.isServiceAccountIdentity }
```

Add `"time"` to the import block if not already present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpserver/... -v -race`
Expected: PASS for the whole package — this must not break any existing test, since `Identity`/`IsServiceAccountIdentity`/`JWTExpiry` all default to their zero values when a test's `Deps` literal doesn't set them.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/server.go internal/mcpserver/server_test.go
git commit -m "$(cat <<'EOF'
feat(mcpserver): add identity fields to Deps and Server

Identity, IsServiceAccountIdentity and JWTExpiry are inert plumbing --
nothing constructs a real Identity or reads these outside the new
accessor yet. Later plans build the login tool and cmd/mcp.go wiring
on top of this.
EOF
)"
```

---

## After this plan

```bash
go build ./internal/vaultapi/... ./config/... ./internal/mcpserver/...
go vet ./internal/vaultapi/... ./config/... ./internal/mcpserver/...
go test ./internal/vaultapi/... ./config/... ./internal/mcpserver/... -race
```

All three must be clean. Then proceed to **Part 3**:
`docs/superpowers/plans/2026-08-25-mcp-interactive-login-part3-mcpserver-login-tool.md`
