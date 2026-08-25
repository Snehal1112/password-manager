# MCP Interactive Login — Part 3: TierLogin and the login Tool

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Before starting:** create one Task (via the TaskCreate tool) per task
> below. Set a task `in_progress` before starting it and `completed`
> immediately after its commit step. Run TaskList at any checkpoint to see
> where this plan stands.

**Goal:** Add the `TierLogin` capability tier and the `login` tool itself, so `rocketvault mcp` can register it — `cmd/mcp.go` still doesn't wire up a real `Identity`, so this plan's tests exercise the tool with a test-constructed `Server`, not the real binary.

**Architecture:** `TierLogin` follows the exact `registerIf`/`TierEnabled` pattern the three existing tiers already use, gated on both the config flag and `Server.IsServiceAccountIdentity()`. The `login` tool itself is a thin handler: validate arguments, call `Client.Login`, swap `Server.identity`, return non-secret identity info.

**Tech Stack:** Go, MCP Go SDK, `testify/require`.

**Spec:** `docs/superpowers/specs/2026-08-25-mcp-interactive-login-design.md`

## Global Constraints

- Depends on Part 1 and Part 2 — do not start until both are merged and their tests pass.
- The `login` tool never echoes the token, only `{username, roles, expires_at}` — matches `set_secret`'s existing precedent of not echoing back what it was just given.
- No `cmd/mcp.go` changes in this plan — that's Part 4.

## Plan Chain

**This is Part 3 of 5.** Previous: `2026-08-25-mcp-interactive-login-part2-vaultapi-login-and-config.md`. Next plan: `docs/superpowers/plans/2026-08-25-mcp-interactive-login-part4-cmd-wiring-and-tests.md`

---

### Task 1: TierLogin

**Files:**
- Modify: `internal/mcpserver/gating.go` (`Tier` constants, `String`, `TierEnabled`)
- Test: `internal/mcpserver/gating_test.go` (append)

**Interfaces:**
- Consumes: `Server.cfg.AllowInteractiveLogin` (Part 2, Task 2), `Server.IsServiceAccountIdentity()` (Part 2, Task 3).
- Produces: `TierLogin Tier` constant. Task 2 (this plan) registers the `login` tool under it.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/gating_test.go`:

```go
func TestTierEnabled_LoginRequiresFlagAndSessionIdentity(t *testing.T) {
	cases := []struct {
		name           string
		allow          bool
		serviceAccount bool
		want           bool
	}{
		{"flag off, session identity", false, false, false},
		{"flag on, session identity", true, false, true},
		{"flag on, service account", true, true, false},
		{"flag off, service account", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.AllowInteractiveLogin = tc.allow
			s, err := New(Deps{
				Config: cfg, Logger: discardLogger(), Version: "test",
				IsServiceAccountIdentity: tc.serviceAccount,
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, s.TierEnabled(TierLogin))
		})
	}
}
```

(If `gating_test.go` does not import `testing` and `github.com/stretchr/testify/require` already, add them.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/... -run TestTierEnabled_LoginRequiresFlagAndSessionIdentity -v`
Expected: FAIL with `undefined: TierLogin`.

- [ ] **Step 3: Add the tier**

In `internal/mcpserver/gating.go`, extend the `Tier` constants:

```go
const (
	TierRead Tier = iota
	TierWrite
	TierDestructive
	TierCrypto
	TierLogin
)
```

Extend `String`:

```go
func (t Tier) String() string {
	switch t {
	case TierWrite:
		return "write"
	case TierDestructive:
		return "destructive"
	case TierCrypto:
		return "crypto"
	case TierLogin:
		return "login"
	default:
		return "read"
	}
}
```

Extend `TierEnabled`:

```go
func (s *Server) TierEnabled(t Tier) bool {
	switch t {
	case TierWrite:
		return s.cfg.AllowWrite
	case TierDestructive:
		return s.cfg.AllowDestructive
	case TierCrypto:
		return s.cfg.AllowCrypto
	case TierLogin:
		// Never enabled under a service account, regardless of config: a
		// service account's whole point is that the agent cannot act as a
		// human, and a login tool that could override that would defeat it.
		return s.cfg.AllowInteractiveLogin && !s.isServiceAccountIdentity
	default:
		return true
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/... -v`
Expected: PASS for the whole package.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/gating.go internal/mcpserver/gating_test.go
git commit -m "$(cat <<'EOF'
feat(mcpserver): add TierLogin

Gated on allow_interactive_login AND not running under a service
account -- the second condition is unconditional, not something config
can override. Nothing registers under this tier yet.
EOF
)"
```

---

### Task 2: The login tool

**Files:**
- Create: `internal/mcpserver/tools_login.go`
- Modify: `internal/mcpserver/register.go` (add `registerLoginTools(s)` to `RegisterAllTools`)
- Test: `internal/mcpserver/tools_login_test.go`

**Interfaces:**
- Consumes: `Client.Login` (Part 2, Task 1), `Server.identity *vaultapi.SwappableSource` and `Server.jwtExpiry` (Part 2, Task 3), `registerIf`/`Annotations`/`errorResult` (existing, `gating.go`/`server.go`/`lifecycle.go`).
- Produces: the registered `login` tool. Part 4's `cmd/mcp.go` wiring and integration test are what actually exercise it against the real binary end to end; this task proves the handler logic in isolation with a fake vault and a real `SwappableSource`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/mcpserver/tools_login_test.go
package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// serverWithIdentity builds a Server wired to f, with swap as both its
// Client's token source and its Deps.Identity -- exactly the relationship
// cmd/mcp.go will set up for real in Part 4.
func serverWithIdentity(t *testing.T, f *fakeVault, swap *vaultapi.SwappableSource, cfg config.MCPConfig) *Server {
	t.Helper()
	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: f.srv.URL, HTTPClient: f.srv.Client(), Tokens: swap, DisableRetry: true,
	})
	require.NoError(t, err)
	s, err := New(Deps{
		Client: client, Config: cfg, Logger: discardLogger(), Version: "test",
		Identity: swap,
	})
	require.NoError(t, err)
	return s
}

func loginEnabledConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowInteractiveLogin = true
	return cfg
}

func TestHandleLogin_Success(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	// fakeVault's handler treats every non-GET request the same way: decode
	// the body, then respond with writeResponse. Client.Login's POST is the
	// only write this test performs, so this is enough to serve it.
	f.writeResponse = `{"token":"access-new","refresh_token":"refresh-new","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`

	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, loginEnabledConfig())
	RegisterAllTools(s)
	cs := connect(t, s)

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "admin", "password": "hunter2", "totp_code": "123456"},
	})
	require.NoError(t, err)

	var out loginResult
	structured(t, result, &out)
	require.Equal(t, "admin", out.Username)
	require.Equal(t, []string{"admin"}, out.Roles)
	require.NotEmpty(t, out.ExpiresAt)

	tok, err := swap.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-new", tok, "the server's identity must now be the logged-in session")
}

func TestHandleLogin_MissingArgumentIsAnError(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, loginEnabledConfig())
	RegisterAllTools(s)
	cs := connect(t, s)

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "admin", "password": "hunter2"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "totp_code")
}

func TestHandleLogin_UpstreamFailureDoesNotSwapIdentity(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/users/login", http.StatusUnauthorized)

	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, loginEnabledConfig())
	RegisterAllTools(s)
	cs := connect(t, s)

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "admin", "password": "wrong", "totp_code": "000000"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)

	tok, err := swap.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "startup-token", tok, "a failed login must not change the server's identity")
}

func TestHandleLogin_AbsentWhenTierDisabled(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, testConfig()) // AllowInteractiveLogin left false
	RegisterAllTools(s)

	require.False(t, contains(s.RegisteredTools(), "login"))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run TestHandleLogin -v`
Expected: FAIL — `loginResult` is undefined and the `login` tool does not exist to call.

- [ ] **Step 3: Write the implementation**

```go
// internal/mcpserver/tools_login.go
package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// loginArgs are the arguments to login.
type loginArgs struct {
	Username string `json:"username" jsonschema:"the RocketVault username to authenticate as"`
	Password string `json:"password" jsonschema:"the account's password"`
	TOTPCode string `json:"totp_code" jsonschema:"the current 6-digit TOTP code from the account's authenticator"`
}

// loginResult confirms who the server is now acting as. It deliberately
// never includes the token: the caller supplied the credentials, so echoing
// back a bearer token would put one in the transcript for no reason.
type loginResult struct {
	Username  string   `json:"username"`
	Roles     []string `json:"roles"`
	ExpiresAt string   `json:"expires_at"`
}

// registerLoginTools adds the login-tier tool.
func registerLoginTools(s *Server) {
	registerIf(s, TierLogin, "login",
		"Authenticate as a RocketVault user with a username, password and current TOTP code, "+
			"replacing this server's identity for the rest of its process lifetime. Every later "+
			"tool call in this conversation acts as this user until the process restarts or login "+
			"is called again. Credentials are arguments only -- they are never logged and the "+
			"resulting token is never echoed back. Unavailable when this server is running under "+
			"a service account.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleLogin)
}

func (s *Server) handleLogin(ctx context.Context, _ *mcp.CallToolRequest, args loginArgs) (*mcp.CallToolResult, loginResult, error) {
	if args.Username == "" || args.Password == "" || args.TOTPCode == "" {
		return errorResult("login requires username, password and totp_code"), loginResult{}, nil
	}

	source, identity, err := s.client.Login(ctx, args.Username, args.Password, args.TOTPCode, s.jwtExpiry)
	if err != nil {
		return errorResult("login failed: %s", err), loginResult{}, nil
	}
	s.identity.Set(source)

	return nil, loginResult{
		Username:  identity.Username,
		Roles:     identity.Roles,
		ExpiresAt: identity.ExpiresAt.Format(time.RFC3339),
	}, nil
}
```

In `internal/mcpserver/register.go`, add the call:

```go
func RegisterAllTools(s *Server) {
	registerSecretsReadTools(s)
	registerKeysReadTools(s)
	registerCertificatesReadTools(s)
	registerVaultsReadTools(s)
	registerAccessReadTools(s)
	registerAuditReadTools(s)
	registerSecretsWriteTools(s)
	registerVaultsWriteTools(s)
	registerAccessWriteTools(s)
	registerKeysWriteTools(s)
	registerCertificatesWriteTools(s)
	registerRecoverTools(s)
	registerDestructiveTools(s)
	registerCryptoTools(s)
	registerLoginTools(s)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpserver/... -v -race`
Expected: PASS for the whole package, including the new `TestHandleLogin_*` tests and every pre-existing test (in particular `TestGatingTable_EveryToolIsAccountedFor`, which enumerates every tier's tools by hand and would fail loudly if `login` slipped into a tier list it doesn't belong to — it must stay unaffected, since none of the existing `configFor` calls set `AllowInteractiveLogin`).

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_login.go internal/mcpserver/register.go internal/mcpserver/tools_login_test.go
git commit -m "$(cat <<'EOF'
feat(mcpserver): add the login tool

Calls Client.Login and swaps Server.identity on success. Registered
under TierLogin, so it is absent from tools/list entirely unless
allow_interactive_login is set and the server is not running under a
service account.
EOF
)"
```

---

### Task 3: Gating coverage for the login tool

**Files:**
- Modify: `internal/mcpserver/gating_table_test.go` (append; does not touch existing `configFor`/`expectedTools` signatures)

**Interfaces:**
- Consumes: `contains`, `newFakeVault`, `staticTestToken`, `testConfig` (all existing test helpers).
- Produces: nothing new — this task only adds coverage.

- [ ] **Step 1: Write the tests**

Append to `internal/mcpserver/gating_table_test.go`:

```go
func TestGatingTable_LoginPresentOnlyWithFlagAndSessionIdentity(t *testing.T) {
	cases := []struct {
		name                  string
		allowInteractiveLogin bool
		serviceAccount        bool
		wantPresent           bool
	}{
		{"default", false, false, false},
		{"flag on, session identity", true, false, true},
		{"flag on, service account", true, true, false},
		{"flag off, service account", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.AllowInteractiveLogin = tc.allowInteractiveLogin

			f := newFakeVault(t, map[string]string{})
			client, err := vaultapi.New(vaultapi.Config{
				BaseURL: f.srv.URL, HTTPClient: f.srv.Client(),
				Tokens: staticTestToken("test-token"), DisableRetry: true,
			})
			require.NoError(t, err)

			s, err := New(Deps{
				Client: client, Config: cfg, Logger: discardLogger(), Version: "test",
				IsServiceAccountIdentity: tc.serviceAccount,
			})
			require.NoError(t, err)
			RegisterAllTools(s)

			require.Equal(t, tc.wantPresent, contains(s.RegisteredTools(), "login"))
		})
	}
}

func TestGatingTable_LoginAbsentFromDefaultConfiguration(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)
	require.False(t, contains(s.RegisteredTools(), "login"),
		"a config with no mcp section must not expose login")
}
```

(`vaultapi` is likely already imported in this file's package via other tests in the package; if `gating_table_test.go` itself has no `vaultapi` import, add `"rocketvault/internal/vaultapi"` to its import block.)

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/mcpserver/... -run TestGatingTable -v`
Expected: PASS, including every pre-existing `TestGatingTable_*` test unchanged.

- [ ] **Step 3: Run the whole package once more**

Run: `go test ./internal/mcpserver/... -v -race`
Expected: PASS, no regressions.

- [ ] **Step 4: Commit**

```bash
git add internal/mcpserver/gating_table_test.go
git commit -m "$(cat <<'EOF'
test(mcpserver): cover login tool gating in the gating table

Login's extra dimension (service-account identity) doesn't fit the
existing configFor/expectedTools helpers, so this adds standalone
cases rather than reshaping the shared 16-combination matrix.
EOF
)"
```

---

## After this plan

```bash
go build ./internal/mcpserver/...
go vet ./internal/mcpserver/...
go test ./internal/mcpserver/... -race
```

All three must be clean. Then proceed to **Part 4**:
`docs/superpowers/plans/2026-08-25-mcp-interactive-login-part4-cmd-wiring-and-tests.md`
