# MCP Interactive Login — Part 4: cmd/mcp.go Wiring and End-to-End Proof

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Before starting:** create one Task (via the TaskCreate tool) per task
> below. Set a task `in_progress` before starting it and `completed`
> immediately after its commit step. Run TaskList at any checkpoint to see
> where this plan stands.

**Goal:** Wire the real `rocketvault mcp` binary to construct a `SwappableSource` and pass identity info into `mcpserver.Deps`, then prove both halves of this feature end to end: the stale-session recovery fix against real on-disk session files, and the `login` tool against a real running vault.

**Architecture:** `cmd/mcp.go`'s `buildMCPServer` gets three additive lines — wrap the resolved token source, compute whether it's a service account from the same fields `resolveMCPTokenSource` already checks, and read `jwt.expiry` via Viper. The two proof tasks use real I/O (`common.SaveSession`/`LoadCurrentSession` on disk, and a real compiled `rocketvault serve` for the MCP integration suite) rather than more fakes — Part 1-3 already covered the logic with fakes; this plan's job is confidence that the real pieces fit together.

**Tech Stack:** Go, Viper, `testify/require`, `oathtool` (already a harness dependency for TOTP codes).

**Spec:** `docs/superpowers/specs/2026-08-25-mcp-interactive-login-design.md`

## Global Constraints

- Depends on Parts 1-3 — do not start until all three are merged and their tests pass.
- Task 3's test is `//go:build integration`-tagged, matching every other test in `internal/mcpserver/integration_harness_test.go` and `integration_test.go` — it must not run under a plain `go test ./...`.
- No documentation changes in this plan — that's Part 5.

## Plan Chain

**This is Part 4 of 5.** Previous: `2026-08-25-mcp-interactive-login-part3-mcpserver-login-tool.md`. Next plan: `docs/superpowers/plans/2026-08-25-mcp-interactive-login-part5-docs-and-verification.md`

---

### Task 1: Wire cmd/mcp.go

**Files:**
- Modify: `cmd/mcp.go` (`buildMCPServer`)
- Test: `cmd/mcp_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.NewSwappableSource` (Part 1, Task 1), `Deps.Identity`/`Deps.IsServiceAccountIdentity`/`Deps.JWTExpiry` (Part 2, Task 3), the existing `resolveMCPTokenSource` (unchanged signature — no existing test in `cmd/mcp_test.go` needs to change).
- Produces: a real `rocketvault mcp` binary that registers `login` when configured to.

- [ ] **Step 1: Write the failing test**

Append to `cmd/mcp_test.go`:

```go
func TestBuildMCPServer_WiresServiceAccountIdentity(t *testing.T) {
	resetMCPViper(t)
	viper.Set("mcp.client_id", "mcp-agent")
	viper.Set("mcp.client_secret", "s3cr3t")

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "https://vault.example.com", "")
	cmd.Flags().String("ca-cert", "", "")
	cmd.Flags().Bool("insecure-skip-verify", false, "")

	logger := mcpserver.NewStderrLogger(slog.LevelInfo)
	server, _, err := buildMCPServer(cmd, logger)
	require.NoError(t, err)
	require.True(t, server.IsServiceAccountIdentity(),
		"a client_id/client_secret configuration must be reported as a service account")
}

func TestBuildMCPServer_SessionIdentityIsNotAServiceAccount(t *testing.T) {
	resetMCPViper(t)
	// A cached session, so buildMCPServer succeeds via the session branch
	// instead of failing before it reaches the assertion below.
	dir := t.TempDir()
	original := common.SessionBaseDir
	common.SessionBaseDir = dir
	t.Cleanup(func() { common.SessionBaseDir = original })
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "t", RefreshToken: "r", Username: "admin",
		ExpiresAt: time.Now().Add(time.Hour), ServerKey: common.LocalServerKey,
	}))

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "https://vault.example.com", "")
	cmd.Flags().String("ca-cert", "", "")
	cmd.Flags().Bool("insecure-skip-verify", false, "")

	logger := mcpserver.NewStderrLogger(slog.LevelInfo)
	server, _, err := buildMCPServer(cmd, logger)
	require.NoError(t, err)
	require.False(t, server.IsServiceAccountIdentity(),
		"a cached-session configuration must not be reported as a service account")
}
```

(Add `"time"` to the import block if not already present.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/... -run TestBuildMCPServer -v`
Expected: FAIL — `buildMCPServer` never sets `IsServiceAccountIdentity` on the constructed `Server` yet, so `TestBuildMCPServer_WiresServiceAccountIdentity` gets `false` where it expects `true`.

- [ ] **Step 3: Wire the fields**

In `cmd/mcp.go`, `buildMCPServer`, change:

```go
	tokens, identity, err := resolveMCPTokenSource(cfg, baseURL, httpClient)
	if err != nil {
		return nil, "", err
	}

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Tokens:     tokens,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to build the vault client: %w", err)
	}

	server, err := mcpserver.New(mcpserver.Deps{
		Client:  client,
		Config:  cfg,
		Logger:  logger,
		Version: rootCmd.Version,
		BaseURL: baseURL,
	})
```

to:

```go
	tokens, identity, err := resolveMCPTokenSource(cfg, baseURL, httpClient)
	if err != nil {
		return nil, "", err
	}

	// Wrapped so the login tool (see internal/mcpserver/tools_login.go) can
	// replace this server's identity at runtime without touching Client.
	swappable := vaultapi.NewSwappableSource(tokens)

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Tokens:     swappable,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to build the vault client: %w", err)
	}

	server, err := mcpserver.New(mcpserver.Deps{
		Client:  client,
		Config:  cfg,
		Logger:  logger,
		Version: rootCmd.Version,
		BaseURL: baseURL,

		Identity: swappable,
		// The same condition resolveMCPTokenSource already used to choose
		// the service-account branch, restated here rather than threaded
		// back through its return values -- it has no other caller that
		// would need the extra value, and every existing test of that
		// function stays unchanged.
		IsServiceAccountIdentity: cfg.ClientID != "" && cfg.ClientSecret != "",
		JWTExpiry:                viper.GetDuration("jwt.expiry"),
	})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/... -v`
Expected: PASS for the whole package, including both new `TestBuildMCPServer_*` tests and every pre-existing `TestResolveMCPTokenSource_*`/`TestMCPStartup_*` test.

- [ ] **Step 5: Commit**

```bash
git add cmd/mcp.go cmd/mcp_test.go
git commit -m "$(cat <<'EOF'
feat(cmd): wire SwappableSource and identity info into mcpserver.Deps

buildMCPServer now wraps the resolved token source so the login tool
can replace it at runtime, and passes through whether this is a
service account and the configured jwt.expiry. This is the last piece
connecting Parts 1-3 to the real binary.
EOF
)"
```

---

### Task 2: Prove the stale-session fix against real disk I/O

**Files:**
- Create: `internal/vaultapi/sessionsource_diskintegration_test.go`

**Interfaces:**
- Consumes: `common.SaveSession`, `common.SessionBaseDir`, `common.LocalServerKey` (existing, `common/session.go`), `NewSessionSource` and its Part 1 Task 2 reload fix.
- Produces: nothing new — this is a proof, not an API.

Part 1's `TestSessionSource_StaleRefreshTokenRecoversFromDisk` proved the reload logic against a `stubStore`. This task reproduces the exact 2026-08-24 failure — a `rocketvault mcp` subprocess outliving a fresh `rocketvault users login` in a different process — against the real `common.SaveSession`/`common.LoadCurrentSession` functions those two processes actually use, so a wiring mistake between `SessionSource` and the real session-cache format cannot hide behind the stub.

- [ ] **Step 1: Write the failing test**

```go
// internal/vaultapi/sessionsource_diskintegration_test.go
package vaultapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

// TestSessionSource_RecoversFromARealCLILoginOnDisk reproduces the exact
// 2026-08-24 failure end to end: a SessionSource constructed before a newer
// `rocketvault users login` writes to the real on-disk session cache must
// recover on its very next Token call, with no process restart.
func TestSessionSource_RecoversFromARealCLILoginOnDisk(t *testing.T) {
	original := common.SessionBaseDir
	common.SessionBaseDir = t.TempDir()
	t.Cleanup(func() { common.SessionBaseDir = original })

	var seenTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		seenTokens = append(seenTokens, body.RefreshToken)

		if body.RefreshToken == "refresh-old" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"final-access","refresh_token":"refresh-final","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"],"expires_at":%q}`,
			time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// A `rocketvault users login` ran once, before the MCP subprocess started.
	old := &common.SessionCache{
		Token: "old-access", RefreshToken: "refresh-old",
		UserID: userID, Username: "admin", Roles: []string{"admin"},
		ExpiresAt: time.Now().Add(-time.Minute), ServerKey: common.LocalServerKey,
	}
	require.NoError(t, common.SaveSession(old))

	// The MCP subprocess starts here, reading `old` at construction --
	// exactly what rocketvault mcp does in cmd/mcp.go via
	// resolveMCPTokenSource -> vaultapi.NewSessionSource.
	src, err := NewSessionSource(SessionConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	// `rocketvault users login` runs again, in a different process, while
	// the MCP subprocess above keeps running.
	fresh := &common.SessionCache{
		Token: "fresh-access", RefreshToken: "refresh-fresh",
		UserID: userID, Username: "admin", Roles: []string{"admin"},
		ExpiresAt: time.Now().Add(-time.Minute), ServerKey: common.LocalServerKey,
	}
	require.NoError(t, common.SaveSession(fresh))

	// The subprocess's very next tool call -- no restart -- must succeed.
	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "final-access", tok)
	require.Equal(t, []string{"refresh-old", "refresh-fresh"}, seenTokens,
		"the stale in-memory token is tried first, then the one the second login wrote to disk")
}
```

- [ ] **Step 2: Run the test to verify it currently passes**

This test does not exercise new production code — it exercises Part 1's already-implemented fix through the real disk path instead of `stubStore`. It should already pass.

Run: `go test ./internal/vaultapi/... -run TestSessionSource_RecoversFromARealCLILoginOnDisk -v`
Expected: PASS. If it fails, that means the real `common.SaveSession`/`LoadCurrentSession` shapes diverge from what Part 1's fix assumed — stop and fix Part 1's implementation, don't adjust this test to match a divergence.

- [ ] **Step 3: Commit**

```bash
git add internal/vaultapi/sessionsource_diskintegration_test.go
git commit -m "$(cat <<'EOF'
test(vaultapi): prove stale-session recovery against real disk I/O

Reproduces the exact 2026-08-24 failure -- an MCP subprocess outliving
a newer CLI login -- through common.SaveSession/LoadCurrentSession
directly, not a stub, so a mismatch between the fix and the real
session-cache format can't hide.
EOF
)"
```

---

### Task 3: Prove the login tool against a real running vault

**Files:**
- Modify: `internal/mcpserver/integration_harness_test.go` (`liveVault` gains `TOTPSecret`; `mcpServer` wraps its token source in a `SwappableSource`)
- Modify: `internal/mcpserver/integration_test.go` (new test)

**Interfaces:**
- Consumes: `startLiveVault`, `totpCode`, `parseTOTPSecret` (existing harness helpers), `vaultapi.NewSwappableSource` (Part 1), the `login` tool (Part 3).
- Produces: nothing new — this is the feature's end-to-end proof against a real compiled binary.

- [ ] **Step 1: Extend the harness to expose a reusable TOTP secret**

In `internal/mcpserver/integration_harness_test.go`, add a field to `liveVault`:

```go
type liveVault struct {
	BaseURL string
	// Token is an admin session token, for provisioning fixtures.
	Token string
	// TOTPSecret is the provisioned admin's base32 TOTP secret, so a test
	// can generate a fresh code and call the login tool as this same user.
	TOTPSecret string
}
```

In `startLiveVault`, capture it:

```go
	totpSecret := parseTOTPSecret(t, string(output))
	live := &liveVault{
		BaseURL:    baseURL,
		Token:      loginToken(t, baseURL, totpSecret),
		TOTPSecret: totpSecret,
	}
```

In `mcpServer`, wrap the token source so the login tool has something to swap and pass it through `Deps.Identity`:

```go
func (l *liveVault) mcpServer(t *testing.T, cfg config.MCPConfig) *Server {
	t.Helper()

	swappable := vaultapi.NewSwappableSource(staticLiveToken(l.Token))
	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    l.BaseURL,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		Tokens:     swappable,
	})
	require.NoError(t, err)

	s, err := New(Deps{
		Client: client, Config: cfg, Logger: discardLogger(), Version: "integration",
		Identity: swappable,
	})
	require.NoError(t, err)
	RegisterAllTools(s)
	return s
}
```

- [ ] **Step 2: Write the failing test**

Append to `internal/mcpserver/integration_test.go`:

```go
func TestLive_LoginSwapsIdentityForSubsequentCalls(t *testing.T) {
	live := startLiveVault(t)
	cfg := liveConfig()
	cfg.AllowInteractiveLogin = true
	cs := connect(t, live.mcpServer(t, cfg))

	var login loginResult
	structured(t, callLive(t, cs, "login", map[string]any{
		"username":  "itadmin",
		"password":  "Integration-Test-Pass-1",
		"totp_code": totpCode(t, live.TOTPSecret),
	}), &login)

	require.Equal(t, "itadmin", login.Username)
	require.NotEmpty(t, login.ExpiresAt)

	// A read tool called after login must still succeed -- it now runs
	// under a freshly issued token rather than the harness's original one,
	// but the same admin identity, so authorization still passes.
	var vaults listVaultsResult
	structured(t, callLive(t, cs, "list_vaults", map[string]any{}), &vaults)

	var names []string
	for _, vault := range vaults.Vaults {
		names = append(names, vault.Name)
	}
	require.Contains(t, names, "default")
}

func TestLive_LoginIsAbsentWithoutTheFlag(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig())) // AllowInteractiveLogin left false

	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "itadmin", "password": "x", "totp_code": "000000"},
	})
	require.Error(t, err, "an unregistered tool must be rejected by the protocol, not reachable at all")
}
```

- [ ] **Step 3: Run the tests**

Run: `go test -tags=integration ./internal/mcpserver/... -run TestLive_Login -v`
Expected: PASS. This builds the real `rocketvault` binary and boots a real `serve` instance — allow it the time that takes.

- [ ] **Step 4: Run the entire integration suite once more**

Run: `go test -tags=integration ./internal/mcpserver/... -v`
Expected: PASS, no regressions in any pre-existing `TestLive_*`/`TestHarness_*` test.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/integration_harness_test.go internal/mcpserver/integration_test.go
git commit -m "$(cat <<'EOF'
test(mcpserver): prove the login tool against a real running vault

Extends the integration harness with a reusable TOTP secret and wraps
its token source in a SwappableSource, then verifies login followed
by a read tool call both succeed against a real compiled binary.
EOF
)"
```

---

## After this plan

```bash
go build ./...
go vet ./...
go test ./... -race
go test -tags=integration ./internal/mcpserver/... -v
```

All four must be clean. Then proceed to **Part 5**:
`docs/superpowers/plans/2026-08-25-mcp-interactive-login-part5-docs-and-verification.md`
