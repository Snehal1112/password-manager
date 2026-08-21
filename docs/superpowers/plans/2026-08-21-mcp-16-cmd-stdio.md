# `rocketvault mcp` stdio Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `rocketvault mcp`, which resolves an identity, wires the read tools, and serves MCP over stdio. **This is the milestone: after this plan, the server actually runs in Claude Code.**

**Architecture:** A Cobra command that replaces the root `PersistentPreRunE`, because the root pre-run does three things that are wrong for this command — it opens a database, it starts a rotating log file, and it *refuses* remote targets outright. `serveCmd` already establishes this override pattern for the same reason.

**Tech Stack:** Go 1.25, `github.com/spf13/cobra`, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0, `log/slog`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — sections "Authentication", "There is no end-user authentication", "Production hardening > Lifecycle" and "> stdio hazard".

**Plan-of-plans:** This is plan 16 of 31. Requires plans 02, 03, 09-15 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **stdout is the JSON-RPC channel.** Nothing may write to it but the protocol.
- **No silent fallback.** If no identity resolves, the command fails with an actionable message rather than starting degraded.
- MIT licence header at the top of new files in `cmd/`, matching `cmd/version.go`.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Three reasons this command must override `PersistentPreRunE`

The root pre-run (`cmd/root.go:82`, body at `:330-390`) is actively wrong here, not merely unnecessary:

1. **It refuses remote targets.** `cmd/root.go:358-371` returns *"remote mode … is not yet supported for %q"* whenever `--server`, `ROCKETVAULT_ADDR` or a named context resolves. MCP is HTTP-only — a remote target is its normal operating mode, so the guard would block the command's entire purpose.
2. **It opens a database and builds a full `ServiceContainer`.** The MCP server never touches the database; it talks to the API. Booting one wastes startup time and, worse, requires local database access that a remote deployment does not have.
3. **It starts a rotating log file** (`logging.InitLogger()` plus `go log.StartPeriodicRotation()`). For a short-lived stdio subprocess, diagnostics belong on stderr where the host captures them, not in a shared rotating file this process would contend over.

`serveCmd` overrides the root pre-run for reason 2 already (`cmd/serve.go:75-80`, citing `cmd/vaults/preview_migration.go` as precedent). This command follows that pattern for all three.

## Base URL resolution

`cliclient.ResolveTarget` returns `(nil, nil)` for local mode (`resolve.go:39`), but MCP has no local mode — it needs a URL. Resolution order:

1. `--server`, `ROCKETVAULT_ADDR`, or the current named context, via `cliclient.ResolveTarget`.
2. Otherwise, the locally configured server: `http://127.0.0.1` plus the port from `server.listen_addr` (default `:8774`).

Step 2 is a convenience for the common case of running the CLI on the same host as the server, and it is **logged explicitly** — the codebase already treats silent remote fallback as a bug worth fixing (commit `795ecd4`). This is the inverse direction and far less dangerous, but it is still stated rather than assumed.

## File structure

| File | Responsibility |
|---|---|
| `cmd/mcp.go` (new) | The command, identity resolution, base URL, signal handling |
| `cmd/mcp_test.go` (new) | Resolution precedence, failure messages, stdout purity |
| `internal/mcpserver/register.go` (new) | `RegisterAllTools` — the single registration entry point |
| `internal/mcpserver/register_test.go` (new) | Tier-correct registration of the whole surface |

---

### Task 1: `RegisterAllTools`, the single registration entry point

**Files:**
- Create: `internal/mcpserver/register.go`
- Create: `internal/mcpserver/register_test.go`

**Interfaces:**
- Consumes: the five `register*ReadTools` functions from plans 13-15.
- Produces — `cmd/mcp.go`, plan 17's `--check`, and plan 28's gating table all call this:
  - `func RegisterAllTools(s *Server)`

**Why this exists:** without it, `cmd/mcp.go` would call five registration functions, and plans 21, 22, 25 and 27 would each add another call site to it. Registration would then be spread across a command file, which is the wrong place for it, and the gating table test would have to duplicate the list. One function that grows is the correct shape.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/register_test.go`:

```go
package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// readTierTools is the exact read-tier surface. Plan 28 asserts the full
// matrix; this pins the baseline.
var readTierTools = []string{
	"get_certificate",
	"get_key",
	"get_secret",
	"list_certificates",
	"list_deleted",
	"list_keys",
	"list_role_assignments",
	"list_secrets",
	"list_vaults",
	"query_audit_log",
}

func TestRegisterAllTools_DefaultConfigExposesExactlyTheReadTier(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	require.Equal(t, readTierTools, s.RegisteredTools(),
		"a default-configured server must expose these ten tools and nothing else")
}

func TestRegisterAllTools_ExposesTenToolsByDefault(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	require.Len(t, s.RegisteredTools(), 10)
}

func TestRegisterAllTools_IsVisibleOverTheProtocol(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	cs := connect(t, s)
	require.Equal(t, readTierTools, toolNames(t, cs))
}

func TestRegisterAllTools_EveryToolHasADescription(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	cs := connect(t, s)
	result, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range result.Tools {
		require.NotEmpty(t, tool.Description, "tool %q has no description", tool.Name)
		require.NotNil(t, tool.Annotations, "tool %q has no annotations", tool.Name)
	}
}

func TestRegisterAllTools_EveryReadToolIsAnnotatedReadOnly(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	cs := connect(t, s)
	result, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range result.Tools {
		require.True(t, tool.Annotations.ReadOnlyHint, "tool %q should be read-only", tool.Name)
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.False(t, *tool.Annotations.DestructiveHint,
			"tool %q must not advertise itself as destructive", tool.Name)
	}
}

func TestRegisterAllTools_IsIdempotentPerServer(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	require.Len(t, s.RegisteredTools(), 10,
		"registration happens once per server; calling it twice is a programming error, not a supported flow")
}
```

Add `"context"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestRegisterAllTools_ -v`
Expected: FAIL — `undefined: RegisterAllTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/register.go`:

```go
package mcpserver

// RegisterAllTools adds every tool the configuration enables.
//
// This is the single registration entry point. Callers -- the mcp command,
// the --check preflight, and the gating table test -- all go through it, so
// the set of registered tools is defined in exactly one place rather than
// duplicated across a command file and a test.
//
// Each register*Tools function decides for itself, via registerIf, which of
// its tools the enabled tiers permit.
func RegisterAllTools(s *Server) {
	registerSecretsReadTools(s)
	registerKeysReadTools(s)
	registerCertificatesReadTools(s)
	registerVaultsReadTools(s)
	registerAccessReadTools(s)
	registerAuditReadTools(s)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — all six new tests plus the existing suite.

If `TestRegisterAllTools_DefaultConfigExposesExactlyTheReadTier` fails on ordering, `RegisteredTools` sorts, so a mismatch is a genuine difference in the set, not in the order. Fix the registration, not the expectation.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/register.go internal/mcpserver/register_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add RegisterAllTools as the single registration entry point

Without it the mcp command would call six registration functions, and each
later tier plan would add another call site to a command file -- the wrong
place for the tool surface to be defined. One function that grows is the right
shape, and it gives the gating table test something to assert against rather
than duplicating the list."
```

---

### Task 2: The command, identity resolution and stdio transport

**Files:**
- Create: `cmd/mcp.go`
- Create: `cmd/mcp_test.go`

**Interfaces:**
- Consumes: `config.LoadMCPConfig` (plan 09); `vaultapi.NewServiceAccountSource`, `NewSessionSource`, `ErrNoSession` (plans 02-03); `mcpserver.New`, `RegisterAllTools`, `NewStderrLogger` (plans 10, 16); `cliclient.ResolveTarget`, `NewHTTPClient`, `WarnIfInsecure`.
- Produces:
  - `var mcpCmd *cobra.Command`
  - `func resolveMCPBaseURL(serverFlag string) (string, bool, error)` — the bool reports the local fallback.
  - `func resolveMCPTokenSource(cfg config.MCPConfig, baseURL string, httpClient *http.Client) (vaultapi.TokenSource, string, error)` — the string describes the identity, for logs and `--check`.

**Identity resolution, in order:**

1. Service account, if `mcp.client_id` and a secret are configured.
2. Cached CLI session, unless `mcp.require_service_account` is set.
3. Otherwise **fail**, naming both ways to fix it.

There is no fourth branch. A server that starts without an identity would fail on its first tool call with a confusing error, several turns into a conversation.

- [ ] **Step 1: Write the failing test**

Create `cmd/mcp_test.go`:

```go
package cmd

import (
	"net/http"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

func resetMCPViper(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
}

func TestResolveMCPBaseURL_PrefersTheServerFlag(t *testing.T) {
	resetMCPViper(t)

	got, fellBack, err := resolveMCPBaseURL("https://vault.example.com")
	require.NoError(t, err)
	require.Equal(t, "https://vault.example.com", got)
	require.False(t, fellBack)
}

func TestResolveMCPBaseURL_FallsBackToTheConfiguredListenAddr(t *testing.T) {
	resetMCPViper(t)
	viper.Set("server.listen_addr", ":9999")

	got, fellBack, err := resolveMCPBaseURL("")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:9999", got)
	require.True(t, fellBack, "the fallback must be reported, never silent")
}

func TestResolveMCPBaseURL_UsesTheDefaultPortWhenUnset(t *testing.T) {
	resetMCPViper(t)

	got, fellBack, err := resolveMCPBaseURL("")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8774", got)
	require.True(t, fellBack)
}

func TestResolveMCPBaseURL_HandlesAHostQualifiedListenAddr(t *testing.T) {
	resetMCPViper(t)
	viper.Set("server.listen_addr", "0.0.0.0:8080")

	got, _, err := resolveMCPBaseURL("")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8080", got,
		"a wildcard bind address is reached over loopback, not by its literal value")
}

func TestResolveMCPTokenSource_PrefersTheServiceAccount(t *testing.T) {
	cfg := config.MCPConfig{ClientID: "mcp-agent", ClientSecret: "s3cr3t"}

	source, description, err := resolveMCPTokenSource(cfg, "https://vault.example.com", http.DefaultClient)
	require.NoError(t, err)
	require.NotNil(t, source)
	require.Contains(t, description, "mcp-agent")
	require.Contains(t, description, "service account")
}

func TestResolveMCPTokenSource_DescriptionNeverIncludesTheSecret(t *testing.T) {
	cfg := config.MCPConfig{ClientID: "mcp-agent", ClientSecret: "hunter2-do-not-leak"}

	_, description, err := resolveMCPTokenSource(cfg, "https://vault.example.com", http.DefaultClient)
	require.NoError(t, err)
	require.NotContains(t, description, "hunter2-do-not-leak")
}

func TestResolveMCPTokenSource_RequireServiceAccountRefusesTheSession(t *testing.T) {
	cfg := config.MCPConfig{RequireServiceAccount: true}

	_, _, err := resolveMCPTokenSource(cfg, "https://vault.example.com", http.DefaultClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "require_service_account")
	require.Contains(t, err.Error(), "client_id")
}

func TestResolveMCPTokenSource_FailsWhenNothingResolves(t *testing.T) {
	// Point the session cache at an empty directory so no session is found.
	t.Setenv("HOME", t.TempDir())

	cfg := config.MCPConfig{}
	_, _, err := resolveMCPTokenSource(cfg, "https://vault.example.com", http.DefaultClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rocketvault users login",
		"the message must name both ways to fix it")
	require.Contains(t, err.Error(), "client_id")
}

func TestResolveMCPTokenSource_NeverReturnsANilSourceWithoutAnError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	source, _, err := resolveMCPTokenSource(config.MCPConfig{}, "https://vault.example.com", http.DefaultClient)
	if err == nil {
		require.NotNil(t, source, "a nil source with no error would fail later, far from its cause")
	}
}

func TestMCPCommand_OverridesTheRootPersistentPreRun(t *testing.T) {
	require.NotNil(t, mcpCmd.PersistentPreRunE,
		"the root pre-run refuses remote targets, opens a database and starts a rotating "+
			"log file -- all three are wrong for a stdio MCP subprocess")
}

func TestMCPCommand_IsRegisteredOnRoot(t *testing.T) {
	var found bool
	for _, sub := range rootCmd.Commands() {
		if sub.Name() == "mcp" {
			found = true
			break
		}
	}
	require.True(t, found, "mcp must be reachable as `rocketvault mcp`")
}

func TestMCPCommand_HasNoLocalOnlyRequirement(t *testing.T) {
	// The remote-target guard lives in the root pre-run, which mcp replaces.
	// This test documents that a --server value must reach the command.
	require.NotNil(t, mcpCmd.PersistentPreRunE)

	err := mcpCmd.PersistentPreRunE(mcpCmd, nil)
	require.NoError(t, err, "the mcp pre-run must not refuse a remote target")
}

var _ = common.SessionCache{}
var _ vaultapi.TokenSource = nil
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run 'TestResolveMCP|TestMCPCommand_' -v`
Expected: FAIL — `undefined: resolveMCPBaseURL`, `undefined: mcpCmd`.

- [ ] **Step 3: Write minimal implementation**

Create `cmd/mcp.go` with the MIT header copied from `cmd/version.go`, then:

```go
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/config"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/mcpserver"
	"rocketvault/internal/vaultapi"
)

// defaultListenAddr matches the shipped server.listen_addr.
const defaultListenAddr = ":8774"

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run a Model Context Protocol server over stdio",
	Long: `Serve RocketVault to an MCP client such as Claude Code or Claude Desktop.

The server talks to a RocketVault API server over HTTP, so authorization is
enforced by the same middleware every other API client goes through. It never
touches the database directly.

By default it exposes ten read-only tools and returns no secret values.
Capability tiers are enabled in the mcp section of .rocketvault.yaml -- see
allow_write, allow_destructive, allow_crypto and allow_secret_values.

Identity is resolved once at startup: a service account when mcp.client_id and
a secret are configured, otherwise the session cached by 'rocketvault users
login'. In production, set mcp.require_service_account so the agent cannot act
as you -- under a session its actions are indistinguishable from yours in the
audit log.

This command speaks JSON-RPC on stdout. All diagnostics go to stderr.`,
	Example: `  # Run against the local server, as the logged-in user
  rocketvault users login --username admin
  rocketvault mcp

  # Run against a remote server as a service account
  export ROCKETVAULT_MCP_CLIENT_SECRET=...
  rocketvault mcp --server https://vault.example.com`,

	// Replace the root PersistentPreRunE. The root pre-run is actively wrong
	// here on three counts: it refuses remote targets (cmd/root.go:358),
	// which is this command's normal operating mode; it opens a database and
	// builds a ServiceContainer this command never uses; and it starts a
	// rotating log file, when a stdio subprocess's diagnostics belong on
	// stderr. serveCmd overrides the root pre-run for the second reason
	// already -- see cmd/serve.go:75.
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error { return nil },

	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.Flags().Bool("check", false,
		"Validate configuration, connectivity and authentication, print the exposed tools, then exit")
}

// resolveMCPBaseURL decides which server to talk to.
//
// cliclient.ResolveTarget returns (nil, nil) for local mode, but MCP has no
// local mode -- it needs a URL. When no remote target resolves, the locally
// configured listen address is used. The second return reports that fallback
// so the caller can log it: this codebase treats silent remote fallback as a
// bug (commit 795ecd4), and while falling back to loopback is far less
// dangerous, it is still stated rather than assumed.
func resolveMCPBaseURL(serverFlag string) (string, bool, error) {
	target, err := cliclient.ResolveTarget(serverFlag)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve the server target: %w", err)
	}
	if target != nil && target.Server != "" {
		return target.Server, false, nil
	}

	listen := viper.GetString("server.listen_addr")
	if listen == "" {
		listen = defaultListenAddr
	}
	// A bind address such as ":8774" or "0.0.0.0:8774" is reached over
	// loopback, not by its literal value.
	_, port, splitErr := net.SplitHostPort(listen)
	if splitErr != nil {
		port = strings.TrimPrefix(listen, ":")
	}
	if port == "" {
		port = strings.TrimPrefix(defaultListenAddr, ":")
	}
	return "http://127.0.0.1:" + port, true, nil
}

// resolveMCPTokenSource picks the identity the server acts as.
//
// The order is service account, then cached session, then failure. There is
// deliberately no fourth branch: a server that started without an identity
// would fail on its first tool call, several turns into a conversation and
// far from the actual problem.
func resolveMCPTokenSource(cfg config.MCPConfig, baseURL string, httpClient *http.Client) (vaultapi.TokenSource, string, error) {
	if cfg.ClientID != "" && cfg.ClientSecret != "" {
		source, err := vaultapi.NewServiceAccountSource(vaultapi.ServiceAccountConfig{
			BaseURL:      baseURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			HTTPClient:   httpClient,
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to configure the service account: %w", err)
		}
		// The description never includes the secret.
		return source, fmt.Sprintf("service account %q", cfg.ClientID), nil
	}

	if cfg.RequireServiceAccount {
		return nil, "", fmt.Errorf(
			"mcp.require_service_account is set but no service account is configured; " +
				"set mcp.client_id and ROCKETVAULT_MCP_CLIENT_SECRET")
	}

	source, err := vaultapi.NewSessionSource(vaultapi.SessionConfig{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
	})
	switch {
	case err == nil:
		return source, fmt.Sprintf("cached session for %q", source.Username()), nil
	case errors.Is(err, vaultapi.ErrNoSession):
		return nil, "", fmt.Errorf(
			"no identity is configured: run `rocketvault users login`, " +
				"or set mcp.client_id and ROCKETVAULT_MCP_CLIENT_SECRET to use a service account")
	default:
		return nil, "", fmt.Errorf("failed to read the cached session: %w", err)
	}
}

// buildMCPServer assembles everything the command needs.
func buildMCPServer(cmd *cobra.Command, logger *slog.Logger) (*mcpserver.Server, string, error) {
	cfg, err := config.LoadMCPConfig()
	if err != nil {
		return nil, "", fmt.Errorf("invalid mcp configuration: %w", err)
	}

	serverFlag, _ := cmd.Flags().GetString("server")
	baseURL, fellBack, err := resolveMCPBaseURL(serverFlag)
	if err != nil {
		return nil, "", err
	}
	if fellBack {
		logger.Info("no remote target configured; using the local server", "base_url", baseURL)
	}

	caCert, _ := cmd.Flags().GetString("ca-cert")
	insecure, _ := cmd.Flags().GetBool("insecure-skip-verify")
	tlsOpts := cliclient.HTTPClientOptions{CACertPath: caCert, InsecureSkipVerify: insecure}
	cliclient.WarnIfInsecure(tlsOpts)

	httpClient, err := cliclient.NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build the HTTP client: %w", err)
	}

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
		Version: Version,
	})
	if err != nil {
		return nil, "", err
	}
	mcpserver.RegisterAllTools(server)
	return server, identity, nil
}

// runMCP serves the protocol over stdio until interrupted.
func runMCP(cmd *cobra.Command, _ []string) error {
	// Diagnostics go to stderr. stdout is the JSON-RPC channel, and a single
	// stray byte there corrupts the session.
	logger := mcpserver.NewStderrLogger(slog.LevelInfo)

	server, identity, err := buildMCPServer(cmd, logger)
	if err != nil {
		return err
	}

	if check, _ := cmd.Flags().GetBool("check"); check {
		return runMCPCheck(cmd, server, identity)
	}

	// Drain in-flight calls on interrupt rather than dropping them.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("mcp server starting",
		"identity", identity,
		"tools", len(server.RegisteredTools()),
		"vault", viper.GetString("mcp.vault"))

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		return fmt.Errorf("mcp server stopped: %w", err)
	}
	logger.Info("mcp server stopped")
	return nil
}

// runMCPCheck is implemented in plan 17.
func runMCPCheck(_ *cobra.Command, _ *mcpserver.Server, _ string) error {
	return fmt.Errorf("--check is not implemented yet")
}
```

Add `"errors"` to the imports. `Version` is the existing package-level version variable used by `cmd/version.go`; if it is named differently there, use that name.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -run 'TestResolveMCP|TestMCPCommand_' -v`
Expected: PASS — all twelve tests.

Then confirm the whole binary still builds and the command appears:

```bash
go build -o rocketvault . && ./rocketvault mcp --help
```

- [ ] **Step 5: Commit**

```bash
git add cmd/mcp.go cmd/mcp_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(cmd): add the rocketvault mcp stdio command

Replaces the root PersistentPreRunE, which is wrong here on three counts: it
refuses remote targets, which is this command's normal operating mode; it
opens a database and builds a ServiceContainer the command never uses; and it
starts a rotating log file, when a stdio subprocess's diagnostics belong on
stderr. serveCmd already overrides it for the second reason.

Identity resolves service account, then cached session, then fails -- there is
no fourth branch, because a server that started without one would fail on its
first tool call, several turns from the actual problem. The failure message
names both ways to fix it, and no message includes the client secret."
```

---

### Task 3: stdout purity and graceful shutdown

**Files:**
- Modify: `cmd/mcp_test.go` (append)
- Modify: `cmd/mcp.go` only if a test reveals a leak

**Interfaces:**
- Consumes: everything from Task 2.
- Produces: no new surface. This task pins the two properties a stdio server cannot get wrong.

**Why stdout purity needs a real test, not a code review:** a stray `fmt.Println` anywhere in the call path — including inside a dependency — corrupts the JSON-RPC stream, and the symptom is a client that fails to initialize with no useful error. Reviewing for it does not scale; asserting it does.

`cliclient.WarnIfInsecure` writes to `os.Stderr` explicitly (`httpclient.go:54`), which is correct. This task confirms nothing else in the startup path writes to stdout.

- [ ] **Step 1: Write the failing test**

Append to `cmd/mcp_test.go`:

```go
// captureStdout runs fn with os.Stdout redirected, returning what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = original }()

	fn()

	require.NoError(t, w.Close())
	captured, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(captured)
}

func TestMCPStartup_WritesNothingToStdout(t *testing.T) {
	resetMCPViper(t)
	t.Setenv("HOME", t.TempDir())

	captured := captureStdout(t, func() {
		cmd := &cobra.Command{}
		cmd.Flags().String("server", "https://vault.example.com", "")
		cmd.Flags().String("ca-cert", "", "")
		cmd.Flags().Bool("insecure-skip-verify", false, "")

		logger := mcpserver.NewStderrLogger(slog.LevelInfo)
		// This fails on identity, which is the point: even the failure path
		// must not touch stdout.
		_, _, _ = buildMCPServer(cmd, logger)
	})

	require.Empty(t, captured,
		"stdout is the JSON-RPC channel; a single stray byte corrupts the session")
}

func TestMCPStartup_LocalFallbackLogsToStderrNotStdout(t *testing.T) {
	resetMCPViper(t)
	viper.Set("server.listen_addr", ":8774")
	t.Setenv("HOME", t.TempDir())

	captured := captureStdout(t, func() {
		cmd := &cobra.Command{}
		cmd.Flags().String("server", "", "")
		cmd.Flags().String("ca-cert", "", "")
		cmd.Flags().Bool("insecure-skip-verify", false, "")

		logger := mcpserver.NewStderrLogger(slog.LevelInfo)
		_, _, _ = buildMCPServer(cmd, logger)
	})

	require.Empty(t, captured,
		"the fallback notice is a diagnostic and belongs on stderr")
}

func TestMCPStartup_InsecureWarningGoesToStderr(t *testing.T) {
	resetMCPViper(t)
	t.Setenv("HOME", t.TempDir())

	captured := captureStdout(t, func() {
		cmd := &cobra.Command{}
		cmd.Flags().String("server", "https://vault.example.com", "")
		cmd.Flags().String("ca-cert", "", "")
		cmd.Flags().Bool("insecure-skip-verify", true, "")

		logger := mcpserver.NewStderrLogger(slog.LevelInfo)
		_, _, _ = buildMCPServer(cmd, logger)
	})

	require.Empty(t, captured,
		"cliclient.WarnIfInsecure writes to stderr; confirm nothing redirects it")
}

func TestMCPStartup_FailureMessagesAreActionable(t *testing.T) {
	resetMCPViper(t)
	t.Setenv("HOME", t.TempDir())

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "https://vault.example.com", "")
	cmd.Flags().String("ca-cert", "", "")
	cmd.Flags().Bool("insecure-skip-verify", false, "")

	logger := mcpserver.NewStderrLogger(slog.LevelInfo)
	_, _, err := buildMCPServer(cmd, logger)

	require.Error(t, err)
	require.Contains(t, err.Error(), "rocketvault users login")
}

func TestMCPStartup_InvalidConfigFailsBeforeAnyNetworkWork(t *testing.T) {
	resetMCPViper(t)
	viper.Set("mcp.max_results", 5000) // Above the ceiling.

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "https://vault.example.com", "")
	cmd.Flags().String("ca-cert", "", "")
	cmd.Flags().Bool("insecure-skip-verify", false, "")

	logger := mcpserver.NewStderrLogger(slog.LevelInfo)
	_, _, err := buildMCPServer(cmd, logger)

	require.ErrorContains(t, err, "max_results",
		"a bad config must fail at startup, not at the first tool call")
}

func TestMCPCommand_HasACheckFlag(t *testing.T) {
	require.NotNil(t, mcpCmd.Flags().Lookup("check"),
		"a misconfiguration otherwise surfaces as an opaque handshake failure in the host")
}
```

Add `"io"`, `"log/slog"`, `"os"`, `"github.com/spf13/cobra"` and `"rocketvault/internal/mcpserver"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestMCPStartup_ -v`
Expected: mostly PASS if Task 2 is correct. Any failure means something in the startup path writes to stdout — find it and fix the source rather than suppressing the output.

`TestMCPCommand_HasACheckFlag` should pass, since Task 2 registered the flag.

- [ ] **Step 3: Write minimal implementation**

No implementation is expected. If a stdout write is found, the fix is to route it to stderr at its source.

One thing to verify by hand: `cobra` prints usage and errors to stdout by default on `RunE` failure. Confirm the command sends both to stderr, and if not, add to `init()`:

```go
	// Cobra writes usage and errors to stdout by default, which would
	// corrupt the protocol stream.
	mcpCmd.SetOut(os.Stderr)
	mcpCmd.SetErr(os.Stderr)
```

This is very likely needed. Treat its absence as a bug, not as the test being wrong.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -race -v` and `go build ./...`
Expected: PASS, race-clean, and the binary builds.

- [ ] **Step 5: Commit**

```bash
git add cmd/mcp.go cmd/mcp_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "test(cmd): pin that mcp startup never writes to stdout

A stray write anywhere in the startup path corrupts the JSON-RPC stream, and
the symptom is a client that fails to initialize with no useful error.
Reviewing for that does not scale; asserting it does.

Cobra writes usage and errors to stdout by default, so the command redirects
both to stderr. Configuration is validated before any network work, so a bad
config fails at startup rather than at the first tool call."
```

---

## Verification

```bash
go build ./...
go test ./cmd/ ./internal/mcpserver/ -race -v
go vet ./cmd/ ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

### End-to-end: this is the milestone

Start a server and log in, in one terminal:

```bash
go build -o rocketvault .
./rocketvault serve &
./rocketvault users login --username admin
```

Confirm the command starts and speaks the protocol. This should print a
JSON-RPC initialize response on stdout and a startup line on stderr:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  | ./rocketvault mcp
```

Confirm stdout carries **only** JSON — this must produce no output at all:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  | ./rocketvault mcp 2>/dev/null | grep -v '^{'
```

Then register it with Claude Code:

```json
{ "mcpServers": { "rocketvault": {
    "command": "/absolute/path/to/rocketvault", "args": ["mcp"] } } }
```

Confirm the tool list shows **exactly ten** read-only tools, and that
`get_secret` exposes no `include_value` argument.

## Notes for the next plan

Plan 17 implements `--check`, replacing the `runMCPCheck` stub, and writes the
install documentation. It is what turns a misconfiguration from an opaque
handshake failure into a clear message.

Everything after that is additive: plans 18-27 add tiers, and each new
`register*Tools` function is added to `RegisterAllTools` — the one place the
tool surface is defined.
