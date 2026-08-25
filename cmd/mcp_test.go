package cmd

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/config"
	"rocketvault/internal/mcpserver"
	"rocketvault/internal/vaultapi"
)

func resetMCPViper(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
}

// withEmptySessionCache ensures no cached CLI session is found.
//
// common.SessionBaseDir is a package-level var computed once at package init
// from $HOME, so t.Setenv("HOME", ...) has no effect on it. Overriding it
// directly is the documented and already-established convention elsewhere in
// this codebase.
func withEmptySessionCache(t *testing.T) {
	t.Helper()
	original := common.SessionBaseDir
	common.SessionBaseDir = t.TempDir()
	t.Cleanup(func() { common.SessionBaseDir = original })
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
	withEmptySessionCache(t)

	cfg := config.MCPConfig{}
	_, _, err := resolveMCPTokenSource(cfg, "https://vault.example.com", http.DefaultClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rocketvault users login",
		"the message must name both ways to fix it")
	require.Contains(t, err.Error(), "client_id")
}

func TestResolveMCPTokenSource_NeverReturnsANilSourceWithoutAnError(t *testing.T) {
	withEmptySessionCache(t)

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
	withEmptySessionCache(t)

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
	withEmptySessionCache(t)

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
	withEmptySessionCache(t)

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
	withEmptySessionCache(t)

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
