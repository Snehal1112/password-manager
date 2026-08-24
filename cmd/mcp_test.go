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
	// common.SessionBaseDir is a package-level var computed once at package
	// init from $HOME, so t.Setenv("HOME", ...) has no effect on it here.
	// Override it directly, per its own "Overridable in tests" contract.
	original := common.SessionBaseDir
	common.SessionBaseDir = t.TempDir()
	t.Cleanup(func() { common.SessionBaseDir = original })

	cfg := config.MCPConfig{}
	_, _, err := resolveMCPTokenSource(cfg, "https://vault.example.com", http.DefaultClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rocketvault users login",
		"the message must name both ways to fix it")
	require.Contains(t, err.Error(), "client_id")
}

func TestResolveMCPTokenSource_NeverReturnsANilSourceWithoutAnError(t *testing.T) {
	original := common.SessionBaseDir
	common.SessionBaseDir = t.TempDir()
	t.Cleanup(func() { common.SessionBaseDir = original })

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
