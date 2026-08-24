package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// resetViper gives each test a clean configuration.
func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
}

func TestLoadMCPConfig_DefaultsAreMaximallyRestrictive(t *testing.T) {
	resetViper(t)

	cfg, err := LoadMCPConfig()
	require.NoError(t, err, "an absent mcp section must be valid, not an error")

	require.False(t, cfg.AllowWrite, "writes must be off by default")
	require.False(t, cfg.AllowDestructive, "destructive operations must be off by default")
	require.False(t, cfg.AllowCrypto, "crypto must be off by default")
	require.False(t, cfg.AllowSecretValues, "secret values must be off by default")
	require.True(t, cfg.ConfirmDestructive, "confirmation defaults to on, being the safer value")
	require.Equal(t, "default", cfg.Vault)
	require.Empty(t, cfg.AllowedVaults)
	require.Equal(t, 50, cfg.MaxResults)
	require.Equal(t, 30*time.Second, cfg.RequestTimeout)
	require.Equal(t, 120, cfg.RateLimit.ReadsPerMinute)
	require.Equal(t, 20, cfg.RateLimit.WritesPerMinute)
}

func TestLoadMCPConfig_ReadsEveryFlag(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.vault", "prod")
	viper.Set("mcp.allowed_vaults", []string{"prod", "staging"})
	viper.Set("mcp.allow_write", true)
	viper.Set("mcp.allow_destructive", true)
	viper.Set("mcp.allow_crypto", true)
	viper.Set("mcp.allow_secret_values", true)
	viper.Set("mcp.require_service_account", true)
	viper.Set("mcp.confirm_destructive", false)
	viper.Set("mcp.max_results", 100)
	viper.Set("mcp.request_timeout", "10s")
	viper.Set("mcp.rate_limit.reads_per_minute", 60)
	viper.Set("mcp.rate_limit.writes_per_minute", 5)
	viper.Set("mcp.client_id", "mcp-agent")
	viper.Set("mcp.client_secret", "from-yaml")

	cfg, err := LoadMCPConfig()
	require.NoError(t, err)

	require.Equal(t, "prod", cfg.Vault)
	require.Equal(t, []string{"prod", "staging"}, cfg.AllowedVaults)
	require.True(t, cfg.AllowWrite)
	require.True(t, cfg.AllowDestructive)
	require.True(t, cfg.AllowCrypto)
	require.True(t, cfg.AllowSecretValues)
	require.True(t, cfg.RequireServiceAccount)
	require.False(t, cfg.ConfirmDestructive)
	require.Equal(t, 100, cfg.MaxResults)
	require.Equal(t, 10*time.Second, cfg.RequestTimeout)
	require.Equal(t, 60, cfg.RateLimit.ReadsPerMinute)
	require.Equal(t, 5, cfg.RateLimit.WritesPerMinute)
	require.Equal(t, "mcp-agent", cfg.ClientID)
	require.Equal(t, "from-yaml", cfg.ClientSecret)
}

func TestLoadMCPConfig_EnvSecretOverridesYAML(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.client_id", "mcp-agent")
	viper.Set("mcp.client_secret", "from-yaml")
	t.Setenv("ROCKETVAULT_MCP_CLIENT_SECRET", "from-env")

	cfg, err := LoadMCPConfig()
	require.NoError(t, err)
	require.Equal(t, "from-env", cfg.ClientSecret,
		"the env var must win, so a deployment need not write the secret to disk")
}

func TestLoadMCPConfig_EnvSecretWorksWithNoYAMLValue(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.client_id", "mcp-agent")
	t.Setenv("ROCKETVAULT_MCP_CLIENT_SECRET", "from-env")

	cfg, err := LoadMCPConfig()
	require.NoError(t, err)
	require.Equal(t, "from-env", cfg.ClientSecret)
}

func TestLoadMCPConfig_PartialSectionKeepsOtherDefaults(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.allow_write", true)

	cfg, err := LoadMCPConfig()
	require.NoError(t, err)
	require.True(t, cfg.AllowWrite)
	require.False(t, cfg.AllowDestructive, "enabling one tier must not enable another")
	require.False(t, cfg.AllowSecretValues)
	require.Equal(t, 50, cfg.MaxResults)
}

func TestMCPConfig_RejectsMaxResultsAboveCeiling(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.max_results", MCPMaxResultsCeiling+1)

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "max_results")
	require.ErrorContains(t, err, "200",
		"the message must name the ceiling so the operator can fix it without reading the source")
}

func TestMCPConfig_RejectsNonPositiveMaxResults(t *testing.T) {
	for _, value := range []int{0, -1} {
		resetViper(t)
		viper.Set("mcp.max_results", value)

		_, err := LoadMCPConfig()
		require.ErrorContains(t, err, "max_results", "value %d", value)
	}
}

func TestMCPConfig_AcceptsMaxResultsAtTheCeiling(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.max_results", MCPMaxResultsCeiling)

	cfg, err := LoadMCPConfig()
	require.NoError(t, err, "the ceiling itself must be allowed")
	require.Equal(t, MCPMaxResultsCeiling, cfg.MaxResults)
}

func TestMCPConfig_RejectsEmptyVault(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.vault", "")

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "vault")
}

func TestMCPConfig_RejectsDefaultVaultOutsideTheAllowlist(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.vault", "prod")
	viper.Set("mcp.allowed_vaults", []string{"staging", "dev"})

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "prod")
	require.ErrorContains(t, err, "allowed_vaults",
		"a default vault the server may not touch would fail on every unqualified call")
}

func TestMCPConfig_AcceptsDefaultVaultInsideTheAllowlist(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.vault", "prod")
	viper.Set("mcp.allowed_vaults", []string{"prod", "staging"})

	cfg, err := LoadMCPConfig()
	require.NoError(t, err)
	require.Equal(t, "prod", cfg.Vault)
}

func TestMCPConfig_RejectsRequireServiceAccountWithoutCredentials(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.require_service_account", true)

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "require_service_account")
	require.ErrorContains(t, err, "client_id",
		"demanding a service account while providing none can never start")
}

func TestMCPConfig_RejectsClientIDWithoutSecret(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.client_id", "mcp-agent")

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "client_secret")
}

func TestMCPConfig_RejectsSecretWithoutClientID(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.client_secret", "s3cr3t")

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "client_id")
}

func TestMCPConfig_ValidationErrorsNeverEchoTheSecret(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.client_secret", "hunter2-do-not-leak")

	_, err := LoadMCPConfig()
	require.Error(t, err)
	require.NotContains(t, err.Error(), "hunter2-do-not-leak")
}

func TestMCPConfig_RejectsNonPositiveTimeout(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.request_timeout", "0s")

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "request_timeout")
}

func TestMCPConfig_RejectsNonPositiveRateLimits(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.rate_limit.reads_per_minute", 0)

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "reads_per_minute")

	resetViper(t)
	viper.Set("mcp.rate_limit.writes_per_minute", -5)

	_, err = LoadMCPConfig()
	require.ErrorContains(t, err, "writes_per_minute")
}

func TestMCPConfig_RejectsBlankEntriesInAllowedVaults(t *testing.T) {
	resetViper(t)
	viper.Set("mcp.vault", "prod")
	viper.Set("mcp.allowed_vaults", []string{"prod", ""})

	_, err := LoadMCPConfig()
	require.ErrorContains(t, err, "allowed_vaults")
}
