package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// serverWithTiers builds a server whose four capability flags are set as
// given, then registers one tool per tier.
func serverWithTiers(t *testing.T, write, destructive, crypto bool) *Server {
	t.Helper()

	cfg := testConfig()
	cfg.AllowWrite = write
	cfg.AllowDestructive = destructive
	cfg.AllowCrypto = crypto

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	noop := func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
		return nil, pingOut{}, nil
	}
	registerIf(s, TierRead, "read_tool", "A read tool.", Annotations{ReadOnly: true}, noop)
	registerIf(s, TierWrite, "write_tool", "A write tool.", Annotations{}, noop)
	registerIf(s, TierDestructive, "destructive_tool", "A destructive tool.", Annotations{Destructive: true}, noop)
	registerIf(s, TierCrypto, "crypto_tool", "A crypto tool.", Annotations{}, noop)
	return s
}

func TestGating_ReadTierIsAlwaysRegistered(t *testing.T) {
	s := serverWithTiers(t, false, false, false)
	require.Equal(t, []string{"read_tool"}, s.RegisteredTools())
}

func TestGating_DisabledTiersAreAbsentFromToolsList(t *testing.T) {
	s := serverWithTiers(t, false, false, false)
	cs := connect(t, s)

	require.Equal(t, []string{"read_tool"}, toolNames(t, cs),
		"a disabled tool must be absent, not present-but-refusing: absent costs no context")
}

func TestGating_EachFlagEnablesOnlyItsOwnTier(t *testing.T) {
	cases := []struct {
		name                       string
		write, destructive, crypto bool
		want                       []string
	}{
		{"none", false, false, false, []string{"read_tool"}},
		{"write only", true, false, false, []string{"read_tool", "write_tool"}},
		{"destructive only", false, true, false, []string{"destructive_tool", "read_tool"}},
		{"crypto only", false, false, true, []string{"crypto_tool", "read_tool"}},
		{"all", true, true, true, []string{"crypto_tool", "destructive_tool", "read_tool", "write_tool"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := serverWithTiers(t, tc.write, tc.destructive, tc.crypto)
			require.Equal(t, tc.want, s.RegisteredTools())
		})
	}
}

func TestGating_DisabledToolCannotBeCalledAtAll(t *testing.T) {
	s := serverWithTiers(t, false, false, false)
	cs := connect(t, s)

	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "destructive_tool", Arguments: map[string]any{"message": "x"},
	})
	require.Error(t, err, "an unregistered tool is a protocol-level unknown-tool error")
}

func TestTierEnabled_ReportsTheConfiguredTiers(t *testing.T) {
	s := serverWithTiers(t, true, false, true)
	require.True(t, s.TierEnabled(TierRead))
	require.True(t, s.TierEnabled(TierWrite))
	require.False(t, s.TierEnabled(TierDestructive))
	require.True(t, s.TierEnabled(TierCrypto))
}

func TestResolveVault_FallsBackToTheConfiguredDefault(t *testing.T) {
	s := newTestServer(t)
	got, err := s.ResolveVault("")
	require.NoError(t, err)
	require.Equal(t, "default", got)
}

func TestResolveVault_PrefersAnExplicitRequest(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "default"
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	got, err := s.ResolveVault("prod")
	require.NoError(t, err)
	require.Equal(t, "prod", got)
}

func TestResolveVault_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging", "dev"}
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	_, err = s.ResolveVault("prod")
	require.ErrorContains(t, err, "prod")
	require.ErrorContains(t, err, "not permitted")
}

func TestResolveVault_AllowsAVaultInsideTheAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging", "prod"}
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	got, err := s.ResolveVault("prod")
	require.NoError(t, err)
	require.Equal(t, "prod", got)
}

func TestResolveVault_EmptyAllowlistPermitsAnyVault(t *testing.T) {
	s := newTestServer(t)
	got, err := s.ResolveVault("anything-at-all")
	require.NoError(t, err)
	require.Equal(t, "anything-at-all", got,
		"an empty allowlist defers to RBAC, which already bounds what the principal can reach")
}

func TestResolveVault_RejectsAMalformedVaultName(t *testing.T) {
	// Every other identifier that reaches a vaultapi URL path is a resolved
	// UUID; the vault segment is the one caller-supplied string that is not.
	// Validating it here, before it can reach path construction, is defense
	// in depth independent of whether any transport-level exploit exists.
	s := newTestServer(t)

	_, err := s.ResolveVault("prod/../../secrets")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "not permitted",
		"this must fail validation, not the allowlist check")
}

func TestResolveVault_ErrorNamesThePermittedVaults(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging", "dev"}
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	_, err = s.ResolveVault("prod")
	require.ErrorContains(t, err, "staging")
	require.ErrorContains(t, err, "dev",
		"naming the permitted set lets the model correct itself instead of guessing")
}

var _ = config.MCPConfig{}
