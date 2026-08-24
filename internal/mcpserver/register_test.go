package mcpserver

import (
	"context"
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
