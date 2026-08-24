package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

const secretsListBody = `{"secrets":[
	{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","name":"db-password","version":3,
	 "tags":["prod","db"],"created_at":"2026-08-01T00:00:00Z"},
	{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3302","name":"api-key","version":1,
	 "created_at":"2026-08-02T00:00:00Z"}
],"total":2}`

// callTool invokes name with args and returns the raw result.
func callTool(t *testing.T, s *Server, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	return result
}

func TestListSecrets_ReturnsSummaries(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{}), &got)

	require.Equal(t, "default", got.Vault)
	require.Len(t, got.Secrets, 2)
	require.Equal(t, "db-password", got.Secrets[0].Name)
	require.Equal(t, 3, got.Secrets[0].Version)
	require.False(t, got.Truncated)
}

func TestListSecrets_NeverReturnsValues(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "value",
		"listing is metadata only; no value field may appear at all")
}

func TestListSecrets_WrapsTagsAsUntrusted(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "UNTRUSTED-VAULT-DATA",
		"tags are user-written and must be marked")
}

func TestListSecrets_UsesTheRequestedVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/prod/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{"vault": "prod"}), &got)
	require.Equal(t, "prod", got.Vault)
	require.True(t, f.hit("/api/v1/vaults/prod/secrets"))
}

func TestListSecrets_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/prod/secrets": secretsListBody})

	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{"vault": "prod"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "not permitted")
	require.Empty(t, f.requested, "a refused vault must not produce a request")
}

func TestListSecrets_AppliesTheConfiguredMaxResults(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})

	cfg := testConfig()
	cfg.MaxResults = 1
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{}), &got)

	require.Len(t, got.Secrets, 1)
	require.True(t, got.Truncated)
	require.NotEmpty(t, got.Note, "a truncated list must say so rather than look complete")
}

func TestListSecrets_CapsAnOversizedRequestedLimit(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})

	cfg := testConfig()
	cfg.MaxResults = 1
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{"limit": 500}), &got)
	require.Len(t, got.Secrets, 1,
		"a model asking for more than the configured cap gets the cap, not its request")
}

func TestListSecrets_SurfacesAForbiddenWithItsHint(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults/default/secrets", http.StatusForbidden)
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Secrets User",
		"the 403 hint must reach the model so the operator learns which grant is missing")
}

func TestListSecrets_IsAnnotatedReadOnly(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "list_secrets" {
			require.True(t, tool.Annotations.ReadOnlyHint)
			require.False(t, *tool.Annotations.DestructiveHint)
			return
		}
	}
	t.Fatal("list_secrets was not registered")
}
