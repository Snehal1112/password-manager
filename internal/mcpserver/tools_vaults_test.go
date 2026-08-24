package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const vaultsListBody = `{"vaults":[
	{"id":"6c3704e0-4f89-11d3-9a0c-0305e82c3601","name":"default","enabled":true,
	 "purge_protection":false,"retention_days":30,"created_at":"2026-01-01T00:00:00Z"},
	{"id":"6c3704e0-4f89-11d3-9a0c-0305e82c3602","name":"prod","enabled":true,
	 "purge_protection":true,"retention_days":90,"created_at":"2026-02-01T00:00:00Z",
	 "tags":{"env":"production"}},
	{"id":"6c3704e0-4f89-11d3-9a0c-0305e82c3603","name":"staging","enabled":true,
	 "purge_protection":false,"retention_days":7,"created_at":"2026-03-01T00:00:00Z"}
],"total":3}`

func TestListVaults_ReturnsEveryVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults": vaultsListBody})
	s := f.server(t, testConfig())
	registerVaultsReadTools(s)

	var got listVaultsResult
	structured(t, callTool(t, s, "list_vaults", map[string]any{}), &got)

	require.Len(t, got.Vaults, 3)
	require.Equal(t, "default", got.Vaults[0].Name)
	require.Equal(t, "prod", got.Vaults[1].Name)
	require.True(t, got.Vaults[1].PurgeProtection)
	require.Equal(t, 90, got.Vaults[1].RetentionDays)
	require.Zero(t, got.FilteredOut)
}

func TestListVaults_TakesNoVaultArgument(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults": vaultsListBody})
	s := f.server(t, testConfig())
	registerVaultsReadTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "list_vaults" {
			continue
		}
		encoded, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(encoded, &schema))
		properties, _ := schema["properties"].(map[string]any)

		_, present := properties["vault"]
		require.False(t, present, "listing vaults cannot be scoped to one vault")
		return
	}
	t.Fatal("list_vaults was not registered")
}

func TestListVaults_FiltersToTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults": vaultsListBody})

	cfg := testConfig()
	cfg.Vault = "prod"
	cfg.AllowedVaults = []string{"prod"}
	s := f.server(t, cfg)
	registerVaultsReadTools(s)

	var got listVaultsResult
	structured(t, callTool(t, s, "list_vaults", map[string]any{}), &got)

	require.Len(t, got.Vaults, 1)
	require.Equal(t, "prod", got.Vaults[0].Name)
	require.Equal(t, 2, got.FilteredOut,
		"the count distinguishes 'no others exist' from 'this server will not show them'")
}

func TestListVaults_EmptyAllowlistFiltersNothing(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults": vaultsListBody})
	s := f.server(t, testConfig())
	registerVaultsReadTools(s)

	var got listVaultsResult
	structured(t, callTool(t, s, "list_vaults", map[string]any{}), &got)
	require.Len(t, got.Vaults, 3)
	require.Zero(t, got.FilteredOut)
}

func TestListVaults_IncludeDeletedIsPassedThrough(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults": vaultsListBody})
	s := f.server(t, testConfig())
	registerVaultsReadTools(s)

	var got listVaultsResult
	structured(t, callTool(t, s, "list_vaults", map[string]any{"include_deleted": true}), &got)
	require.NotEmpty(t, got.Vaults)
	require.True(t, f.hit("/api/v1/vaults"))
}

func TestListVaults_WrapsTagValues(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults": vaultsListBody})
	s := f.server(t, testConfig())
	registerVaultsReadTools(s)

	result := callTool(t, s, "list_vaults", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "UNTRUSTED-VAULT-DATA",
		"vault tags are operator-written free text")
}

func TestListVaults_AppliesTheConfiguredMaxResults(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults": vaultsListBody})

	cfg := testConfig()
	cfg.MaxResults = 2
	s := f.server(t, cfg)
	registerVaultsReadTools(s)

	var got listVaultsResult
	structured(t, callTool(t, s, "list_vaults", map[string]any{}), &got)
	require.Len(t, got.Vaults, 2)
	require.True(t, got.Truncated)
}

func TestListVaults_ForbiddenIsAnError(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults", http.StatusForbidden)
	s := f.server(t, testConfig())
	registerVaultsReadTools(s)

	result := callTool(t, s, "list_vaults", map[string]any{})
	require.True(t, result.IsError)
}
