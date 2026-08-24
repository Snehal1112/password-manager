package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const assignmentID = "7d4804e0-4f89-11d3-9a0c-0305e82c3701"

func TestGrantVaultRole_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerAccessWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestGrantVaultRole_GrantsTheRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + assignmentID + `","principal_id":"` + dbSecretUUID + `",
		"principal_username":"mcp-agent","principal_type":"service_account",
		"role":"Key Vault Secrets User","vault_name":"default"}`
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	var got grantVaultRoleResult
	structured(t, callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "mcp-agent", "role": "Key Vault Secrets User",
		"principal_type": "service_account",
	}), &got)

	require.Equal(t, "Key Vault Secrets User", got.Role)
	require.Equal(t, "default", got.Vault)
	require.Equal(t, "mcp-agent", f.lastWriteBody["principal"])
	require.Equal(t, "service_account", f.lastWriteBody["principal_type"])
}

func TestGrantVaultRole_DefaultsPrincipalTypeToUser(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + assignmentID + `","role":"Key Vault Reader"}`
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	_ = callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Reader",
	})

	_, present := f.lastWriteBody["principal_type"]
	require.False(t, present, "the server defaults it; sending nothing is correct")
}

func TestGrantVaultRole_RestatesWhatWasGranted(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + assignmentID + `","principal_username":"alice",
		"principal_type":"user","role":"Key Vault Administrator"}`
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	var got grantVaultRoleResult
	structured(t, callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Administrator",
	}), &got)

	require.Equal(t, "Key Vault Administrator", got.Role)
	require.NotEmpty(t, got.AssignmentID,
		"the assignment id is what a later revoke needs")
}

func TestGrantVaultRole_RequiresPrincipalAndRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	require.True(t, callTool(t, s, "grant_vault_role", map[string]any{"role": "Key Vault Reader"}).IsError)
	require.True(t, callTool(t, s, "grant_vault_role", map[string]any{"principal": "alice"}).IsError)
}

func TestGrantVaultRole_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := writeConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerAccessWriteTools(s)

	result := callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Reader", "vault": "prod",
	})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestGrantVaultRole_ForbiddenNamesTheDataAccessAdminRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults/default/role-assignments", http.StatusForbidden)
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	result := callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Reader",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Data Access Administrator")
}

func TestGrantVaultRole_DescriptionNamesItsRequirement(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "grant_vault_role" {
			require.Contains(t, tool.Description, "Data Access Administrator",
				"a role grant changes who can reach the vault; the requirement should be visible up front")
			require.False(t, tool.Annotations.ReadOnlyHint)
			return
		}
	}
	t.Fatal("grant_vault_role was not registered")
}
