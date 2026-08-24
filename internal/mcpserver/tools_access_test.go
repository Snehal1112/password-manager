package mcpserver

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const roleAssignmentsBody = `{"role_assignments":[
	{"id":"7d4804e0-4f89-11d3-9a0c-0305e82c3701","principal_id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
	 "principal_username":"mcp-agent","principal_type":"service_account",
	 "role":"Key Vault Secrets User","vault_name":"default","created_at":"2026-08-01T00:00:00Z"},
	{"id":"7d4804e0-4f89-11d3-9a0c-0305e82c3702","principal_id":"3f2504e0-4f89-11d3-9a0c-0305e82c3302",
	 "principal_username":"alice","principal_type":"user",
	 "role":"Key Vault Administrator","vault_name":"default","created_at":"2026-08-02T00:00:00Z"}
],"total":2}`

func TestListRoleAssignments_ReturnsGrants(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/role-assignments": roleAssignmentsBody,
	})
	s := f.server(t, testConfig())
	registerAccessReadTools(s)

	var got listRoleAssignmentsResult
	structured(t, callTool(t, s, "list_role_assignments", map[string]any{}), &got)

	require.Equal(t, "default", got.Vault)
	require.Len(t, got.Assignments, 2)
	require.Equal(t, "Key Vault Secrets User", got.Assignments[0].Role)
	require.Equal(t, "service_account", got.Assignments[0].PrincipalType)
}

func TestListRoleAssignments_WrapsPrincipalUsername(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/role-assignments": roleAssignmentsBody,
	})
	s := f.server(t, testConfig())
	registerAccessReadTools(s)

	result := callTool(t, s, "list_role_assignments", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	require.Contains(t, string(encoded), "UNTRUSTED-VAULT-DATA",
		"a username is chosen at account creation and is user-controlled")
	require.Contains(t, string(encoded), "Key Vault Secrets User")
	require.NotContains(t, string(encoded), "UNTRUSTED-VAULT-DATA>>Key Vault",
		"role names come from a fixed set and are not wrapped")
}

func TestListRoleAssignments_UsesTheRequestedVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/prod/role-assignments": roleAssignmentsBody,
	})
	s := f.server(t, testConfig())
	registerAccessReadTools(s)

	var got listRoleAssignmentsResult
	structured(t, callTool(t, s, "list_role_assignments", map[string]any{"vault": "prod"}), &got)
	require.Equal(t, "prod", got.Vault)
}

func TestListRoleAssignments_ForbiddenNamesTheDataAccessAdminRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults/default/role-assignments", http.StatusForbidden)
	s := f.server(t, testConfig())
	registerAccessReadTools(s)

	result := callTool(t, s, "list_role_assignments", map[string]any{})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Data Access Administrator",
		"this is the role grantable per vault that permits managing assignments")
}

func TestListRoleAssignments_AppliesTheConfiguredMaxResults(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/role-assignments": roleAssignmentsBody,
	})
	cfg := testConfig()
	cfg.MaxResults = 1
	s := f.server(t, cfg)
	registerAccessReadTools(s)

	var got listRoleAssignmentsResult
	structured(t, callTool(t, s, "list_role_assignments", map[string]any{}), &got)
	require.Len(t, got.Assignments, 1)
	require.True(t, got.Truncated)
}

func TestListRoleAssignments_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerAccessReadTools(s)

	result := callTool(t, s, "list_role_assignments", map[string]any{"vault": "prod"})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}
