package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeleteItem_IsAbsentWithoutAllowDestructive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true // Write alone must not unlock deletion.
	s := f.server(t, cfg)
	registerDestructiveTools(s)

	require.Empty(t, s.RegisteredTools(),
		"allow_write must not be a larger grant than its name suggests")
}

func TestDeleteItem_SoftDeletesTheItem(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got deleteItemResult
	structured(t, callTool(t, s, "delete_item", map[string]any{
		"type": "secrets", "name": "db-password", "confirm": "db-password",
	}), &got)

	require.Equal(t, "db-password", got.Name)
	require.True(t, got.Recoverable, "a soft-deleted item can still be restored")
	require.True(t, f.hit("/api/v1/vaults/default/secrets/"+dbSecretUUID))
}

func TestDeleteItem_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "delete_item", map[string]any{"type": "secrets", "name": "db-password"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "confirm")
	require.Empty(t, f.requested, "an unconfirmed call must make no request at all")
}

func TestDeleteItem_RefusesAMismatchedConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "delete_item", map[string]any{
		"type": "secrets", "name": "db-password", "confirm": "api-key",
	})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestDeleteItem_SkipsConfirmationWhenDisabled(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`

	cfg := destructiveConfig()
	cfg.ConfirmDestructive = false
	s := f.server(t, cfg)
	registerDestructiveTools(s)

	result := callTool(t, s, "delete_item", map[string]any{"type": "secrets", "name": "db-password"})
	require.False(t, result.IsError)
}

func TestPurgeItem_PermanentlyRemovesTheItem(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"old-password"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got purgeItemResult
	structured(t, callTool(t, s, "purge_item", map[string]any{
		"type": "secrets", "name": "old-password", "confirm": "old-password",
	}), &got)

	require.Equal(t, "old-password", got.Name)
	require.True(t, f.hit("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/purge"))
}

func TestPurgeItem_ResolvesAgainstTheDeletedListing(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	_ = callTool(t, s, "purge_item", map[string]any{
		"type": "secrets", "name": "gone", "confirm": "gone",
	})
	require.False(t, f.hit("/api/v1/vaults/default/secrets"),
		"only an already-deleted item can be purged")
}

func TestPurgeItem_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_item", map[string]any{"type": "secrets", "name": "gone"})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestPurgeItem_DescriptionSaysItIsIrreversible(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	var deleteDesc, purgeDesc string
	for _, tool := range tools.Tools {
		switch tool.Name {
		case "delete_item":
			deleteDesc = tool.Description
		case "purge_item":
			purgeDesc = tool.Description
		}
	}

	require.Contains(t, purgeDesc, "annot be undone")
	require.Contains(t, deleteDesc, "recover",
		"the difference between the two is what a caller choosing between them needs")
}

func TestDeleteAndPurge_AreAnnotatedDestructive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	seen := 0
	for _, tool := range tools.Tools {
		if tool.Name != "delete_item" && tool.Name != "purge_item" {
			continue
		}
		seen++
		require.False(t, tool.Annotations.ReadOnlyHint)
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.True(t, *tool.Annotations.DestructiveHint,
			"a host relies on this to prompt; understating it removes the operator's last check")
	}
	require.Equal(t, 2, seen)
}

func TestPurgeItem_ProtectionRefusalIsSurfaced(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.failWith("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/purge", http.StatusForbidden)
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_item", map[string]any{
		"type": "secrets", "name": "gone", "confirm": "gone",
	})
	require.True(t, result.IsError,
		"purge protection is enforced server-side and its refusal must reach the caller")
}

func TestPurgeVault_PurgesTheNamedVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got purgeVaultResult
	structured(t, callTool(t, s, "purge_vault", map[string]any{
		"vault": "default", "confirm": "default",
	}), &got)

	require.Equal(t, "default", got.Vault)
	require.True(t, got.Purged)
	require.True(t, f.hit("/api/v1/vaults/default/purge"))
}

func TestPurgeVault_RequiresAnExplicitVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{"confirm": "default"})
	require.True(t, result.IsError,
		"defaulting the target of an irreversible whole-vault deletion would be reckless")
	require.Contains(t, renderContent(result), "vault")
	require.Empty(t, f.requested)
}

func TestPurgeVault_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{"vault": "default"})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestPurgeVault_ConfirmsTheVaultName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{
		"vault": "default", "confirm": "some-other-vault",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "default")
	require.Empty(t, f.requested)
}

func TestPurgeVault_RespectsTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := destructiveConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{"vault": "prod", "confirm": "prod"})
	require.True(t, result.IsError,
		"a pinned server must not be able to purge a vault outside its scope")
	require.Empty(t, f.requested)
}

func TestPurgeVault_DescriptionSaysItIsIrreversible(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "purge_vault" {
			require.Contains(t, tool.Description, "annot be undone")
			require.True(t, *tool.Annotations.DestructiveHint)
			return
		}
	}
	t.Fatal("purge_vault was not registered")
}

func TestRevokeVaultRole_RevokesByAssignmentID(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got revokeVaultRoleResult
	structured(t, callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": assignmentID, "confirm": assignmentID,
	}), &got)

	require.Equal(t, assignmentID, got.AssignmentID)
	require.True(t, got.Revoked)
	require.True(t, f.hit("/api/v1/vaults/default/role-assignments/"+assignmentID))
}

func TestRevokeVaultRole_RejectsAPrincipalName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": "alice", "confirm": "alice",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "assignment id")
	require.Empty(t, f.requested)
}

func TestRevokeVaultRole_DescriptionPointsAtListRoleAssignments(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "revoke_vault_role" {
			require.Contains(t, tool.Description, "list_role_assignments",
				"a model asked to revoke alice's access needs to know where the id comes from")
			require.Contains(t, tool.Description, "assignment")
			return
		}
	}
	t.Fatal("revoke_vault_role was not registered")
}

func TestRevokeVaultRole_ConfirmsTheAssignmentIDNotAPrincipal(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": assignmentID, "confirm": "alice",
	})
	require.True(t, result.IsError,
		"a principal can hold several roles, so confirming a name would authorise the wrong thing")
	require.Empty(t, f.requested)
}

func TestRevokeVaultRole_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{"assignment_id": assignmentID})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestRevokeVaultRole_ForbiddenNamesTheDataAccessAdminRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults/default/role-assignments/"+assignmentID, http.StatusForbidden)
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": assignmentID, "confirm": assignmentID,
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Data Access Administrator")
}

func TestDestructiveTier_HasExactlyFourTools(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	require.Equal(t,
		[]string{"delete_item", "purge_item", "purge_vault", "revoke_vault_role"},
		s.RegisteredTools())
}
