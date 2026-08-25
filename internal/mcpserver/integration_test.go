//go:build integration

package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// liveConfig returns a config with every tier enabled, for exercising the
// full surface against a real server.
func liveConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowWrite = true
	cfg.AllowDestructive = true
	cfg.AllowCrypto = true
	cfg.AllowSecretValues = true
	cfg.ConfirmDestructive = true
	return cfg
}

// callLive invokes a tool and requires success, reporting the tool's own
// error text on failure.
func callLive(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	require.False(t, result.IsError, "%s failed: %s", name, renderContent(result))
	return result
}

func TestLive_ListVaultsSeesTheDefaultVault(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var got listVaultsResult
	structured(t, callLive(t, cs, "list_vaults", map[string]any{}), &got)

	var names []string
	for _, vault := range got.Vaults {
		names = append(names, vault.Name)
	}
	require.Contains(t, names, "default",
		"every deployment ships a default vault")
}

func TestLive_SetThenGetSecretRoundTrips(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var set setSecretResult
	structured(t, callLive(t, cs, "set_secret", map[string]any{
		"name": "integration-secret", "value": "integration-value",
	}), &set)
	require.True(t, set.Created)

	var got getSecretResult
	structured(t, callLive(t, cs, "get_secret", map[string]any{
		"name": "integration-secret", "include_value": true,
	}), &got)

	require.Equal(t, "integration-secret", got.Name)
	require.Equal(t, "integration-value", got.Value,
		"a real round trip through encryption, storage and decryption")
	require.True(t, got.ValueDisclosed)
}

func TestLive_SetSecretTwiceCreatesASecondVersion(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var first setSecretResult
	structured(t, callLive(t, cs, "set_secret", map[string]any{
		"name": "versioned", "value": "v1",
	}), &first)
	require.True(t, first.Created)

	var second setSecretResult
	structured(t, callLive(t, cs, "set_secret", map[string]any{
		"name": "versioned", "value": "v2",
	}), &second)
	require.False(t, second.Created, "the second call is an update")
	require.Greater(t, second.Version, first.Version)
}

func TestLive_ListSecretsUsesTheRealWrapperKey(t *testing.T) {
	// This is the class of failure the unit suite cannot catch: if the
	// wrapper key were misread, the fake would carry the same wrong key and
	// both would agree.
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "listed", "value": "x"})

	var got listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{}), &got)

	require.NotEmpty(t, got.Secrets, "a decoded empty list would mean the wrapper key is wrong")
	require.Equal(t, "listed", got.Secrets[0].Name)
}

func TestLive_ListSecretsNeverCarriesValues(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "hidden", "value": "must-not-appear"})

	result := callLive(t, cs, "list_secrets", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "must-not-appear",
		"the real list route omits values, and this proves it rather than assuming")
}

func TestLive_CreateAndGetKeyReturnsPublicComponents(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "integration-key", "type": "RSA", "bits": 2048,
	})

	var got getKeyResult
	structured(t, callLive(t, cs, "get_key", map[string]any{"name": "integration-key"}), &got)

	require.Equal(t, "RSA", got.Type)
	require.True(t, got.HasPublicComponents,
		"a software RSA key must expose n and e; empty components would mean the JWK path is broken")
	require.NotEmpty(t, got.PublicJWK.N)
	require.NotEmpty(t, got.PublicJWK.E)
}

func TestLive_GetKeyNeverReturnsPrivateMaterial(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "private-check", "type": "RSA", "bits": 2048,
	})

	result := callLive(t, cs, "get_key", map[string]any{"name": "private-check"})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	require.NotContains(t, string(encoded), "PRIVATE KEY")
	require.NotContains(t, string(encoded), "BEGIN RSA")
}

func TestLive_SignThenVerifyRoundTrips(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "sign-key", "type": "RSA", "bits": 2048,
	})

	data := base64.StdEncoding.EncodeToString([]byte("integration payload"))

	var signed signResult
	structured(t, callLive(t, cs, "sign", map[string]any{
		"key_name": "sign-key", "data_base64": data,
	}), &signed)
	require.NotEmpty(t, signed.SignatureBase64)

	var checked verifyResult
	structured(t, callLive(t, cs, "verify", map[string]any{
		"key_name": "sign-key", "data_base64": data,
		"signature_base64": signed.SignatureBase64,
		"algorithm":        signed.Algorithm,
	}), &checked)

	require.True(t, checked.Valid,
		"a signature this server produced must verify against it")
}

func TestLive_VerifyRejectsATamperedSignature(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "tamper-key", "type": "RSA", "bits": 2048,
	})

	data := base64.StdEncoding.EncodeToString([]byte("payload"))
	var signed signResult
	structured(t, callLive(t, cs, "sign", map[string]any{
		"key_name": "tamper-key", "data_base64": data,
	}), &signed)

	var checked verifyResult
	structured(t, callLive(t, cs, "verify", map[string]any{
		"key_name":         "tamper-key",
		"data_base64":      base64.StdEncoding.EncodeToString([]byte("different payload")),
		"signature_base64": signed.SignatureBase64,
		"algorithm":        signed.Algorithm,
	}), &checked)

	require.False(t, checked.Valid, "different data must not verify")
}

func TestLive_DeleteThenRecoverRestoresTheSecret(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "doomed", "value": "x"})

	callLive(t, cs, "delete_item", map[string]any{
		"type": "secrets", "name": "doomed", "confirm": "doomed",
	})

	var deleted listDeletedResult
	structured(t, callLive(t, cs, "list_deleted", map[string]any{"type": "secrets"}), &deleted)

	var names []string
	for _, item := range deleted.Items {
		names = append(names, item.Name)
	}
	require.Contains(t, names, "doomed",
		"the deleted listing is a different route with a different wrapper key")

	callLive(t, cs, "recover_deleted", map[string]any{"type": "secrets", "name": "doomed"})

	var listed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{}), &listed)

	var liveNames []string
	for _, secret := range listed.Secrets {
		liveNames = append(liveNames, secret.Name)
	}
	require.Contains(t, liveNames, "doomed", "recovery must return it to the live listing")
}

func TestLive_UnconfirmedDeleteChangesNothing(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "survivor", "value": "x"})

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "delete_item", Arguments: map[string]any{"type": "secrets", "name": "survivor"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)

	var listed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{}), &listed)

	var names []string
	for _, secret := range listed.Secrets {
		names = append(names, secret.Name)
	}
	require.Contains(t, names, "survivor",
		"a refused confirmation must leave the vault untouched")
}

func TestLive_AllowlistRefusesAnUnpermittedVault(t *testing.T) {
	live := startLiveVault(t)

	cfg := liveConfig()
	cfg.Vault = "default"
	cfg.AllowedVaults = []string{"default"}
	cs := connect(t, live.mcpServer(t, cfg))

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "list_secrets", Arguments: map[string]any{"vault": "some-other-vault"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "not permitted",
		"the guard refuses locally, before the server is even asked")
}

func TestLive_CreateVaultThenUseIt(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_vault", map[string]any{"name": "integration-vault"})

	// Creating a vault grants no data-plane access on it, same as "default"
	// -- see the comment in startLiveVault.
	live.grantVaultRole(t, "integration-vault", "itadmin", "Key Vault Administrator")

	callLive(t, cs, "set_secret", map[string]any{
		"name": "scoped", "value": "x", "vault": "integration-vault",
	})

	var listed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{"vault": "integration-vault"}), &listed)
	require.Len(t, listed.Secrets, 1)

	// The default vault must not see it: vault scoping is a real boundary.
	var defaultListed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{"vault": "default"}), &defaultListed)

	for _, secret := range defaultListed.Secrets {
		require.NotEqual(t, "scoped", secret.Name,
			"a secret in one vault must not appear in another")
	}
}

func TestLive_GrantThenListRoleAssignment(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var granted grantVaultRoleResult
	structured(t, callLive(t, cs, "grant_vault_role", map[string]any{
		"principal": "itadmin", "role": "Key Vault Secrets User",
	}), &granted)
	require.NotEmpty(t, granted.AssignmentID)

	var listed listRoleAssignmentsResult
	structured(t, callLive(t, cs, "list_role_assignments", map[string]any{}), &listed)

	var ids []string
	for _, assignment := range listed.Assignments {
		ids = append(ids, assignment.ID)
	}
	require.Contains(t, ids, granted.AssignmentID,
		"the id a grant returns must be the one a revoke can use")
}

func TestLive_ToolsListMatchesTheGatingTable(t *testing.T) {
	live := startLiveVault(t)

	// Default configuration against a real server: exactly the read tier.
	cs := connect(t, live.mcpServer(t, testConfig()))
	require.Len(t, toolNames(t, cs), 10)

	full := connect(t, live.mcpServer(t, liveConfig()))
	require.Len(t, toolNames(t, full), 27)
}

func TestLive_UnknownSecretGivesAnActionableError(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "db-password", "value": "x"})

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_secret", Arguments: map[string]any{"name": "db-pass"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "did you mean",
		"near-miss suggestions must work against real data, not just fixtures")
	require.Contains(t, renderContent(result), "db-password")
}

func TestLive_LoginSwapsIdentityForSubsequentCalls(t *testing.T) {
	live := startLiveVault(t)
	cfg := liveConfig()
	cfg.AllowInteractiveLogin = true
	cs := connect(t, live.mcpServer(t, cfg))

	var login loginResult
	structured(t, callLive(t, cs, "login", map[string]any{
		"username":  "itadmin",
		"password":  "Integration-Test-Pass-1",
		"totp_code": totpCode(t, live.TOTPSecret),
	}), &login)

	require.Equal(t, "itadmin", login.Username)
	require.NotEmpty(t, login.ExpiresAt)

	// A read tool called after login must still succeed -- it now runs
	// under a freshly issued token rather than the harness's original one,
	// but the same admin identity, so authorization still passes.
	var vaults listVaultsResult
	structured(t, callLive(t, cs, "list_vaults", map[string]any{}), &vaults)

	var names []string
	for _, vault := range vaults.Vaults {
		names = append(names, vault.Name)
	}
	require.Contains(t, names, "default")
}

func TestLive_LoginIsAbsentWithoutTheFlag(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig())) // AllowInteractiveLogin left false

	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "itadmin", "password": "x", "totp_code": "000000"},
	})
	require.Error(t, err, "an unregistered tool must be rejected by the protocol, not reachable at all")
}
