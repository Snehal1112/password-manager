package mcpserver

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	signKeyUUID  = "4a1504e0-4f89-11d3-9a0c-0305e82c3401"
	keysListBody = `{"keys":[
		{"id":"4a1504e0-4f89-11d3-9a0c-0305e82c3401","name":"signing-key","type":"RSA",
		 "enabled":true,"revoked":false,"tags":["prod"],"created_at":"2026-08-01T00:00:00Z"},
		{"id":"4a1504e0-4f89-11d3-9a0c-0305e82c3402","name":"hsm-key","type":"RSA",
		 "enabled":true,"revoked":false,"created_at":"2026-08-02T00:00:00Z"}
	]}`
	keyGetBody = `{"id":"4a1504e0-4f89-11d3-9a0c-0305e82c3401","name":"signing-key","type":"RSA",
		"bits":2048,"enabled":true,"tags":["prod"],"n":"sXchDaQ","e":"AQAB",
		"created_at":"2026-08-01T00:00:00Z"}`
	keyVersionsBody = `[{"key_id":"4a1504e0-4f89-11d3-9a0c-0305e82c3401","version":1,
		"created_at":"2026-06-01T00:00:00Z","n":"old-n","e":"AQAB"}]`
	keyPolicyBody = `{"key_id":"4a1504e0-4f89-11d3-9a0c-0305e82c3401","rotate_after_days":90,
		"notify_before_expiry_days":14,"expiry_days":365,"enabled":true,
		"next_rotation_at":"2026-11-01T00:00:00Z"}`
)

func keyRoutes() map[string]string {
	return map[string]string{
		"/api/v1/vaults/default/keys":                                    keysListBody,
		"/api/v1/vaults/default/keys/" + signKeyUUID:                     keyGetBody,
		"/api/v1/vaults/default/keys/" + signKeyUUID + "/versions":       keyVersionsBody,
		"/api/v1/vaults/default/keys/" + signKeyUUID + "/rotationpolicy": keyPolicyBody,
	}
}

func TestListKeys_ReturnsSummaries(t *testing.T) {
	f := newFakeVault(t, keyRoutes())
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	var got listKeysResult
	structured(t, callTool(t, s, "list_keys", map[string]any{}), &got)

	require.Equal(t, "default", got.Vault)
	require.Len(t, got.Keys, 2)
	require.Equal(t, "signing-key", got.Keys[0].Name)
	require.Equal(t, "RSA", got.Keys[0].Type)
	require.True(t, got.Keys[0].Enabled)
}

func TestListKeys_CarriesNoPrivateMaterial(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"k",
			"value":"-----BEGIN PRIVATE KEY-----LEAKED-----END PRIVATE KEY-----"}]}`,
	})
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	result := callTool(t, s, "list_keys", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}

func TestListKeys_AppliesTheConfiguredMaxResults(t *testing.T) {
	f := newFakeVault(t, keyRoutes())
	cfg := testConfig()
	cfg.MaxResults = 1
	s := f.server(t, cfg)
	registerKeysReadTools(s)

	var got listKeysResult
	structured(t, callTool(t, s, "list_keys", map[string]any{}), &got)
	require.Len(t, got.Keys, 1)
	require.True(t, got.Truncated)
	require.NotEmpty(t, got.Note)
}

func TestListKeys_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, keyRoutes())
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerKeysReadTools(s)

	result := callTool(t, s, "list_keys", map[string]any{"vault": "prod"})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestGetKey_ReturnsMetadataAndPublicComponents(t *testing.T) {
	f := newFakeVault(t, keyRoutes())
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	var got getKeyResult
	structured(t, callTool(t, s, "get_key", map[string]any{"name": "signing-key"}), &got)

	require.Equal(t, "signing-key", got.Name)
	require.Equal(t, "RSA", got.Type)
	require.Equal(t, 2048, got.Bits)
	require.Equal(t, "sXchDaQ", got.PublicJWK.N)
	require.Equal(t, "AQAB", got.PublicJWK.E)
	require.True(t, got.HasPublicComponents)
}

func TestGetKey_IncludesVersionsAndRotationPolicy(t *testing.T) {
	f := newFakeVault(t, keyRoutes())
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	var got getKeyResult
	structured(t, callTool(t, s, "get_key", map[string]any{"name": "signing-key"}), &got)

	require.Len(t, got.Versions, 1)
	require.Equal(t, 1, got.Versions[0].Version)
	require.NotNil(t, got.RotationPolicy)
	require.Equal(t, 90, got.RotationPolicy.RotateAfterDays)
}

func TestGetKey_AbsentRotationPolicyIsNil(t *testing.T) {
	routes := keyRoutes()
	delete(routes, "/api/v1/vaults/default/keys/"+signKeyUUID+"/rotationpolicy")

	f := newFakeVault(t, routes)
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	var got getKeyResult
	structured(t, callTool(t, s, "get_key", map[string]any{"name": "signing-key"}), &got)
	require.Nil(t, got.RotationPolicy, "most keys have no policy, which is not a failure")
	require.Equal(t, "signing-key", got.Name)
}

func TestGetKey_HSMKeyWithoutComponentsIsNormal(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": keysListBody,
		"/api/v1/vaults/default/keys/" + signKeyUUID: `{"id":"` + signKeyUUID + `",
			"name":"signing-key","type":"RSA","enabled":true}`,
	})
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	result := callTool(t, s, "get_key", map[string]any{"name": "signing-key"})
	require.False(t, result.IsError, "an HSM key's absent components are expected, not an error")

	var got getKeyResult
	structured(t, result, &got)
	require.False(t, got.HasPublicComponents)
}

func TestGetKey_CarriesNoPrivateMaterial(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": keysListBody,
		"/api/v1/vaults/default/keys/" + signKeyUUID: `{"id":"` + signKeyUUID + `","name":"signing-key",
			"value":"-----BEGIN PRIVATE KEY-----LEAKED-----END PRIVATE KEY-----"}`,
	})
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	result := callTool(t, s, "get_key", map[string]any{"name": "signing-key"})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
	require.NotContains(t, string(encoded), "PRIVATE KEY")
}

func TestGetKey_ForbiddenSurfacesTheCryptoRoleHint(t *testing.T) {
	f := newFakeVault(t, keyRoutes())
	f.failWith("/api/v1/vaults/default/keys", http.StatusForbidden)
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	result := callTool(t, s, "get_key", map[string]any{"name": "signing-key"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Crypto User")
}

func TestGetKey_RequiresAName(t *testing.T) {
	f := newFakeVault(t, keyRoutes())
	s := f.server(t, testConfig())
	registerKeysReadTools(s)

	result := callTool(t, s, "get_key", map[string]any{})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "name")
}
