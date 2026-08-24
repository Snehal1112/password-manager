package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// writeConfig returns a config with the write tier enabled.
func writeConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowWrite = true
	return cfg
}

func TestSetSecret_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerSecretsWriteTools(s)

	require.Empty(t, s.RegisteredTools(),
		"a write tool must not exist at all when the tier is off")
}

func TestSetSecret_CreatesANewSecret(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","version":1}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	var got setSecretResult
	structured(t, callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "s3cr3t",
	}), &got)

	require.True(t, got.Created)
	require.Equal(t, "api-key", got.Name)
	require.Equal(t, 1, got.Version)
	require.Equal(t, "default", got.Vault)
}

func TestSetSecret_UpdatesAnExistingSecret(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"db-password","version":5}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	var got setSecretResult
	structured(t, callTool(t, s, "set_secret", map[string]any{
		"name": "db-password", "value": "new-value",
	}), &got)

	require.False(t, got.Created, "an existing name is an update")
	require.Equal(t, 5, got.Version)
}

func TestSetSecret_NeverEchoesTheValueBack(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","value":"s3cr3t-echo","version":1}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{"name": "api-key", "value": "s3cr3t-echo"})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	require.NotContains(t, string(encoded), "s3cr3t-echo",
		"the caller supplied the value; there is no reason to send it back")
}

func TestSetSecret_WorksWithDisclosureDisabled(t *testing.T) {
	// Supplying a value is not the same as being shown one.
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","version":1}`

	cfg := writeConfig()
	cfg.AllowSecretValues = false
	s := f.server(t, cfg)
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{"name": "api-key", "value": "s3cr3t"})
	require.False(t, result.IsError,
		"allow_secret_values governs reading, not writing")
}

func TestSetSecret_AcceptsOptionalMetadata(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","version":1}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "s3cr3t",
		"tags": []any{"prod"}, "content_type": "text/plain",
		"expires_at": "2027-01-01T00:00:00Z",
	})
	require.False(t, result.IsError)
	require.Equal(t, "text/plain", f.lastWriteBody["content_type"])
	require.NotNil(t, f.lastWriteBody["expires_at"])
}

func TestSetSecret_RejectsAnUnparseableExpiry(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "s3cr3t", "expires_at": "next tuesday",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "RFC3339",
		"the error must say what format is expected, so the model can retry correctly")
}

func TestSetSecret_RequiresANameAndValue(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	require.True(t, callTool(t, s, "set_secret", map[string]any{"value": "v"}).IsError)
	require.True(t, callTool(t, s, "set_secret", map[string]any{"name": "n"}).IsError)
}

func TestSetSecret_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := writeConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "v", "vault": "prod",
	})
	require.True(t, result.IsError)
	require.Empty(t, f.requested, "a refused vault must produce no request at all")
}

func TestSetSecret_AnnotationsAreHonest(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "set_secret" {
			continue
		}
		require.False(t, tool.Annotations.ReadOnlyHint)
		require.False(t, tool.Annotations.IdempotentHint,
			"calling it twice creates two versions, so it is not idempotent")
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.False(t, *tool.Annotations.DestructiveHint,
			"an update adds a version rather than removing the old one")
		return
	}
	t.Fatal("set_secret was not registered")
}

func TestSetSecret_ForbiddenSurfacesTheOfficerRoleHint(t *testing.T) {
	// The forbidden response must land on the write itself, not the
	// existence-check GET that SetSecret issues first: both hit the same
	// list path, and a GET failure there would surface a read-tier hint
	// instead of the write-tier one this test pins.
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"api-key"}],"total":1}`,
	})
	f.failWith("/api/v1/vaults/default/secrets/"+dbSecretUUID, http.StatusForbidden)
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{"name": "api-key", "value": "v"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Secrets Officer")
}
