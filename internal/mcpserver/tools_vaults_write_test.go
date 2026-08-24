package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const prodVaultID = "6c3704e0-4f89-11d3-9a0c-0305e82c3601"

func TestCreateVault_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerVaultsWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestCreateVault_CreatesTheVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + prodVaultID + `","name":"analytics","enabled":true,"retention_days":90}`
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	var got createVaultResult
	structured(t, callTool(t, s, "create_vault", map[string]any{"name": "analytics"}), &got)

	require.Equal(t, "analytics", got.Name)
	require.Equal(t, 90, got.RetentionDays)
	require.Equal(t, "analytics", f.lastWriteBody["name"])
}

func TestCreateVault_OmitsUnsetSecuritySettings(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + prodVaultID + `","name":"analytics"}`
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	_ = callTool(t, s, "create_vault", map[string]any{"name": "analytics"})

	_, present := f.lastWriteBody["purge_protection"]
	require.False(t, present,
		"an unmentioned security setting must mean 'server default', not 'off'")
}

func TestCreateVault_SendsExplicitSecuritySettings(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + prodVaultID + `","name":"analytics"}`
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	_ = callTool(t, s, "create_vault", map[string]any{
		"name": "analytics", "purge_protection": true, "retention_days": 30,
	})

	require.Equal(t, true, f.lastWriteBody["purge_protection"])
	require.EqualValues(t, 30, f.lastWriteBody["retention_days"])
}

func TestCreateVault_RefusesANameOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := writeConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerVaultsWriteTools(s)

	result := callTool(t, s, "create_vault", map[string]any{"name": "analytics"})
	require.True(t, result.IsError,
		"creating a vault this server is then forbidden to touch would be odd to permit")
	require.Empty(t, f.requested)
}

func TestCreateVault_RequiresAName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	require.True(t, callTool(t, s, "create_vault", map[string]any{}).IsError)
}

func TestCreateVault_ConflictIsExplained(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults", http.StatusConflict)
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	result := callTool(t, s, "create_vault", map[string]any{"name": "prod"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "already exists",
		"a duplicate name is the likeliest failure and should read as one")
}

func TestCreateVault_AnnotationsAreHonest(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "create_vault" {
			require.False(t, tool.Annotations.ReadOnlyHint)
			require.False(t, *tool.Annotations.DestructiveHint)
			return
		}
	}
	t.Fatal("create_vault was not registered")
}
