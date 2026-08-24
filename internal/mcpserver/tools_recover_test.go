package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecoverDeleted_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerRecoverTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestRecoverDeleted_IsPresentWithAllowWriteAlone(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	cfg.AllowDestructive = false
	s := f.server(t, cfg)
	registerRecoverTools(s)

	require.Equal(t, []string{"recover_deleted"}, s.RegisteredTools(),
		"recovery is additive; gating it behind the destructive tier would mean "+
			"an operator who can write cannot undo a deletion")
}

func TestRecoverDeleted_RestoresTheItem(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"old-password"}],"total":1}`,
	})
	f.writeResponse = `{"message":"Secret recovered successfully","id":"` + dbSecretUUID + `"}`

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	var got recoverDeletedResult
	structured(t, callTool(t, s, "recover_deleted", map[string]any{
		"type": "secrets", "name": "old-password",
	}), &got)

	require.Equal(t, "old-password", got.Name)
	require.Equal(t, "secrets", got.Type)
	require.Equal(t, "default", got.Vault)
	require.True(t, f.hit("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/restore"))
}

func TestRecoverDeleted_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind string
		path string
		body string
		id   string
	}{
		{"secrets", "/api/v1/vaults/default/deleted/secrets",
			`{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`, dbSecretUUID},
		{"keys", "/api/v1/vaults/default/deleted/keys",
			`{"deleted_keys":[{"id":"` + signKeyUUID + `","name":"gone"}],"total":1}`, signKeyUUID},
		{"certificates", "/api/v1/vaults/default/deleted/certificates",
			`{"deleted_certificates":[{"id":"` + tlsCertUUID + `","name":"gone"}],"total":1}`, tlsCertUUID},
	}

	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			f := newFakeVault(t, map[string]string{tc.path: tc.body})
			f.writeResponse = `{"message":"recovered","id":"` + tc.id + `"}`

			cfg := testConfig()
			cfg.AllowWrite = true
			s := f.server(t, cfg)
			registerRecoverTools(s)

			result := callTool(t, s, "recover_deleted", map[string]any{"type": tc.kind, "name": "gone"})
			require.False(t, result.IsError)
			require.True(t, f.hit("/api/v1/vaults/default/deleted/"+tc.kind+"/"+tc.id+"/restore"))
		})
	}
}

func TestRecoverDeleted_NeedsNoConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.writeResponse = `{"message":"recovered","id":"` + dbSecretUUID + `"}`

	cfg := destructiveConfig() // ConfirmDestructive is on.
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "secrets", "name": "gone"})
	require.False(t, result.IsError,
		"recovery undoes damage; asking to confirm it adds friction where friction is unhelpful")
}

func TestRecoverDeleted_UnknownNamePointsAtListDeleted(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[],"total":0}`,
	})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "secrets", "name": "nope"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "list_deleted")
}

func TestRecoverDeleted_RejectsAnUnknownType(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "vaults", "name": "x"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "secrets")
	require.Empty(t, f.requested)
}

func TestRecoverDeleted_RequiresTypeAndName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	require.True(t, callTool(t, s, "recover_deleted", map[string]any{"name": "x"}).IsError)
	require.True(t, callTool(t, s, "recover_deleted", map[string]any{"type": "secrets"}).IsError)
}

func TestRecoverDeleted_IsNotAnnotatedDestructive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "recover_deleted" {
			require.False(t, tool.Annotations.ReadOnlyHint)
			require.NotNil(t, tool.Annotations.DestructiveHint)
			require.False(t, *tool.Annotations.DestructiveHint,
				"restoring an item destroys nothing; a host should not prompt as though it does")
			require.True(t, tool.Annotations.IdempotentHint,
				"recovering an already-recovered item leaves the same state")
			return
		}
	}
	t.Fatal("recover_deleted was not registered")
}

func TestRecoverDeleted_ForbiddenIsSurfaced(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.failWith("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/restore", http.StatusForbidden)

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "secrets", "name": "gone"})
	require.True(t, result.IsError)
}
