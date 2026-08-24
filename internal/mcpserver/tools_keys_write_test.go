package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateKey_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerKeysWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestCreateKey_CreatesAnRSAKey(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"signing-key","type":"RSA","bits":2048,"enabled":true}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got createKeyResult
	structured(t, callTool(t, s, "create_key", map[string]any{
		"name": "signing-key", "type": "RSA", "bits": 2048,
	}), &got)

	require.Equal(t, "signing-key", got.Name)
	require.Equal(t, "RSA", got.Type)
	require.Equal(t, 2048, got.Bits)
	require.EqualValues(t, 2048, f.lastWriteBody["bits"])
}

func TestCreateKey_CreatesAnECDSAKey(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"ec-key","type":"ECDSA","curve":"P-256"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got createKeyResult
	structured(t, callTool(t, s, "create_key", map[string]any{
		"name": "ec-key", "type": "ECDSA", "curve": "P-256",
	}), &got)

	require.Equal(t, "P-256", got.Curve)
	require.Equal(t, "P-256", f.lastWriteBody["curve"])
}

func TestCreateKey_RejectsTheWrongECTypeName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "create_key", map[string]any{"name": "k", "type": "EC"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "ECDSA")
	require.Empty(t, f.requested, "a known-bad type must not reach the server")
}

func TestCreateKey_DescriptionMentionsTheHSMRuleForOCT(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "create_key" {
			require.Contains(t, tool.Description, "HSM",
				"a model asked for an AES key will pick OCT and needs to know it requires an HSM")
			return
		}
	}
	t.Fatal("create_key was not registered")
}

func TestCreateKey_ReturnsNoPrivateMaterial(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"k","type":"RSA",
		"value":"-----BEGIN PRIVATE KEY-----LEAKED"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "create_key", map[string]any{"name": "k", "type": "RSA", "bits": 2048})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}

func TestCreateKey_RequiresNameAndType(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	require.True(t, callTool(t, s, "create_key", map[string]any{"type": "RSA"}).IsError)
	require.True(t, callTool(t, s, "create_key", map[string]any{"name": "k"}).IsError)
}

func TestRotateKey_CreatesANewVersion(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"signing-key","type":"RSA"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got rotateKeyResult
	structured(t, callTool(t, s, "rotate_key", map[string]any{"name": "signing-key"}), &got)

	require.Equal(t, "signing-key", got.Name)
	require.True(t, f.hit("/api/v1/vaults/default/keys/"+signKeyUUID+"/rotate"))
}

func TestRotateKey_IsNotAnnotatedIdempotent(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "rotate_key" {
			continue
		}
		require.False(t, tool.Annotations.IdempotentHint,
			"each call creates another version; a host must not treat a retry as free")
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.False(t, *tool.Annotations.DestructiveHint,
			"rotation adds a version and leaves the previous one intact")
		return
	}
	t.Fatal("rotate_key was not registered")
}

func TestRotateKey_UnknownNameIsActionable(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "rotate_key", map[string]any{"name": "signing-ke"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "did you mean")
}

func TestRotateKey_ForbiddenNamesTheCryptoOfficerRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.failWith("/api/v1/vaults/default/keys/"+signKeyUUID+"/rotate", http.StatusForbidden)
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "rotate_key", map[string]any{"name": "signing-key"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Crypto Officer")
}

func TestSetKeyRotationPolicy_ReplacesThePolicy(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","rotate_after_days":90,
		"notify_before_expiry_days":14,"expiry_days":365,"enabled":true,
		"next_rotation_at":"2026-11-01T00:00:00Z"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got setKeyRotationPolicyResult
	structured(t, callTool(t, s, "set_key_rotation_policy", map[string]any{
		"name": "signing-key", "rotate_after_days": 90,
		"notify_before_expiry_days": 14, "expiry_days": 365, "enabled": true,
	}), &got)

	require.Equal(t, 90, got.RotateAfterDays)
	require.Equal(t, 365, got.ExpiryDays)
	require.True(t, got.Enabled)
	require.EqualValues(t, 90, f.lastWriteBody["rotate_after_days"])
}

func TestSetKeyRotationPolicy_AllFieldsAreRequiredInTheSchema(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "set_key_rotation_policy" {
			continue
		}
		encoded, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(encoded, &schema))

		required, _ := schema["required"].([]any)
		var names []string
		for _, item := range required {
			names = append(names, item.(string))
		}

		for _, field := range []string{"rotate_after_days", "notify_before_expiry_days", "expiry_days", "enabled"} {
			require.Contains(t, names, field,
				"this operation replaces the policy, so an omittable field could silently zero itself")
		}
		return
	}
	t.Fatal("set_key_rotation_policy was not registered")
}

func TestSetKeyRotationPolicy_RejectsAMissingField(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "set_key_rotation_policy", map[string]any{
		"name": "signing-key", "rotate_after_days": 90,
	})
	require.True(t, result.IsError,
		"a partial policy must be refused, not sent with the rest zeroed")
	require.Empty(t, f.requested)
}

func TestSetKeyRotationPolicy_DistinguishesFalseFromMissing(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","enabled":false}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "set_key_rotation_policy", map[string]any{
		"name": "signing-key", "rotate_after_days": 90,
		"notify_before_expiry_days": 14, "expiry_days": 365, "enabled": false,
	})
	require.False(t, result.IsError, "an explicit false is a supplied value")
	require.Equal(t, false, f.lastWriteBody["enabled"])
}

func TestSetKeyRotationPolicy_DescriptionSaysItReplaces(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "set_key_rotation_policy" {
			require.Contains(t, tool.Description, "Replaces",
				"the caller must know this is not a partial update")
			require.Contains(t, tool.Description, "get_key",
				"and where to read the current values from")
			return
		}
	}
	t.Fatal("set_key_rotation_policy was not registered")
}

func TestSetKeyRotationPolicy_IsAnnotatedIdempotent(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "set_key_rotation_policy" {
			require.True(t, tool.Annotations.IdempotentHint,
				"a full replacement applied twice leaves the same state")
			return
		}
	}
	t.Fatal("set_key_rotation_policy was not registered")
}
