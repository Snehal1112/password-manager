package mcpserver

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// cryptoConfig returns a config with the crypto tier enabled.
func cryptoConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowCrypto = true
	return cfg
}

const keysForCryptoBody = `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`

func TestSign_IsAbsentWithoutAllowCrypto(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerCryptoTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestSign_SignsData(t *testing.T) {
	signature := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","algorithm":"RS256",
		"value":"` + base64.StdEncoding.EncodeToString(signature) + `","version":3}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	var got signResult
	structured(t, callTool(t, s, "sign", map[string]any{
		"key_name":    "signing-key",
		"data_base64": base64.StdEncoding.EncodeToString([]byte("hello")),
	}), &got)

	require.Equal(t, base64.StdEncoding.EncodeToString(signature), got.SignatureBase64)
	require.Equal(t, "RS256", got.Algorithm)
	require.Equal(t, 3, got.Version)
}

func TestSign_RejectsInvalidBase64(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	result := callTool(t, s, "sign", map[string]any{
		"key_name": "signing-key", "data_base64": "not base64!!!",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "base64",
		"the error must name the expected encoding so the caller can correct it")
	require.False(t, f.hit("/api/v1/vaults/default/keys/"+signKeyUUID+"/sign"))
}

func TestSign_PassesAnExplicitVersion(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","value":"AAAA","version":2}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	_ = callTool(t, s, "sign", map[string]any{
		"key_name": "signing-key", "data_base64": "aGVsbG8=", "version": 2,
	})
	require.EqualValues(t, 2, f.lastWriteBody["version"],
		"verifying an old signature after a rotation needs the version that made it")
}

func TestSign_RequiresKeyAndData(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	require.True(t, callTool(t, s, "sign", map[string]any{"data_base64": "aGk="}).IsError)
	require.True(t, callTool(t, s, "sign", map[string]any{"key_name": "signing-key"}).IsError)
}

func TestSign_IsNotAnnotatedReadOnly(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "sign" {
			require.False(t, tool.Annotations.ReadOnlyHint,
				"it uses the vault's private key on the caller's behalf, which a host should be able to prompt on")
			require.False(t, *tool.Annotations.DestructiveHint)
			return
		}
	}
	t.Fatal("sign was not registered")
}

func TestVerify_ReportsAValidSignature(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","algorithm":"RS256","valid":true,"version":3}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	var got verifyResult
	structured(t, callTool(t, s, "verify", map[string]any{
		"key_name": "signing-key", "data_base64": "aGVsbG8=", "signature_base64": "3q2+7w==",
	}), &got)

	require.True(t, got.Valid)
	require.Equal(t, 3, got.Version)
}

func TestVerify_AnInvalidSignatureIsNotAToolError(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","algorithm":"RS256","valid":false}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	result := callTool(t, s, "verify", map[string]any{
		"key_name": "signing-key", "data_base64": "aGVsbG8=", "signature_base64": "AAAA",
	})
	require.False(t, result.IsError,
		"a forged signature is a successful answer, not a failure: the model must be able to tell "+
			"'this is forged' from 'the vault is unreachable'")

	var got verifyResult
	structured(t, result, &got)
	require.False(t, got.Valid)
}

func TestVerify_RequiresDataAndSignature(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	require.True(t, callTool(t, s, "verify", map[string]any{
		"key_name": "k", "signature_base64": "AAAA"}).IsError)
	require.True(t, callTool(t, s, "verify", map[string]any{
		"key_name": "k", "data_base64": "aGk="}).IsError)
}
