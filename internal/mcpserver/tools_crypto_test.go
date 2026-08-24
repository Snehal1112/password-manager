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

func TestEncrypt_AcceptsPlainText(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","algorithm":"RSA-OAEP","value":"Y2lwaGVy"}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	var got encryptResult
	structured(t, callTool(t, s, "encrypt", map[string]any{
		"key_name": "signing-key", "plaintext": "hello",
	}), &got)

	require.Equal(t, "Y2lwaGVy", got.CiphertextBase64)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), f.lastWriteBody["value"],
		"plain text is encoded here so the caller need not, and cannot forget to")
}

func TestEncrypt_AcceptsBase64ForBinaryData(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","value":"Y2lwaGVy"}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	binary := base64.StdEncoding.EncodeToString([]byte{0x00, 0xFF, 0xFE})
	result := callTool(t, s, "encrypt", map[string]any{
		"key_name": "signing-key", "plaintext_base64": binary,
	})
	require.False(t, result.IsError)
	require.Equal(t, binary, f.lastWriteBody["value"])
}

func TestEncrypt_RejectsBothInputsAtOnce(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	result := callTool(t, s, "encrypt", map[string]any{
		"key_name": "signing-key", "plaintext": "hello", "plaintext_base64": "aGVsbG8=",
	})
	require.True(t, result.IsError,
		"two sources for the same data would leave which one was used ambiguous")
}

func TestEncrypt_RejectsNeitherInput(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	result := callTool(t, s, "encrypt", map[string]any{"key_name": "signing-key"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "plaintext")
}

func TestEncrypt_ReturnsTheNonce(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","algorithm":"AES256-GCM",
		"value":"Y2lwaGVy","nonce":"` + nonce + `"}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	var got encryptResult
	structured(t, callTool(t, s, "encrypt", map[string]any{
		"key_name": "signing-key", "plaintext": "hello", "algorithm": "AES256-GCM",
	}), &got)

	require.Equal(t, nonce, got.NonceBase64,
		"decryption requires this; a caller that discards it has lost the plaintext for good")
	require.NotEmpty(t, got.Note, "and the result should say so")
}

func TestEncrypt_NoNoteWhenThereIsNoNonce(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","algorithm":"RSA-OAEP","value":"Y2lwaGVy"}`
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	var got encryptResult
	structured(t, callTool(t, s, "encrypt", map[string]any{
		"key_name": "signing-key", "plaintext": "hello",
	}), &got)

	require.Empty(t, got.NonceBase64)
	require.Empty(t, got.Note)
}

func TestEncrypt_RejectsInvalidBase64Input(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	result := callTool(t, s, "encrypt", map[string]any{
		"key_name": "signing-key", "plaintext_base64": "not base64!!!",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "base64")
}

func TestEncrypt_IsPresentWithoutAllowSecretValues(t *testing.T) {
	// Encrypting does not disclose anything, so it needs only the tier flag.
	f := newFakeVault(t, map[string]string{})

	cfg := cryptoConfig()
	cfg.AllowSecretValues = false
	s := f.server(t, cfg)
	registerCryptoTools(s)

	require.Contains(t, s.RegisteredTools(), "encrypt")
}

// fullCryptoConfig enables both the crypto tier and value disclosure.
func fullCryptoConfig() config.MCPConfig {
	cfg := cryptoConfig()
	cfg.AllowSecretValues = true
	return cfg
}

func TestDecrypt_IsAbsentWithoutAllowSecretValues(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, cryptoConfig()) // crypto on, disclosure off
	registerCryptoTools(s)

	require.NotContains(t, s.RegisteredTools(), "decrypt",
		"decrypt returns plaintext; without this gate, disabling secret disclosure would mean nothing")
	require.Contains(t, s.RegisteredTools(), "encrypt",
		"the other three crypto tools are unaffected")
}

func TestDecrypt_IsAbsentWithoutAllowCrypto(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowSecretValues = true // disclosure alone is not enough
	s := f.server(t, cfg)
	registerCryptoTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestDecrypt_IsPresentWithBothFlags(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, fullCryptoConfig())
	registerCryptoTools(s)

	require.Contains(t, s.RegisteredTools(), "decrypt")
}

func TestDecrypt_ReturnsTextForValidUTF8(t *testing.T) {
	plaintext := []byte("the-decrypted-secret")
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","algorithm":"RSA-OAEP",
		"value":"` + base64.StdEncoding.EncodeToString(plaintext) + `","version":1}`
	s := f.server(t, fullCryptoConfig())
	registerCryptoTools(s)

	var got decryptResult
	structured(t, callTool(t, s, "decrypt", map[string]any{
		"key_name": "signing-key", "ciphertext_base64": "Y2lwaGVy",
	}), &got)

	require.Equal(t, "the-decrypted-secret", got.Plaintext)
	require.False(t, got.PlaintextIsBase64)
}

func TestDecrypt_ReturnsBase64ForBinaryPlaintext(t *testing.T) {
	binary := []byte{0x00, 0xFF, 0xFE, 0x80}
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `",
		"value":"` + base64.StdEncoding.EncodeToString(binary) + `"}`
	s := f.server(t, fullCryptoConfig())
	registerCryptoTools(s)

	var got decryptResult
	structured(t, callTool(t, s, "decrypt", map[string]any{
		"key_name": "signing-key", "ciphertext_base64": "Y2lwaGVy",
	}), &got)

	require.True(t, got.PlaintextIsBase64,
		"returning invalid UTF-8 as a JSON string would corrupt it silently via U+FFFD replacement")
	require.Equal(t, base64.StdEncoding.EncodeToString(binary), got.Plaintext)
}

func TestDecrypt_SendsTheNonce(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","value":"aGk="}`
	s := f.server(t, fullCryptoConfig())
	registerCryptoTools(s)

	nonce := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	_ = callTool(t, s, "decrypt", map[string]any{
		"key_name": "signing-key", "ciphertext_base64": "Y2lwaGVy",
		"nonce_base64": nonce, "algorithm": "AES256-GCM",
	})
	require.Equal(t, nonce, f.lastWriteBody["nonce"])
}

func TestDecrypt_RejectsInvalidBase64Ciphertext(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	s := f.server(t, fullCryptoConfig())
	registerCryptoTools(s)

	result := callTool(t, s, "decrypt", map[string]any{
		"key_name": "signing-key", "ciphertext_base64": "not base64!!!",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "base64")
}

func TestDecrypt_ErrorNeverContainsThePlaintext(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/keys": keysForCryptoBody})
	f.failWith("/api/v1/vaults/default/keys/"+signKeyUUID+"/decrypt", 403)
	s := f.server(t, fullCryptoConfig())
	registerCryptoTools(s)

	result := callTool(t, s, "decrypt", map[string]any{
		"key_name": "signing-key", "ciphertext_base64": "Y2lwaGVy",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Crypto")
}

func TestCryptoTier_ExposesThreeToolsWithoutDisclosure(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, cryptoConfig())
	registerCryptoTools(s)

	require.Equal(t, []string{"encrypt", "sign", "verify"}, s.RegisteredTools())
}

func TestCryptoTier_ExposesFourToolsWithDisclosure(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, fullCryptoConfig())
	registerCryptoTools(s)

	require.Equal(t, []string{"decrypt", "encrypt", "sign", "verify"}, s.RegisteredTools())
}
