# Crypto Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register the four crypto tools — `sign`, `verify`, `encrypt` and `decrypt` — completing the tool surface at 27.

**Architecture:** Plan 21's tool shape with `TierCrypto`. Two problems are specific to this tier and are solved here: how bytes cross a JSON boundary, and the fact that `decrypt` produces plaintext and therefore needs a second gate.

**Tech Stack:** Go 1.25, `encoding/base64`, `unicode/utf8`, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Crypto tier".

**Plan-of-plans:** This is plan 27 of 31, completing Group H and the tool surface. Requires plans 12, 21 and 26 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **`registerIf(s, TierCrypto, ...)`** — absent unless `allow_crypto` is set.
- **`decrypt` requires `allow_secret_values` as well.**
- **No crypto tool is destructive** and none requires confirmation. They mutate nothing.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Why `decrypt` needs a second gate

Without it there is a trivial bypass. An operator who set `allow_crypto: true` and `allow_secret_values: false` has said "you may use my keys, but you may not read my secrets". A model could then:

1. Read a secret's ciphertext from wherever it is stored.
2. Call `decrypt`.
3. Read the plaintext.

The `allow_secret_values` gate would have been meaningless. More directly: `decrypt` returns plaintext, and `allow_secret_values` is the flag that governs whether plaintext reaches the model. Which plaintext it is does not change what the flag means.

So `decrypt` is registered **only when both flags are set**, and its absence when disclosure is off is structural, not a runtime refusal — the same approach plan 13 took for `include_value`.

## Base64 is not redaction

`decrypt` returns base64 on the wire. Base64 is an encoding, not protection: anyone reading the transcript can decode it in a second.

This matters for the leak tests. A redaction check that searches responses for the raw plaintext string would **pass** while the base64 of that same plaintext sits in the payload. Task 2's tests therefore search for both forms, and plan 28's sweep must do the same.

## How bytes cross the JSON boundary

`vaultapi` takes and returns `[]byte`, but a model can only send JSON. The tools therefore take base64 strings, with two accommodations that matter in practice:

- **`encrypt` accepts plain text as an alternative.** A caller encrypting `"hello"` should not have to base64 it first; `plaintext` and `plaintext_base64` are alternatives, exactly one required. Binary data still has a path.
- **`decrypt` returns text when the plaintext is valid UTF-8**, and base64 otherwise, saying which. Returning invalid UTF-8 as a JSON string would corrupt it silently — Go replaces invalid bytes with U+FFFD on marshal, so the caller would receive plausible-looking but wrong data with no indication.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/tools_crypto.go` (new) | `registerCryptoTools` and all four tools |
| `internal/mcpserver/tools_crypto_test.go` (new) | All four, gating, and encoding edge cases |
| `internal/mcpserver/register.go` (modify) | Add the registration call |

---

### Task 1: `sign` and `verify`

**Files:**
- Create: `internal/mcpserver/tools_crypto.go`
- Create: `internal/mcpserver/tools_crypto_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.Sign`, `Verify` (plan 26).
- Produces: `func registerCryptoTools(s *Server)`, `signArgs`, `signResult`, `verifyArgs`, `verifyResult`.

**Annotations:** `ReadOnly: false`, `Destructive: false`, `Idempotent: true`.

`ReadOnly` is false even though nothing changes. These tools use the vault's private key on the caller's behalf, which is a distinct authority from reading — a host prompting on first use is appropriate, and claiming read-only would suppress that. `Idempotent` is true: signing the same bytes twice with the same key yields the same signature for deterministic algorithms, and in any case produces no additional effect on the vault, which is what the hint actually means.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_crypto_test.go`:

```go
package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
		"key_name": "signing-key",
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestSign_|TestVerify_' -v`
Expected: FAIL — `undefined: registerCryptoTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_crypto.go`:

```go
package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type signArgs struct {
	KeyName    string `json:"key_name" jsonschema:"the signing key's name, or its id"`
	DataBase64 string `json:"data_base64" jsonschema:"the data to sign, base64-encoded"`
	Algorithm  string `json:"algorithm,omitempty" jsonschema:"RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 or ES512; defaults to RS256"`
	Version    int    `json:"version,omitempty" jsonschema:"a specific key version; omit to use the current one"`
	Vault      string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type signResult struct {
	Vault           string `json:"vault"`
	KeyName         string `json:"key_name"`
	Algorithm       string `json:"algorithm"`
	SignatureBase64 string `json:"signature_base64"`
	// Version records which key version signed, which is what verifying
	// later requires after a rotation.
	Version int `json:"version"`
}

type verifyArgs struct {
	KeyName         string `json:"key_name" jsonschema:"the key's name, or its id"`
	DataBase64      string `json:"data_base64" jsonschema:"the original data, base64-encoded"`
	SignatureBase64 string `json:"signature_base64" jsonschema:"the signature to check, base64-encoded"`
	Algorithm       string `json:"algorithm,omitempty" jsonschema:"the algorithm the signature was made with"`
	Version         int    `json:"version,omitempty" jsonschema:"the key version that signed; omit to use the current one"`
	Vault           string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type verifyResult struct {
	Vault     string `json:"vault"`
	KeyName   string `json:"key_name"`
	Algorithm string `json:"algorithm"`
	Valid     bool   `json:"valid"`
	Version   int    `json:"version"`
}

// decodeBase64Arg decodes a base64 argument, naming the field on failure.
func decodeBase64Arg(field, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64-encoded", field)
	}
	return decoded, nil
}

// registerCryptoTools adds the crypto-tier tools.
//
// None of them is destructive and none needs confirmation: they mutate
// nothing. They are gated at all because they use the vault's private keys on
// the caller's behalf, which is a distinct authority from reading or writing
// -- not because they destroy anything.
func registerCryptoTools(s *Server) {
	registerIf(s, TierCrypto, "sign",
		"Sign data with a key held in the vault. The private key never leaves the vault. "+
			"Data is base64-encoded, and the result records which key version signed.",
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleSign)

	registerIf(s, TierCrypto, "verify",
		"Check a signature against its original data using a key in the vault. "+
			"A signature that does not match returns valid=false; that is an answer, not an error.",
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleVerify)
}

func (s *Server) handleSign(ctx context.Context, _ *mcp.CallToolRequest, args signArgs) (*mcp.CallToolResult, signResult, error) {
	if args.KeyName == "" {
		return errorResult("sign requires a key_name"), signResult{}, nil
	}
	data, err := decodeBase64Arg("data_base64", args.DataBase64)
	if err != nil {
		return errorResult("%s", err), signResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), signResult{}, nil
	}

	signed, err := s.client.Sign(ctx, vault, args.KeyName, data, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not sign with key %q in vault %q: %s",
			args.KeyName, vault, err), signResult{}, nil
	}

	return nil, signResult{
		Vault:           vault,
		KeyName:         args.KeyName,
		Algorithm:       signed.Algorithm,
		SignatureBase64: base64.StdEncoding.EncodeToString(signed.Signature),
		Version:         signed.Version,
	}, nil
}

func (s *Server) handleVerify(ctx context.Context, _ *mcp.CallToolRequest, args verifyArgs) (*mcp.CallToolResult, verifyResult, error) {
	if args.KeyName == "" {
		return errorResult("verify requires a key_name"), verifyResult{}, nil
	}
	data, err := decodeBase64Arg("data_base64", args.DataBase64)
	if err != nil {
		return errorResult("%s", err), verifyResult{}, nil
	}
	signature, err := decodeBase64Arg("signature_base64", args.SignatureBase64)
	if err != nil {
		return errorResult("%s", err), verifyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), verifyResult{}, nil
	}

	checked, err := s.client.Verify(ctx, vault, args.KeyName, data, signature, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not verify with key %q in vault %q: %s",
			args.KeyName, vault, err), verifyResult{}, nil
	}

	// A false result is returned as a successful call. Reporting it as a tool
	// error would leave the model unable to tell a forgery from an
	// unreachable vault.
	return nil, verifyResult{
		Vault:     vault,
		KeyName:   args.KeyName,
		Algorithm: checked.Algorithm,
		Valid:     checked.Valid,
		Version:   checked.Version,
	}, nil
}
```

Add `registerCryptoTools(s)` to `RegisterAllTools`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run 'TestSign_|TestVerify_' -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_crypto.go internal/mcpserver/tools_crypto_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the sign and verify tools

Neither is annotated read-only despite changing nothing. They use the vault's
private key on the caller's behalf, which is a distinct authority from
reading, and claiming read-only would suppress a host prompt that is
appropriate on first use.

A signature that does not match returns valid=false as a successful call. A
tool error would leave the model unable to tell a forgery from an unreachable
vault, which are opposite conclusions."
```

---

### Task 2: `encrypt`

**Files:**
- Modify: `internal/mcpserver/tools_crypto.go`
- Modify: `internal/mcpserver/tools_crypto_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.Client.Encrypt` (plan 26).
- Produces: `encryptArgs`, `encryptResult`.

**`plaintext` and `plaintext_base64` are alternatives, exactly one required.** A caller encrypting a string should not have to base64 it first — that is friction with a silent failure mode, since forgetting to encode produces a request that succeeds and encrypts the wrong bytes. Binary data keeps a path through the base64 field.

**The nonce is returned prominently.** AES-GCM decryption requires it; a caller that discards it has permanently lost the plaintext. The result includes it and the description says why.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/tools_crypto_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestEncrypt_ -v`
Expected: FAIL — `encrypt` is not registered.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/tools_crypto.go`:

```go
// encryptArgs are the arguments to encrypt.
//
// plaintext and plaintext_base64 are alternatives and exactly one is
// required. Accepting plain text removes friction with a silent failure mode:
// a caller who forgot to encode would otherwise send a request that succeeds
// and encrypts the wrong bytes.
type encryptArgs struct {
	KeyName         string `json:"key_name" jsonschema:"the key's name, or its id"`
	Plaintext       string `json:"plaintext,omitempty" jsonschema:"the text to encrypt; use plaintext_base64 instead for binary data"`
	PlaintextBase64 string `json:"plaintext_base64,omitempty" jsonschema:"the data to encrypt, base64-encoded; use plaintext instead for text"`
	Algorithm       string `json:"algorithm,omitempty" jsonschema:"RSA-OAEP, RSA-OAEP-256 or AES256-GCM"`
	Version         int    `json:"version,omitempty" jsonschema:"a specific key version; omit to use the current one"`
	Vault           string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type encryptResult struct {
	Vault            string `json:"vault"`
	KeyName          string `json:"key_name"`
	Algorithm        string `json:"algorithm"`
	CiphertextBase64 string `json:"ciphertext_base64"`
	// NonceBase64 is present for AES-GCM. Decryption requires it.
	NonceBase64 string `json:"nonce_base64,omitempty"`
	Version     int    `json:"version"`
	// Note warns that the nonce must be kept, when there is one.
	Note string `json:"note,omitempty"`
}

// resolvePlaintextArg picks between the two plaintext inputs.
func resolvePlaintextArg(text, encoded string) ([]byte, error) {
	switch {
	case text != "" && encoded != "":
		return nil, fmt.Errorf("give either plaintext or plaintext_base64, not both")
	case text != "":
		return []byte(text), nil
	case encoded != "":
		return decodeBase64Arg("plaintext_base64", encoded)
	default:
		return nil, fmt.Errorf("encrypt requires plaintext or plaintext_base64")
	}
}

func (s *Server) handleEncrypt(ctx context.Context, _ *mcp.CallToolRequest, args encryptArgs) (*mcp.CallToolResult, encryptResult, error) {
	if args.KeyName == "" {
		return errorResult("encrypt requires a key_name"), encryptResult{}, nil
	}
	plaintext, err := resolvePlaintextArg(args.Plaintext, args.PlaintextBase64)
	if err != nil {
		return errorResult("%s", err), encryptResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), encryptResult{}, nil
	}

	encrypted, err := s.client.Encrypt(ctx, vault, args.KeyName, plaintext, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not encrypt with key %q in vault %q: %s",
			args.KeyName, vault, err), encryptResult{}, nil
	}

	result := encryptResult{
		Vault:            vault,
		KeyName:          args.KeyName,
		Algorithm:        encrypted.Algorithm,
		CiphertextBase64: base64.StdEncoding.EncodeToString(encrypted.Ciphertext),
		Version:          encrypted.Version,
	}
	if len(encrypted.Nonce) > 0 {
		result.NonceBase64 = base64.StdEncoding.EncodeToString(encrypted.Nonce)
		result.Note = "Keep nonce_base64 with the ciphertext: decryption requires it, and without it the plaintext cannot be recovered."
	}
	return nil, result, nil
}
```

Register it in `registerCryptoTools`:

```go
	registerIf(s, TierCrypto, "encrypt",
		"Encrypt data with a key held in the vault. For AES-GCM the result includes a nonce that must be kept "+
			"alongside the ciphertext, since decryption requires it.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleEncrypt)
```

`Idempotent` is false here: AES-GCM generates a fresh nonce per call, so two calls with identical arguments produce different ciphertext.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestEncrypt_ -v`
Expected: PASS — all eight tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_crypto.go internal/mcpserver/tools_crypto_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the encrypt tool

plaintext and plaintext_base64 are alternatives, exactly one required.
Accepting plain text removes friction with a silent failure mode: a caller who
forgot to encode would otherwise send a request that succeeds and encrypts the
wrong bytes.

The AES-GCM nonce is returned with a note explaining that it must be kept,
because a caller that discards it has permanently lost the plaintext. encrypt
is annotated non-idempotent, since a fresh nonce per call means identical
arguments produce different ciphertext."
```

---

### Task 3: `decrypt`, gated twice

**Files:**
- Modify: `internal/mcpserver/tools_crypto.go`
- Modify: `internal/mcpserver/tools_crypto_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.Client.Decrypt` (plan 26), `s.MayDiscloseValues` (plan 12).
- Produces: `decryptArgs`, `decryptResult`.

**Registration requires both `allow_crypto` and `allow_secret_values`.** Without the second gate, an operator who disabled secret disclosure but enabled crypto could have any ciphertext decrypted and read — the disclosure flag would mean nothing. The absence is structural rather than a runtime refusal, matching plan 13's handling of `include_value`.

**Output encoding is decided by the data.** Valid UTF-8 is returned as text; anything else is returned as base64 with `plaintext_is_base64: true`. Returning invalid UTF-8 as a JSON string would corrupt it silently, since Go replaces invalid bytes with U+FFFD on marshal — the caller would receive plausible but wrong data with no indication anything happened.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/tools_crypto_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestDecrypt_|TestCryptoTier_' -v`
Expected: FAIL — `decrypt` is not registered.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/tools_crypto.go`, adding `"unicode/utf8"` to the imports:

```go
type decryptArgs struct {
	KeyName          string `json:"key_name" jsonschema:"the key's name, or its id"`
	CiphertextBase64 string `json:"ciphertext_base64" jsonschema:"the ciphertext to decrypt, base64-encoded"`
	NonceBase64      string `json:"nonce_base64,omitempty" jsonschema:"the nonce returned by encrypt; required for AES-GCM"`
	Algorithm        string `json:"algorithm,omitempty" jsonschema:"the algorithm the ciphertext was produced with"`
	Version          int    `json:"version,omitempty" jsonschema:"the key version that encrypted; omit to use the current one"`
	Vault            string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type decryptResult struct {
	Vault     string `json:"vault"`
	KeyName   string `json:"key_name"`
	Algorithm string `json:"algorithm"`
	// Plaintext is text when the decrypted bytes are valid UTF-8, and
	// base64 otherwise. PlaintextIsBase64 says which.
	Plaintext string `json:"plaintext"`
	// PlaintextIsBase64 exists because returning invalid UTF-8 as a JSON
	// string would corrupt it silently: Go replaces invalid bytes with
	// U+FFFD on marshal, so the caller would get plausible but wrong data
	// with no indication.
	PlaintextIsBase64 bool `json:"plaintext_is_base64"`
	Version           int  `json:"version"`
}

func (s *Server) handleDecrypt(ctx context.Context, _ *mcp.CallToolRequest, args decryptArgs) (*mcp.CallToolResult, decryptResult, error) {
	if args.KeyName == "" {
		return errorResult("decrypt requires a key_name"), decryptResult{}, nil
	}
	ciphertext, err := decodeBase64Arg("ciphertext_base64", args.CiphertextBase64)
	if err != nil {
		return errorResult("%s", err), decryptResult{}, nil
	}

	var nonce []byte
	if args.NonceBase64 != "" {
		nonce, err = decodeBase64Arg("nonce_base64", args.NonceBase64)
		if err != nil {
			return errorResult("%s", err), decryptResult{}, nil
		}
	}

	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), decryptResult{}, nil
	}

	decrypted, err := s.client.Decrypt(ctx, vault, args.KeyName, ciphertext, nonce, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not decrypt with key %q in vault %q: %s",
			args.KeyName, vault, err), decryptResult{}, nil
	}

	// Revealing here is the deliberate act this tool exists for, and it is
	// reachable only because both allow_crypto and allow_secret_values are
	// set -- the tool is not registered otherwise.
	plaintext := decrypted.Plaintext.Reveal()

	result := decryptResult{
		Vault:     vault,
		KeyName:   args.KeyName,
		Algorithm: decrypted.Algorithm,
		Version:   decrypted.Version,
	}
	if utf8.ValidString(plaintext) {
		result.Plaintext = plaintext
	} else {
		result.Plaintext = base64.StdEncoding.EncodeToString([]byte(plaintext))
		result.PlaintextIsBase64 = true
	}
	return nil, result, nil
}
```

Register it conditionally in `registerCryptoTools`:

```go
	// decrypt is gated twice. allow_crypto admits the tier, but decrypt
	// returns plaintext, and allow_secret_values is the flag governing
	// whether plaintext reaches the model. Without the second gate, an
	// operator who disabled disclosure could still have any ciphertext
	// decrypted and read, making that flag meaningless.
	if s.MayDiscloseValues() {
		registerIf(s, TierCrypto, "decrypt",
			"Decrypt ciphertext with a key held in the vault and return the plaintext. "+
				"For AES-GCM, pass the nonce that encrypt returned.",
			Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
			s.handleDecrypt)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_crypto.go internal/mcpserver/tools_crypto_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the decrypt tool, gated on both flags

decrypt requires allow_crypto and allow_secret_values. Without the second
gate, an operator who disabled secret disclosure but enabled crypto could
still have any ciphertext decrypted and read, which would make the disclosure
flag meaningless. The absence is structural rather than a runtime refusal,
matching how include_value is handled.

Plaintext comes back as text when it is valid UTF-8 and base64 otherwise, with
a flag saying which. Returning invalid UTF-8 as a JSON string would corrupt it
silently, since Go replaces invalid bytes with U+FFFD on marshal and the
caller would get plausible but wrong data with no indication."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ ./internal/vaultapi/ -race -v
go vet ./internal/mcpserver/ ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

**The tool surface is complete.** Counts by configuration:

| Configuration | Tools |
|---|---|
| default | 10 |
| `+ allow_write` | 19 |
| `+ allow_destructive` | 23 |
| `+ allow_crypto` | 26 |
| `+ allow_secret_values` | 27 |

Note the last row: `allow_secret_values` adds `decrypt` and changes
`get_secret`'s schema, which is why 26 and 27 differ by one tool rather than by
a capability. Plan 28 pins every combination.

Confirm the double gate directly:

```bash
go test ./internal/mcpserver/ -run 'TestDecrypt_IsAbsent|TestCryptoTier_' -v
```

## Notes for the next plan

Plan 28 builds the gating table across all 27 tools and every flag
combination, and wires it into CI.

**One thing it must not miss:** the leak sweep has to search for **base64 of
the plaintext as well as the plaintext itself**. `decrypt` returns base64 for
binary data, and `sign`/`encrypt` return base64 throughout — a sweep that only
looked for raw strings would pass while an encoded secret sat in the payload.
Base64 is an encoding, not protection.
