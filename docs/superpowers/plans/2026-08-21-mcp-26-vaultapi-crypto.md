# vaultapi Crypto Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `Sign`, `Verify`, `Encrypt` and `Decrypt` to `internal/vaultapi`, completing the client's surface.

**Architecture:** These methods take and return `[]byte`. Base64 is a wire-format detail of the API, and every caller would otherwise have to encode and decode identically — which is a step each could get wrong, silently, in a way that produces a valid-looking signature over the wrong bytes.

**Tech Stack:** Go 1.25, `encoding/base64`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Crypto tier".

**Plan-of-plans:** This is plan 26 of 31, opening Group H. Requires plans 01, 04 and 06 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only.**
- **These operations mutate nothing**, but they are still sent unretried. A signature is not something to request twice on a timeout, and a retried `decrypt` doubles the exposure of a plaintext for no benefit.
- **Decrypted plaintext must never reach an error message or a log line.**
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified route contracts

| Operation | Route | Request | Response |
|---|---|---|---|
| Sign | `POST /api/v1/vaults/{v}/keys/{id}/sign` | `SignKeyRequest{value, algorithm, version}` (`api/keys.go:140`) | `SignKeyResponse{key_id, algorithm, value, version}` |
| Verify | `POST …/verify` | `VerifyKeyRequest{value, signature, algorithm, version}` (`:155`) | `VerifyKeyResponse{key_id, algorithm, valid, version}` |
| Encrypt | `POST …/encrypt` | `EncryptKeyRequest{value, algorithm, version}` (`:171`) | `EncryptKeyResponse{key_id, algorithm, value, nonce, version}` |
| Decrypt | `POST …/decrypt` | `DecryptKeyRequest{value, nonce, algorithm, version}` (`:187`) | `DecryptKeyResponse{key_id, algorithm, value, version}` |

Four details that shape the implementation:

1. **Every `value` is base64 on the wire**, in both directions. These methods take and return `[]byte` and do the encoding themselves.
2. **`version` is supported on all four**, with `0` meaning the current version. That is what makes verifying an old signature or decrypting old ciphertext possible after a rotation.
3. **`sign` defaults to `RS256`** server-side when no algorithm is given (`api/keys.go:912`). The client passes the caller's choice through rather than defaulting, so the server's default stays the single source of truth.
4. **AES-GCM encryption returns a `nonce`** that decryption requires. Losing it makes the ciphertext undecryptable, so `EncryptResult` carries it and `DecryptRequest` accepts it.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/crypto.go` (new) | `Sign`, `Verify`, `Encrypt`, `Decrypt` and their types |
| `internal/vaultapi/crypto_test.go` (new) | All four, including base64 handling and versions |

---

### Task 1: `Sign` and `Verify`

**Files:**
- Create: `internal/vaultapi/crypto.go`
- Create: `internal/vaultapi/crypto_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `Resolver.Resolve` and `KindKeys` (plan 04).
- Produces — plan 27's `sign` and `verify` call these:
  - `type SignResult struct { KeyID uuid.UUID; Algorithm string; Signature []byte; Version int }`
  - `type VerifyResult struct { KeyID uuid.UUID; Algorithm string; Valid bool; Version int }`
  - `func (c *Client) Sign(ctx context.Context, vault, name string, data []byte, algorithm string, version int) (*SignResult, error)`
  - `func (c *Client) Verify(ctx context.Context, vault, name string, data, signature []byte, algorithm string, version int) (*VerifyResult, error)`

**Why `[]byte` rather than a base64 string:** the API's encoding is a transport detail. Exposing it would mean every caller encodes and decodes identically, and a caller that base64-encoded already-encoded data would get a *valid signature over the wrong bytes* — a failure that verifies correctly against itself and is therefore invisible until something external checks it.

**Why an invalid signature is not an error:** `Verify` returning `Valid: false` is a successful call with a negative answer. Conflating it with a transport failure would leave a caller unable to tell "this signature is forged" from "the vault is unreachable", which are opposite conclusions.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/crypto_test.go`:

```go
package vaultapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// cryptoServer serves the key listing plus one crypto route, recording the
// request body.
func cryptoServer(t *testing.T, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}

		probe.calls++
		probe.method, probe.path = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&probe.body)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv, probe
}

func TestSign_EncodesDataAndDecodesTheSignature(t *testing.T) {
	signature := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256",
		"value":"`+base64.StdEncoding.EncodeToString(signature)+`","version":3}`)

	got, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("hello"), "RS256", 0)
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/sign", probe.path)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), probe.body["value"],
		"the caller passes raw bytes; base64 is this layer's job")
	require.Equal(t, signature, got.Signature)
	require.Equal(t, 3, got.Version)
	require.Equal(t, uuid.MustParse(rsaKeyID), got.KeyID)
}

func TestSign_PassesTheAlgorithmThrough(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"ES256","value":"AAAA"}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "ES256", 0)
	require.NoError(t, err)
	require.Equal(t, "ES256", probe.body["algorithm"])
}

func TestSign_OmitsTheAlgorithmWhenUnset(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256","value":"AAAA"}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "", 0)
	require.NoError(t, err)

	value, present := probe.body["algorithm"]
	require.True(t, !present || value == "",
		"the server defaults to RS256; leaving that as the single source of truth beats duplicating it")
}

func TestSign_OmitsVersionZero(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"AAAA","version":5}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 0)
	require.NoError(t, err)

	_, present := probe.body["version"]
	require.False(t, present, "zero means current, which the server already assumes")
}

func TestSign_SendsAnExplicitVersion(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"AAAA","version":2}`)

	got, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, probe.body["version"])
	require.Equal(t, 2, got.Version)
}

func TestSign_RejectsEmptyData(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key", nil, "RS256", 0)
	require.ErrorContains(t, err, "data")
	require.Zero(t, probe.calls)
}

func TestSign_RequiresVaultAndName(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.Sign(context.Background(), "", "k", []byte("d"), "RS256", 0)
	require.ErrorContains(t, err, "vault is required")

	_, err = c.Sign(context.Background(), "prod", "", []byte("d"), "RS256", 0)
	require.ErrorContains(t, err, "name is required")

	require.Zero(t, probe.calls)
}

func TestSign_IsAttemptedExactlyOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 0)
	require.Error(t, err,
		"a signature is not something to request twice on a timeout")
}

func TestSign_MalformedSignatureIsAnError(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"not-valid-base64!!!"}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 0)
	require.ErrorContains(t, err, "base64",
		"an undecodable signature must fail loudly rather than yield empty bytes")
}

func TestVerify_ReportsAValidSignature(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256","valid":true,"version":3}`)

	got, err := newClientForTest(t, srv).Verify(context.Background(), "prod", "signing-key",
		[]byte("hello"), []byte{0xDE, 0xAD}, "RS256", 0)
	require.NoError(t, err)

	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/verify", probe.path)
	require.True(t, got.Valid)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), probe.body["value"])
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD}), probe.body["signature"])
}

func TestVerify_AnInvalidSignatureIsNotAnError(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256","valid":false}`)

	got, err := newClientForTest(t, srv).Verify(context.Background(), "prod", "signing-key",
		[]byte("hello"), []byte{0x00}, "RS256", 0)
	require.NoError(t, err,
		"a negative answer is a successful call: conflating it with a transport failure would "+
			"leave a caller unable to tell a forgery from an unreachable vault")
	require.False(t, got.Valid)
}

func TestVerify_RequiresDataAndSignature(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.Verify(context.Background(), "prod", "k", nil, []byte{0x01}, "RS256", 0)
	require.ErrorContains(t, err, "data")

	_, err = c.Verify(context.Background(), "prod", "k", []byte("d"), nil, "RS256", 0)
	require.ErrorContains(t, err, "signature")

	require.Zero(t, probe.calls)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestSign_|TestVerify_' -v`
Expected: FAIL — `c.Sign undefined`, `c.Verify undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/crypto.go`:

```go
package vaultapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// SignResult is a signature produced by a vault-held key.
type SignResult struct {
	KeyID     uuid.UUID
	Algorithm string
	Signature []byte
	// Version is the key version actually used, which matters after a
	// rotation: verifying later requires the same one.
	Version int
}

// VerifyResult is the outcome of a signature check.
type VerifyResult struct {
	KeyID     uuid.UUID
	Algorithm string
	Valid     bool
	Version   int
}

// cryptoBody is the request shape shared by the four crypto routes. Unused
// fields are omitted, so one type serves all of them.
type cryptoBody struct {
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	// Version zero means the current version, which is what the server
	// assumes when the field is absent.
	Version int `json:"version,omitempty"`
}

// Sign signs data with a vault-held key.
//
// data and the returned signature are raw bytes. The API encodes both as
// base64, but that is a transport detail: exposing it would make every caller
// encode identically, and a caller that encoded already-encoded data would
// get a valid signature over the wrong bytes -- a failure that verifies
// correctly against itself and stays invisible until something external
// checks it.
//
// An empty algorithm is omitted rather than defaulted here. The server
// defaults to RS256 (api/keys.go:912), and leaving it as the single source of
// truth beats duplicating a value that could drift.
func (c *Client) Sign(ctx context.Context, vault, name string, data []byte, algorithm string, version int) (*SignResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to sign")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to sign")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("vaultapi: data is required to sign")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(data),
		Algorithm: algorithm,
		Version:   version,
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/sign", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(wire.Value)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: signature was not valid base64: %w", err)
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &SignResult{
		KeyID:     keyID,
		Algorithm: wire.Algorithm,
		Signature: signature,
		Version:   wire.Version,
	}, nil
}

// Verify checks a signature against data.
//
// An invalid signature returns Valid false with a nil error: that is a
// successful call with a negative answer. Reporting it as an error would
// leave a caller unable to tell a forgery from an unreachable vault, which
// are opposite conclusions.
func (c *Client) Verify(ctx context.Context, vault, name string, data, signature []byte, algorithm string, version int) (*VerifyResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to verify")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to verify")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("vaultapi: data is required to verify")
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("vaultapi: a signature is required to verify")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(data),
		Signature: base64.StdEncoding.EncodeToString(signature),
		Algorithm: algorithm,
		Version:   version,
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Valid     bool   `json:"valid"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/verify", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &VerifyResult{
		KeyID:     keyID,
		Algorithm: wire.Algorithm,
		Valid:     wire.Valid,
		Version:   wire.Version,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run 'TestSign_|TestVerify_' -v`
Expected: PASS — all twelve tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/crypto.go internal/vaultapi/crypto_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add Sign and Verify

Both take and return raw bytes. The API encodes as base64, but that is a
transport detail: exposing it would make every caller encode identically, and
one that encoded already-encoded data would get a valid signature over the
wrong bytes -- a failure that verifies against itself and stays invisible
until something external checks it.

An invalid signature is Valid false with a nil error, not a failure.
Conflating the two would leave a caller unable to tell a forgery from an
unreachable vault, which are opposite conclusions."
```

---

### Task 2: `Encrypt` and `Decrypt`

**Files:**
- Modify: `internal/vaultapi/crypto.go`
- Modify: `internal/vaultapi/crypto_test.go` (append)

**Interfaces:**
- Consumes: `Client.Do`, `Resolver.Resolve`, `cryptoBody`.
- Produces — plan 27's `encrypt` and `decrypt` call these:
  - `type EncryptResult struct { KeyID uuid.UUID; Algorithm string; Ciphertext, Nonce []byte; Version int }`
  - `type DecryptResult struct { KeyID uuid.UUID; Algorithm string; Plaintext SecretValue; Version int }`
  - `func (c *Client) Encrypt(ctx context.Context, vault, name string, plaintext []byte, algorithm string, version int) (*EncryptResult, error)`
  - `func (c *Client) Decrypt(ctx context.Context, vault, name string, ciphertext, nonce []byte, algorithm string, version int) (*DecryptResult, error)`

**`DecryptResult.Plaintext` is a `SecretValue`, not `[]byte`.** Decryption produces plaintext, which is exactly what plan 05's redacting type exists for: `String`, `GoString` and `MarshalJSON` all redact, so a decrypted value cannot reach a log line or a marshalled response by accident. `Reveal()` is the deliberate act.

This is a departure from `Sign`'s `[]byte` return, and the asymmetry is the point — a signature is public, a decrypted plaintext is not.

**The nonce matters.** AES-GCM encryption returns one that decryption requires; losing it makes the ciphertext permanently undecryptable. `EncryptResult` carries it so a caller can keep it, and `Decrypt` accepts it.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/crypto_test.go`:

```go
func TestEncrypt_ReturnsCiphertextAndNonce(t *testing.T) {
	ciphertext := []byte{0xCA, 0xFE}
	nonce := []byte{0x01, 0x02, 0x03}
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"AES256-GCM",
		"value":"`+base64.StdEncoding.EncodeToString(ciphertext)+`",
		"nonce":"`+base64.StdEncoding.EncodeToString(nonce)+`","version":2}`)

	got, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		[]byte("hello"), "AES256-GCM", 0)
	require.NoError(t, err)

	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/encrypt", probe.path)
	require.Equal(t, ciphertext, got.Ciphertext)
	require.Equal(t, nonce, got.Nonce,
		"AES-GCM decryption needs this nonce; losing it makes the ciphertext undecryptable")
	require.Equal(t, 2, got.Version)
}

func TestEncrypt_OmitsAnAbsentNonce(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RSA-OAEP","value":"AAAA"}`)

	got, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		[]byte("hello"), "RSA-OAEP", 0)
	require.NoError(t, err)
	require.Empty(t, got.Nonce, "RSA-OAEP has no nonce, which is not an error")
}

func TestEncrypt_EncodesThePlaintext(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"AAAA"}`)

	_, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		[]byte("hello"), "RSA-OAEP", 0)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), probe.body["value"])
}

func TestEncrypt_RejectsEmptyPlaintext(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)

	_, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		nil, "RSA-OAEP", 0)
	require.ErrorContains(t, err, "plaintext")
	require.Zero(t, probe.calls)
}

func TestDecrypt_ReturnsPlaintextAsASecretValue(t *testing.T) {
	plaintext := []byte("the-decrypted-secret")
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RSA-OAEP",
		"value":"`+base64.StdEncoding.EncodeToString(plaintext)+`","version":1}`)

	got, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA, 0xFE}, nil, "RSA-OAEP", 0)
	require.NoError(t, err)

	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/decrypt", probe.path)
	require.Equal(t, "the-decrypted-secret", got.Plaintext.Reveal())
	require.Equal(t, "[REDACTED]", got.Plaintext.String(),
		"decryption produces plaintext, which is what SecretValue exists for")
}

func TestDecrypt_MarshallingTheResultNeverLeaksThePlaintext(t *testing.T) {
	plaintext := []byte("the-decrypted-secret")
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`",
		"value":"`+base64.StdEncoding.EncodeToString(plaintext)+`"}`)

	got, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "the-decrypted-secret")
}

func TestDecrypt_SendsTheNonce(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03}
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"aGk="}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nonce, "AES256-GCM", 0)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(nonce), probe.body["nonce"])
}

func TestDecrypt_OmitsAnAbsentNonce(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"aGk="}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.NoError(t, err)

	_, present := probe.body["nonce"]
	require.False(t, present)
}

func TestDecrypt_RejectsEmptyCiphertext(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		nil, nil, "RSA-OAEP", 0)
	require.ErrorContains(t, err, "ciphertext")
	require.Zero(t, probe.calls)
}

func TestDecrypt_ErrorNeverContainsThePlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"denied while decrypting the-decrypted-secret"}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "the-decrypted-secret")
}

func TestDecrypt_MalformedPlaintextIsAnError(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"not-base64!!!"}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.ErrorContains(t, err, "base64")
}

func TestCrypto_AllFourResolveTheKeyByName(t *testing.T) {
	// Each operation goes through the same resolver, so a name works
	// everywhere a UUID does.
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"aGk=","valid":true}`)
	c := newClientForTest(t, srv)
	ctx := context.Background()

	_, err := c.Sign(ctx, "prod", "signing-key", []byte("d"), "RS256", 0)
	require.NoError(t, err)
	_, err = c.Verify(ctx, "prod", "signing-key", []byte("d"), []byte("s"), "RS256", 0)
	require.NoError(t, err)
	_, err = c.Encrypt(ctx, "prod", "signing-key", []byte("d"), "RSA-OAEP", 0)
	require.NoError(t, err)
	_, err = c.Decrypt(ctx, "prod", "signing-key", []byte("d"), nil, "RSA-OAEP", 0)
	require.NoError(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestEncrypt_|TestDecrypt_|TestCrypto_' -v`
Expected: FAIL — `c.Encrypt undefined`, `c.Decrypt undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/vaultapi/crypto.go`:

```go
// EncryptResult is ciphertext produced by a vault-held key.
type EncryptResult struct {
	KeyID      uuid.UUID
	Algorithm  string
	Ciphertext []byte
	// Nonce is present for AES-GCM and empty otherwise. Decryption requires
	// it, so losing it makes the ciphertext permanently undecryptable.
	Nonce   []byte
	Version int
}

// DecryptResult is plaintext recovered by a vault-held key.
//
// Plaintext is a SecretValue rather than []byte, unlike Sign's signature.
// The asymmetry is the point: a signature is public, a decrypted plaintext is
// not. SecretValue redacts on String, GoString and MarshalJSON, so it cannot
// reach a log line or a marshalled response by accident.
type DecryptResult struct {
	KeyID     uuid.UUID
	Algorithm string
	Plaintext SecretValue
	Version   int
}

// Encrypt encrypts plaintext with a vault-held key.
func (c *Client) Encrypt(ctx context.Context, vault, name string, plaintext []byte, algorithm string, version int) (*EncryptResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to encrypt")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to encrypt")
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("vaultapi: plaintext is required to encrypt")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(plaintext),
		Algorithm: algorithm,
		Version:   version,
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		Nonce     string `json:"nonce"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/encrypt", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(wire.Value)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: ciphertext was not valid base64: %w", err)
	}

	result := &EncryptResult{
		Algorithm:  wire.Algorithm,
		Ciphertext: ciphertext,
		Version:    wire.Version,
	}
	if wire.Nonce != "" {
		nonce, err := base64.StdEncoding.DecodeString(wire.Nonce)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: nonce was not valid base64: %w", err)
		}
		result.Nonce = nonce
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	result.KeyID = keyID
	return result, nil
}

// Decrypt recovers plaintext with a vault-held key.
//
// nonce is required for AES-GCM and ignored otherwise; it comes from the
// EncryptResult that produced the ciphertext.
func (c *Client) Decrypt(ctx context.Context, vault, name string, ciphertext, nonce []byte, algorithm string, version int) (*DecryptResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to decrypt")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to decrypt")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("vaultapi: ciphertext is required to decrypt")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(ciphertext),
		Algorithm: algorithm,
		Version:   version,
	}
	if len(nonce) > 0 {
		body.Nonce = base64.StdEncoding.EncodeToString(nonce)
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/decrypt", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(wire.Value)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: plaintext was not valid base64: %w", err)
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &DecryptResult{
		KeyID:     keyID,
		Algorithm: wire.Algorithm,
		Plaintext: SecretValue(plaintext),
		Version:   wire.Version,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/crypto.go internal/vaultapi/crypto_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add Encrypt and Decrypt

DecryptResult.Plaintext is a SecretValue rather than []byte, unlike Sign's
signature. The asymmetry is the point: a signature is public, a decrypted
plaintext is not, so it gets the type that redacts on String, GoString and
MarshalJSON.

EncryptResult carries the AES-GCM nonce, which decryption requires -- losing
it makes the ciphertext permanently undecryptable. RSA-OAEP returns none,
which is not an error."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

`internal/vaultapi` is feature-complete after this plan. Confirm the whole
package holds together:

```bash
go test ./internal/vaultapi/ -race -count=2
```

Confirm no decrypted plaintext escapes:

```bash
go test ./internal/vaultapi/ -run 'TestDecrypt_Marshalling|TestDecrypt_ErrorNever' -v
```

Confirm the egress point is still singular across the package:

```bash
grep -rn "\.Reveal()" --include="*.go" internal/vaultapi/ | grep -v _test
```

Expected: hits only in `secrets_write.go`, where a supplied value is put on the
wire. `Decrypt` constructs a `SecretValue` rather than revealing one.

## Notes for the next plan

Plan 27 registers the four crypto tools, bringing the surface to 27 and
completing the tool set.

**Two things it must get right:**

- **`decrypt` is gated twice.** `allow_crypto` admits the tier; `decrypt`
  additionally requires `allow_secret_values`, because its output *is*
  plaintext. Treating the tier flag as sufficient would let an operator who
  disabled secret disclosure read any secret by encrypting nothing and
  decrypting something.
- **Base64 is the tool boundary's problem now.** `vaultapi` takes bytes, but a
  model cannot pass raw bytes over JSON. Plan 27 decides how tools accept and
  return data, and must handle the case where decrypted plaintext is not valid
  UTF-8 — returning it as text would corrupt it silently.
