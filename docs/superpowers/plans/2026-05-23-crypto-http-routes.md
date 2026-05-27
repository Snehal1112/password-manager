# Crypto Operations HTTP Routes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose `Sign`, `Verify`, `Encrypt`, and `Decrypt` operations as HTTP endpoints on existing keys, expanding the cryptographic algorithm coverage to match Azure Key Vault's supported algorithms. The service methods already exist in `internal/services/keys/crypto_service.go`; this plan adds four HTTP routes and the missing algorithm implementations.

**Architecture:** Following the existing wrap/unwrap pattern: add routes in `api/keys.go`, add handlers to `api/keys.go`, pass calls through the service container, and expand `internal/crypto/crypto_operations.go` with the missing algorithm primitives (PS256/384/512 for RSA-PSS signing; no additional encryption algorithms in scope for this plan — those are handled by the wrap/unwrap routes).

**Tech Stack:** Go 1.24.2, `crypto/rsa`, `crypto/ecdsa`, `crypto/elliptic`, Gorilla Mux, `net/http`, testify.

**Spec:** `docs/plans/2026-05-23-azure-keyvault-parity-audit.md` §Keys rows: Sign/Verify operations, Encryption operations.

**Depends on:** [2026-05-23-bug-fixes-rsa-oaep-cert-autorenew.md](2026-05-23-bug-fixes-rsa-oaep-cert-autorenew.md) (RSA-OAEP-256 constant).

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `internal/crypto/crypto_operations.go` | Modify | Add PS256/PS384/PS512 (RSA-PSS) sign/verify paths |
| `internal/services/keys/crypto_service.go` | Modify | Add PS256/384/512 to `Sign`/`Verify` algorithm validation |
| `model/key.go` | Modify | Add `SignRequest`, `SignResponse`, `VerifyRequest`, `VerifyResponse`, `EncryptRequest`, `EncryptResponse`, `DecryptRequest`, `DecryptResponse` HTTP types |
| `api/keys.go` | Modify | Register 4 new routes; add 4 handlers: `signKey`, `verifyKey`, `encryptKey`, `decryptKey` |
| `internal/crypto/crypto_operations_test.go` | Modify | Add RSA-PSS sign/verify tests for PS256/384/512 |
| `api/keys_crypto_test.go` | Create | HTTP-layer tests for all four new endpoints |

---

## Task 1: Add PS256/PS384/PS512 (RSA-PSS) to `crypto_operations.go`

**Files:**
- Modify: `internal/crypto/crypto_operations.go`

- [ ] **Step 1: Write failing tests for PS256/PS384/PS512**

In `internal/crypto/crypto_operations_test.go`, add:

```go
func TestSign_RSA_PSS_Algorithms(t *testing.T) {
	ops := NewCryptoOperations()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := encodeRSAPrivateKeyToPEM(t, key)
	data := []byte("data to sign with PSS")

	for _, alg := range []SignatureAlgorithm{"PS256", "PS384", "PS512"} {
		t.Run(string(alg), func(t *testing.T) {
			sig, err := ops.Sign(pemKey, "RSA", data, alg)
			require.NoError(t, err)
			assert.NotEmpty(t, sig.Signature)
			assert.Equal(t, alg, sig.Algorithm)

			v, err := ops.Verify(pemKey, "RSA", data, sig.Signature, alg)
			require.NoError(t, err)
			assert.True(t, v.Valid)

			// Mutated data must not verify
			v2, err := ops.Verify(pemKey, "RSA", append(data, 0), sig.Signature, alg)
			require.NoError(t, err)
			assert.False(t, v2.Valid)
		})
	}
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/crypto/... -run "TestSign_RSA_PSS" -v 2>&1 | tail -15
```

Expected: FAIL — `PS256` etc. not supported.

- [ ] **Step 3: Add PS256/PS384/PS512 constants**

In `internal/crypto/crypto_operations.go`, find the `SignatureAlgorithm` constants block:

```go
const (
	AlgorithmRS256 SignatureAlgorithm = "RS256"
	AlgorithmRS384 SignatureAlgorithm = "RS384"
	AlgorithmRS512 SignatureAlgorithm = "RS512"
	AlgorithmES256 SignatureAlgorithm = "ES256"
	AlgorithmES384 SignatureAlgorithm = "ES384"
	AlgorithmES512 SignatureAlgorithm = "ES512"
)
```

Append:

```go
	// RSA-PSS — Azure "PS256", "PS384", "PS512"
	AlgorithmPS256 SignatureAlgorithm = "PS256"
	AlgorithmPS384 SignatureAlgorithm = "PS384"
	AlgorithmPS512 SignatureAlgorithm = "PS512"
```

- [ ] **Step 4: Update `getHasher` and `getHashType` helpers to include PS algorithms**

Find `getHasher` (maps algorithm to `hash.Hash`). Add cases:

```go
case AlgorithmPS256:
    return sha256.New(), nil
case AlgorithmPS384:
    return sha512.New384(), nil
case AlgorithmPS512:
    return sha512.New(), nil
```

Find `getHashType` (maps algorithm to `crypto.Hash`). Add cases:

```go
case AlgorithmPS256:
    return crypto.SHA256, nil
case AlgorithmPS384:
    return crypto.SHA384, nil
case AlgorithmPS512:
    return crypto.SHA512, nil
```

- [ ] **Step 5: Add PSS signing/verifying in `Sign` and `Verify` RSA dispatch**

In the `Sign` function, find the `case "RSA":` block. It currently only uses `rsa.SignPKCS1v15`. Add a PSS branch before the PKCS1 call:

```go
case "RSA":
    rsaKey, ok := privateKey.(*rsa.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("invalid RSA private key")
    }
    hashType, err := getHashType(algorithm)
    if err != nil {
        return nil, err
    }
    var signature []byte
    switch algorithm {
    case AlgorithmPS256, AlgorithmPS384, AlgorithmPS512:
        signature, err = rsa.SignPSS(rand.Reader, rsaKey, hashType, digest, nil)
    default:
        signature, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, hashType, digest)
    }
    if err != nil {
        return nil, fmt.Errorf("RSA signing failed: %w", err)
    }
```

In the `Verify` function, find the `case "RSA":` block. Add PSS verification:

```go
case "RSA":
    rsaKey, ok := privateKey.(*rsa.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("invalid RSA private key")
    }
    hashType, err := getHashType(algorithm)
    if err != nil {
        return nil, err
    }
    var verifyErr error
    switch algorithm {
    case AlgorithmPS256, AlgorithmPS384, AlgorithmPS512:
        verifyErr = rsa.VerifyPSS(&rsaKey.PublicKey, hashType, digest, signature, nil)
    default:
        verifyErr = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, hashType, digest, signature)
    }
    valid = (verifyErr == nil)
```

- [ ] **Step 6: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/crypto/... -run "TestSign_RSA_PSS" -v 2>&1 | tail -20
```

Expected: all PS256/PS384/PS512 sub-tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/crypto/crypto_operations.go internal/crypto/crypto_operations_test.go
git commit -m "feat(crypto): add PS256/PS384/PS512 RSA-PSS sign/verify support"
```

---

## Task 2: Add HTTP request/response types to `model/key.go`

**Files:**
- Modify: `model/key.go`

- [ ] **Step 1: Add request/response types**

Append to `model/key.go` (after existing types):

```go
// --- Crypto operation request/response types ---

type SignKeyRequest struct {
	Data      []byte `json:"data"`      // base64-encoded data to sign
	Algorithm string `json:"algorithm"` // RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
}

type SignKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature []byte `json:"signature"` // base64-encoded
}

type VerifyKeyRequest struct {
	Data      []byte `json:"data"`      // base64-encoded original data
	Signature []byte `json:"signature"` // base64-encoded signature
	Algorithm string `json:"algorithm"`
}

type VerifyKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Valid     bool   `json:"valid"`
}

type EncryptKeyRequest struct {
	Plaintext []byte `json:"plaintext"` // base64-encoded
	Algorithm string `json:"algorithm"` // RSA-OAEP, RSA-OAEP-256, AES256-GCM
}

type EncryptKeyResponse struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	Ciphertext []byte `json:"ciphertext"` // base64-encoded
	Nonce      []byte `json:"nonce,omitempty"`
}

type DecryptKeyRequest struct {
	Ciphertext []byte `json:"ciphertext"` // base64-encoded
	Nonce      []byte `json:"nonce,omitempty"`
	Algorithm  string `json:"algorithm"`
}

type DecryptKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Plaintext []byte `json:"plaintext"` // base64-encoded
}
```

- [ ] **Step 2: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add model/key.go
git commit -m "feat(model): add Sign/Verify/Encrypt/Decrypt request-response types to key model"
```

---

## Task 3: Register the four new HTTP routes

**Files:**
- Modify: `api/keys.go`

- [ ] **Step 1: Write failing HTTP integration tests**

Create `api/keys_crypto_test.go`:

```go
package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignEndpoint verifies POST /keys/{key_id}/sign returns 200 with a non-empty signature.
func TestSignEndpoint(t *testing.T) {
	srv := newTestServer(t) // use existing test server helper in the api package tests
	keyID := createTestKey(t, srv, "RSA")

	body, _ := json.Marshal(map[string]interface{}{
		"data":      []byte("hello world"),
		"algorithm": "RS256",
	})
	resp := doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/sign", body)
	require.Equal(t, http.StatusOK, resp.Code)

	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.NotEmpty(t, out["signature"])
}

// TestVerifyEndpoint verifies POST /keys/{key_id}/verify returns {valid:true} for a correct signature.
func TestVerifyEndpoint(t *testing.T) {
	srv := newTestServer(t)
	keyID := createTestKey(t, srv, "RSA")

	// Sign first
	signBody, _ := json.Marshal(map[string]interface{}{"data": []byte("msg"), "algorithm": "RS256"})
	signResp := doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/sign", signBody)
	require.Equal(t, http.StatusOK, signResp.Code)
	var signOut map[string]interface{}
	json.NewDecoder(signResp.Body).Decode(&signOut)

	// Verify
	verifyBody, _ := json.Marshal(map[string]interface{}{
		"data":      []byte("msg"),
		"signature": signOut["signature"],
		"algorithm": "RS256",
	})
	resp := doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/verify", verifyBody)
	require.Equal(t, http.StatusOK, resp.Code)
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	assert.True(t, out["valid"].(bool))
}

// TestEncryptDecryptEndpoint verifies round-trip encrypt/decrypt.
func TestEncryptDecryptEndpoint(t *testing.T) {
	srv := newTestServer(t)
	keyID := createTestKey(t, srv, "RSA")
	plaintext := []byte("my secret data")

	encBody, _ := json.Marshal(map[string]interface{}{
		"plaintext": plaintext,
		"algorithm": "RSA-OAEP",
	})
	encResp := doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/encrypt", encBody)
	require.Equal(t, http.StatusOK, encResp.Code)
	var encOut map[string]interface{}
	json.NewDecoder(encResp.Body).Decode(&encOut)

	decBody, _ := json.Marshal(map[string]interface{}{
		"ciphertext": encOut["ciphertext"],
		"algorithm":  "RSA-OAEP",
	})
	decResp := doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/decrypt", decBody)
	require.Equal(t, http.StatusOK, decResp.Code)
	var decOut map[string]interface{}
	json.NewDecoder(decResp.Body).Decode(&decOut)
	assert.Equal(t, plaintext, decOut["plaintext"])
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestSign|TestVerify|TestEncrypt|TestDecrypt" -v 2>&1 | tail -15
```

Expected: FAIL — routes don't exist (404).

- [ ] **Step 3: Register routes in `InitKeys`**

In `api/keys.go`, find `InitKeys`:

```go
func (api *API) InitKeys() {
	k := api.BaseRoutes.Keys

	// Basic CRUD operations.
	k.Handle("", ApiSessionRequired(api.App, createKey)).Methods("POST")
	// ...
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/wrap", ApiSessionRequired(api.App, wrapKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/unwrap", ApiSessionRequired(api.App, unwrapKey)).Methods("POST")

	api.Logger.Infoln("Keys API routes initialized")
}
```

Add four new routes before the log line:

```go
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/sign", ApiSessionRequired(api.App, signKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/verify", ApiSessionRequired(api.App, verifyKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/encrypt", ApiSessionRequired(api.App, encryptKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/decrypt", ApiSessionRequired(api.App, decryptKey)).Methods("POST")
```

- [ ] **Step 4: Implement `signKey` handler**

Add to `api/keys.go` (after the `unwrapKey` handler):

```go
func signKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["key_id"])
	if err != nil {
		c.SetInvalidParamError("key_id")
		c.HandleError(w, r)
		return
	}

	var req model.SignKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParamError("body")
		c.HandleError(w, r)
		return
	}
	if len(req.Data) == 0 {
		c.SetInvalidParamError("data")
		c.HandleError(w, r)
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RS256"
	}

	userID := c.GetUserID()
	cryptoSvc := c.App.GetServiceContainer().GetCryptoService()
	result, err := cryptoSvc.Sign(r.Context(), keyservices.SignRequest{
		KeyID:     keyID,
		Data:      req.Data,
		Algorithm: req.Algorithm,
		UserID:    userID,
	})
	if err != nil {
		c.SetError(err.Error(), http.StatusBadRequest)
		c.HandleError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.SignKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: result.Algorithm,
		Signature: result.Signature,
	})
}
```

- [ ] **Step 5: Implement `verifyKey` handler**

```go
func verifyKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["key_id"])
	if err != nil {
		c.SetInvalidParamError("key_id")
		c.HandleError(w, r)
		return
	}

	var req model.VerifyKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Data) == 0 || len(req.Signature) == 0 {
		c.SetInvalidParamError("body")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	cryptoSvc := c.App.GetServiceContainer().GetCryptoService()
	result, err := cryptoSvc.Verify(r.Context(), keyservices.VerifyRequest{
		KeyID:     keyID,
		Data:      req.Data,
		Signature: req.Signature,
		Algorithm: req.Algorithm,
		UserID:    userID,
	})
	if err != nil {
		c.SetError(err.Error(), http.StatusBadRequest)
		c.HandleError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.VerifyKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: result.Algorithm,
		Valid:     result.Valid,
	})
}
```

- [ ] **Step 6: Implement `encryptKey` handler**

```go
func encryptKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["key_id"])
	if err != nil {
		c.SetInvalidParamError("key_id")
		c.HandleError(w, r)
		return
	}

	var req model.EncryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Plaintext) == 0 {
		c.SetInvalidParamError("body")
		c.HandleError(w, r)
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	userID := c.GetUserID()
	cryptoSvc := c.App.GetServiceContainer().GetCryptoService()
	result, err := cryptoSvc.Encrypt(r.Context(), keyservices.EncryptRequest{
		KeyID:     keyID,
		Data:      req.Plaintext,
		Algorithm: req.Algorithm,
		UserID:    userID,
	})
	if err != nil {
		c.SetError(err.Error(), http.StatusBadRequest)
		c.HandleError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.EncryptKeyResponse{
		KeyID:      keyID.String(),
		Algorithm:  result.Algorithm,
		Ciphertext: result.Ciphertext,
		Nonce:      result.Nonce,
	})
}
```

- [ ] **Step 7: Implement `decryptKey` handler**

```go
func decryptKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["key_id"])
	if err != nil {
		c.SetInvalidParamError("key_id")
		c.HandleError(w, r)
		return
	}

	var req model.DecryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Ciphertext) == 0 {
		c.SetInvalidParamError("body")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	cryptoSvc := c.App.GetServiceContainer().GetCryptoService()
	result, err := cryptoSvc.Decrypt(r.Context(), keyservices.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Algorithm:  req.Algorithm,
		UserID:     userID,
	})
	if err != nil {
		c.SetError(err.Error(), http.StatusBadRequest)
		c.HandleError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.DecryptKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: result.Algorithm,
		Plaintext: result.Plaintext,
	})
}
```

- [ ] **Step 8: Resolve any import issues**

After adding handlers, verify the import block at the top of `api/keys.go` includes all required packages. Add any missing imports:

```go
import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)
```

Adjust the import path prefix to match the existing imports in the file.

- [ ] **Step 9: Build and run HTTP tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./api/... -run "TestSign|TestVerify|TestEncrypt|TestDecrypt" -v 2>&1 | tail -20
```

Expected: all four HTTP tests PASS.

- [ ] **Step 10: Commit**

```bash
git add api/keys.go api/keys_crypto_test.go model/key.go
git commit -m "feat(api): add POST /keys/{id}/sign, /verify, /encrypt, /decrypt HTTP routes"
```

---

## Task 4: Update OpenAPI spec

**Files:**
- Modify: `docs/api-specification.yaml`

- [ ] **Step 1: Add paths for all four new endpoints**

In `docs/api-specification.yaml`, after the `/keys/{key_id}/unwrap` section, add:

```yaml
  /keys/{key_id}/sign:
    post:
      summary: Sign data using a key
      tags: [Keys]
      security:
        - bearerAuth: []
      parameters:
        - name: key_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [data, algorithm]
              properties:
                data:
                  type: string
                  format: byte
                  description: Base64-encoded data to sign
                algorithm:
                  type: string
                  enum: [RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512]
      responses:
        '200':
          description: Signature result
          content:
            application/json:
              schema:
                type: object
                properties:
                  key_id:
                    type: string
                  algorithm:
                    type: string
                  signature:
                    type: string
                    format: byte

  /keys/{key_id}/verify:
    post:
      summary: Verify a signature using a key
      tags: [Keys]
      security:
        - bearerAuth: []
      parameters:
        - name: key_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [data, signature, algorithm]
              properties:
                data:
                  type: string
                  format: byte
                signature:
                  type: string
                  format: byte
                algorithm:
                  type: string
                  enum: [RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512]
      responses:
        '200':
          description: Verification result
          content:
            application/json:
              schema:
                type: object
                properties:
                  valid:
                    type: boolean

  /keys/{key_id}/encrypt:
    post:
      summary: Encrypt data using a key
      tags: [Keys]
      security:
        - bearerAuth: []
      parameters:
        - name: key_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [plaintext, algorithm]
              properties:
                plaintext:
                  type: string
                  format: byte
                algorithm:
                  type: string
                  enum: [RSA-OAEP, RSA-OAEP-256, AES256-GCM]
      responses:
        '200':
          description: Encrypted result
          content:
            application/json:
              schema:
                type: object
                properties:
                  ciphertext:
                    type: string
                    format: byte
                  nonce:
                    type: string
                    format: byte

  /keys/{key_id}/decrypt:
    post:
      summary: Decrypt data using a key
      tags: [Keys]
      security:
        - bearerAuth: []
      parameters:
        - name: key_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [ciphertext, algorithm]
              properties:
                ciphertext:
                  type: string
                  format: byte
                nonce:
                  type: string
                  format: byte
                algorithm:
                  type: string
                  enum: [RSA-OAEP, RSA-OAEP-256, AES256-GCM]
      responses:
        '200':
          description: Decrypted result
          content:
            application/json:
              schema:
                type: object
                properties:
                  plaintext:
                    type: string
                    format: byte
```

- [ ] **Step 2: Commit**

```bash
git add docs/api-specification.yaml
git commit -m "docs(api): document sign/verify/encrypt/decrypt key endpoints in OpenAPI spec"
```

---

## Task 5: Full regression pass

- [ ] **Step 1: Run full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|ok" | sort
```

Expected: all packages `ok`.

- [ ] **Step 2: Build final binary**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build -o /tmp/rocketvault-crypto-routes . && echo "build ok"
```

Expected: `build ok`.

- [ ] **Step 3: Validate OpenAPI spec (optional, if tooling is available)**

```bash
cd /home/numericlabs/data/rocket/rocketvault && ./validate-api-docs.sh 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: Sign/Verify/Encrypt/Decrypt HTTP routes complete — crypto operations parity"
```
