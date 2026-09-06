# API Refactor 06 — Generic Crypto-Operation Runner

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the six ~55-line crypto handlers into one shared spine plus six declarative specs.

**Architecture:** `cryptoOp[Req, In, Res]` carries three type parameters because the operation has three genuinely distinct stages: the decoded wire request, the base64-decoded binary inputs, and the response body. The third parameter is what lets the spine keep the **exact step ordering** of the current handlers — base64 decoding happens before the service is resolved, and collapsing to two parameters would silently swap those two steps.

**Tech Stack:** Go 1.25 generics.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0. Generics available.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Do not modify any `_test.go` file in this plan.** `api/keys_crypto_test.go` is the densest behavioral suite in the package and is the primary oracle here.
- **Step order is behavior.** Each handler currently runs: parse id, build scope, decode body, check required fields, apply the default algorithm, base64-decode, resolve the service, invoke, map errors, encode. The spine must run those in that order. A reordering changes which error a malformed request gets.
- Every error string must stay verbatim.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Add the `cryptoOp` spine

**Files:**
- Modify: `api/keys_crypto.go` (add at the top, above the six handlers; leave them in place for now)

**Interfaces:**
- Consumes: `resourceID`, `decodeBody[T]`, `b64Field` (plan 03); `svc[T]` (plan 04); `writeJSON[T]` (plan 02); `scopeFromRequest` (`api/context.go`); `writeKeyError` (`api/errors_key.go`).
- Produces:
  - `type cryptoOp[Req any, In any, Res any] struct`
  - `func (op cryptoOp[Req, In, Res]) handler() func(*Context, http.ResponseWriter, *http.Request)`

  Task 2 defines six values of this type.

- [ ] **Step 1: Write the spine**

Add to `api/keys_crypto.go`:

```go
// cryptoOp is the shared spine of the six key crypto handlers.
//
// All six run the same steps in the same order and differ only in their wire
// types, their default algorithm, which fields are required, and which fields
// carry base64. Writing that spine once means a change to the ordering — which
// is behavior, since it decides which error a malformed request gets — happens
// in one place instead of six.
//
// The three type parameters mirror the three stages: Req is the decoded wire
// request, In is the base64-decoded binary input, Res is the response body.
// Separating In from Req is what keeps base64 decoding ahead of service
// resolution, matching the handlers this replaces.
type cryptoOp[Req any, In any, Res any] struct {
	// DefaultAlgorithm is applied when the request omits one. It is only
	// consulted when AlgorithmField is non-nil.
	DefaultAlgorithm string

	// AlgorithmField returns a pointer to the request's algorithm field so a
	// default can be written into it. It is nil for the operations that have no
	// default and pass through whatever the client sent — verify and decrypt.
	AlgorithmField func(*Req) *string

	// Required returns an empty string when the request carries everything the
	// operation needs, and otherwise the exact message for the 400.
	Required func(Req) string

	// Decode turns the request's base64 fields into binary. It sets c.Err and
	// returns false on a malformed field.
	Decode func(c *Context, req Req) (In, bool)

	// Invoke performs the operation and builds the response body. Its error is
	// mapped by writeKeyError, so it should return the service error unwrapped.
	Invoke func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req Req, in In) (Res, error)
}

// handler turns a cryptoOp into a registrable API handler.
func (op cryptoOp[Req, In, Res]) handler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		keyID, ok := resourceID(c, c.Params.KeyID, "key_id")
		if !ok {
			return
		}

		scope, ok := scopeFromRequest(c, r)
		if !ok {
			return
		}

		req, ok := decodeBody[Req](c, r)
		if !ok {
			return
		}

		if msg := op.Required(req); msg != "" {
			c.SetInvalidParam(msg)
			return
		}

		if op.AlgorithmField != nil {
			if field := op.AlgorithmField(&req); *field == "" {
				*field = op.DefaultAlgorithm
			}
		}

		in, ok := op.Decode(c, req)
		if !ok {
			return
		}

		cs, ok := svc(c, container.ServiceContainerInterface.GetCryptoService)
		if !ok {
			return
		}

		res, err := op.Invoke(r.Context(), cs, keyID, scope, req, in)
		if err != nil {
			writeKeyError(c, err)
			return
		}

		writeJSON(w, res)
	}
}
```

Add `"context"` to the file's imports.

- [ ] **Step 2: Gate**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/ && ./scripts/verify-api-refactor.sh
```
Expected: `gofmt -l` silent, `PASS ... coverage 86.0%`. Nothing uses the spine yet, so behavior is unchanged by construction.

- [ ] **Step 3: Commit**

```bash
git add api/keys_crypto.go
git commit -S -m "refactor(api): add generic crypto-operation spine"
```

---

### Task 2: Convert wrap, unwrap, sign

**Files:**
- Modify: `api/keys_crypto.go`

**Interfaces:**
- Consumes: `cryptoOp` from Task 1.
- Produces: `wrapKey`, `unwrapKey`, `signKey` as package-level `var`s of function type, keeping the exact names `registerKeyRoutes` already passes to `ApiSessionRequired`.

Because the route registrations in `api/keys.go` reference these by bare name, converting a `func` to a `var` of the same name and signature requires no change at the call site.

- [ ] **Step 1: Replace `wrapKey` and `unwrapKey`**

Delete both handler funcs and add:

```go
// wrapKey wraps plaintext key material using the vault key identified by {key_id}.
var wrapKey = cryptoOp[WrapKeyRequest, []byte, WrapKeyResponse]{
	DefaultAlgorithm: "RSA-OAEP",
	AlgorithmField:   func(req *WrapKeyRequest) *string { return &req.Algorithm },
	Required: func(req WrapKeyRequest) string {
		if req.PlaintextKey == "" {
			return "plaintext_key is required"
		}
		return ""
	},
	Decode: func(c *Context, req WrapKeyRequest) ([]byte, bool) {
		return b64Field(c, req.PlaintextKey, "plaintext_key")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req WrapKeyRequest, in []byte) (WrapKeyResponse, error) {
		result, err := cs.WrapKey(ctx, keyservices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       scope.ActorID(),
			VaultID:      scope.VaultID(),
			Scope:        scope,
			PlaintextKey: in,
			Algorithm:    req.Algorithm,
			Version:      req.Version,
		})
		if err != nil {
			return WrapKeyResponse{}, err
		}
		return WrapKeyResponse{
			WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
			Algorithm:  result.Algorithm,
			Version:    result.Version,
		}, nil
	},
}.handler()

// unwrapKey recovers plaintext key material from wrapped bytes using the vault key identified by {key_id}.
var unwrapKey = cryptoOp[UnwrapKeyRequest, []byte, UnwrapKeyResponse]{
	DefaultAlgorithm: "RSA-OAEP",
	AlgorithmField:   func(req *UnwrapKeyRequest) *string { return &req.Algorithm },
	Required: func(req UnwrapKeyRequest) string {
		if req.WrappedKey == "" {
			return "wrapped_key is required"
		}
		return ""
	},
	Decode: func(c *Context, req UnwrapKeyRequest) ([]byte, bool) {
		return b64Field(c, req.WrappedKey, "wrapped_key")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req UnwrapKeyRequest, in []byte) (UnwrapKeyResponse, error) {
		result, err := cs.UnwrapKey(ctx, keyservices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     scope.ActorID(),
			VaultID:    scope.VaultID(),
			Scope:      scope,
			WrappedKey: in,
			Algorithm:  req.Algorithm,
			Version:    req.Version,
		})
		if err != nil {
			return UnwrapKeyResponse{}, err
		}
		return UnwrapKeyResponse{
			PlaintextKey: base64.StdEncoding.EncodeToString(result.PlaintextKey),
			Algorithm:    result.Algorithm,
			Version:      result.Version,
		}, nil
	},
}.handler()
```

- [ ] **Step 2: Replace `signKey`**

```go
// signKey signs data using the vault key identified by {key_id}.
var signKey = cryptoOp[SignKeyRequest, []byte, SignKeyResponse]{
	DefaultAlgorithm: "RS256",
	AlgorithmField:   func(req *SignKeyRequest) *string { return &req.Algorithm },
	Required: func(req SignKeyRequest) string {
		if req.Value == "" {
			return "value is required"
		}
		return ""
	},
	Decode: func(c *Context, req SignKeyRequest) ([]byte, bool) {
		return b64Field(c, req.Value, "value")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req SignKeyRequest, in []byte) (SignKeyResponse, error) {
		result, err := cs.Sign(ctx, keyservices.SignRequest{
			KeyID:     keyID,
			Data:      in,
			Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
			UserID:    scope.ActorID(),
			VaultID:   scope.VaultID(),
			Scope:     scope,
			Version:   req.Version,
		})
		if err != nil {
			return SignKeyResponse{}, err
		}
		return SignKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Value:     base64.StdEncoding.EncodeToString(result.Signature),
			Version:   result.Version,
		}, nil
	},
}.handler()
```

- [ ] **Step 3: Gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
go test ./api/... -count=1 -run 'Wrap|Unwrap|Sign' -v 2>&1 | tail -30
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: the targeted run passes, gate `PASS ... coverage 86.0%`, `OK: no test files touched`.

```bash
git add api/keys_crypto.go
git commit -S -m "refactor(api): express wrap, unwrap and sign as crypto-op specs"
```

---

### Task 3: Convert verify, encrypt, decrypt

**Files:**
- Modify: `api/keys_crypto.go`

**Interfaces:**
- Consumes: `cryptoOp` from Task 1.
- Produces: `verifyKey`, `encryptKey`, `decryptKey` as package-level `var`s, plus two small input structs `verifyInputs` and `decryptInputs` used only as the `In` type parameter.

These three are the awkward ones and are grouped together on purpose: verify decodes two fields, decrypt decodes one plus a conditional one, and encrypt has a conditional response field. Neither verify nor decrypt sets a default algorithm — `AlgorithmField` is nil for both, which is not an oversight but a copy of current behavior.

- [ ] **Step 1: Replace `verifyKey`**

```go
// verifyInputs carries verify's two base64-decoded fields.
type verifyInputs struct {
	Data      []byte
	Signature []byte
}

// verifyKey verifies a signature using the vault key identified by {key_id}.
//
// AlgorithmField is nil deliberately: verify applies no default algorithm and
// passes through whatever the client sent, matching the handler it replaces.
var verifyKey = cryptoOp[VerifyKeyRequest, verifyInputs, VerifyKeyResponse]{
	Required: func(req VerifyKeyRequest) string {
		if req.Value == "" || req.Signature == "" {
			return "value and signature are required"
		}
		return ""
	},
	Decode: func(c *Context, req VerifyKeyRequest) (verifyInputs, bool) {
		data, ok := b64Field(c, req.Value, "value")
		if !ok {
			return verifyInputs{}, false
		}
		sig, ok := b64Field(c, req.Signature, "signature")
		if !ok {
			return verifyInputs{}, false
		}
		return verifyInputs{Data: data, Signature: sig}, true
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req VerifyKeyRequest, in verifyInputs) (VerifyKeyResponse, error) {
		result, err := cs.Verify(ctx, keyservices.VerifyRequest{
			KeyID:     keyID,
			Data:      in.Data,
			Signature: in.Signature,
			Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
			UserID:    scope.ActorID(),
			VaultID:   scope.VaultID(),
			Scope:     scope,
			Version:   req.Version,
		})
		if err != nil {
			return VerifyKeyResponse{}, err
		}
		return VerifyKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Valid:     result.Valid,
			Version:   result.Version,
		}, nil
	},
}.handler()
```

- [ ] **Step 2: Replace `encryptKey` and `decryptKey`**

```go
// encryptKey encrypts data using the vault key identified by {key_id}.
var encryptKey = cryptoOp[EncryptKeyRequest, []byte, EncryptKeyResponse]{
	DefaultAlgorithm: "RSA-OAEP",
	AlgorithmField:   func(req *EncryptKeyRequest) *string { return &req.Algorithm },
	Required: func(req EncryptKeyRequest) string {
		if req.Value == "" {
			return "value is required"
		}
		return ""
	},
	Decode: func(c *Context, req EncryptKeyRequest) ([]byte, bool) {
		return b64Field(c, req.Value, "value")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req EncryptKeyRequest, in []byte) (EncryptKeyResponse, error) {
		result, err := cs.Encrypt(ctx, keyservices.EncryptRequest{
			KeyID:     keyID,
			Data:      in,
			Algorithm: crypto.EncryptionAlgorithm(req.Algorithm),
			UserID:    scope.ActorID(),
			VaultID:   scope.VaultID(),
			Scope:     scope,
			Version:   req.Version,
		})
		if err != nil {
			return EncryptKeyResponse{}, err
		}
		res := EncryptKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Value:     base64.StdEncoding.EncodeToString(result.Ciphertext),
			Version:   result.Version,
		}
		// Nonce is only present for AEAD modes such as AES-GCM. Encoding an
		// empty slice would put an empty string on the wire where the field was
		// previously omitted.
		if len(result.Nonce) > 0 {
			res.Nonce = base64.StdEncoding.EncodeToString(result.Nonce)
		}
		return res, nil
	},
}.handler()

// decryptInputs carries decrypt's ciphertext and its optional nonce.
type decryptInputs struct {
	Ciphertext []byte
	Nonce      []byte
}

// decryptKey decrypts data using the vault key identified by {key_id}.
//
// AlgorithmField is nil deliberately: decrypt applies no default algorithm,
// matching the handler it replaces.
var decryptKey = cryptoOp[DecryptKeyRequest, decryptInputs, DecryptKeyResponse]{
	Required: func(req DecryptKeyRequest) string {
		if req.Value == "" {
			return "value is required"
		}
		return ""
	},
	Decode: func(c *Context, req DecryptKeyRequest) (decryptInputs, bool) {
		ciphertext, ok := b64Field(c, req.Value, "value")
		if !ok {
			return decryptInputs{}, false
		}
		// An absent nonce is legitimate for non-AEAD algorithms, so only a
		// present-but-malformed one is an error.
		var nonce []byte
		if req.Nonce != "" {
			nonce, ok = b64Field(c, req.Nonce, "nonce")
			if !ok {
				return decryptInputs{}, false
			}
		}
		return decryptInputs{Ciphertext: ciphertext, Nonce: nonce}, true
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req DecryptKeyRequest, in decryptInputs) (DecryptKeyResponse, error) {
		result, err := cs.Decrypt(ctx, keyservices.DecryptRequest{
			KeyID:      keyID,
			Ciphertext: in.Ciphertext,
			Nonce:      in.Nonce,
			Algorithm:  crypto.EncryptionAlgorithm(req.Algorithm),
			UserID:     scope.ActorID(),
			VaultID:    scope.VaultID(),
			Scope:      scope,
			Version:    req.Version,
		})
		if err != nil {
			return DecryptKeyResponse{}, err
		}
		return DecryptKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Value:     base64.StdEncoding.EncodeToString(result.Plaintext),
			Version:   result.Version,
		}, nil
	},
}.handler()
```

- [ ] **Step 3: Verify the collapse, gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
wc -l keys_crypto.go
git show 4dc0285:api/keys.go | sed -n '822,1193p' | wc -l
```
The original six handlers were 372 lines. `keys_crypto.go` including the spine should land well under that; if it is larger, the abstraction is not paying for itself and that is worth reporting rather than hiding.

Run the full crypto suite explicitly — it is the primary oracle for this plan:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./api/... -count=1 -run 'Crypto|Wrap|Unwrap|Sign|Verify|Encrypt|Decrypt' -v 2>&1 | tail -40
```
Expected: all pass. Pay particular attention to `TestEncryptKey/DecryptKey_HSMRejectsAlgorithm_Returns400` — it pins that a PKCS#11 rejection surfaces as a 400 with no backend detail leaked, which depends on `writeKeyError` still being reached from `Invoke`'s error return.

Run:
```bash
gofmt -l api/
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: `gofmt -l` silent, `PASS ... coverage 86.0%`, `OK: no test files touched`.

```bash
git add api/keys_crypto.go
git commit -S -m "refactor(api): express verify, encrypt and decrypt as crypto-op specs"
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-07-soft-delete.md` next.**
