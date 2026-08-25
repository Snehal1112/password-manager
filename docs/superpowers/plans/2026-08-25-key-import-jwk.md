# Key Import (JWK/BYOK) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a caller import externally-generated RSA/ECDSA key material (as a JWK) into a vault, over both the CLI and the REST API, storing it exactly as if RocketVault had generated it.

**Architecture:** A new `ParseJWK` helper turns a JWK's JSON into a Go `crypto.PrivateKey`. A new `KeyProvider.ImportKey` method (implemented on both `SoftwareKeyProvider` and `PKCS11KeyProvider`) turns that Go key into an opaque handle, exactly mirroring how `GenerateRSAKey`/`GenerateECDSAKey` already produce handles. `KeyService.ImportKey` wraps that the same way `CreateRSAKey` wraps generation: validate, call the provider, branch on PKCS#11-vs-software storage, persist, audit-log. A new collection-level route, `POST /keys/import`, and CLI command, `keys import`, expose it, gated by the `ActionKeysImport` data action that already exists but is currently unroutable.

**Tech Stack:** Go 1.24, `github.com/go-jose/go-jose/v4` (already a dependency), `github.com/miekg/pkcs11`, Cobra, testify/mock.

**Spec:** `docs/superpowers/specs/2026-08-25-key-import-jwk-design.md`

## Global Constraints

- No new third-party dependency — `go-jose/go-jose/v4 v4.1.4` is already in `go.mod`.
- An imported key on an HSM-backed vault must end up exactly as non-extractable as a generated one (`CKA_EXTRACTABLE: false`, `CKA_SENSITIVE: true`) — this is load-bearing for `docs/superpowers/specs/2026-08-25-key-export-decision-record.md`'s guarantee.
- `ParseJWK` rejects a public-only JWK (no private component) — importing such a JWK as a usable signing/decrypting key is meaningless.
- The new route is collection-level, `POST /keys/import`, not `/keys/{id}/import` — see spec Design §7.
- Follow existing package/file conventions exactly: `internal/services/keys/key_service.go`'s `Create*Key` shape, `cmd/keys/create.go`'s CLI shape, `api/keys.go`'s `createKey` handler shape.

---

### Task 1: `ParseJWK` helper

**Files:**
- Create: `internal/signing/jwk_parse.go`
- Test: `internal/signing/jwk_parse_test.go`

**Interfaces:**
- Consumes: nothing from this codebase (only `github.com/go-jose/go-jose/v4` and stdlib `crypto`/`crypto/rsa`/`crypto/ecdsa`)
- Produces: `func ParseJWK(jwkJSON []byte) (privateKey crypto.PrivateKey, keyType string, err error)` and `var ErrJWKNoPrivateKey error`, both in package `signing` — consumed by Task 4 (`KeyService.ImportKey`)

- [ ] **Step 1: Write the failing tests**

```go
// internal/signing/jwk_parse_test.go
package signing_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/signing"
)

func marshalJWK(t *testing.T, key any) []byte {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key}
	data, err := jwk.MarshalJSON()
	require.NoError(t, err)
	return data
}

func TestParseJWK_ValidRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	parsed, keyType, err := signing.ParseJWK(marshalJWK(t, priv))
	require.NoError(t, err)
	assert.Equal(t, "RSA", keyType)
	parsedRSA, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey, got %T", parsed)
	assert.Equal(t, priv.N, parsedRSA.N)
	assert.Equal(t, priv.D, parsedRSA.D)
}

func TestParseJWK_ValidECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parsed, keyType, err := signing.ParseJWK(marshalJWK(t, priv))
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", keyType)
	parsedEC, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey, got %T", parsed)
	assert.Equal(t, priv.D, parsedEC.D)
}

func TestParseJWK_PublicOnlyRSA_Rejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, _, err = signing.ParseJWK(marshalJWK(t, &priv.PublicKey))
	require.ErrorIs(t, err, signing.ErrJWKNoPrivateKey)
}

func TestParseJWK_InvalidJSON_Rejected(t *testing.T) {
	_, _, err := signing.ParseJWK([]byte("not json"))
	require.Error(t, err)
}

func TestParseJWK_UnsupportedKeyType_Rejected(t *testing.T) {
	// A symmetric ("oct") JWK is well-formed JSON but not an RSA/ECDSA key.
	symmetric := []byte(`{"kty":"oct","k":"c2VjcmV0LWtleS1tYXRlcmlhbA"}`)
	_, _, err := signing.ParseJWK(symmetric)
	require.Error(t, err)
	assert.NotErrorIs(t, err, signing.ErrJWKNoPrivateKey, "an oct key has a 'private' component and must fail as unsupported, not as public-only")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/signing/... -run TestParseJWK -v`
Expected: FAIL — `signing.ParseJWK` and `signing.ErrJWKNoPrivateKey` undefined.

- [ ] **Step 3: Write the implementation**

```go
// internal/signing/jwk_parse.go
package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// ErrJWKNoPrivateKey is returned when a supplied JWK carries no private key
// material -- only a public JWK -- and so cannot be imported as a usable key.
var ErrJWKNoPrivateKey = errors.New("jwk contains no private key material")

// ParseJWK parses a JWK containing private key material and returns the
// concrete Go key together with its RocketVault key-type string ("RSA" or
// "ECDSA"). It rejects public-only JWKs and any kty/crv combination
// RocketVault does not support for import.
func ParseJWK(jwkJSON []byte) (privateKey crypto.PrivateKey, keyType string, err error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, "", fmt.Errorf("invalid JWK: %w", err)
	}
	if jwk.IsPublic() {
		return nil, "", ErrJWKNoPrivateKey
	}
	switch key := jwk.Key.(type) {
	case *rsa.PrivateKey:
		return key, "RSA", nil
	case *ecdsa.PrivateKey:
		return key, "ECDSA", nil
	default:
		return nil, "", fmt.Errorf("unsupported JWK key type: %T", jwk.Key)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/signing/... -run TestParseJWK -v`
Expected: PASS, all five subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/signing/jwk_parse.go internal/signing/jwk_parse_test.go
git commit -m "feat(signing): add ParseJWK for key import"
```

---

### Task 2: `SoftwareKeyProvider.ImportKey`

**Files:**
- Modify: `internal/crypto/provider.go` (add `ImportKey` to the `KeyProvider` interface)
- Modify: `internal/crypto/software_provider.go` (implement it)
- Test: `internal/crypto/software_provider_test.go`

**Interfaces:**
- Consumes: nothing new (stdlib `crypto`, `crypto/x509`, `encoding/pem`)
- Produces: `KeyProvider.ImportKey(ctx context.Context, keyType string, privateKey crypto.PrivateKey) (handle string, err error)` — consumed by Task 4 (`KeyService.ImportKey`) and implemented again by Task 3 (`PKCS11KeyProvider`)

- [ ] **Step 1: Write the failing test**

Find the existing software-provider test file (`internal/crypto/software_provider_test.go`) and add:

```go
func TestSoftwareKeyProvider_ImportKey_RSA(t *testing.T) {
	p := NewSoftwareKeyProvider()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "RSA", priv)
	require.NoError(t, err)
	assert.NotEmpty(t, handle)

	block, _ := pem.Decode([]byte(handle))
	require.NotNil(t, block, "handle must be PEM, matching GenerateRSAKey's contract")
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	parsedRSA, ok := parsedKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, priv.N, parsedRSA.N)
}

func TestSoftwareKeyProvider_ImportKey_ECDSA(t *testing.T) {
	p := NewSoftwareKeyProvider()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "ECDSA", priv)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(handle))
	require.NotNil(t, block)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	parsedEC, ok := parsedKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, priv.D, parsedEC.D)
}

func TestSoftwareKeyProvider_ImportKey_UnsupportedType_ReturnsError(t *testing.T) {
	p := NewSoftwareKeyProvider()
	_, err := p.ImportKey(context.Background(), "RSA", "not a key")
	require.Error(t, err)
}
```

Add any missing imports (`crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `crypto/rsa`, `crypto/x509`, `encoding/pem`) to the test file's import block if not already present.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/crypto/... -run TestSoftwareKeyProvider_ImportKey -v`
Expected: FAIL — `p.ImportKey` undefined (compile error).

- [ ] **Step 3: Add `ImportKey` to the `KeyProvider` interface**

In `internal/crypto/provider.go`, add to the interface (after `GenerateAESKey`, before `Sign`):

```go
	// ImportKey imports externally-generated key material and returns an
	// opaque handle in the same shape GenerateRSAKey/GenerateECDSAKey return
	// -- PEM for SoftwareKeyProvider, a CKA_LABEL for PKCS11KeyProvider.
	// keyType is "RSA" or "ECDSA".
	ImportKey(ctx context.Context, keyType string, privateKey crypto.PrivateKey) (handle string, err error)
```

Add `"crypto"` to `provider.go`'s import block (package `internal/crypto` can import stdlib `crypto` without a name collision — the existing `internal/crypto/crypto_operations.go` already does this).

- [ ] **Step 4: Implement `SoftwareKeyProvider.ImportKey`**

In `internal/crypto/software_provider.go`, add:

```go
// ImportKey PEM-encodes externally-supplied key material, matching
// GenerateRSAKey/GenerateECDSAKey's existing "handle is PEM" contract.
func (p *SoftwareKeyProvider) ImportKey(_ context.Context, keyType string, privateKey crypto.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal imported %s key: %w", keyType, err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}
```

Add `"crypto"`, `"crypto/x509"`, `"encoding/pem"` to the file's import block if not already present.

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/crypto/... -run TestSoftwareKeyProvider_ImportKey -v`
Expected: PASS.

- [ ] **Step 6: Run the full package test suite to confirm nothing else broke**

Run: `go build ./... && go test ./internal/crypto/... ./internal/services/... -v 2>&1 | tail -50`
Expected: builds clean. Some other tests will still fail here only if `PKCS11KeyProvider` doesn't yet satisfy the widened `KeyProvider` interface — that's Task 3, expected at this point.

- [ ] **Step 7: Commit**

```bash
git add internal/crypto/provider.go internal/crypto/software_provider.go internal/crypto/software_provider_test.go
git commit -m "feat(crypto): add KeyProvider.ImportKey, software implementation"
```

---

### Task 3: `PKCS11KeyProvider.ImportKey`

**Files:**
- Modify: `internal/crypto/pkcs11_provider.go`
- Test: `internal/crypto/pkcs11_provider_test.go`

**Interfaces:**
- Consumes: `KeyProvider.ImportKey` signature from Task 2; `newTestPKCS11Provider(t)` test helper (`internal/crypto/pkcs11_provider_test.go:34`, already exists)
- Produces: satisfies `KeyProvider` for `*PKCS11KeyProvider`, unblocking Task 4's provider-agnostic `KeyService.ImportKey`

- [ ] **Step 1: Write the failing test**

Add to `internal/crypto/pkcs11_provider_test.go`, near the existing `TestPKCS11Provider_GenerateRSAKey`:

```go
func TestPKCS11Provider_ImportKey_RSA_IsNonExtractable(t *testing.T) {
	p := newTestPKCS11Provider(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "RSA", priv)
	require.NoError(t, err)
	assert.Len(t, handle, 36, "handle must be a UUID label, matching GenerateRSAKey's contract")

	// The imported key must be usable for the same operations a generated
	// key supports, and must carry the same non-extractability guarantee.
	sig, err := p.Sign(context.Background(), handle, "RSA", []byte("test data"), crypto.AlgorithmRS256)
	require.NoError(t, err)
	ok, err := p.Verify(context.Background(), handle, "RSA", []byte("test data"), sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestPKCS11Provider_ImportKey_ECDSA(t *testing.T) {
	p := newTestPKCS11Provider(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "ECDSA", priv)
	require.NoError(t, err)

	sig, err := p.Sign(context.Background(), handle, "ECDSA", []byte("test data"), crypto.AlgorithmES256)
	require.NoError(t, err)
	ok, err := p.Verify(context.Background(), handle, "ECDSA", []byte("test data"), sig, crypto.AlgorithmES256)
	require.NoError(t, err)
	assert.True(t, ok)
}
```

This test file is `package crypto_test` and already imports `"rocketvault/internal/crypto"` unaliased (`internal/crypto/pkcs11_provider_test.go:12`), referenced as `crypto.XXX` — that's `crypto.AlgorithmRS256`/`crypto.AlgorithmES256` (`internal/crypto/crypto_operations.go:27,32`), not stdlib `crypto`. Add `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `crypto/rsa` to this test file's import block for the new tests' key generation (these are stdlib subpackages, so they coexist with the unaliased `rocketvault/internal/crypto` import without collision).

- [ ] **Step 2: Run the test to verify it fails**

Run: `SOFTHSM2_LIB=<path> go test ./internal/crypto/... -run TestPKCS11Provider_ImportKey -v`
Expected: FAIL — `p.ImportKey` undefined (compile error), or SKIP if SoftHSM2 isn't set up in this environment (see the file's `softhsmAvailable()` guard) — if skipped, still proceed to Step 3, since the software-provider tests from Task 2 already exercise the interface addition and this step only adds coverage for environments with SoftHSM2 available.

- [ ] **Step 3: Implement `PKCS11KeyProvider.ImportKey`**

In `internal/crypto/pkcs11_provider.go`, add after `GenerateECDSAKey`:

```go
// ImportKey imports externally-supplied key material onto the token via
// C_CreateObject, using the same CKA_EXTRACTABLE: false / CKA_SENSITIVE: true
// attribute template GenerateRSAKey/GenerateECDSAKey apply to generated keys
// -- an imported key ends up exactly as non-extractable as a generated one.
func (p *PKCS11KeyProvider) ImportKey(_ context.Context, keyType string, privateKey crypto.PrivateKey) (string, error) {
	session, err := p.openRWSession()
	if err != nil {
		return "", err
	}
	defer p.closeSession(session)

	label := uuid.New().String()

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if len(key.Primes) != 2 {
			return "", fmt.Errorf("pkcs11 import: only two-prime RSA keys are supported")
		}
		key.Precompute()
		pubAttrs := []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
			p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_RSA),
			p11.NewAttribute(p11.CKA_LABEL, label),
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_ENCRYPT, true),
			p11.NewAttribute(p11.CKA_VERIFY, true),
			p11.NewAttribute(p11.CKA_MODULUS, key.N.Bytes()),
			p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
		}
		privAttrs := []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
			p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_RSA),
			p11.NewAttribute(p11.CKA_LABEL, label),
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_PRIVATE, true),
			p11.NewAttribute(p11.CKA_SENSITIVE, true),
			p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
			p11.NewAttribute(p11.CKA_DECRYPT, true),
			p11.NewAttribute(p11.CKA_SIGN, true),
			p11.NewAttribute(p11.CKA_MODULUS, key.N.Bytes()),
			p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
			p11.NewAttribute(p11.CKA_PRIVATE_EXPONENT, key.D.Bytes()),
			p11.NewAttribute(p11.CKA_PRIME_1, key.Primes[0].Bytes()),
			p11.NewAttribute(p11.CKA_PRIME_2, key.Primes[1].Bytes()),
			p11.NewAttribute(p11.CKA_EXPONENT_1, key.Precomputed.Dp.Bytes()),
			p11.NewAttribute(p11.CKA_EXPONENT_2, key.Precomputed.Dq.Bytes()),
			p11.NewAttribute(p11.CKA_COEFFICIENT, key.Precomputed.Qinv.Bytes()),
		}
		if _, err := p.ctx.CreateObject(session, pubAttrs); err != nil {
			return "", fmt.Errorf("pkcs11 rsa import (public): %w", err)
		}
		if _, err := p.ctx.CreateObject(session, privAttrs); err != nil {
			return "", fmt.Errorf("pkcs11 rsa import (private): %w", err)
		}
		return label, nil

	case *ecdsa.PrivateKey:
		curveName, ok := curveNameFor(key.Curve)
		if !ok {
			return "", fmt.Errorf("%w: unsupported EC curve for import", ErrUnsupportedCurve)
		}
		oid := ecOID[curveName]
		ecParams, err := asn1.Marshal(oid)
		if err != nil {
			return "", fmt.Errorf("marshal ec params: %w", err)
		}
		ecPoint, err := asn1.Marshal(elliptic.Marshal(key.Curve, key.X, key.Y))
		if err != nil {
			return "", fmt.Errorf("marshal ec point: %w", err)
		}
		pubAttrs := []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
			p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
			p11.NewAttribute(p11.CKA_LABEL, label),
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_VERIFY, true),
			p11.NewAttribute(p11.CKA_EC_PARAMS, ecParams),
			p11.NewAttribute(p11.CKA_EC_POINT, ecPoint),
		}
		privAttrs := []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
			p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
			p11.NewAttribute(p11.CKA_LABEL, label),
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_PRIVATE, true),
			p11.NewAttribute(p11.CKA_SENSITIVE, true),
			p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
			p11.NewAttribute(p11.CKA_SIGN, true),
			p11.NewAttribute(p11.CKA_EC_PARAMS, ecParams),
			p11.NewAttribute(p11.CKA_VALUE, key.D.Bytes()),
		}
		if _, err := p.ctx.CreateObject(session, pubAttrs); err != nil {
			return "", fmt.Errorf("pkcs11 ecdsa import (public): %w", err)
		}
		if _, err := p.ctx.CreateObject(session, privAttrs); err != nil {
			return "", fmt.Errorf("pkcs11 ecdsa import (private): %w", err)
		}
		return label, nil

	default:
		return "", fmt.Errorf("pkcs11 import: unsupported key type %T", privateKey)
	}
}

// curveNameFor reverse-looks-up ecOID's key by elliptic.Curve, so ImportKey
// can find the same OID GenerateECDSAKey used to create the curve name from.
func curveNameFor(curve elliptic.Curve) (string, bool) {
	switch curve.Params().Name {
	case "P-256":
		return "P-256", true
	case "P-384":
		return "P-384", true
	case "P-521":
		return "P-521", true
	default:
		return "", false
	}
}
```

Add `"crypto"`, `"crypto/ecdsa"`, `"crypto/rsa"`, `"math/big"` to `pkcs11_provider.go`'s import block if not already present (check first — `asn1`, `elliptic` are very likely already imported given `GenerateECDSAKey`'s existing use of `ecOID`/`asn1.Marshal`/`elliptic`).

Note: `curveNameFor` only recognizes NIST curves (P-256/P-384/P-521), not P-256K — importing a secp256k1 key is out of scope for this pass (the spec's Non-goals didn't call out curve scope explicitly, but P-256K import support can be added later by extending this switch; flag this as a known v1 limitation, not a bug).

- [ ] **Step 4: Run the test to verify it passes (or is skipped without SoftHSM2)**

Run: `SOFTHSM2_LIB=<path> go test ./internal/crypto/... -run TestPKCS11Provider_ImportKey -v`
Expected: PASS if SoftHSM2 is configured; SKIP with the "softhsm2-util not found" message otherwise — either outcome is acceptable to proceed, but if SoftHSM2 IS available in this environment, it must PASS, not error.

- [ ] **Step 5: Run the full crypto package suite**

Run: `go build ./... && go test ./internal/crypto/... -v 2>&1 | tail -80`
Expected: builds clean, all tests PASS or SKIP (no FAIL).

- [ ] **Step 6: Commit**

```bash
git add internal/crypto/pkcs11_provider.go internal/crypto/pkcs11_provider_test.go
git commit -m "feat(crypto): implement PKCS11KeyProvider.ImportKey"
```

---

### Task 4: `KeyService.ImportKey`

**Files:**
- Modify: `internal/services/keys/key_service.go`
- Test: `internal/services/keys/key_service_extended_test.go`

**Interfaces:**
- Consumes: `signing.ParseJWK` (Task 1), `crypto.KeyProvider.ImportKey` (Tasks 2-3), `isPKCS11Handle` (`key_service.go:1052`, existing), `keyService.applyCreatePurgeProtection` (`key_service.go:209`, existing — widened in Step 3 below)
- Produces: `KeyService.ImportKey(ctx context.Context, req ImportKeyRequest) (*CreateKeyResult, error)` and `type ImportKeyRequest struct{...}` — consumed by Task 5 (retry decorator), Task 7 (API handler), Task 8 (CLI)

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/keys/key_service_extended_test.go` (reuse the file's existing `mockKeyRepository`, `setupKeyTestMasterKey()`, `newKeyLogger()` helpers):

```go
func TestImportKey_SuccessWithSoftwareKey_RSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	userID := uuid.New()
	result, err := svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-rsa",
		JWK:    jwkJSON,
		UserID: userID,
	})
	require.NoError(t, err)
	assert.Equal(t, "imported-rsa", result.Name)
	assert.Equal(t, model.KeyTypeRSA, result.Type)

	require.NotNil(t, createdKey)
	assert.Equal(t, model.KeyTypeRSA, createdKey.Type)
	assert.NotEmpty(t, createdKey.Value)
	// Value is common.EncryptSecret-encrypted PEM, not the raw handle.
	assert.NotContains(t, createdKey.Value, "PRIVATE KEY")
	repo.AssertExpectations(t)
}

func TestImportKey_SuccessWithSoftwareKey_ECDSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.Anything).Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	result, err := svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-ecdsa",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.NoError(t, err)
	assert.Equal(t, model.KeyTypeECDSA, result.Type)
	repo.AssertExpectations(t)
}

func TestImportKey_MalformedJWK_Rejected(t *testing.T) {
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: &mockKeyRepository{},
		KeyProvider:   &mockKeyProviderForService{},
		Logger:        newKeyLogger(),
	})

	_, err := svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "bad",
		JWK:    []byte("not json"),
		UserID: uuid.New(),
	})
	require.Error(t, err)
}

func TestImportKey_PublicOnlyJWK_Rejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: &mockKeyRepository{},
		KeyProvider:   &mockKeyProviderForService{},
		Logger:        newKeyLogger(),
	})

	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "public-only",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.ErrorIs(t, err, signing.ErrJWKNoPrivateKey)
}

func TestImportKey_ProviderStoresPKCS11Handle_NotEncrypted(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	provider := &mockKeyProviderForService{}
	// A PKCS#11 handle is a 36-char UUID label, per isPKCS11Handle.
	provider.On("ImportKey", "RSA", mock.Anything).Return("11111111-2222-3333-4444-555555555555", nil)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "hsm-imported",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	assert.Equal(t, "pkcs11:11111111-2222-3333-4444-555555555555", createdKey.Value)
}
```

Add `mockKeyProviderForService.ImportKey` to the existing mock (in whichever file declares `mockKeyProviderForService` — `key_service_extended_test.go`, per the spec's research):

```go
func (m *mockKeyProviderForService) ImportKey(_ context.Context, keyType string, privateKey crypto.PrivateKey) (string, error) {
	args := m.Called(keyType, privateKey)
	return args.String(0), args.Error(1)
}
```

Add imports as needed: `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `crypto/rsa`, `jose "github.com/go-jose/go-jose/v4"`, `"rocketvault/internal/signing"`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/keys/... -run TestImportKey -v`
Expected: FAIL — `ImportKeyRequest`, `svc.ImportKey`, `mockKeyProviderForService.ImportKey` undefined (compile errors).

- [ ] **Step 3: Add `ImportKeyRequest` and the `ImportKey` method to the interface**

In `internal/services/keys/key_service.go`, add next to `CreateKeyRequest` (after its closing brace, around line 58):

```go
// ImportKeyRequest represents a request to import externally-generated key
// material supplied as a JWK.
type ImportKeyRequest struct {
	Name            string
	JWK             []byte // raw JWK JSON, parsed via signing.ParseJWK
	Tags            []string
	UserID          uuid.UUID
	VaultID         uuid.UUID // Target vault; defaults to the default vault when nil.
	Enabled         *bool     // Defaults to true if nil.
	ExpiresAt       *time.Time
	NotBefore       *time.Time
	PurgeProtection *bool
}
```

In the `KeyService` interface (around line 97, after `CreateOctKey`), add:

```go
	// ImportKey stores externally-generated key material supplied as a JWK.
	// The imported key is subject to the same non-extractability guarantee as
	// a generated key of the same backend -- see
	// docs/superpowers/specs/2026-08-25-key-export-decision-record.md.
	ImportKey(ctx context.Context, req ImportKeyRequest) (*CreateKeyResult, error)
```

- [ ] **Step 4: Widen `applyCreatePurgeProtection` to take just what it needs**

`applyCreatePurgeProtection` currently takes a `CreateKeyRequest` but only reads `req.PurgeProtection`. Change its signature to avoid needing a `CreateKeyRequest` from `ImportKey`:

```go
func (s *keyService) applyCreatePurgeProtection(ctx context.Context, purgeProtection *bool, keyID uuid.UUID, action string, userID uuid.UUID) error {
	if purgeProtection == nil || !*purgeProtection {
		return nil
	}
	if err := s.keyRepo.SetPurgeProtection(ctx, keyID, true); err != nil {
		s.logger.LogAuditError(userID.String(), action, "failed", "failed to set purge protection", err)
		return fmt.Errorf("failed to set purge protection: %w", err)
	}
	return nil
}
```

Update the three existing call sites (`CreateRSAKey`, `CreateECDSAKey`, `CreateOctKey`) from
`s.applyCreatePurgeProtection(ctx, req, key.ID, "create_rsa_key")` to
`s.applyCreatePurgeProtection(ctx, req.PurgeProtection, key.ID, "create_rsa_key", req.UserID)` (and the equivalent for the other two).

- [ ] **Step 5: Implement `keyService.ImportKey`**

Add to `internal/services/keys/key_service.go`, after `CreateOctKey`:

```go
// ImportKey stores externally-generated key material supplied as a JWK. It
// follows the same generate-then-store shape as CreateRSAKey/CreateECDSAKey,
// substituting JWK parsing + provider import for provider generation.
func (s *keyService) ImportKey(ctx context.Context, req ImportKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"user_id": req.UserID.String(),
	}).Info("Importing key")

	privateKey, keyType, err := signing.ParseJWK(req.JWK)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "invalid JWK", err)
		return nil, fmt.Errorf("invalid JWK: %w", err)
	}

	handle, err := s.keyProvider.ImportKey(ctx, keyType, privateKey)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "failed to import key material", err)
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	var storedValue string
	if isPKCS11Handle(handle) {
		storedValue = "pkcs11:" + handle
	} else {
		storedValue, err = common.EncryptSecret(handle)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "failed to encrypt key", err)
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	modelType := model.KeyTypeRSA
	if keyType == "ECDSA" {
		modelType = model.KeyTypeECDSA
	}

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      modelType,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store imported key: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req.PurgeProtection, key.ID, "import_key", req.UserID); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "import_key", "success", fmt.Sprintf("key imported: %s, ID: %s", req.Name, key.ID))

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}
```

Add `"rocketvault/internal/signing"` to `key_service.go`'s import block.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/services/keys/... -run TestImportKey -v`
Expected: PASS, all five tests.

- [ ] **Step 7: Run the full keys package suite to confirm the `applyCreatePurgeProtection` signature change didn't break the three existing callers**

Run: `go build ./... && go test ./internal/services/keys/... -v 2>&1 | tail -100`
Expected: builds clean, no FAIL.

- [ ] **Step 8: Commit**

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_service_extended_test.go
git commit -m "feat(keys): add KeyService.ImportKey"
```

---

### Task 5: Retry decorator passthrough + mock regeneration

**Files:**
- Modify: `internal/services/retry/retry_key_service.go`
- Modify (generated): `internal/services/keys/mocks/mock_KeyService.go`
- Test: `internal/services/retry/retry_key_service_test.go` (or wherever `RetryKeyService` is already tested — locate first)

**Interfaces:**
- Consumes: `keys.KeyService.ImportKey`, `keys.ImportKeyRequest` (Task 4)
- Produces: `retryKeyService` satisfies the widened `RetryKeyService` interface; `mocks.MockKeyService` gains an `ImportKey` expecter, needed by Task 7/8's handler and CLI tests if they mock the service

- [ ] **Step 1: Confirm the compile break**

Run: `go build ./... 2>&1 | grep -i retrykeyservice`
Expected: a "does not implement keys.KeyService (missing method ImportKey)" error, or equivalent — this confirms the decorator needs the new method before anything else in the build can succeed.

- [ ] **Step 2: Add the passthrough**

In `internal/services/retry/retry_key_service.go`, add, matching the existing `CreateRSAKey` shape exactly:

```go
// ImportKey imports a key with retry logic for database operations.
func (s *retryKeyService) ImportKey(ctx context.Context, req keys.ImportKeyRequest) (*keys.CreateKeyResult, error) {
	return retried(ctx, s.retryService, func() (*keys.CreateKeyResult, error) {
		return s.baseService.ImportKey(ctx, req)
	})
}
```

- [ ] **Step 3: Verify the build is unblocked**

Run: `go build ./... 2>&1`
Expected: no `retrykeyservice`/`ImportKey` errors. Other packages (mocks, api, cmd) will still fail to build until later tasks — that's expected at this point; only confirm this specific error class is gone.

- [ ] **Step 4: Regenerate the `KeyService` mock**

Run: `mockery` from the repo root (uses `.mockery.yaml`, which already lists `KeyService` under `rocketvault/internal/services/keys`).

If `mockery` is not installed, install it per the project's existing tooling convention (check `Makefile`/CI workflow for the exact version pin before installing an arbitrary one).

Verify: `git diff --stat internal/services/keys/mocks/mock_KeyService.go` shows new `ImportKey`/`ImportKey_Call`/expecter additions and nothing else changed.

- [ ] **Step 5: Run the retry package's existing key-service tests**

Run: `go test ./internal/services/retry/... -v 2>&1 | tail -60`
Expected: PASS (no new test needed here — the passthrough is exercised implicitly by the interface satisfaction; if the retry package's test suite constructs a `retryKeyService` and calls its methods via table-driven tests, add one row for `ImportKey` following that file's existing pattern; if it doesn't test individual passthroughs at all today, this step confirms nothing broke rather than adding new coverage).

- [ ] **Step 6: Commit**

```bash
git add internal/services/retry/retry_key_service.go internal/services/keys/mocks/mock_KeyService.go
git commit -m "feat(keys): retry passthrough and regenerated mock for ImportKey"
```

---

### Task 6: Authorization routing — `mapKeyAction` gains `case "import"`

**Files:**
- Modify: `internal/services/authorization/data_actions.go`
- Modify: `internal/services/authorization/data_actions_test.go` (existing file — has `TestMapRouteToDataAction`, the table-driven test this task adds rows to)

**Interfaces:**
- Consumes: `model.ActionKeysImport` (`model/azure_roles.go:54`, already exists), `MapRouteToDataAction` (the wrapper `TestMapRouteToDataAction` exercises — confirm its exact name/signature in `data_actions.go` before writing the test, since the test calls it with a full path string like `/api/v1/keys/abc/rotate`, not `mapKeyAction` directly)
- Produces: `mapKeyAction("POST", "import")` now returns `(model.ActionKeysImport, RouteVaultData)` — consumed by Task 7 (the API route's `PolicyMiddleware` authorization)

- [ ] **Step 1: Write the failing test**

Add a row to `TestMapRouteToDataAction`'s table in `internal/services/authorization/data_actions_test.go`, in the "Keys" section (`data_actions_test.go:39-`), next to `{"create key", ...}`:

```go
		{"import key", http.MethodPost, "/api/v1/keys/import", model.ActionKeysImport, RouteVaultData},
```

Also add a negative case confirming the wrong HTTP method on the same path fails closed, matching the style of `TestMapRouteToDataActionUnmappedMethodFailsClosed` (`data_actions_test.go:130`) — read that test first and add an equivalent row/case for `GET /api/v1/keys/import` there (it should map to `""`, the fail-closed empty action), rather than inventing a new test function.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: FAIL — the new "import key" row does not match; `mapKeyAction` has no `case "import"` yet.

- [ ] **Step 3: Add the case**

In `internal/services/authorization/data_actions.go`, `mapKeyAction` (`data_actions.go:140-208`), add a new case alongside the existing `case "restore":` (around line 150), inside the top-level `switch rest` block:

```go
	case "import":
		if method == http.MethodPost {
			return model.ActionKeysImport, RouteVaultData
		}
		return "", RouteVaultData
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: PASS.

- [ ] **Step 5: Run the full authorization package suite**

Run: `go test ./internal/services/authorization/... -v 2>&1 | tail -60`
Expected: no FAIL.

- [ ] **Step 6: Commit**

```bash
git add internal/services/authorization/data_actions.go internal/services/authorization/data_actions_test.go
git commit -m "feat(authz): route POST /keys/import to ActionKeysImport"
```

---

### Task 7: API — `POST /keys/import`

**Files:**
- Modify: `api/keys.go`
- Modify: `api/keys_crud_test.go` (existing file — has the hand-rolled `mockKeyService` and `createKey` tests this task mirrors)

**Interfaces:**
- Consumes: `keys.KeyService.ImportKey`/`ImportKeyRequest` (Task 4), `mapKeyAction`'s new `"import"` case (Task 6, exercised via `PolicyMiddleware`, not called directly by the handler)
- Produces: `POST /keys/import` (both legacy and vault-scoped routers) — end-user-facing; nothing downstream in this plan consumes it directly (the CLI in Task 8 goes through the service layer, not this HTTP route, since `keys` commands are local-only today, matching `create`)

- [ ] **Step 1: Add `ImportKey` to the hand-rolled `mockKeyService`**

`api/keys_crud_test.go`'s `mockKeyService` (starting `api/keys_crud_test.go:48`) implements `keyServices.KeyService` by hand for these tests — it must gain the new method before anything in this file compiles. Add, matching the existing `CreateRSAKey` mock shape exactly:

```go
func (m *mockKeyService) ImportKey(ctx context.Context, req keyServices.ImportKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}
```

- [ ] **Step 2: Write the failing tests**

Add to `api/keys_crud_test.go`, next to `TestCreateKey_RSA_Success_Returns201` (`api/keys_crud_test.go:400`), reusing `newKeyCtx`, `makeKeyModel`, `keyLegacyVaultScope` exactly as that test does:

```go
func TestImportKey_Success_Returns201(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ImportKey", mock.Anything, mock.MatchedBy(func(req keyServices.ImportKeyRequest) bool {
		return req.Name == "imported-key" && len(req.JWK) > 0
	})).Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "imported-key", Type: model.KeyTypeRSA}, nil)
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return(makeKeyModel(keyID), nil)

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "imported-key",
		"jwk":  json.RawMessage(`{"kty":"RSA","n":"...","e":"AQAB","d":"..."}`),
	})
	r := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(body))

	importKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestImportKey_MissingName_Returns400(t *testing.T) {
	svc := &mockKeyService{}
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"jwk": json.RawMessage(`{"kty":"RSA"}`)})
	r := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(body))

	importKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "ImportKey", mock.Anything, mock.Anything)
}

func TestImportKey_MissingJWK_Returns400(t *testing.T) {
	svc := &mockKeyService{}
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "imported-key"})
	r := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(body))

	importKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestImportKey_ServiceError_Returns500(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("ImportKey", mock.Anything, mock.Anything).Return(nil, errors.New("provider unavailable"))

	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "imported-key",
		"jwk":  json.RawMessage(`{"kty":"RSA","n":"...","e":"AQAB","d":"..."}`),
	})
	r := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(body))

	importKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.NotEqual(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./api/... -run TestImportKey -v`
Expected: FAIL — `importKey`, `ImportKeyRequest` undefined (compile error).

- [ ] **Step 4: Add the route and request/response types**

In `api/keys.go`, add near `CreateKeyRequest` (after its closing brace):

```go
// ImportKeyRequest represents the request structure for importing a
// cryptographic key from a JWK.
type ImportKeyRequest struct {
	Name    string          `json:"name"`
	JWK     json.RawMessage `json:"jwk"`
	Tags    []string        `json:"tags"`
	Enabled *bool           `json:"enabled,omitempty"`
	// PurgeProtection is optional; nil leaves the stored default alone.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}
```

Add the route in `registerKeyRoutes`, next to the existing `POST ""`:

```go
	k.Handle("", ApiSessionRequired(api.App, createKey)).Methods("POST")
	k.Handle("/import", ApiSessionRequired(api.App, importKey)).Methods("POST")
```

Add the handler, templated off `createKey` (`api/keys.go:316-`):

```go
// importKey imports a cryptographic key from caller-supplied JWK material.
func importKey(c *Context, w http.ResponseWriter, r *http.Request) {
	// Authorization happens in PolicyMiddleware: importing a key requires the
	// Microsoft.KeyVault/vaults/keys/import/action data action, granted by
	// Key Vault Crypto Officer or Key Vault Administrator in this vault.

	var req ImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Name == "" || len(req.JWK) == 0 {
		c.SetInvalidParam("name and jwk are required")
		return
	}

	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	enabled := req.Enabled
	if enabled == nil {
		t := true
		enabled = &t
	}

	result, err := keyService.ImportKey(r.Context(), keyservices.ImportKeyRequest{
		Name:            req.Name,
		JWK:             []byte(req.JWK),
		Tags:            req.Tags,
		UserID:          userID,
		VaultID:         vaultID,
		Enabled:         enabled,
		PurgeProtection: req.PurgeProtection,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	createScope := model.NewVaultScope(vaultID, userID)
	key, err := keyService.GetKey(r.Context(), result.KeyID, createScope)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(buildKeyResponse(key, keyJWK(c, r, keyService, result.KeyID, createScope, 0))) //nolint:errcheck,gosec
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./api/... -run TestImportKey -v`
Expected: PASS, all four tests.

- [ ] **Step 6: Run the full API package suite**

Run: `go build ./... && go test ./api/... -v 2>&1 | tail -100`
Expected: no FAIL.

- [ ] **Step 7: Commit**

```bash
git add api/keys.go api/keys_crud_test.go
git commit -m "feat(api): add POST /keys/import"
```

---

### Task 8: CLI — `rocketvault keys import`

**Files:**
- Create: `cmd/keys/import.go`
- Modify: `cmd/keys.go` (register the new command)
- Modify: `cmd/keys/keys_cmd_test.go` (existing file — has `TestMain`'s Init registrations, the hand-rolled `keyCmdKeyService` mock, and the `create` command's own tests this task mirrors)

**Interfaces:**
- Consumes: `keyServices.ImportKeyRequest`/`ImportKey` (Task 4), `vaultcli.RequireDataAction` (existing), `model.ActionKeysImport` (existing), test helpers already in `cmd/keys/keys_cmd_test.go`: `newAllowedContainer` (line 222), `newTestCmd` (line 323), `viperSet` (line 333), `buildAdminCtx` (line 297)
- Produces: `rocketvault keys import` command, `InitKeysImport(keysCmd *cobra.Command) *cobra.Command` — end-user-facing, nothing downstream in this plan consumes it

- [ ] **Step 1: Add `ImportKey` to the hand-rolled `keyCmdKeyService` mock**

`cmd/keys/keys_cmd_test.go`'s `keyCmdKeyService` (starting `cmd/keys/keys_cmd_test.go:54`) implements `keyServices.KeyService` by hand — it must gain the new method before this package compiles. Add, matching the existing `CreateRSAKey` mock shape exactly:

```go
func (m *keyCmdKeyService) ImportKey(ctx context.Context, req keyServices.ImportKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}
```

Register the new command in `TestMain` (`cmd/keys/keys_cmd_test.go:33-49`), next to `InitKeysCreate(parent)`:

```go
	InitKeysCreate(parent)
	InitKeysImport(parent)
```

- [ ] **Step 2: Write the failing tests**

Add to `cmd/keys/keys_cmd_test.go`, next to `TestCreateCmd_MissingName`/`TestCreateCmd_RSASuccess` (`cmd/keys/keys_cmd_test.go:383`, `:428`), reusing the exact same helpers those tests use:

```go
func TestImportCmd_MissingName(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cleanup := viperSet(map[string]any{
		"key-import-name": "", "key-import-jwk": `{"kty":"RSA"}`,
	})
	defer cleanup()
	cmd, _ := newTestCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name is required")
}

func TestImportCmd_MissingJWK(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cleanup := viperSet(map[string]any{
		"key-import-name": "imported-key", "key-import-jwk": "", "key-import-jwk-file": "",
	})
	defer cleanup()
	cmd, _ := newTestCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--jwk or --jwk-file is required")
}

func TestImportCmd_BothJWKFlags_MutuallyExclusive(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cleanup := viperSet(map[string]any{
		"key-import-name": "imported-key", "key-import-jwk": `{"kty":"RSA"}`, "key-import-jwk-file": "/tmp/x.json",
	})
	defer cleanup()
	cmd, _ := newTestCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "mutually exclusive")
}

func TestImportCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "imported-key", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("ImportKey", mock.Anything, mock.MatchedBy(func(r keyServices.ImportKeyRequest) bool {
		return r.Name == "imported-key" && r.VaultID == vaultID && len(r.JWK) > 0
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]any{
		"key-import-name": "imported-key", "key-import-jwk": `{"kty":"RSA","n":"...","e":"AQAB","d":"..."}`, "key-import-tags": "",
	})
	defer cleanup()

	cmd, buf := newTestCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestImportCmd_JWKFile(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.jwk.json")
	require.NoError(t, err)
	_, err = tmpFile.WriteString(`{"kty":"RSA","n":"...","e":"AQAB","d":"..."}`)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	keySvc := &keyCmdKeyService{}
	sc, _ := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "from-file", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("ImportKey", mock.Anything, mock.Anything).Return(result, nil)

	ctx := buildAdminCtx(sc)
	cleanup := viperSet(map[string]any{
		"key-import-name": "from-file", "key-import-jwk-file": tmpFile.Name(), "key-import-jwk": "",
	})
	defer cleanup()

	cmd, buf := newTestCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err = cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}
```

`require` must already be imported in this file (check the existing import block; if `require` isn't there yet, add `"github.com/stretchr/testify/require"`).

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./cmd/keys/... -run TestImportCmd -v`
Expected: FAIL — `InitKeysImport`, `importCmd` undefined (compile error).

- [ ] **Step 4: Implement `cmd/keys/import.go`**

```go
/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package keys

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an externally-generated key",
	Long: `Import an RSA or ECDSA private key supplied as a JWK into the target vault,
storing it exactly as if RocketVault had generated it -- encrypted PEM for a
software-backed vault, a non-extractable PKCS#11 object for an HSM-backed one.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/import/action data action in the target vault.

--name and one of --jwk-file or --jwk (inline JSON) are required. A JWK with
no private key material (public-only) is rejected.

The key is created in the vault named by --vault, which defaults to
"default".`,
	Example: `  # Import from a JWK file
  rocketvault keys import --name <name> --jwk-file ./key.jwk.json

  # Import from inline JSON
  rocketvault keys import --name <name> --jwk '{"kty":"RSA","n":"...","e":"AQAB","d":"..."}'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		name := viper.GetString("key-import-name")
		jwkInline := viper.GetString("key-import-jwk")
		jwkFile := viper.GetString("key-import-jwk-file")
		tagsStr := viper.GetString("key-import-tags")

		if name == "" {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "name is required", nil)
			return fmt.Errorf("name is required")
		}
		if jwkInline == "" && jwkFile == "" {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "one of --jwk or --jwk-file is required", nil)
			return fmt.Errorf("one of --jwk or --jwk-file is required")
		}
		if jwkInline != "" && jwkFile != "" {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "--jwk and --jwk-file are mutually exclusive", nil)
			return fmt.Errorf("--jwk and --jwk-file are mutually exclusive")
		}

		var jwkBytes []byte
		if jwkFile != "" {
			data, err := os.ReadFile(jwkFile)
			if err != nil {
				log.LogAuditError(claims.UserID.String(), "import_key", "failed", fmt.Sprintf("failed to read jwk file: %s", err), err)
				return fmt.Errorf("failed to read jwk file: %w", err)
			}
			jwkBytes = data
		} else {
			jwkBytes = []byte(jwkInline)
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		keyService := serviceContainer.GetKeyService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysImport, model.OpCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		req := keyServices.ImportKeyRequest{
			Name:    name,
			JWK:     jwkBytes,
			Tags:    tags,
			UserID:  claims.UserID,
			VaultID: vaultID,
		}
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		result, err := keyService.ImportKey(ctx, req)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", fmt.Sprintf("failed to import key: %s", err), err)
			return fmt.Errorf("failed to import key: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "import_key", "success", fmt.Sprintf("key imported: %s, ID: %s", result.Name, result.KeyID))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Type", "Tags", "Created"}
		row := []string{
			result.KeyID.String(),
			result.Name,
			result.Type,
			strings.Join(result.Tags, ","),
			result.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitKeysImport initializes the import command for keys and adds it to the
// keys command.
func InitKeysImport(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(importCmd)

	importCmd.Flags().String("name", "", "Name for the imported key")
	importCmd.Flags().String("jwk", "", "Inline JWK JSON containing private key material")
	importCmd.Flags().String("jwk-file", "", "Path to a file containing JWK JSON")
	importCmd.Flags().String("tags", "", "Comma-separated tags for the key")
	importCmd.Flags().Bool("purge-protection", false, "Protect the key from being purged")
	viper.BindPFlag("key-import-name", importCmd.Flags().Lookup("name"))         //nolint:errcheck,gosec
	viper.BindPFlag("key-import-jwk", importCmd.Flags().Lookup("jwk"))           //nolint:errcheck,gosec
	viper.BindPFlag("key-import-jwk-file", importCmd.Flags().Lookup("jwk-file")) //nolint:errcheck,gosec
	viper.BindPFlag("key-import-tags", importCmd.Flags().Lookup("tags"))         //nolint:errcheck,gosec

	return keysCmd
}
```

Register it in `cmd/keys.go`, next to `keys.InitKeysCreate(keysCmd)` (`cmd/keys.go:70`):

```go
	keys.InitKeysCreate(keysCmd)
	keys.InitKeysImport(keysCmd)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/keys/... -run TestImportCmd -v`
Expected: PASS, all six tests.

- [ ] **Step 6: Run the full CLI keys package suite**

Run: `go build ./... && go test ./cmd/keys/... -v 2>&1 | tail -100`
Expected: no FAIL.

- [ ] **Step 7: Manual smoke test**

```bash
go run main.go keys import --name smoke-test-key --jwk-file /tmp/test.jwk.json --vault default
```

(Generate a throwaway test JWK file first, e.g. via a short Go one-liner using `jose.JSONWebKey{Key: privKey}.MarshalJSON()`, or reuse one produced by a unit test.) Confirm the command outputs a table with the new key's ID, and that `rocketvault keys get --id <id>` returns it.

- [ ] **Step 8: Commit**

```bash
git add cmd/keys/import.go cmd/keys.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cli): add keys import command"
```

---

### Task 9: Full build/test verification and documentation flip

**Files:**
- Modify: `.claude/azure-keyvault-parity.md`
- Modify: `.claude/roadmap-azure-parity-and-beyond.md`
- Modify: `README.md`
- Modify: `docs/cli-guide.md`
- Modify: `docs/api-developer-guide.md`

**Interfaces:**
- Consumes: nothing (documentation only)
- Produces: nothing consumed elsewhere — this is the plan's terminal task

- [ ] **Step 1: Full build and test suite**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tail -100`
Expected: builds clean, `go vet` clean, no FAIL anywhere in the suite (not just the packages touched by this plan — a broad regression check).

- [ ] **Step 2: Flip the parity doc's "Import key" row from ❌ to ✅**

In `.claude/azure-keyvault-parity.md`, the "Import key" row (§2, currently line ~40, previously amended 2026-08-25 to add a design-doc citation while still ❌) — update its RocketVault column and Status column to ✅, describing the shipped route: `POST /keys/import`, gated by `ActionKeysImport` via `mapKeyAction`'s new `case "import"`.

- [ ] **Step 3: Update the Scorecard**

In the same file's Summary/Scorecard section, move "§2. Key management — operations" from its current `8 | 3 | 2 | 0` to `9 | 3 | 1 | 0` (one row moves ❌→✅), update the Total row, and remove "key import" from the "genuinely closable ❌ rows" sentence.

- [ ] **Step 4: Mark the roadmap item closed**

In `.claude/roadmap-azure-parity-and-beyond.md` Phase 1, mark the "Key import (JWK)" bullet closed, matching whatever markup a neighboring already-closed Phase 1 item uses (check e.g. how "Rotation-policy scheduler" was marked once it shipped, if it has been, or check the file's own convention for closed vs. open Phase 1 items).

- [ ] **Step 5: Update README's roadmap checklist**

In `README.md`'s `## Roadmap > Planned > Phase 1` checklist, change `- [ ] Key import (JWK)` to `- [x] Key import (JWK)`, and consider moving it into the `### Shipped` section's most recent dated block, matching how other recently-shipped items were documented there.

- [ ] **Step 6: Update the CLI and API guides**

Add `keys import` to `docs/cli-guide.md` alongside `keys create`. Add `POST /keys/import`'s request/response shape to `docs/api-developer-guide.md`.

- [ ] **Step 7: Commit**

```bash
git add .claude/azure-keyvault-parity.md .claude/roadmap-azure-parity-and-beyond.md README.md docs/cli-guide.md docs/api-developer-guide.md
git commit -m "docs: mark key import (JWK) shipped"
```
