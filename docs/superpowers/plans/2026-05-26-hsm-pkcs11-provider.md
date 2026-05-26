# HSM PKCS#11 Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pluggable PKCS#11 key-provider interface so RocketVault can generate and use keys stored in a hardware security module (or SoftHSM2 for dev/test) without changing any behaviour when HSM is disabled.

**Architecture:** A `KeyProvider` interface in `internal/crypto/provider.go` is implemented by two concrete types: `SoftwareKeyProvider` (wraps existing Go crypto, zero behaviour change) and `PKCS11KeyProvider` (uses miekg/pkcs11 to delegate all key operations to the token). The active provider is selected at startup from config and injected into `KeyService` and `CryptoService` via the service container. Keys created on a PKCS#11 token are identified in the DB by a `pkcs11:<label>` handle; keys created by the software provider continue to use the existing encrypted-PEM format.

**Tech Stack:** Go 1.26, `github.com/miekg/pkcs11` v1.1.1, SoftHSM2 (dev/test), `github.com/spf13/viper`, SQLite/PostgreSQL via `database/sql`

---

## Context: Current Code Paths

Before modifying anything, understand the three sites that call the raw key generation functions today:

- `internal/services/keys/key_service.go:122` — `crypto.GenerateRSAKeyPEM(req.Bits)` inside `CreateRSAKey`.
- `internal/services/keys/key_service.go:203` — `crypto.GenerateECDSAKeyPEM(req.Curve)` inside `CreateECDSAKey`.
- `internal/services/keys/key_service.go:499–503` — both functions called inside `RotateKey` via a `switch` on `existing.Type`.

After generation, every call site immediately wraps the PEM with `common.EncryptSecret(pem)` before storing it in `keys.value`. The decryption side lives in `internal/services/keys/crypto_service.go`: `Sign`, `Verify`, `Encrypt`, and `Decrypt` all call `common.DecryptSecret(key.Value)` and then pass the plaintext PEM to `s.cryptoOps.*`.

The `pkcs11:` prefix strategy uses this asymmetry: when `key.Value` starts with `pkcs11:`, the `cryptoService` methods skip the AES-GCM round-trip and route directly to the PKCS#11 provider. The private key material never touches Go memory in that path.

---

## Task 1: Define `KeyProvider` interface and `SoftwareKeyProvider` stub

### Files changed
- `internal/crypto/provider.go` — new file
- `internal/crypto/software_provider.go` — new file (stub, no logic yet)
- `internal/crypto/software_provider_test.go` — new file (failing tests first)

### Step 1.1 — Write failing tests

Create `internal/crypto/software_provider_test.go`:

```go
package crypto_test

import (
	"context"
	gocrypto "crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
)

func TestSoftwareKeyProvider_GenerateRSAKey_Returns_PEM(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)
	assert.Contains(t, handle, "RSA PRIVATE KEY")
}

func TestSoftwareKeyProvider_GenerateECDSAKey_P256(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateECDSAKey(context.Background(), "P-256")
	require.NoError(t, err)
	assert.Contains(t, handle, "EC PRIVATE KEY")
}

func TestSoftwareKeyProvider_GenerateECDSAKey_P256K(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateECDSAKey(context.Background(), "P-256K")
	require.NoError(t, err)
	assert.Contains(t, handle, "EC PRIVATE KEY")
}

func TestSoftwareKeyProvider_Sign_RSA(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	sig, err := p.Sign(context.Background(), handle, "RSA", []byte("hello"), crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestSoftwareKeyProvider_Verify_RSA(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("hello world")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS256)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestSoftwareKeyProvider_Encrypt_Decrypt_RSA_OAEP(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	plaintext := []byte("secret payload")
	ct, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.NotEmpty(t, ct)

	pt, err := p.Decrypt(context.Background(), handle, ct, nonce, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestSoftwareKeyProvider_Close_NoError(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	assert.NoError(t, p.Close())
}

// Compile-time interface check.
var _ crypto.KeyProvider = (*crypto.SoftwareKeyProvider)(nil)

// Ensure Sign uses the gocrypto package (import kept alive).
var _ gocrypto.Hash = gocrypto.SHA256
```

Run the tests — they must fail because neither file exists yet:

```bash
go test ./internal/crypto/... -v -run TestSoftwareKeyProvider
# Expected: compilation error — crypto.KeyProvider undefined
```

### Step 1.2 — Create `internal/crypto/provider.go`

```go
// Package crypto provides cryptographic utilities for the password manager.
// This file defines the KeyProvider interface that abstracts key generation
// and raw crypto operations behind a stable contract.
package crypto

import (
	"context"
	gocrypto "crypto"
)

// KeyProvider abstracts key generation and raw crypto operations.
// Implementations may use in-process Go crypto (SoftwareKeyProvider)
// or an external PKCS#11 token (PKCS11KeyProvider).
type KeyProvider interface {
	// GenerateRSAKey generates an RSA key and returns an opaque handle string.
	// For SoftwareKeyProvider the handle is PEM. For PKCS11KeyProvider it is
	// the CKA_LABEL of the key object on the token.
	GenerateRSAKey(ctx context.Context, bits int) (handle string, err error)

	// GenerateECDSAKey generates an ECDSA key. curveName is "P-256", "P-384",
	// "P-521", or "P-256K".
	GenerateECDSAKey(ctx context.Context, curveName string) (handle string, err error)

	// Sign signs data with the key identified by handle using the given algorithm.
	Sign(ctx context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error)

	// Verify verifies a signature. Returns true if valid.
	Verify(ctx context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error)

	// Encrypt encrypts data with the key identified by handle.
	// nonce is non-nil for AES-GCM; nil for RSA modes.
	Encrypt(ctx context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) (ciphertext []byte, nonce []byte, err error)

	// Decrypt decrypts ciphertext with the key identified by handle.
	Decrypt(ctx context.Context, handle string, data []byte, nonce []byte, algorithm EncryptionAlgorithm) ([]byte, error)

	// Close releases any resources held by the provider (e.g., PKCS#11 session).
	Close() error
}

// Ensure the standard library crypto package is referenced so callers that
// import this file can use gocrypto.Hash values alongside our algorithm types.
var _ gocrypto.Hash = gocrypto.SHA256
```

### Step 1.3 — Create stub `internal/crypto/software_provider.go`

```go
package crypto

import (
	"context"
	"fmt"
)

// SoftwareKeyProvider implements KeyProvider using in-process Go crypto.
// It wraps the existing GenerateRSAKeyPEM / GenerateECDSAKeyPEM helpers and
// delegates sign/verify/encrypt/decrypt to CryptoOperations.
type SoftwareKeyProvider struct {
	ops *CryptoOperations
}

// NewSoftwareKeyProvider creates a SoftwareKeyProvider backed by the standard
// Go crypto library. No configuration is required.
func NewSoftwareKeyProvider() *SoftwareKeyProvider {
	return &SoftwareKeyProvider{ops: NewCryptoOperations()}
}

// GenerateRSAKey generates an RSA private key; returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateRSAKey(_ context.Context, bits int) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// GenerateECDSAKey generates an ECDSA private key; returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateECDSAKey(_ context.Context, curveName string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// Sign signs data using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Sign(_ context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// Verify verifies a signature using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Verify(_ context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

// Encrypt encrypts data using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

// Decrypt decrypts ciphertext using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Decrypt(_ context.Context, handle string, data []byte, nonce []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// Close is a no-op for the software provider.
func (p *SoftwareKeyProvider) Close() error { return nil }
```

### Step 1.4 — Confirm tests still fail (compile succeeds, logic fails)

```bash
go test ./internal/crypto/... -v -run TestSoftwareKeyProvider
# Expected: test failures with "not implemented"
```

### Step 1.5 — Commit the skeleton

```bash
git add internal/crypto/provider.go internal/crypto/software_provider.go internal/crypto/software_provider_test.go
git commit -m "feat(crypto): add KeyProvider interface and SoftwareKeyProvider stub"
```

---

## Task 2: Implement `SoftwareKeyProvider` fully

### Files changed
- `internal/crypto/software_provider.go` — full implementation

### Step 2.1 — Implement all methods

Replace the stub body with real implementations. Each method delegates to the already-tested helpers in `key_crypto.go` and `crypto_operations.go`.

```go
package crypto

import (
	"context"
)

// SoftwareKeyProvider implements KeyProvider using in-process Go crypto.
// It wraps the existing GenerateRSAKeyPEM / GenerateECDSAKeyPEM helpers and
// delegates sign/verify/encrypt/decrypt to CryptoOperations.
type SoftwareKeyProvider struct {
	ops *CryptoOperations
}

// NewSoftwareKeyProvider creates a SoftwareKeyProvider backed by the standard
// Go crypto library. No configuration is required.
func NewSoftwareKeyProvider() *SoftwareKeyProvider {
	return &SoftwareKeyProvider{ops: NewCryptoOperations()}
}

// GenerateRSAKey generates an RSA private key and returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateRSAKey(_ context.Context, bits int) (string, error) {
	return GenerateRSAKeyPEM(bits)
}

// GenerateECDSAKey generates an ECDSA private key and returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateECDSAKey(_ context.Context, curveName string) (string, error) {
	return GenerateECDSAKeyPEM(curveName)
}

// Sign signs data using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Sign(_ context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	result, err := p.ops.Sign(handle, keyType, data, algorithm)
	if err != nil {
		return nil, err
	}
	return result.Signature, nil
}

// Verify verifies a signature using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Verify(_ context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error) {
	result, err := p.ops.Verify(handle, keyType, data, sig, algorithm)
	if err != nil {
		return false, err
	}
	return result.Valid, nil
}

// Encrypt encrypts data using the key PEM stored in handle.
// Returns (ciphertext, nonce, error). nonce is nil for RSA modes.
func (p *SoftwareKeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	result, err := p.ops.Encrypt(handle, data, algorithm)
	if err != nil {
		return nil, nil, err
	}
	return result.Ciphertext, result.Nonce, nil
}

// Decrypt decrypts ciphertext using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Decrypt(_ context.Context, handle string, data []byte, nonce []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	result, err := p.ops.Decrypt(handle, data, nonce, algorithm)
	if err != nil {
		return nil, err
	}
	return result.Plaintext, nil
}

// Close is a no-op for the software provider.
func (p *SoftwareKeyProvider) Close() error { return nil }
```

### Step 2.2 — Run tests and confirm they pass

```bash
go test ./internal/crypto/... -v -run TestSoftwareKeyProvider
# Expected: all tests PASS
```

### Step 2.3 — Verify the whole package still builds cleanly

```bash
go build ./internal/crypto/...
```

### Step 2.4 — Commit

```bash
git add internal/crypto/software_provider.go
git commit -m "feat(crypto): implement SoftwareKeyProvider delegating to existing CryptoOperations"
```

---

## Task 3: Add PKCS#11 dependency and implement `PKCS11KeyProvider` key generation

### Files changed
- `go.mod` / `go.sum` — new dependency
- `internal/crypto/pkcs11_provider.go` — new file

### Step 3.1 — Add the dependency

```bash
go get github.com/miekg/pkcs11@v1.1.1
go mod tidy
```

Verify `go.mod` now contains:

```
require (
    ...
    github.com/miekg/pkcs11 v1.1.1
)
```

### Step 3.2 — Create `internal/crypto/pkcs11_provider.go`

This file uses a CGo binding; it compiles only when `CGO_ENABLED=1` (default). No build tag is needed — the `miekg/pkcs11` package itself handles unavailability gracefully by returning an error from `New()`.

```go
package crypto

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/google/uuid"
	p11 "github.com/miekg/pkcs11"
)

// ErrUnsupportedCurve is returned when a curve is valid in software but not
// supported by the PKCS#11 mechanism set (e.g., secp256k1 / P-256K).
var ErrUnsupportedCurve = errors.New("curve not supported by PKCS#11 provider")

// ErrUnsupportedAlgorithm is returned when a crypto algorithm is valid for the
// software provider but not routed through PKCS#11 (e.g., AES-GCM key ops).
var ErrUnsupportedAlgorithm = errors.New("algorithm not supported by PKCS#11 provider")

// PKCS11Config holds the runtime configuration for PKCS11KeyProvider.
// Values are typically read from the viper config block under "hsm.*".
type PKCS11Config struct {
	// LibPath is the absolute path to the PKCS#11 shared library, e.g.
	// /usr/lib/softhsm/libsofthsm2.so or /usr/lib/libCryptoki2_64.so.
	LibPath string

	// TokenLabel is the CKA_LABEL of the token to use. The provider will
	// scan available slots to find the matching token automatically.
	TokenLabel string

	// PIN is the user PIN for the token.
	PIN string

	// SlotID is the explicit slot index. 0 means auto-detect by TokenLabel.
	SlotID uint
}

// PKCS11KeyProvider implements KeyProvider by delegating all key operations
// to a PKCS#11 token. Private key material never enters Go memory.
type PKCS11KeyProvider struct {
	ctx    *p11.Ctx
	cfg    PKCS11Config
	slotID uint
}

// NewPKCS11KeyProvider initialises a PKCS#11 context, locates the token, and
// opens a connection. Call Close() when the provider is no longer needed.
func NewPKCS11KeyProvider(cfg PKCS11Config) (*PKCS11KeyProvider, error) {
	ctx := p11.New(cfg.LibPath)
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11 initialize: %w", err)
	}

	slotID, err := findSlot(ctx, cfg)
	if err != nil {
		ctx.Destroy()
		return nil, err
	}

	return &PKCS11KeyProvider{
		ctx:    ctx,
		cfg:    cfg,
		slotID: slotID,
	}, nil
}

// findSlot locates the PKCS#11 slot that holds the configured token.
// When cfg.SlotID > 0 that value is used directly; otherwise the slot list
// is searched by matching CKA_LABEL to cfg.TokenLabel.
func findSlot(ctx *p11.Ctx, cfg PKCS11Config) (uint, error) {
	if cfg.SlotID > 0 {
		return cfg.SlotID, nil
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 get slot list: %w", err)
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		// Token labels are padded to 32 characters with spaces.
		label := trimPKCS11String(info.Label)
		if label == cfg.TokenLabel {
			return slot, nil
		}
	}

	return 0, fmt.Errorf("pkcs11: token with label %q not found", cfg.TokenLabel)
}

// trimPKCS11String removes trailing space padding from PKCS#11 string fields.
func trimPKCS11String(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ' ' {
			return s[:i+1]
		}
	}
	return ""
}

// openRWSession opens a read-write user session on the configured slot.
func (p *PKCS11KeyProvider) openRWSession() (p11.SessionHandle, error) {
	session, err := p.ctx.OpenSession(p.slotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 open session: %w", err)
	}
	if err := p.ctx.Login(session, p11.CKU_USER, p.cfg.PIN); err != nil {
		_ = p.ctx.CloseSession(session)
		return 0, fmt.Errorf("pkcs11 login: %w", err)
	}
	return session, nil
}

// closeSession logs out and closes a session, swallowing errors that would
// only mask a more important error from the caller.
func (p *PKCS11KeyProvider) closeSession(session p11.SessionHandle) {
	_ = p.ctx.Logout(session)
	_ = p.ctx.CloseSession(session)
}

// GenerateRSAKey generates an RSA key pair on the token. The private key never
// leaves the token. Returns the CKA_LABEL UUID string as the handle.
func (p *PKCS11KeyProvider) GenerateRSAKey(_ context.Context, bits int) (string, error) {
	session, err := p.openRWSession()
	if err != nil {
		return "", err
	}
	defer p.closeSession(session)

	label := uuid.New().String()
	bitsVal := p11.NewAttribute(p11.CKA_MODULUS_BITS, bits)

	pubAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_RSA),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_ENCRYPT, true),
		p11.NewAttribute(p11.CKA_VERIFY, true),
		p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
		bitsVal,
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
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	_, _, err = p.ctx.GenerateKeyPair(session, mech, pubAttrs, privAttrs)
	if err != nil {
		return "", fmt.Errorf("pkcs11 rsa key gen: %w", err)
	}

	return label, nil
}

// ecOID maps Go curve names to their DER-encoded ASN.1 OID for PKCS#11
// CKA_EC_PARAMS. secp256k1 is intentionally excluded.
var ecOID = map[string]asn1.ObjectIdentifier{
	"P-256": {1, 2, 840, 10045, 3, 1, 7},  // prime256v1
	"P-384": {1, 3, 132, 0, 34},            // secp384r1
	"P-521": {1, 3, 132, 0, 35},            // secp521r1
}

// GenerateECDSAKey generates an EC key pair on the token. Returns the
// CKA_LABEL UUID string as the handle. P-256K is not supported on PKCS#11
// and returns ErrUnsupportedCurve.
func (p *PKCS11KeyProvider) GenerateECDSAKey(_ context.Context, curveName string) (string, error) {
	oid, ok := ecOID[curveName]
	if !ok {
		// P-256K (secp256k1) is not in the standard PKCS#11 curve OID table.
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCurve, curveName)
	}

	ecParams, err := asn1.Marshal(oid)
	if err != nil {
		return "", fmt.Errorf("marshal ec params: %w", err)
	}

	session, err := p.openRWSession()
	if err != nil {
		return "", err
	}
	defer p.closeSession(session)

	label := uuid.New().String()

	pubAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_VERIFY, true),
		p11.NewAttribute(p11.CKA_EC_PARAMS, ecParams),
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
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_EC_KEY_PAIR_GEN, nil)}
	_, _, err = p.ctx.GenerateKeyPair(session, mech, pubAttrs, privAttrs)
	if err != nil {
		return "", fmt.Errorf("pkcs11 ec key gen (%s): %w", curveName, err)
	}

	return label, nil
}

// findPrivateKey finds the private key object on the token by CKA_LABEL.
func (p *PKCS11KeyProvider) findPrivateKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11 find init: %w", err)
	}
	defer func() { _ = p.ctx.FindObjectsFinal(session) }()

	handles, _, err := p.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11: private key not found for label %q", label)
	}
	return handles[0], nil
}

// findPublicKey finds the public key object on the token by CKA_LABEL.
func (p *PKCS11KeyProvider) findPublicKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11 find init: %w", err)
	}
	defer func() { _ = p.ctx.FindObjectsFinal(session) }()

	handles, _, err := p.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11: public key not found for label %q", label)
	}
	return handles[0], nil
}

// Sign, Verify, Encrypt, Decrypt stubs — implemented in Tasks 4 and 5.

// Sign signs data with the private key identified by handle (CKA_LABEL).
func (p *PKCS11KeyProvider) Sign(_ context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	return nil, fmt.Errorf("not implemented — see Task 4")
}

// Verify verifies a signature using the public key identified by handle.
func (p *PKCS11KeyProvider) Verify(_ context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error) {
	return false, fmt.Errorf("not implemented — see Task 4")
}

// Encrypt encrypts data using the public key on the token. RSA-OAEP only.
func (p *PKCS11KeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not implemented — see Task 5")
}

// Decrypt decrypts data using the private key on the token. RSA-OAEP only.
func (p *PKCS11KeyProvider) Decrypt(_ context.Context, handle string, data []byte, nonce []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	return nil, fmt.Errorf("not implemented — see Task 5")
}

// Close finalises the PKCS#11 context and releases the library handle.
func (p *PKCS11KeyProvider) Close() error {
	return p.ctx.Finalize()
}
```

### Step 3.3 — Verify compilation

```bash
go build ./internal/crypto/...
```

### Step 3.4 — Commit

```bash
git add go.mod go.sum internal/crypto/pkcs11_provider.go
git commit -m "feat(crypto): add PKCS11KeyProvider skeleton with RSA and EC key generation"
```

---

## Task 4: Implement `PKCS11KeyProvider.Sign` and `Verify`

### Files changed
- `internal/crypto/pkcs11_provider.go` — Sign and Verify implemented

### Step 4.1 — Write failing integration tests first

Create `internal/crypto/pkcs11_provider_test.go` with sign/verify cases (full file shown in Task 6). For now, add unit-level tests that will fail because `Sign` returns "not implemented":

```go
// pkcs11_sign_test.go (temporary; replaced by full integration test in Task 6)
// This snippet shows the pattern. Real test is in pkcs11_provider_test.go.
```

The full integration test file is provided in Task 6. For now, confirm compilation only:

```bash
go build ./internal/crypto/...
```

### Step 4.2 — Implement `Sign`

Replace the `Sign` stub with:

```go
// signMechanism maps a SignatureAlgorithm to the PKCS#11 mechanism and
// indicates whether the data must be pre-hashed before calling C_Sign.
type signMechanism struct {
	mech     uint
	preHash  bool
	hashAlgo SignatureAlgorithm
}

var signMechanisms = map[SignatureAlgorithm]signMechanism{
	// RSA PKCS#1 v1.5 — token hashes internally.
	AlgorithmRS256: {p11.CKM_SHA256_RSA_PKCS, false, ""},
	AlgorithmRS384: {p11.CKM_SHA384_RSA_PKCS, false, ""},
	AlgorithmRS512: {p11.CKM_SHA512_RSA_PKCS, false, ""},

	// RSA-PSS — token hashes and pads internally.
	AlgorithmPS256: {p11.CKM_SHA256_RSA_PKCS_PSS, false, ""},
	AlgorithmPS384: {p11.CKM_SHA384_RSA_PKCS_PSS, false, ""},
	AlgorithmPS512: {p11.CKM_SHA512_RSA_PKCS_PSS, false, ""},

	// ECDSA — token accepts pre-hashed digest via CKM_ECDSA.
	AlgorithmES256: {p11.CKM_ECDSA, true, AlgorithmES256},
	AlgorithmES384: {p11.CKM_ECDSA, true, AlgorithmES384},
	AlgorithmES512: {p11.CKM_ECDSA, true, AlgorithmES512},
}

// Sign signs data with the private key identified by handle (CKA_LABEL).
// For RSA, the token computes the digest internally.
// For ECDSA, data is pre-hashed in Go and the raw digest is sent to C_Sign.
func (p *PKCS11KeyProvider) Sign(_ context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	mechInfo, ok := signMechanisms[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	session, err := p.openRWSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	privKey, err := p.findPrivateKey(session, handle)
	if err != nil {
		return nil, err
	}

	input := data
	if mechInfo.preHash {
		// ECDSA via CKM_ECDSA expects the raw digest, not the original data.
		hasher, herr := getHasher(mechInfo.hashAlgo)
		if herr != nil {
			return nil, herr
		}
		hasher.Write(data)
		input = hasher.Sum(nil)
	}

	mech := []*p11.Mechanism{p11.NewMechanism(mechInfo.mech, nil)}
	if err := p.ctx.SignInit(session, mech, privKey); err != nil {
		return nil, fmt.Errorf("pkcs11 sign init: %w", err)
	}

	sig, err := p.ctx.Sign(session, input)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 sign: %w", err)
	}

	return sig, nil
}
```

### Step 4.3 — Implement `Verify`

```go
// Verify verifies a signature using the public key identified by handle.
// The mechanism selection mirrors Sign: RSA verifies the digest internally;
// ECDSA receives the pre-hashed digest.
func (p *PKCS11KeyProvider) Verify(_ context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error) {
	mechInfo, ok := signMechanisms[algorithm]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	session, err := p.openRWSession()
	if err != nil {
		return false, err
	}
	defer p.closeSession(session)

	pubKey, err := p.findPublicKey(session, handle)
	if err != nil {
		return false, err
	}

	input := data
	if mechInfo.preHash {
		hasher, herr := getHasher(mechInfo.hashAlgo)
		if herr != nil {
			return false, herr
		}
		hasher.Write(data)
		input = hasher.Sum(nil)
	}

	mech := []*p11.Mechanism{p11.NewMechanism(mechInfo.mech, nil)}
	if err := p.ctx.VerifyInit(session, mech, pubKey); err != nil {
		return false, fmt.Errorf("pkcs11 verify init: %w", err)
	}

	if err := p.ctx.Verify(session, input, sig); err != nil {
		// CKR_SIGNATURE_INVALID is a normal "not valid" outcome, not a system error.
		if isSignatureInvalid(err) {
			return false, nil
		}
		return false, fmt.Errorf("pkcs11 verify: %w", err)
	}

	return true, nil
}

// isSignatureInvalid returns true when the PKCS#11 error is CKR_SIGNATURE_INVALID
// or CKR_SIGNATURE_LEN_RANGE (both are "valid parse, wrong signature" outcomes).
func isSignatureInvalid(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return s == "pkcs11: 0xC0: CKR_SIGNATURE_INVALID" ||
		s == "pkcs11: 0xC1: CKR_SIGNATURE_LEN_RANGE"
}
```

### Step 4.4 — Build check

```bash
go build ./internal/crypto/...
```

### Step 4.5 — Commit

```bash
git add internal/crypto/pkcs11_provider.go
git commit -m "feat(crypto): implement PKCS11KeyProvider Sign and Verify via C_Sign/C_Verify"
```

---

## Task 5: Implement `PKCS11KeyProvider.Encrypt` and `Decrypt`

### Files changed
- `internal/crypto/pkcs11_provider.go` — Encrypt and Decrypt implemented

### Step 5.1 — Write failing test (inline, later merged into integration test)

The full integration test in Task 6 covers Encrypt/Decrypt. Confirm build only at this stage.

### Step 5.2 — Implement `Encrypt`

RSA-OAEP is the only encryption algorithm supported via PKCS#11. All other algorithms (AES-GCM, AES-CBC, AES-KW) operate on symmetric keys stored outside the token and are not routed here. Callers that request an unsupported algorithm receive `ErrUnsupportedAlgorithm`.

```go
// Encrypt encrypts plaintext using the RSA public key on the token.
// Only AlgorithmRSAOAEP and AlgorithmRSAOAEP256 are supported.
// AES algorithms must use the software provider path.
func (p *PKCS11KeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	oaepParams, err := oaepMechParams(algorithm)
	if err != nil {
		return nil, nil, err
	}

	session, err := p.openRWSession()
	if err != nil {
		return nil, nil, err
	}
	defer p.closeSession(session)

	pubKey, err := p.findPublicKey(session, handle)
	if err != nil {
		return nil, nil, err
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS_OAEP, oaepParams)}
	if err := p.ctx.EncryptInit(session, mech, pubKey); err != nil {
		return nil, nil, fmt.Errorf("pkcs11 encrypt init: %w", err)
	}

	ct, err := p.ctx.Encrypt(session, data)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11 encrypt: %w", err)
	}

	// RSA-OAEP does not use a nonce; return nil for the nonce slot.
	return ct, nil, nil
}

// Decrypt decrypts ciphertext using the RSA private key on the token.
// Only AlgorithmRSAOAEP and AlgorithmRSAOAEP256 are supported.
func (p *PKCS11KeyProvider) Decrypt(_ context.Context, handle string, data []byte, _ []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	oaepParams, err := oaepMechParams(algorithm)
	if err != nil {
		return nil, err
	}

	session, err := p.openRWSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	privKey, err := p.findPrivateKey(session, handle)
	if err != nil {
		return nil, err
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS_OAEP, oaepParams)}
	if err := p.ctx.DecryptInit(session, mech, privKey); err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt init: %w", err)
	}

	pt, err := p.ctx.Decrypt(session, data)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt: %w", err)
	}

	return pt, nil
}

// oaepMechParams returns the CK_RSA_PKCS_OAEP_PARAMS bytes for the given
// algorithm. Only RSA-OAEP (SHA-1) and RSA-OAEP-256 (SHA-256) are supported.
func oaepMechParams(algorithm EncryptionAlgorithm) ([]byte, error) {
	// CK_RSA_PKCS_OAEP_PARAMS encoding for miekg/pkcs11 is the raw C struct
	// serialised as a byte slice. The library accepts a *p11.OAEPParams helper.
	switch algorithm {
	case AlgorithmRSAOAEP:
		params := p11.NewOAEPParams(
			p11.CKM_SHA_1,
			p11.CKG_MGF1_SHA1,
			p11.CKZ_DATA_SPECIFIED,
			nil,
		)
		return params, nil
	case AlgorithmRSAOAEP256:
		params := p11.NewOAEPParams(
			p11.CKM_SHA256,
			p11.CKG_MGF1_SHA256,
			p11.CKZ_DATA_SPECIFIED,
			nil,
		)
		return params, nil
	default:
		return nil, fmt.Errorf("%w: %s (use software provider for AES operations)", ErrUnsupportedAlgorithm, algorithm)
	}
}
```

**Implementation note for `p11.NewOAEPParams`:** The `miekg/pkcs11` v1.1.1 library exposes `OAEPParams` via a helper that serialises the C struct. If the exact function signature differs in the installed version, use the equivalent struct literal:

```go
// Alternative if NewOAEPParams is not available in v1.1.1:
import "unsafe"

type ckOAEPParams struct {
    hashAlg    uint32
    mgf        uint32
    source     uint32
    pSourceData uintptr
    ulSourceDataLen uint32
}

// Then serialize with:
raw := (*[unsafe.Sizeof(ckOAEPParams{})]byte)(unsafe.Pointer(&params))[:]
```

Use whichever form compiles. The integration tests (Task 6) will confirm correctness.

### Step 5.3 — Build check

```bash
go build ./internal/crypto/...
```

### Step 5.4 — Commit

```bash
git add internal/crypto/pkcs11_provider.go
git commit -m "feat(crypto): implement PKCS11KeyProvider Encrypt/Decrypt via CKM_RSA_PKCS_OAEP"
```

---

## Task 6: Write integration tests for `PKCS11KeyProvider` using SoftHSM2

### Files changed
- `internal/crypto/pkcs11_provider_test.go` — new file

### Step 6.1 — Install and initialise SoftHSM2

Run once on the development machine or CI worker:

```bash
sudo apt install softhsm2
mkdir -p ~/.config/softhsm2
# Create a minimal softhsm2.conf pointing to a writable token directory.
cat > ~/.config/softhsm2/softhsm2.conf <<'EOF'
directories.tokendir = /tmp/softhsm2-tokens/
objectstore.backend = file
EOF
mkdir -p /tmp/softhsm2-tokens
softhsm2-util --init-token --slot 0 --label rocketvault --pin 1234 --so-pin 0000
# Confirm the token is visible:
softhsm2-util --show-slots
```

Find the library path:

```bash
find /usr/lib -name "libsofthsm2.so" 2>/dev/null
# Typically /usr/lib/softhsm/libsofthsm2.so or /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

Set the environment variable used by the tests:

```bash
export SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf
```

### Step 6.2 — Create `internal/crypto/pkcs11_provider_test.go`

```go
package crypto_test

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
)

// softhsmAvailable returns true when softhsm2-util is on PATH and the
// SOFTHSM2_LIB environment variable points to the shared library.
func softhsmAvailable() bool {
	_, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return false
	}
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		return false
	}
	if _, err := os.Stat(lib); err != nil {
		return false
	}
	return true
}

// newTestPKCS11Provider creates a PKCS11KeyProvider against the local SoftHSM2
// token. The test is skipped when SoftHSM2 is not available.
func newTestPKCS11Provider(t *testing.T) *crypto.PKCS11KeyProvider {
	t.Helper()
	if !softhsmAvailable() {
		t.Skip("softhsm2-util not found or SOFTHSM2_LIB not set; skipping PKCS#11 integration tests")
	}

	lib := os.Getenv("SOFTHSM2_LIB")
	cfg := crypto.PKCS11Config{
		LibPath:    lib,
		TokenLabel: "rocketvault",
		PIN:        "1234",
	}

	p, err := crypto.NewPKCS11KeyProvider(cfg)
	require.NoError(t, err, "failed to create PKCS11KeyProvider")
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// --- Key generation ---

func TestPKCS11Provider_GenerateRSAKey(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)
	assert.NotEmpty(t, handle, "handle must be a non-empty UUID label")
	// A UUID label has exactly 36 characters.
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateECDSAKey_P256(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateECDSAKey(context.Background(), "P-256")
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateECDSAKey_P384(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateECDSAKey(context.Background(), "P-384")
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateECDSAKey_P521(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateECDSAKey(context.Background(), "P-521")
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateECDSAKey_P256K_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)
	_, err := p.GenerateECDSAKey(context.Background(), "P-256K")
	require.Error(t, err)
	assert.ErrorIs(t, err, crypto.ErrUnsupportedCurve)
}

// --- Sign / Verify ---

func TestPKCS11Provider_SignVerify_RSA_RS256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("rocketvault pkcs11 sign test")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.True(t, valid, "signature must verify as valid")
}

func TestPKCS11Provider_SignVerify_RSA_RS512(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("rs512 test payload")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS512)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmRS512)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPKCS11Provider_SignVerify_RSA_PS256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("ps256 test payload")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmPS256)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmPS256)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPKCS11Provider_SignVerify_ECDSA_ES256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateECDSAKey(context.Background(), "P-256")
	require.NoError(t, err)

	data := []byte("ecdsa sign test")
	sig, err := p.Sign(context.Background(), handle, "ECDSA", data, crypto.AlgorithmES256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := p.Verify(context.Background(), handle, "ECDSA", data, sig, crypto.AlgorithmES256)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPKCS11Provider_Verify_TamperedData_ReturnsFalse(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("original")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS256)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", []byte("tampered"), sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.False(t, valid, "tampered data must not verify")
}

// --- Encrypt / Decrypt ---

func TestPKCS11Provider_EncryptDecrypt_RSA_OAEP(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	plaintext := []byte("hsm encryption test")
	ct, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.NotEmpty(t, ct)
	assert.Nil(t, nonce, "RSA-OAEP nonce must be nil")

	pt, err := p.Decrypt(context.Background(), handle, ct, nil, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestPKCS11Provider_EncryptDecrypt_RSA_OAEP256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	plaintext := []byte("oaep256 payload")
	ct, _, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmRSAOAEP256)
	require.NoError(t, err)

	pt, err := p.Decrypt(context.Background(), handle, ct, nil, crypto.AlgorithmRSAOAEP256)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestPKCS11Provider_Encrypt_AES_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	_, _, err = p.Encrypt(context.Background(), handle, []byte("data"), crypto.AlgorithmAES256)
	require.Error(t, err)
	assert.ErrorIs(t, err, crypto.ErrUnsupportedAlgorithm)
}

// --- Interface compliance ---

// Ensure PKCS11KeyProvider satisfies KeyProvider at compile time.
var _ crypto.KeyProvider = (*crypto.PKCS11KeyProvider)(nil)
```

### Step 6.3 — Run integration tests

```bash
export SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so
go test ./internal/crypto/... -v -run TestPKCS11Provider -count=1
```

All tests must pass. If SoftHSM2 is not installed, all tests skip cleanly.

### Step 6.4 — Run all crypto tests together

```bash
go test ./internal/crypto/... -v
```

### Step 6.5 — Commit

```bash
git add internal/crypto/pkcs11_provider_test.go
git commit -m "test(crypto): add PKCS11KeyProvider integration tests with SoftHSM2 skip guard"
```

---

## Task 7: Inject `KeyProvider` into `KeyService` and add `pkcs11:` prefix routing in `CryptoService`

### Files changed
- `internal/services/keys/key_service.go` — inject `KeyProvider`, replace direct crypto calls
- `internal/services/keys/crypto_service.go` — detect `pkcs11:` prefix, route to HSM provider

### Step 7.1 — Update `key_service.go`

#### 7.1.1 — Add `keyProvider` field to `keyService` and `KeyServiceConfig`

Find the struct declarations and update them:

```go
// keyService implements KeyService by coordinating key operations
// and access control while delegating to repository layer.
type keyService struct {
	keyRepo     repositories.KeyRepositoryInterface
	keyProvider crypto.KeyProvider
	logger      *logging.Logger
}

// KeyServiceConfig holds the dependencies for key service.
type KeyServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	KeyProvider   crypto.KeyProvider
	Logger        *logging.Logger
}

// NewKeyService creates a new KeyService with the provided dependencies.
func NewKeyService(config KeyServiceConfig) KeyService {
	return &keyService{
		keyRepo:     config.KeyRepository,
		keyProvider: config.KeyProvider,
		logger:      config.Logger,
	}
}
```

#### 7.1.2 — Replace `CreateRSAKey` generation call (line 122)

Remove:
```go
privateKeyPEM, err := crypto.GenerateRSAKeyPEM(req.Bits)
```

Replace with:
```go
// Generate key via the configured provider (software or PKCS#11 HSM).
handle, err := s.keyProvider.GenerateRSAKey(ctx, req.Bits)
if err != nil {
    s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to generate RSA key", err)
    return nil, fmt.Errorf("failed to generate RSA key: %w", err)
}
```

Then update the encrypt-and-store block to be provider-aware:

```go
// For the software provider the handle is a PEM string; encrypt it before storage.
// For the PKCS#11 provider the handle is a UUID label; prefix it and store as-is.
var storedValue string
if isPKCS11Handle(handle) {
    storedValue = "pkcs11:" + handle
} else {
    encrypted, encErr := common.EncryptSecret(handle)
    if encErr != nil {
        s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to encrypt key", encErr)
        return nil, fmt.Errorf("failed to encrypt key: %w", encErr)
    }
    storedValue = encrypted
}
```

Update `key.Value` assignment:
```go
key := &model.Key{
    ...
    Value: storedValue,
    ...
}
```

#### 7.1.3 — Apply the same change to `CreateECDSAKey` (line 203)

Remove:
```go
privateKeyPEM, err := crypto.GenerateECDSAKeyPEM(req.Curve)
```

Replace with:
```go
handle, err := s.keyProvider.GenerateECDSAKey(ctx, req.Curve)
if err != nil {
    s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to generate ECDSA key", err)
    return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
}

var storedValue string
if isPKCS11Handle(handle) {
    storedValue = "pkcs11:" + handle
} else {
    encrypted, encErr := common.EncryptSecret(handle)
    if encErr != nil {
        s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to encrypt key", encErr)
        return nil, fmt.Errorf("failed to encrypt key: %w", encErr)
    }
    storedValue = encrypted
}
```

#### 7.1.4 — Apply the same change to `RotateKey` (lines 499–503)

Remove the switch block:
```go
var newPEM string
switch existing.Type {
case model.KeyTypeRSA:
    newPEM, err = crypto.GenerateRSAKeyPEM(bits)
case model.KeyTypeECDSA:
    newPEM, err = crypto.GenerateECDSAKeyPEM(curve)
case model.KeyTypeES256K:
    newPEM, err = crypto.GenerateECDSAKeyPEM("P-256K")
default:
    ...
}
```

Replace with:
```go
var newHandle string
switch existing.Type {
case model.KeyTypeRSA:
    newHandle, err = s.keyProvider.GenerateRSAKey(ctx, bits)
case model.KeyTypeECDSA:
    newHandle, err = s.keyProvider.GenerateECDSAKey(ctx, curve)
case model.KeyTypeES256K:
    newHandle, err = s.keyProvider.GenerateECDSAKey(ctx, "P-256K")
default:
    s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "unsupported key type for rotation", nil)
    return nil, fmt.Errorf("unsupported key type for rotation: %s", existing.Type)
}
if err != nil {
    s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "key generation failed", err)
    return nil, fmt.Errorf("key generation failed: %w", err)
}

var encryptedNew string
if isPKCS11Handle(newHandle) {
    encryptedNew = "pkcs11:" + newHandle
} else {
    encryptedNew, err = common.EncryptSecret(newHandle)
    if err != nil {
        s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "key encryption failed", err)
        return nil, fmt.Errorf("key encryption failed: %w", err)
    }
}
```

#### 7.1.5 — Add `isPKCS11Handle` helper at bottom of `key_service.go`

```go
// isPKCS11Handle returns true when handle is a UUID label returned by the
// PKCS#11 provider rather than a PEM string from the software provider.
// PKCS#11 labels are UUID v4 strings (36 chars, hyphens in canonical positions).
func isPKCS11Handle(handle string) bool {
	return len(handle) == 36 &&
		handle[8] == '-' && handle[13] == '-' &&
		handle[18] == '-' && handle[23] == '-'
}
```

### Step 7.2 — Update `crypto_service.go` to route `pkcs11:` handles

The four methods `Sign`, `Verify`, `Encrypt`, `Decrypt` all call `common.DecryptSecret(key.Value)` today. Add a routing helper and update each method.

#### Add `keyProvider` field to `cryptoService`

```go
// cryptoService implements CryptoService.
type cryptoService struct {
	keyRepo     repositories.KeyRepositoryInterface
	cryptoOps   *crypto.CryptoOperations
	keyProvider crypto.KeyProvider
	logger      *logging.Logger
}

// CryptoServiceConfig holds dependencies for crypto service.
type CryptoServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	KeyProvider   crypto.KeyProvider
	Logger        *logging.Logger
}

// NewCryptoService creates a new crypto service.
func NewCryptoService(config CryptoServiceConfig) CryptoService {
	return &cryptoService{
		keyRepo:     config.KeyRepository,
		cryptoOps:   crypto.NewCryptoOperations(),
		keyProvider: config.KeyProvider,
		logger:      config.Logger,
	}
}
```

#### Add `resolveKeyHandle` helper

Place this private function after `NewCryptoService`:

```go
const pkcs11Prefix = "pkcs11:"

// resolveKeyHandle decodes the stored key value into a plain handle string.
// For software keys, the stored value is AES-GCM encrypted PEM; this decrypts
// it and returns the PEM. For PKCS#11 keys, the stored value has the "pkcs11:"
// prefix; this strips the prefix and returns the bare UUID label.
// The boolean return is true when the handle refers to a PKCS#11 key.
func resolveKeyHandle(storedValue string) (handle string, isPKCS11 bool, err error) {
	if strings.HasPrefix(storedValue, pkcs11Prefix) {
		return strings.TrimPrefix(storedValue, pkcs11Prefix), true, nil
	}
	decrypted, decErr := common.DecryptSecret(storedValue)
	if decErr != nil {
		return "", false, fmt.Errorf("failed to decrypt key: %w", decErr)
	}
	return decrypted, false, nil
}
```

Add `"strings"` to the import block of `crypto_service.go`.

#### Update `Sign`

Replace the existing decrypt + ops call block:

```go
// Decrypt the private key
decryptedKey, err := common.DecryptSecret(key.Value)
if err != nil {
    ...
    return nil, fmt.Errorf("failed to decrypt key: %w", err)
}

// Perform sign operation
signResult, err := s.cryptoOps.Sign(decryptedKey, key.Type, req.Data, req.Algorithm)
```

With:

```go
handle, isPKCS11, err := resolveKeyHandle(key.Value)
if err != nil {
    s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Failed to resolve key handle", err)
    return nil, err
}

var signature []byte
var digest []byte
if isPKCS11 {
    signature, err = s.keyProvider.Sign(ctx, handle, key.Type, req.Data, req.Algorithm)
    if err != nil {
        s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "PKCS#11 signing failed", err)
        return nil, fmt.Errorf("signing failed: %w", err)
    }
} else {
    signResult, signErr := s.cryptoOps.Sign(handle, key.Type, req.Data, req.Algorithm)
    if signErr != nil {
        s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Signing operation failed", signErr)
        return nil, fmt.Errorf("signing failed: %w", signErr)
    }
    signature = signResult.Signature
    digest = signResult.Digest
}
```

Update the return to use the local `signature` and `digest` variables.

#### Update `Verify` analogously

```go
handle, isPKCS11, err := resolveKeyHandle(key.Value)
if err != nil {
    s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Failed to resolve key handle", err)
    return nil, err
}

var valid bool
if isPKCS11 {
    valid, err = s.keyProvider.Verify(ctx, handle, key.Type, req.Data, req.Signature, req.Algorithm)
    if err != nil {
        s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "PKCS#11 verification failed", err)
        return nil, fmt.Errorf("verification failed: %w", err)
    }
} else {
    verifyResult, verifyErr := s.cryptoOps.Verify(handle, key.Type, req.Data, req.Signature, req.Algorithm)
    if verifyErr != nil {
        s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Verification operation failed", verifyErr)
        return nil, fmt.Errorf("verification failed: %w", verifyErr)
    }
    valid = verifyResult.Valid
}
```

#### Update `Encrypt` analogously

```go
handle, isPKCS11, err := resolveKeyHandle(key.Value)
if err != nil {
    s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Failed to resolve key handle", err)
    return nil, err
}

var ct, nonce []byte
if isPKCS11 {
    ct, nonce, err = s.keyProvider.Encrypt(ctx, handle, req.Data, req.Algorithm)
    if err != nil {
        s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "PKCS#11 encryption failed", err)
        return nil, fmt.Errorf("encryption failed: %w", err)
    }
} else {
    encResult, encErr := s.cryptoOps.Encrypt(handle, req.Data, req.Algorithm)
    if encErr != nil {
        s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Encryption operation failed", encErr)
        return nil, fmt.Errorf("encryption failed: %w", encErr)
    }
    ct = encResult.Ciphertext
    nonce = encResult.Nonce
}

return &EncryptResult{
    Ciphertext: ct,
    Algorithm:  req.Algorithm,
    Nonce:      nonce,
    KeyID:      req.KeyID,
}, nil
```

#### Update `Decrypt` analogously

```go
handle, isPKCS11, err := resolveKeyHandle(key.Value)
if err != nil {
    s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Failed to resolve key handle", err)
    return nil, err
}

var plaintext []byte
if isPKCS11 {
    plaintext, err = s.keyProvider.Decrypt(ctx, handle, req.Ciphertext, req.Nonce, req.Algorithm)
    if err != nil {
        s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "PKCS#11 decryption failed", err)
        return nil, fmt.Errorf("decryption failed: %w", err)
    }
} else {
    decResult, decErr := s.cryptoOps.Decrypt(handle, req.Ciphertext, req.Nonce, req.Algorithm)
    if decErr != nil {
        s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Decryption operation failed", decErr)
        return nil, fmt.Errorf("decryption failed: %w", decErr)
    }
    plaintext = decResult.Plaintext
}

return &DecryptResult{
    Plaintext: plaintext,
    Algorithm: req.Algorithm,
    KeyID:     req.KeyID,
}, nil
```

### Step 7.3 — Build and test

```bash
go build ./...
go test ./internal/services/keys/... -v
```

### Step 7.4 — Commit

```bash
git add internal/services/keys/key_service.go internal/services/keys/crypto_service.go
git commit -m "feat(keys): inject KeyProvider into KeyService and CryptoService; add pkcs11: handle routing"
```

---

## Task 8: Wire provider selection in `service_container.go` and update config

### Files changed
- `internal/container/service_container.go` — provider selection at startup
- `.rocketvault.yaml` — add commented HSM block

### Step 8.1 — Add `keyProvider` field to `ServiceContainer`

In the `ServiceContainer` struct, add:

```go
// Key provider (software or PKCS#11 HSM).
keyProvider crypto.KeyProvider
```

Add import at top of `service_container.go`:

```go
"rocketvault/internal/crypto"
```

### Step 8.2 — Add `GetKeyProvider` to `ServiceContainerInterface`

In `ServiceContainerInterface`, add the getter:

```go
GetKeyProvider() crypto.KeyProvider
```

Add the implementation method on `*ServiceContainer`:

```go
// GetKeyProvider returns the active key provider (software or PKCS#11).
func (c *ServiceContainer) GetKeyProvider() crypto.KeyProvider {
	return c.keyProvider
}
```

### Step 8.3 — Wire provider selection in `initializeServices`

Add this block after the retry service initialisation and before the authentication service initialisation:

```go
// Initialise the key provider based on hsm.enabled config.
// Default is the software provider (no behaviour change).
if viperCfg.GetBool("hsm.enabled") {
    hsmCfg := crypto.PKCS11Config{
        LibPath:    viperCfg.GetString("hsm.lib_path"),
        TokenLabel: viperCfg.GetString("hsm.token_label"),
        PIN:        viperCfg.GetString("hsm.pin"),
        SlotID:     uint(viperCfg.GetUint("hsm.slot_id")),
    }
    p11Provider, p11Err := crypto.NewPKCS11KeyProvider(hsmCfg)
    if p11Err != nil {
        cacheCancel()
        return fmt.Errorf("failed to initialise PKCS#11 key provider: %w", p11Err)
    }
    c.keyProvider = p11Provider
    c.logger.Info("PKCS#11 HSM key provider initialised")
} else {
    c.keyProvider = crypto.NewSoftwareKeyProvider()
    c.logger.Info("Software key provider initialised (HSM disabled)")
}
```

### Step 8.4 — Pass `KeyProvider` into `KeyService` and `CryptoService`

Find the existing `keyService` and `keyCryptoService` initialisation calls in `initializeServices` and add the `KeyProvider` field:

```go
c.keyService = keyServices.NewKeyService(keyServices.KeyServiceConfig{
    KeyRepository: c.keyRepository,
    KeyProvider:   c.keyProvider,   // <-- add this line
    Logger:        c.logger,
})

c.keyCryptoService = keyServices.NewCryptoService(keyServices.CryptoServiceConfig{
    KeyRepository: c.keyRepository,
    KeyProvider:   c.keyProvider,   // <-- add this line
    Logger:        c.logger,
})
```

### Step 8.5 — Update `Close()` to close the key provider

Find the `Close()` method on `*ServiceContainer` and add:

```go
if c.keyProvider != nil {
    if err := c.keyProvider.Close(); err != nil {
        c.logger.WithError(err).Warn("Failed to close key provider")
    }
}
```

This ensures the PKCS#11 library is properly finalised on shutdown.

### Step 8.6 — Add HSM config block to `.rocketvault.yaml`

Append the following commented block at the end of the development config file:

```yaml
# HSM / PKCS#11 configuration.
# Set hsm.enabled: true and configure lib_path, token_label, and pin to route
# all key generation and crypto operations through a hardware security module
# or SoftHSM2. When disabled (default), the built-in Go crypto path is used
# and all keys are stored as AES-GCM encrypted PEM in the database.
#
# Dev/test setup with SoftHSM2:
#   sudo apt install softhsm2
#   softhsm2-util --init-token --slot 0 --label rocketvault --pin 1234 --so-pin 0000
#
# hsm:
#   enabled: false
#   lib_path: /usr/lib/softhsm/libsofthsm2.so
#   token_label: rocketvault
#   pin: "1234"
#   slot_id: 0   # 0 = auto-detect by token_label
```

### Step 8.7 — Full build and test

```bash
go build ./...
go test ./... -count=1
```

### Step 8.8 — Commit

```bash
git add internal/container/service_container.go .rocketvault.yaml
git commit -m "feat(container): wire KeyProvider selection from hsm.enabled config; update .rocketvault.yaml"
```

---

## Verification Checklist

After all tasks are complete, run the following to confirm the integration is correct end-to-end.

- [ ] `go build ./...` passes with zero errors.
- [ ] `go test ./internal/crypto/... -v` — all `TestSoftwareKeyProvider_*` tests pass.
- [ ] `go test ./internal/crypto/... -v -run TestPKCS11Provider` — tests skip gracefully without SoftHSM2, pass with it.
- [ ] `go test ./internal/services/keys/... -v` — all existing key service tests pass.
- [ ] `go test ./internal/container/... -v` — service container tests pass.
- [ ] `go test ./... -count=1` — full test suite passes.
- [ ] Start the server with default config (`hsm.enabled` absent / false) and confirm key create/sign/verify/encrypt/decrypt endpoints behave identically to before this change.
- [ ] Enable HSM (`hsm.enabled: true`) with a running SoftHSM2 token, create an RSA key, confirm `keys.value` in the DB starts with `pkcs11:`, and confirm sign/verify through the API routes correctly.

---

## Database Impact

No schema changes are required. The `keys.value` column is `TEXT` and already stores arbitrary strings. The `pkcs11:` prefix is a new value format, not a new column. Existing encrypted-PEM keys remain fully usable alongside new PKCS#11-label keys in the same database.

---

## Error Sentinel Summary

| Sentinel | Package | Meaning |
|---|---|---|
| `ErrUnsupportedCurve` | `internal/crypto` | Curve valid in software but not in PKCS#11 (e.g., P-256K). |
| `ErrUnsupportedAlgorithm` | `internal/crypto` | Algorithm valid in software but not routed through PKCS#11 (e.g., AES-GCM). |

Both sentinels are exported so callers can use `errors.Is()` to distinguish recoverable routing decisions from unexpected failures.
