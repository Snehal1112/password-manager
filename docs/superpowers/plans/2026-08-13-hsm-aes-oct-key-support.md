# HSM-Backed AES (oct) Key Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the HSM half of the parity gap in `.claude/azure-keyvault-parity.md` §8 ("HSM-backed keys: 🟡 PKCS#11 provider; RSA-OAEP only") by adding genuine symmetric (AES/`oct`) key support to the PKCS#11 provider — key generation plus AES-KW wrap/unwrap — gated to HSM mode only, matching Azure's real restriction that symmetric key creation is Managed-HSM-exclusive (never available on Standard/Premium vaults, which is what RocketVault's software provider models).

**Architecture:** `crypto.KeyProvider` gains one new method, `GenerateAESKey(ctx, bits) (handle string, err error)`. `PKCS11KeyProvider` implements it for real, generating a non-extractable `CKO_SECRET_KEY`/`CKK_AES` object via `CKM_AES_KEY_GEN`. `SoftwareKeyProvider` implements it by returning a new sentinel error (`ErrOctKeysRequireHSM`) — this is not a stub to fill in later, it's the intended permanent behavior, mirroring how `PKCS11KeyProvider.GenerateECDSAKey` already returns `ErrUnsupportedCurve` for P-256K in the other direction. `PKCS11KeyProvider.Encrypt`/`Decrypt` gain an AES-KW branch (`CKM_AES_KEY_WRAP_PAD`, looked up via a new `findSecretKey` alongside the existing `findPrivateKey`/`findPublicKey`) so the existing `crypto_service.go` `WrapKey`/`UnwrapKey` code paths — which already dispatch generically through `keyProvider.Encrypt`/`Decrypt` — work unchanged once their hardcoded RSA-OAEP-only HSM allowlist is relaxed to include the three AES-KW algorithms. A new `KeyService.CreateOctKey` mirrors `CreateRSAKey`/`CreateECDSAKey` exactly, and the API's `createKey` handler gains a third `Type` branch. AES-CBC wrap has no PKCS#11 mechanism equivalent and stays software-key-only — this plan does not add it, and says so in the parity doc.

**Tech Stack:** Go, `github.com/miekg/pkcs11` v1.1.1 (already vendored), SoftHSM2 (dev/CI-optional, tests self-skip without it).

## Global Constraints

- `go build ./...` and `go vet ./...` must pass after every task.
- PKCS#11 integration tests in this plan follow the existing self-skip pattern (`internal/crypto/pkcs11_provider_test.go`'s `softhsmAvailable()`/`newTestPKCS11Provider(t)`) — they will not run in this environment (no SoftHSM2 installed) and that is expected; do not attempt to install SoftHSM2 as part of this plan. Unit-level coverage for the non-PKCS11 code paths (the software provider's new error, `crypto_service.go`'s relaxed allowlist, `KeyService.CreateOctKey`, the API handler) uses hand-written mocks and must pass in this environment.
- Symmetric key creation is HSM-only by design, matching Azure (Managed HSM only, never Standard/Premium vaults). Do not add a software-provider code path that actually generates AES keys — `ErrOctKeysRequireHSM` is the correct, permanent behavior for `SoftwareKeyProvider.GenerateAESKey`, not a placeholder.
- Do not add AES-CBC wrap support for HSM keys — there is no PKCS#11 mechanism for it, and inventing one (e.g. faking it with raw AES-CBC via a non-standard mechanism) would silently diverge from what the hardware actually supports.

---

### Task 1: Add `GenerateAESKey` to the `KeyProvider` interface and both implementations

**Files:**
- Modify: `internal/crypto/provider.go` (interface)
- Modify: `internal/crypto/software_provider.go` (new sentinel error + method)
- Modify: `internal/crypto/pkcs11_provider.go` (real implementation + `findSecretKey` helper)
- Modify: `internal/crypto/pkcs11_provider_test.go` (new skip-guarded integration tests)
- Modify: `internal/services/keys/key_service_extended_test.go`, `internal/services/keys/crypto_service_cache_test.go`, `internal/services/keys/key_service_cache_test.go` (add the new method to each hand-rolled `KeyProvider` mock)

**Interfaces:**
- Produces: `KeyProvider.GenerateAESKey(ctx context.Context, bits int) (handle string, err error)`, `crypto.ErrOctKeysRequireHSM` — consumed by Task 2's `KeyService.CreateOctKey`.

- [ ] **Step 1: Add the sentinel error and interface method**

In `internal/crypto/software_provider.go`, add near the top (after the `import` block):

```go
// ErrOctKeysRequireHSM is returned by SoftwareKeyProvider.GenerateAESKey.
// Symmetric (oct/AES) key creation is Managed-HSM-only in Azure Key Vault —
// Standard and Premium vaults never allow it — and RocketVault's software
// provider models that same restriction: only PKCS11KeyProvider implements
// this method for real.
var ErrOctKeysRequireHSM = errors.New("symmetric (oct/AES) key creation requires an HSM-backed key provider (hsm.enabled: true)")
```

Add `"errors"` to this file's import block.

In `internal/crypto/provider.go`, add to the `KeyProvider` interface (after `GenerateECDSAKey`):

```go
	// GenerateAESKey generates a symmetric AES key. bits must be 128, 192, or
	// 256. Only PKCS11KeyProvider supports this — Azure restricts symmetric
	// key creation to Managed HSM, never Standard/Premium vaults, and
	// SoftwareKeyProvider mirrors that by always returning ErrOctKeysRequireHSM.
	GenerateAESKey(ctx context.Context, bits int) (handle string, err error)
```

- [ ] **Step 2: Implement the software provider's stub**

In `internal/crypto/software_provider.go`, add after `GenerateECDSAKey`:

```go
// GenerateAESKey always fails: see ErrOctKeysRequireHSM.
func (p *SoftwareKeyProvider) GenerateAESKey(_ context.Context, _ int) (string, error) {
	return "", ErrOctKeysRequireHSM
}
```

- [ ] **Step 3: Write the failing PKCS#11 integration tests**

Append to `internal/crypto/pkcs11_provider_test.go` (these will be skipped in this environment — see Global Constraints — but must compile and be correct):

```go
// --- AES (oct) key generation and wrap/unwrap ---

func TestPKCS11Provider_GenerateAESKey_128(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateAESKey(context.Background(), 128)
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateAESKey_256(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateAESKey_InvalidBits_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)
	_, err := p.GenerateAESKey(context.Background(), 100)
	assert.Error(t, err)
}

func TestPKCS11Provider_WrapUnwrap_AES256KW(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	plaintext := []byte("hsm aes-kw wrap test, arbitrary length, not block-aligned")
	wrapped, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA256KW)
	require.NoError(t, err)
	assert.NotEmpty(t, wrapped)
	assert.Nil(t, nonce, "AES-KW nonce must be nil")

	unwrapped, err := p.Decrypt(context.Background(), handle, wrapped, nil, crypto.AlgorithmA256KW)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapped)
}

func TestPKCS11Provider_WrapUnwrap_AES128KW(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 128)
	require.NoError(t, err)

	plaintext := []byte("short")
	wrapped, _, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA128KW)
	require.NoError(t, err)

	unwrapped, err := p.Decrypt(context.Background(), handle, wrapped, nil, crypto.AlgorithmA128KW)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapped)
}

func TestPKCS11Provider_Encrypt_AESKWWithRSAKey_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)

	// An RSA key has no CKO_SECRET_KEY object under its label, so AES-KW
	// against it must fail at the find-secret-key step.
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	_, _, err = p.Encrypt(context.Background(), handle, []byte("test"), crypto.AlgorithmA256KW)
	assert.Error(t, err)
}
```

- [ ] **Step 4: Run tests to confirm they compile and self-skip**

Run: `go build ./... && go vet ./... && go test ./internal/crypto/... -run TestPKCS11Provider_GenerateAESKey -v`

Expected: `SKIP` for every new test (no SoftHSM2 in this environment) — this confirms the code compiles against the real `p11` package constants used in the next step, without yet having implemented them (so this step should actually be run *after* Step 5's implementation, not before — Go doesn't have a "compiles but method missing" red state the way a dynamic language would; skip this compile-check sub-step and treat Step 5 as the implementation step, then run the full build once at Step 6).

- [ ] **Step 5: Implement `GenerateAESKey`, `findSecretKey`, and the AES-KW `Encrypt`/`Decrypt` branch**

In `internal/crypto/pkcs11_provider.go`, add after `GenerateECDSAKey` (after its closing brace, before `findPrivateKey`):

```go
// GenerateAESKey generates a non-extractable AES secret key on the token.
// Returns the CKA_LABEL UUID string as the handle. bits must be 128, 192, or
// 256.
func (p *PKCS11KeyProvider) GenerateAESKey(_ context.Context, bits int) (string, error) {
	if bits != 128 && bits != 192 && bits != 256 {
		return "", fmt.Errorf("%w: AES key size must be 128, 192, or 256 bits", ErrUnsupportedAlgorithm)
	}

	session, err := p.openRWSession()
	if err != nil {
		return "", err
	}
	defer p.closeSession(session)

	label := uuid.New().String()

	attrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_ENCRYPT, true),
		p11.NewAttribute(p11.CKA_DECRYPT, true),
		p11.NewAttribute(p11.CKA_WRAP, true),
		p11.NewAttribute(p11.CKA_UNWRAP, true),
		p11.NewAttribute(p11.CKA_VALUE_LEN, bits/8),
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_GEN, nil)}
	if _, err := p.ctx.GenerateKey(session, mech, attrs); err != nil {
		return "", fmt.Errorf("pkcs11 aes key gen: %w", err)
	}

	return label, nil
}
```

Add after `findPublicKey`:

```go
// findSecretKey finds the AES secret key object on the token by CKA_LABEL.
func (p *PKCS11KeyProvider) findSecretKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
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
		return 0, fmt.Errorf("pkcs11: secret key not found for label %q", label)
	}
	return handles[0], nil
}

// isAESKWAlgorithm reports whether algorithm is an AES-KW variant, which maps
// to CKM_AES_KEY_WRAP_PAD against a CKO_SECRET_KEY object rather than the
// RSA-OAEP path against a CKO_PUBLIC_KEY/CKO_PRIVATE_KEY pair.
func isAESKWAlgorithm(algorithm EncryptionAlgorithm) bool {
	switch algorithm {
	case AlgorithmA128KW, AlgorithmA192KW, AlgorithmA256KW:
		return true
	default:
		return false
	}
}
```

Change `Encrypt`:

```go
// Encrypt encrypts plaintext using the RSA public key on the token.
// Only AlgorithmRSAOAEP and AlgorithmRSAOAEP256 are supported.
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

	// RSA-OAEP does not use a nonce.
	return ct, nil, nil
}
```

to:

```go
// Encrypt performs RSA-OAEP encryption with the token's RSA public key, or
// AES-KW wrapping with the token's AES secret key, depending on algorithm.
func (p *PKCS11KeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	session, err := p.openRWSession()
	if err != nil {
		return nil, nil, err
	}
	defer p.closeSession(session)

	if isAESKWAlgorithm(algorithm) {
		key, err := p.findSecretKey(session, handle)
		if err != nil {
			return nil, nil, err
		}

		mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_WRAP_PAD, nil)}
		if err := p.ctx.EncryptInit(session, mech, key); err != nil {
			return nil, nil, fmt.Errorf("pkcs11 aes-kw wrap init: %w", err)
		}
		ct, err := p.ctx.Encrypt(session, data)
		if err != nil {
			return nil, nil, fmt.Errorf("pkcs11 aes-kw wrap: %w", err)
		}
		// AES-KW does not use a nonce.
		return ct, nil, nil
	}

	oaepParams, err := oaepMechParams(algorithm)
	if err != nil {
		return nil, nil, err
	}

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

	// RSA-OAEP does not use a nonce.
	return ct, nil, nil
}
```

Change `Decrypt` the same way:

```go
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
```

to:

```go
// Decrypt performs RSA-OAEP decryption with the token's RSA private key, or
// AES-KW unwrapping with the token's AES secret key, depending on algorithm.
func (p *PKCS11KeyProvider) Decrypt(_ context.Context, handle string, data []byte, _ []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	session, err := p.openRWSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	if isAESKWAlgorithm(algorithm) {
		key, err := p.findSecretKey(session, handle)
		if err != nil {
			return nil, err
		}

		mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_WRAP_PAD, nil)}
		if err := p.ctx.DecryptInit(session, mech, key); err != nil {
			return nil, fmt.Errorf("pkcs11 aes-kw unwrap init: %w", err)
		}
		pt, err := p.ctx.Decrypt(session, data)
		if err != nil {
			return nil, fmt.Errorf("pkcs11 aes-kw unwrap: %w", err)
		}
		return pt, nil
	}

	oaepParams, err := oaepMechParams(algorithm)
	if err != nil {
		return nil, err
	}

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
```

- [ ] **Step 6: Add the new method to the three hand-rolled `KeyProvider` mocks**

In `internal/services/keys/key_service_extended_test.go`, add after `mockKeyProviderForService.GenerateECDSAKey` (line ~58):

```go
func (m *mockKeyProviderForService) GenerateAESKey(_ context.Context, bits int) (string, error) {
	args := m.Called(bits)
	return args.String(0), args.Error(1)
}
```

In `internal/services/keys/crypto_service_cache_test.go`, add after `mockKeyProvider.GenerateECDSAKey`:

```go
func (m *mockKeyProvider) GenerateAESKey(_ context.Context, bits int) (string, error) {
	args := m.Called(bits)
	return args.String(0), args.Error(1)
}
```

In `internal/services/keys/key_service_cache_test.go`, add after `mockKeyProviderForRotate.GenerateECDSAKey`:

```go
func (m *mockKeyProviderForRotate) GenerateAESKey(_ context.Context, _ int) (string, error) {
	return "", errors.New("not implemented")
}
```
(Match whichever error-construction style — `errors.New` vs a package-level sentinel — that file already uses for its other "not implemented" stubs; check before adding a new import.)

- [ ] **Step 7: Build and run the full crypto/keys test suites**

Run: `go build ./... && go vet ./... && go test ./internal/crypto/... ./internal/services/keys/... -v 2>&1 | tail -100`

Expected: clean build; the new PKCS#11 tests `SKIP`; every other test (including every existing test using the three mocks touched in Step 6) still `PASS`.

- [ ] **Step 8: Commit**

```bash
git add internal/crypto/provider.go internal/crypto/software_provider.go internal/crypto/pkcs11_provider.go \
  internal/crypto/pkcs11_provider_test.go internal/services/keys/key_service_extended_test.go \
  internal/services/keys/crypto_service_cache_test.go internal/services/keys/key_service_cache_test.go
git commit -m "feat(crypto): add HSM-backed AES key generation and AES-KW wrap/unwrap"
```

---

### Task 2: Relax the HSM wrap/unwrap algorithm allowlist in `crypto_service.go`

**Files:**
- Modify: `internal/services/keys/crypto_service.go` (`WrapKey`, `UnwrapKey`)
- Test: `internal/services/keys/crypto_service_cache_test.go` or the nearest existing `WrapKey`/`UnwrapKey` test file (`internal/services/keys/wrap_key_test.go` per the earlier HSM investigation)

**Interfaces:**
- Consumes: `crypto.KeyProvider.Encrypt`/`Decrypt` (Task 1, now AES-KW-aware for PKCS#11 handles).
- Produces: no change to `WrapKey`/`UnwrapKey`'s signatures — only which algorithms are accepted for HSM-backed keys.

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/keys/wrap_key_test.go` (or wherever the existing `TestWrapKey_*Rejects*HSM*`/similar test lives — grep `grep -rn "HSM-backed keys" internal/services/keys/*_test.go` to find and extend the existing negative-case test file rather than creating a new one):

```go
// TestWrapKey_HSMKey_AllowsAES256KW verifies that A256KW is now accepted for
// PKCS#11-backed keys (it was previously rejected as RSA-OAEP-only).
func TestWrapKey_HSMKey_AllowsAES256KW(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeOct, Value: "pkcs11:aes-label", Enabled: true}

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(key, nil)

	provider := &mockKeyProvider{}
	provider.On("Encrypt", mock.Anything, "aes-label", []byte("plaintext"), crypto.AlgorithmA256KW).
		Return([]byte("wrapped"), []byte(nil), nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, KeyProvider: provider, Logger: logger})

	result, err := svc.WrapKey(context.Background(), WrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: scope,
		PlaintextKey: []byte("plaintext"), Algorithm: "A256KW",
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("wrapped"), result.WrappedKey)
	provider.AssertExpectations(t)
}

// TestWrapKey_HSMKey_RejectsAES256CBC verifies AES-CBC stays rejected for
// PKCS#11-backed keys — there is no PKCS#11 mechanism for it.
func TestWrapKey_HSMKey_RejectsAES256CBC(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeOct, Value: "pkcs11:aes-label", Enabled: true}

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(key, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, KeyProvider: &mockKeyProvider{}, Logger: logger})

	_, err := svc.WrapKey(context.Background(), WrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: scope,
		PlaintextKey: []byte("plaintext"), Algorithm: "A256CBC",
	})
	assert.Error(t, err)
}
```

Adjust the exact `mockKeyRepository`/`mockKeyProvider`/`NewCryptoService`/`CryptoServiceConfig`/`WrapKeyRequest` field names to match whatever this test file's existing tests already use — do not guess a different shape than what's already established there.

- [ ] **Step 2: Run tests to verify `TestWrapKey_HSMKey_AllowsAES256KW` fails**

Run: `go test ./internal/services/keys/... -run 'TestWrapKey_HSMKey_AllowsAES256KW|TestWrapKey_HSMKey_RejectsAES256CBC' -v`

Expected: `TestWrapKey_HSMKey_AllowsAES256KW` FAILs (current code rejects every non-RSA-OAEP algorithm for HSM keys); `TestWrapKey_HSMKey_RejectsAES256CBC` already PASSes (it's testing existing, unchanged behavior).

- [ ] **Step 3: Relax the allowlist**

In `internal/services/keys/crypto_service.go`, add above `WrapKey` (or anywhere else at package scope in this file):

```go
// isHSMWrapAlgorithm reports whether algorithm has a PKCS#11 mechanism
// equivalent that crypto.PKCS11KeyProvider implements. AES-CBC wrap has none
// and stays software-key-only.
func isHSMWrapAlgorithm(algorithm string) bool {
	switch algorithm {
	case "RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW":
		return true
	default:
		return false
	}
}
```

Change both occurrences of:

```go
	// AES wrap/unwrap requires a software key; HSM keys only support RSA-OAEP variants.
	if wrapIsPKCS11 && req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
		return nil, fmt.Errorf("algorithm %q is not supported for HSM-backed keys; use RSA-OAEP or RSA-OAEP-256", req.Algorithm)
	}
```

(in `WrapKey`, with `wrapIsPKCS11`) and:

```go
	// AES wrap/unwrap requires a software key; HSM keys only support RSA-OAEP variants.
	if unwrapIsPKCS11 && req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
		return nil, fmt.Errorf("algorithm %q is not supported for HSM-backed keys; use RSA-OAEP or RSA-OAEP-256", req.Algorithm)
	}
```

(in `UnwrapKey`, with `unwrapIsPKCS11`) to:

```go
	// AES-CBC wrap has no PKCS#11 mechanism and stays software-key-only; every
	// other supported algorithm now has an HSM path (RSA-OAEP variants via the
	// RSA public/private key pair, AES-KW variants via the AES secret key).
	if wrapIsPKCS11 && !isHSMWrapAlgorithm(req.Algorithm) {
		return nil, fmt.Errorf("algorithm %q is not supported for HSM-backed keys; use RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, or A256KW", req.Algorithm)
	}
```

and the `Unwrap` equivalent with `unwrapIsPKCS11`, same message.

Also update `UnwrapKey`'s doc comment ("decrypts wrapped key material using RSA-OAEP, RSA-OAEP-256, AES-KW, or AES-CBC with the specified vault key") if it currently implies uniform support across software and HSM keys — clarify AES-CBC is software-key-only.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/keys/... -run 'TestWrapKey_HSMKey_AllowsAES256KW|TestWrapKey_HSMKey_RejectsAES256CBC' -v`

Expected: both PASS.

- [ ] **Step 5: Run the full keys package suite**

Run: `go build ./... && go vet ./... && go test ./internal/services/keys/... -v 2>&1 | tail -60`

Expected: all pass, including every pre-existing `WrapKey`/`UnwrapKey` test (the RSA-OAEP HSM path and the software-key AES-CBC/AES-KW paths are both unchanged).

- [ ] **Step 6: Commit**

```bash
git add internal/services/keys/crypto_service.go internal/services/keys/wrap_key_test.go
git commit -m "feat(keys): allow AES-KW wrap/unwrap for HSM-backed keys"
```

---

### Task 3: Add `KeyService.CreateOctKey`

**Files:**
- Modify: `internal/services/keys/key_service.go` (interface, implementation)
- Modify: `internal/services/keys/mocks/mock_KeyService.go` (regenerate via `mockery`)
- Test: `internal/services/keys/key_service_test.go` (or the nearest file testing `CreateRSAKey`/`CreateECDSAKey` — mirror its test shape)

**Interfaces:**
- Consumes: `crypto.KeyProvider.GenerateAESKey` (Task 1).
- Produces: `KeyService.CreateOctKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)` — consumed by Task 4's API handler.

- [ ] **Step 1: Add the interface method**

In `internal/services/keys/key_service.go`, change:

```go
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
```

to:

```go
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	// CreateOctKey creates a symmetric AES key. HSM-only — see
	// crypto.ErrOctKeysRequireHSM.
	CreateOctKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
```

- [ ] **Step 2: Write the failing test**

Add to `internal/services/keys/key_service_test.go` (mirroring whatever `TestCreateRSAKey_*` test already exists there for structure — use the same mock repo/provider/logger construction pattern already in that file):

```go
func TestCreateOctKey_Success(t *testing.T) {
	userID := uuid.New()
	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.Type == model.KeyTypeOct && k.Bits == 256
	})).Return(nil)

	provider := &mockKeyProvider{}
	provider.On("GenerateAESKey", 256).Return("aes-label", nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: provider, Logger: logger})

	result, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{
		Name: "my-aes-key", Bits: 256, UserID: userID,
	})
	require.NoError(t, err)
	assert.Equal(t, model.KeyTypeOct, result.Type)
	repo.AssertExpectations(t)
	provider.AssertExpectations(t)
}

func TestCreateOctKey_InvalidBits_ReturnsError(t *testing.T) {
	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: &mockKeyRepository{}, KeyProvider: &mockKeyProvider{}, Logger: logger})

	_, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{
		Name: "bad", Bits: 100, UserID: uuid.New(),
	})
	assert.Error(t, err)
}

func TestCreateOctKey_SoftwareProvider_ReturnsError(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProvider{}
	provider.On("GenerateAESKey", 256).Return("", crypto.ErrOctKeysRequireHSM)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: provider, Logger: logger})

	_, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{
		Name: "my-aes-key", Bits: 256, UserID: uuid.New(),
	})
	require.ErrorIs(t, err, crypto.ErrOctKeysRequireHSM)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
```

Adjust the mock type/constructor names in these three tests to whatever `internal/services/keys/key_service_test.go` (or wherever `TestCreateRSAKey_*` actually lives — confirm with `grep -rn "func TestCreateRSAKey" internal/services/keys/*_test.go` first) already uses for its `KeyRepository`/`KeyProvider` mocks — do not introduce a fourth, differently-named mock type when one of the three from Task 1 Step 6 already fits.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/services/keys/... -run TestCreateOctKey -v`

Expected: FAIL (compile error — `CreateOctKey` doesn't exist yet).

- [ ] **Step 4: Implement `CreateOctKey`**

In `internal/services/keys/key_service.go`, add after `CreateECDSAKey`'s closing brace:

```go
// CreateOctKey creates a new symmetric AES key. Requires an HSM-backed key
// provider — see crypto.ErrOctKeysRequireHSM.
func (s *keyService) CreateOctKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"bits":    req.Bits,
		"user_id": req.UserID.String(),
	}).Info("Creating AES (oct) key")

	if req.Bits != 128 && req.Bits != 192 && req.Bits != 256 {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "invalid AES key size: must be 128, 192, or 256", nil)
		return nil, fmt.Errorf("invalid AES key size: must be 128, 192, or 256")
	}

	handle, err := s.keyProvider.GenerateAESKey(ctx, req.Bits)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "failed to generate AES key", err)
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// AES keys are HSM-only: GenerateAESKey never returns a software (PEM)
	// handle, so the value is always the PKCS#11 label — no plaintext key
	// material ever reaches this process.
	storedValue := "pkcs11:" + handle

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      model.KeyTypeOct,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Bits:      req.Bits,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store AES key: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_oct_key", "success", fmt.Sprintf("AES key created: %s, ID: %s", req.Name, key.ID))

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/services/keys/... -run TestCreateOctKey -v`

Expected: PASS (3 tests).

- [ ] **Step 6: Regenerate the `KeyService` mock**

Run: `cd /home/numericlabs/data/rocket/rocketvault && mockery && go build ./... && go vet ./...`

- [ ] **Step 7: Commit**

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_service_test.go internal/services/keys/mocks/mock_KeyService.go
git commit -m "feat(keys): add KeyService.CreateOctKey (HSM-only symmetric key generation)"
```

---

### Task 4: Wire `oct` into the `createKey` API handler and validation

**Files:**
- Modify: `api/keys.go` (`createKey`)
- Modify: `internal/validation/key_validation.go` (`ValidateKeyCreate`)
- Test: `api/keys_crud_test.go` (or wherever `TestCreateKey_*` handler tests live)

**Interfaces:**
- Consumes: `keyService.CreateOctKey` (Task 3).
- Produces: no new exported symbols — `POST /keys` (and the vault-scoped equivalent) now accepts `"type": "OCT"` with a `"bits"` of 128/192/256.

- [ ] **Step 1: Write the failing handler tests**

Add to `api/keys_crud_test.go`:

```go
func TestCreateKey_OctType_CallsCreateOctKey(t *testing.T) {
	svc := &mockKeyService{}
	keyID := uuid.New()
	svc.On("CreateOctKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Bits == 256
	})).Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "aes-key", Type: model.KeyTypeOct, CreatedAt: time.Now()}, nil)
	svc.On("GetKey", mock.Anything, keyID, mock.Anything).Return(&model.Key{
		ID: keyID, Name: "aes-key", Type: model.KeyTypeOct, Bits: 256, Enabled: true,
	}, nil)

	c := newKeyCtx(svc)
	body, _ := json.Marshal(map[string]any{"name": "aes-key", "type": "oct", "bits": 256})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateKey_OctType_InvalidBits_Returns400(t *testing.T) {
	c := newKeyCtx(&mockKeyService{})
	body, _ := json.Marshal(map[string]any{"name": "aes-key", "type": "oct", "bits": 100})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))

	createKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

Add `"bytes"`, `"encoding/json"`, `"time"` to this file's imports if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run TestCreateKey_OctType -v`

Expected: FAIL — `type: must be RSA or ECDSA` (400) instead of the expected dispatch, since `"OCT"` isn't accepted yet.

- [ ] **Step 3: Update validation**

In `internal/validation/key_validation.go`, change:

```go
		validation.Field(&req.Type,
			validation.Required,
			validation.In(model.KeyTypeRSA, model.KeyTypeECDSA),
		),
		validation.Field(&req.Bits,
			validation.When(req.Type == model.KeyTypeRSA,
				validation.Required,
				validation.In(2048, 3072, 4096),
			),
		),
```

to:

```go
		validation.Field(&req.Type,
			validation.Required,
			validation.In(model.KeyTypeRSA, model.KeyTypeECDSA, "OCT"),
		),
		validation.Field(&req.Bits,
			validation.When(req.Type == model.KeyTypeRSA,
				validation.Required,
				validation.In(2048, 3072, 4096),
			),
			validation.When(req.Type == "OCT",
				validation.Required,
				validation.In(128, 192, 256),
			),
		),
```

(`"OCT"` is a literal here, matching this function's existing style of literal curve strings like `"P-256"` rather than named constants — the stored, persisted type is still the lowercase `model.KeyTypeOct`, set explicitly by `CreateOctKey`, not derived from this uppercased API-layer string.)

- [ ] **Step 4: Update the `createKey` handler**

In `api/keys.go`, change:

```go
	// Validate key type.
	req.Type = strings.ToUpper(req.Type)
	if req.Type != "RSA" && req.Type != "ECDSA" {
		c.SetInvalidParam("type: must be RSA or ECDSA")
		return
	}
```

to:

```go
	// Validate key type.
	req.Type = strings.ToUpper(req.Type)
	if req.Type != "RSA" && req.Type != "ECDSA" && req.Type != "OCT" {
		c.SetInvalidParam("type: must be RSA, ECDSA, or OCT")
		return
	}
```

and change:

```go
	var result *keyservices.CreateKeyResult
	if req.Type == "RSA" {
		// Validate RSA key size.
		if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
			if req.Bits == 0 {
				req.Bits = 2048 // Default RSA key size.
			} else {
				c.SetInvalidParam("bits: must be 2048, 3072, or 4096")
				return
			}
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateRSAKey(r.Context(), createReq)
	} else {
		// Validate ECDSA curve.
		if req.Curve == "" {
			req.Curve = "P-256" // Default ECDSA curve.
		}
		if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" && req.Curve != "P-256K" {
			c.SetInvalidParam("curve: must be P-256, P-384, P-521, or P-256K")
			return
		}
		createReq.Curve = req.Curve
		result, err = keyService.CreateECDSAKey(r.Context(), createReq)
	}
```

to:

```go
	var result *keyservices.CreateKeyResult
	switch req.Type {
	case "RSA":
		// Validate RSA key size.
		if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
			if req.Bits == 0 {
				req.Bits = 2048 // Default RSA key size.
			} else {
				c.SetInvalidParam("bits: must be 2048, 3072, or 4096")
				return
			}
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateRSAKey(r.Context(), createReq)
	case "OCT":
		if req.Bits != 128 && req.Bits != 192 && req.Bits != 256 {
			c.SetInvalidParam("bits: must be 128, 192, or 256")
			return
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateOctKey(r.Context(), createReq)
	default:
		// Validate ECDSA curve.
		if req.Curve == "" {
			req.Curve = "P-256" // Default ECDSA curve.
		}
		if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" && req.Curve != "P-256K" {
			c.SetInvalidParam("curve: must be P-256, P-384, P-521, or P-256K")
			return
		}
		createReq.Curve = req.Curve
		result, err = keyService.CreateECDSAKey(r.Context(), createReq)
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./api/... -run TestCreateKey_OctType -v`

Expected: PASS (2 tests).

- [ ] **Step 6: Run the full suite and lint**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tail -80 && golangci-lint run ./... 2>&1 | tail -60`

Expected: clean build, all tests pass, no new lint findings in touched files.

- [ ] **Step 7: Commit**

```bash
git add api/keys.go internal/validation/key_validation.go api/keys_crud_test.go
git commit -m "feat(api): accept OCT key type in POST /keys (HSM-only)"
```

---

### Task 5: Update the parity doc

**Files:**
- Modify: `.claude/azure-keyvault-parity.md`

- [ ] **Step 1: Update §3's AES row**

Change:
```
| Wrap/Encrypt — AES (KW/CBC) | Managed HSM only | A128/192/256 KW + CBC (software keys) | ➕ |
```
to:
```
| Wrap/Encrypt — AES (KW/CBC) | Managed HSM only | A128/192/256 KW on software keys (➕, beyond Azure) **and** on HSM-backed AES keys (✅ matches Azure's Managed-HSM-only restriction); A128/192/256 CBC on software keys only, no PKCS#11 mechanism exists for CBC wrap | ✅ (KW) / ➕ (CBC, software only) |
```

- [ ] **Step 2: Update §8's HSM row**

Change:
```
| HSM-backed keys | ✅ Premium (FIPS 140-3 L3) | 🟡 PKCS#11 provider (`hsm.enabled`); RSA-OAEP only | 🟡 |
```
to:
```
| HSM-backed keys | ✅ Premium (FIPS 140-3 L3) | 🟡 PKCS#11 provider (`hsm.enabled`); RSA sign/verify/encrypt/decrypt, EC sign/verify (P-256/P-384/P-521), and AES-KW generate/wrap/unwrap all HSM-backed; P-256K and AES-CBC remain software-only | 🟡 |
```

- [ ] **Step 3: Update the Summary's Partial (🟡) HSM bullet**

Change:
```
- **HSM**: PKCS#11 path exists but is not the default and is RSA-OAEP-limited; no
  FIPS 140-3 L3 validation.
```
to:
```
- **HSM**: PKCS#11 path exists but is not the default; covers RSA (sign/verify/
  encrypt/decrypt), EC P-256/P-384/P-521 (sign/verify), and AES-KW (generate/wrap/
  unwrap) — P-256K and AES-CBC remain software-only (P-256K: no PKCS#11 mechanism
  verified against real hardware in this environment; AES-CBC: no PKCS#11 mechanism
  exists at all). No FIPS 140-3 L3 validation (a certification process, not
  achievable through code).
```

- [ ] **Step 4: Commit**

```bash
git add .claude/azure-keyvault-parity.md
git commit -m "docs(parity): reflect HSM-backed AES-KW support"
```
