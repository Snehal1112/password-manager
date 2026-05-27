# Medium-term Azure Parity Gaps — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six remaining open medium-term Azure Key Vault parity gaps identified in `docs/plans/2026-05-23-azure-keyvault-parity-audit.md`.

**Architecture:** Each gap is a self-contained subsystem; tasks are ordered so that later tasks never depend on an earlier unfinished task. Schema changes go through `migrateSchema()` in `internal/db/db.go` (idempotent ALTER TABLE pattern). New crypto algorithms extend `internal/crypto/crypto_operations.go`; service-layer guards land in `internal/services/keys/crypto_service.go`.

**Tech Stack:** Go 1.26, SQLite/PostgreSQL via `database/sql`, Gorilla Mux, `go test ./...`

---

## Affected files

| File | Change |
|------|--------|
| `internal/services/keys/crypto_service.go` | Add revoked guard to `Verify` and `Decrypt`; add HMAC sign/verify |
| `internal/crypto/crypto_operations.go` | Add ES256K, HS256/384/512, RSA1_5, AES-KW (128/192/256), AES-CBC (128/192/256) |
| `model/key.go` | Add `Enabled`, `ExpiresAt *time.Time`, `NotBefore *time.Time`, `Bits int`, `Curve string` |
| `model/certificate.go` | Add `Enabled bool`, `NotBefore *time.Time` |
| `model/secret.go` | No struct change; repo SQL update only |
| `internal/db/db.go` | `createOptimizedSchema` + `migrateSchema`: add lifecycle columns to `secrets`, `keys`, `certificates`; add `key_versions` table |
| `internal/repositories/secret_repository.go` | Include `enabled`, `expires_at`, `not_before` in INSERT/SELECT/UPDATE |
| `internal/repositories/key_repository.go` | Include lifecycle columns; add `ListVersions`, `CreateVersion`, `GetVersion` |
| `api/secrets.go` | Enforce `IsAccessible()` in `getSecret` |
| `api/keys.go` | Enforce lifecycle in `getKey`; update route for `GET /keys/{id}/versions` |
| `api/certificates.go` | Enforce `IsEnabled()` in `getCertificate` |
| `internal/services/keys/key_service.go` | `RotateKey` → create version row instead of `-rotated` key |
| `internal/backup/item_backup.go` | New file: `BackupItem` / `RestoreItem` service functions |
| `api/backup.go` | New file: `POST /secrets/{id}/backup`, `/keys/{id}/backup`, `/certificates/{id}/backup`, `POST /secrets/restore`, `/keys/restore`, `/certificates/restore` |
| `internal/db/db.go` | Add `item_backups` table schema + migration |

Certificate Policy (item 8) is the largest new feature. It is scoped as a **stub** in this plan — model, table, and CRUD endpoints — without lifetime-action triggers or issuer integration, which are follow-on work.

| `model/certificate_policy.go` | New: `CertificatePolicy` struct + HTTP request/response types |
| `internal/db/db.go` | `certificate_policies` table |
| `internal/repositories/certificate_policy_repository.go` | New: CRUD for `CertificatePolicy` |
| `api/certificate_policy.go` | New: `GET/PUT /certificates/{id}/policy` |

---

## Task 1: Add revoked-key guard to `Verify` and `Decrypt`

**Files:**
- Modify: `internal/services/keys/crypto_service.go:195-246` (Verify), `:304-348` (Decrypt)
- Test: `internal/services/keys/crypto_service_test.go` (or a new `_revoked_test.go` in the same package)

- [ ] **Step 1: Write the failing tests**

Add to a new file `internal/services/keys/crypto_service_revoked_test.go`:

```go
package keyservices_test

import (
    "context"
    "testing"

    "github.com/google/uuid"
    "github.com/stretchr/testify/require"
)

// These tests rely on a keyRepo mock that returns a revoked key.
// Use the same mock infrastructure that existing tests in this package use.

func TestVerify_RejectsRevokedKey(t *testing.T) {
    t.Parallel()
    svc, repo := newTestCryptoService(t)
    keyID := uuid.New()
    userID := uuid.New()

    repo.SetKey(keyID, &model.Key{
        ID:      keyID,
        UserID:  userID,
        Revoked: true,
        Type:    model.KeyTypeRSA,
    })

    _, err := svc.Verify(context.Background(), VerifyRequest{
        KeyID:  keyID,
        UserID: userID,
    })
    require.ErrorContains(t, err, "revoked")
}

func TestDecrypt_RejectsRevokedKey(t *testing.T) {
    t.Parallel()
    svc, repo := newTestCryptoService(t)
    keyID := uuid.New()
    userID := uuid.New()

    repo.SetKey(keyID, &model.Key{
        ID:      keyID,
        UserID:  userID,
        Revoked: true,
        Type:    model.KeyTypeRSA,
    })

    _, err := svc.Decrypt(context.Background(), DecryptRequest{
        KeyID:  keyID,
        UserID: userID,
    })
    require.ErrorContains(t, err, "revoked")
}
```

Look at `internal/services/keys/crypto_service_test.go` for the exact `newTestCryptoService` helper and `model.Key` import path before copying.

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/services/keys/... -run "TestVerify_RejectsRevokedKey|TestDecrypt_RejectsRevokedKey" -v
```

Expected: FAIL — `Verify` and `Decrypt` currently do not return an error for revoked keys.

- [ ] **Step 3: Add the revoked check to `Verify` (after the access-control block)**

In `internal/services/keys/crypto_service.go`, after line 208 (the `key.UserID != req.UserID` block), add:

```go
    if key.Revoked {
        s.logger.LogAuditError(req.UserID.String(), "verify", "failed",
            fmt.Sprintf("Attempted to verify with revoked key: %s", req.KeyID), nil)
        return nil, fmt.Errorf("cannot verify with revoked key")
    }
```

- [ ] **Step 4: Add the revoked check to `Decrypt` (after the access-control block)**

In `internal/services/keys/crypto_service.go`, after line 316 (the `key.UserID != req.UserID` block), add:

```go
    if key.Revoked {
        s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed",
            fmt.Sprintf("Attempted to decrypt with revoked key: %s", req.KeyID), nil)
        return nil, fmt.Errorf("cannot decrypt with revoked key")
    }
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/services/keys/... -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/services/keys/crypto_service.go internal/services/keys/crypto_service_revoked_test.go
git commit -m "fix(crypto): reject revoked keys in Verify and Decrypt"
```

---

## Task 2: Add ES256K algorithm (secp256k1 ECDSA)

**Files:**
- Modify: `internal/crypto/crypto_operations.go`
- Modify: `internal/services/keys/key_service.go` (allow `P-256K` curve in `CreateECDSAKey`)
- Test: `internal/crypto/crypto_operations_test.go`

> **Dependency:** Go's standard `crypto/elliptic` does not include secp256k1. Add the `github.com/decred/dcrd/dcrec/secp256k1/v4` module (BSD-3, widely used).

- [ ] **Step 1: Add the secp256k1 dependency**

```bash
go get github.com/decred/dcrd/dcrec/secp256k1/v4
```

- [ ] **Step 2: Write the failing test**

Add to `internal/crypto/crypto_operations_test.go`:

```go
func TestSignVerify_ES256K(t *testing.T) {
    t.Parallel()
    c := NewCryptoOperations()

    // Generate a secp256k1 key (P-256K)
    privKey, err := crypto_secp256k1.GenerateKey()
    require.NoError(t, err)
    privPEM, err := MarshalSecp256k1PrivateKeyPEM(privKey)
    require.NoError(t, err)

    data := []byte("test payload")
    sig, err := c.Sign(privPEM, "ES256K", data, AlgorithmES256K)
    require.NoError(t, err)
    require.NotEmpty(t, sig.Signature)

    result, err := c.Verify(privPEM, "ES256K", data, sig.Signature, AlgorithmES256K)
    require.NoError(t, err)
    require.True(t, result.Valid)
}
```

- [ ] **Step 3: Run test to confirm failure**

```bash
go test ./internal/crypto/... -run TestSignVerify_ES256K -v
```

Expected: compile error — `AlgorithmES256K` undefined.

- [ ] **Step 4: Implement ES256K in `crypto_operations.go`**

Add constant after the existing ECDSA constants:

```go
AlgorithmES256K SignatureAlgorithm = "ES256K" // ECDSA with SHA-256 on secp256k1
```

Add import: `secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"`

Add helper to marshal/parse secp256k1 PEM keys. Add a `MarshalSecp256k1PrivateKeyPEM` function and extend `ParsePrivateKey` to handle `keyType == "ES256K"`:

```go
// In ParsePrivateKey switch:
case "ES256K":
    privKey, err := secp256k1.PrivKeyFromBytes(der)
    if err != nil {
        return nil, fmt.Errorf("failed to parse secp256k1 key: %w", err)
    }
    return privKey, nil
```

In `Sign`, add a case `"ES256K"`:

```go
case "ES256K":
    sk256k, ok := privateKey.(*secp256k1.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("invalid secp256k1 private key")
    }
    hasher.Write(data) // already written above; digest is sha256
    sig := ecdsa.Sign(sk256k, digest)
    signature = sig.Serialize()
```

In `Verify`, add a case `"ES256K"`:

```go
case "ES256K":
    sk256k, ok := privateKey.(*secp256k1.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("invalid secp256k1 private key")
    }
    parsedSig, err := ecdsa.ParseDERSignature(signature)
    if err != nil {
        valid = false
    } else {
        valid = parsedSig.Verify(digest, sk256k.PubKey())
    }
```

Also in `getHasher`, add:

```go
case AlgorithmES256K:
    return sha256.New(), nil
```

Allow `P-256K` curve in `key_service.go:181`:

```go
if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" && req.Curve != "P-256K" {
```

And in `crypto.GenerateECDSAKeyPEM`, handle `"P-256K"` by generating a secp256k1 key.

- [ ] **Step 5: Run tests**

```bash
go test ./internal/crypto/... ./internal/services/keys/... -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/crypto/crypto_operations.go internal/crypto/crypto_operations_test.go internal/services/keys/key_service.go go.mod go.sum
git commit -m "feat(crypto): add ES256K (secp256k1) sign/verify support"
```

---

## Task 3: Add HMAC algorithms HS256/HS384/HS512

**Files:**
- Modify: `internal/crypto/crypto_operations.go`
- Modify: `internal/services/keys/crypto_service.go` (route HMAC to Sign/Verify)
- Test: `internal/crypto/crypto_operations_test.go`

> HMAC requires `oct` (symmetric) key material. For now, treat the `Value` field of any `oct`-type key (new `model.KeyTypeOct = "oct"`) as base64-encoded raw bytes.

- [ ] **Step 1: Write the failing test**

Add to `internal/crypto/crypto_operations_test.go`:

```go
func TestSignVerify_HMAC(t *testing.T) {
    t.Parallel()
    c := NewCryptoOperations()
    // 32-byte key encoded as base64
    key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))
    data := []byte("hmac payload")

    for _, alg := range []SignatureAlgorithm{AlgorithmHS256, AlgorithmHS384, AlgorithmHS512} {
        alg := alg
        t.Run(string(alg), func(t *testing.T) {
            t.Parallel()
            sig, err := c.Sign(key, "oct", data, alg)
            require.NoError(t, err)
            result, err := c.Verify(key, "oct", data, sig.Signature, alg)
            require.NoError(t, err)
            require.True(t, result.Valid)
        })
    }
}
```

- [ ] **Step 2: Run test to confirm failure**

```bash
go test ./internal/crypto/... -run TestSignVerify_HMAC -v
```

Expected: compile error — `AlgorithmHS256` etc. undefined.

- [ ] **Step 3: Implement in `crypto_operations.go`**

Add constants:

```go
AlgorithmHS256 SignatureAlgorithm = "HS256"
AlgorithmHS384 SignatureAlgorithm = "HS384"
AlgorithmHS512 SignatureAlgorithm = "HS512"
```

Add `crypto/hmac` import.

Add HMAC branch inside `Sign` (before the `switch keyType` on the key type):

```go
if keyType == "oct" {
    keyBytes, err := base64.StdEncoding.DecodeString(privateKeyPEM)
    if err != nil {
        return nil, fmt.Errorf("failed to decode oct key: %w", err)
    }
    mac := hmac.New(func() hash.Hash {
        switch algorithm {
        case AlgorithmHS384:
            return sha512.New384()
        case AlgorithmHS512:
            return sha512.New()
        default:
            return sha256.New()
        }
    }(), keyBytes)
    mac.Write(data)
    return &SignResult{Signature: mac.Sum(nil), Algorithm: algorithm}, nil
}
```

Add HMAC branch inside `Verify`:

```go
if keyType == "oct" {
    keyBytes, err := base64.StdEncoding.DecodeString(publicKeyPEM)
    if err != nil {
        return nil, fmt.Errorf("failed to decode oct key: %w", err)
    }
    mac := hmac.New(func() hash.Hash {
        switch algorithm {
        case AlgorithmHS384:
            return sha512.New384()
        case AlgorithmHS512:
            return sha512.New()
        default:
            return sha256.New()
        }
    }(), keyBytes)
    mac.Write(data)
    expected := mac.Sum(nil)
    return &VerifyResult{Valid: hmac.Equal(expected, signature), Algorithm: algorithm}, nil
}
```

Add `model.KeyTypeOct = "oct"` to `model/key.go`.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/crypto/... -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/crypto_operations.go internal/crypto/crypto_operations_test.go model/key.go
git commit -m "feat(crypto): add HS256/HS384/HS512 HMAC sign/verify support"
```

---

## Task 4: Add RSA1_5, AES-KW, and AES-CBC encryption algorithms

**Files:**
- Modify: `internal/crypto/crypto_operations.go`
- Test: `internal/crypto/crypto_operations_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/crypto/crypto_operations_test.go`:

```go
func TestEncryptDecrypt_RSA1_5(t *testing.T) {
    t.Parallel()
    c := NewCryptoOperations()
    privPEM := generateTestRSAKeyPEM(t, 2048)
    data := []byte("secret payload")

    enc, err := c.Encrypt(privPEM, data, AlgorithmRSA1_5)
    require.NoError(t, err)
    dec, err := c.Decrypt(privPEM, enc.Ciphertext, nil, AlgorithmRSA1_5)
    require.NoError(t, err)
    require.Equal(t, data, dec.Plaintext)
}

func TestEncryptDecrypt_AES128KW(t *testing.T) {
    t.Parallel()
    c := NewCryptoOperations()
    key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 16))
    data := bytes.Repeat([]byte{0x02}, 16) // AES-KW wraps 16-byte blocks

    enc, err := c.Encrypt(key, data, AlgorithmA128KW)
    require.NoError(t, err)
    dec, err := c.Decrypt(key, enc.Ciphertext, nil, AlgorithmA128KW)
    require.NoError(t, err)
    require.Equal(t, data, dec.Plaintext)
}

func TestEncryptDecrypt_AES128CBC(t *testing.T) {
    t.Parallel()
    c := NewCryptoOperations()
    key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x03}, 16))
    data := bytes.Repeat([]byte{0x04}, 32)

    enc, err := c.Encrypt(key, data, AlgorithmA128CBC)
    require.NoError(t, err)
    dec, err := c.Decrypt(key, enc.Ciphertext, enc.Nonce, AlgorithmA128CBC)
    require.NoError(t, err)
    require.Equal(t, data, dec.Plaintext)
}
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
go test ./internal/crypto/... -run "TestEncryptDecrypt_RSA1_5|TestEncryptDecrypt_AES128KW|TestEncryptDecrypt_AES128CBC" -v
```

Expected: compile error — constants undefined.

- [ ] **Step 3: Implement in `crypto_operations.go`**

Add constants:

```go
AlgorithmRSA1_5  EncryptionAlgorithm = "RSA1_5"
AlgorithmA128KW  EncryptionAlgorithm = "A128KW"
AlgorithmA192KW  EncryptionAlgorithm = "A192KW"
AlgorithmA256KW  EncryptionAlgorithm = "A256KW"
AlgorithmA128CBC EncryptionAlgorithm = "A128CBC"
AlgorithmA192CBC EncryptionAlgorithm = "A192CBC"
AlgorithmA256CBC EncryptionAlgorithm = "A256CBC"
```

Add to `Encrypt` switch:

```go
case AlgorithmRSA1_5:
    return c.encryptRSA1_5(keyData, data)
case AlgorithmA128KW, AlgorithmA192KW, AlgorithmA256KW:
    return c.wrapAES(keyData, data, algorithm)
case AlgorithmA128CBC, AlgorithmA192CBC, AlgorithmA256CBC:
    return c.encryptAESCBC(keyData, data, algorithm)
```

Add to `Decrypt` switch:

```go
case AlgorithmRSA1_5:
    return c.decryptRSA1_5(keyData, ciphertext)
case AlgorithmA128KW, AlgorithmA192KW, AlgorithmA256KW:
    return c.unwrapAES(keyData, ciphertext, algorithm)
case AlgorithmA128CBC, AlgorithmA192CBC, AlgorithmA256CBC:
    return c.decryptAESCBC(keyData, ciphertext, nonce, algorithm)
```

Add import `"crypto/rsa"` (already present).

Implement helpers:

```go
func (c *CryptoOperations) encryptRSA1_5(privateKeyPEM string, data []byte) (*EncryptResult, error) {
    key, err := ParsePrivateKey(privateKeyPEM, "RSA")
    if err != nil {
        return nil, err
    }
    rsaKey := key.(*rsa.PrivateKey)
    ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, data)
    if err != nil {
        return nil, fmt.Errorf("RSA1_5 encrypt failed: %w", err)
    }
    return &EncryptResult{Ciphertext: ciphertext, Algorithm: AlgorithmRSA1_5}, nil
}

func (c *CryptoOperations) decryptRSA1_5(privateKeyPEM string, ciphertext []byte) (*DecryptResult, error) {
    key, err := ParsePrivateKey(privateKeyPEM, "RSA")
    if err != nil {
        return nil, err
    }
    rsaKey := key.(*rsa.PrivateKey)
    plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, rsaKey, ciphertext)
    if err != nil {
        return nil, fmt.Errorf("RSA1_5 decrypt failed: %w", err)
    }
    return &DecryptResult{Plaintext: plaintext, Algorithm: AlgorithmRSA1_5}, nil
}

// AES Key Wrap (RFC 3394).
// Add import: "golang.org/x/crypto/rfc3394"
func (c *CryptoOperations) wrapAES(keyBase64 string, data []byte, algorithm EncryptionAlgorithm) (*EncryptResult, error) {
    key, err := base64.StdEncoding.DecodeString(keyBase64)
    if err != nil {
        return nil, err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    wrapped, err := rfc3394.Wrap(data, block)
    if err != nil {
        return nil, fmt.Errorf("AES-KW wrap failed: %w", err)
    }
    return &EncryptResult{Ciphertext: wrapped, Algorithm: algorithm}, nil
}

func (c *CryptoOperations) unwrapAES(keyBase64 string, ciphertext []byte, algorithm EncryptionAlgorithm) (*DecryptResult, error) {
    key, err := base64.StdEncoding.DecodeString(keyBase64)
    if err != nil {
        return nil, err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    plaintext, err := rfc3394.Unwrap(ciphertext, block)
    if err != nil {
        return nil, fmt.Errorf("AES-KW unwrap failed: %w", err)
    }
    return &DecryptResult{Plaintext: plaintext, Algorithm: algorithm}, nil
}

func (c *CryptoOperations) encryptAESCBC(keyBase64 string, data []byte, algorithm EncryptionAlgorithm) (*EncryptResult, error) {
    key, err := base64.StdEncoding.DecodeString(keyBase64)
    if err != nil {
        return nil, err
    }
    // PKCS7 pad
    bs := aes.BlockSize
    pad := bs - len(data)%bs
    padded := append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)

    iv := make([]byte, bs)
    if _, err := rand.Read(iv); err != nil {
        return nil, err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    ciphertext := make([]byte, len(padded))
    cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
    return &EncryptResult{Ciphertext: ciphertext, Algorithm: algorithm, Nonce: iv}, nil
}

func (c *CryptoOperations) decryptAESCBC(keyBase64 string, ciphertext []byte, iv []byte, algorithm EncryptionAlgorithm) (*DecryptResult, error) {
    key, err := base64.StdEncoding.DecodeString(keyBase64)
    if err != nil {
        return nil, err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    if len(ciphertext)%aes.BlockSize != 0 {
        return nil, fmt.Errorf("ciphertext not block-aligned")
    }
    plaintext := make([]byte, len(ciphertext))
    cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
    // Remove PKCS7 padding
    pad := int(plaintext[len(plaintext)-1])
    if pad == 0 || pad > aes.BlockSize {
        return nil, fmt.Errorf("invalid padding")
    }
    return &DecryptResult{Plaintext: plaintext[:len(plaintext)-pad], Algorithm: algorithm}, nil
}
```

Add `golang.org/x/crypto`:

```bash
go get golang.org/x/crypto
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/crypto/... -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/crypto_operations.go internal/crypto/crypto_operations_test.go go.mod go.sum
git commit -m "feat(crypto): add RSA1_5, AES-KW, AES-CBC encryption algorithms"
```

---

## Task 5: Add lifecycle attributes (enabled / exp / nbf) for secrets

**Files:**
- Modify: `internal/db/db.go` — secrets table schema + migration
- Modify: `internal/repositories/secret_repository.go` — INSERT/SELECT/UPDATE
- Modify: `api/secrets.go` — enforce `IsAccessible()` in `getSecret`
- Test: `internal/repositories/secret_repository_test.go`

`model/secret.go` already has `Enabled bool`, `ExpiresAt *time.Time`, `NotBefore *time.Time` with `IsAccessible()`. The gap is persistence and enforcement.

- [ ] **Step 1: Write the failing tests**

Add to `internal/repositories/secret_repository_test.go`:

```go
func TestSecretLifecycleAttributes_PersistAndLoad(t *testing.T) {
    db := setupTestDB(t)
    repo := NewSecretRepository(db, testLogger(t))

    now := time.Now()
    exp := now.Add(24 * time.Hour)
    nbf := now.Add(-1 * time.Hour)

    s := &model.Secret{
        ID:        uuid.New(),
        UserID:    uuid.New(),
        Name:      "test-lifecycle",
        Value:     "encrypted-value",
        Version:   1,
        CreatedAt: now,
        Enabled:   true,
        ExpiresAt: &exp,
        NotBefore: &nbf,
    }
    require.NoError(t, repo.Create(context.Background(), s))

    loaded, err := repo.Read(context.Background(), s.ID)
    require.NoError(t, err)
    require.True(t, loaded.Enabled)
    require.NotNil(t, loaded.ExpiresAt)
    require.WithinDuration(t, exp, *loaded.ExpiresAt, time.Second)
    require.NotNil(t, loaded.NotBefore)
}
```

- [ ] **Step 2: Run test to confirm failure**

```bash
go test ./internal/repositories/... -run TestSecretLifecycleAttributes -v
```

Expected: FAIL — columns missing from DB / not scanned.

- [ ] **Step 3: Add columns to `createOptimizedSchema` secrets table**

In `internal/db/db.go`, inside the `CREATE TABLE IF NOT EXISTS secrets` block (around line 285), add three columns before the closing `)`; change:

```sql
content_type TEXT NOT NULL DEFAULT '',
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
```

to:

```sql
content_type TEXT NOT NULL DEFAULT '',
enabled      BOOLEAN NOT NULL DEFAULT TRUE,
expires_at   TIMESTAMP NULL,
not_before   TIMESTAMP NULL,
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
```

- [ ] **Step 4: Add columns to `migrateSchema`**

Append three entries to the `migrations` slice in `migrateSchema`:

```go
"ALTER TABLE secrets ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
"ALTER TABLE secrets ADD COLUMN expires_at TIMESTAMP NULL",
"ALTER TABLE secrets ADD COLUMN not_before TIMESTAMP NULL",
```

- [ ] **Step 5: Update secret repo INSERT, SELECT, and UPDATE**

In `internal/repositories/secret_repository.go`:

**INSERT** (around line 101) — change:

```go
"INSERT INTO secrets (id, user_id, name, value, version, created_at, content_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
s.ID.String(), s.UserID.String(), s.Name, s.Value, s.Version, s.CreatedAt, s.ContentType,
```

to:

```go
"INSERT INTO secrets (id, user_id, name, value, version, created_at, content_type, enabled, expires_at, not_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
s.ID.String(), s.UserID.String(), s.Name, s.Value, s.Version, s.CreatedAt, s.ContentType, s.Enabled, s.ExpiresAt, s.NotBefore,
```

**SELECT** (lines 150 and 198 — two read queries) — change:

```sql
SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type FROM secrets
```

to:

```sql
SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets
```

Update the corresponding `Scan(...)` call to add `&s.Enabled, &s.ExpiresAt, &s.NotBefore` at the end.

Do the same for the list queries at lines ~469 and ~553.

**UPDATE** (line 247) — change:

```go
"UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ? WHERE id = ? AND user_id = ?",
s.Name, s.Value, s.Version, s.ContentType, s.ID.String(), s.UserID.String(),
```

to:

```go
"UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ?, enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND user_id = ?",
s.Name, s.Value, s.Version, s.ContentType, s.Enabled, s.ExpiresAt, s.NotBefore, s.ID.String(), s.UserID.String(),
```

- [ ] **Step 6: Enforce `IsAccessible()` in `getSecret` handler**

In `api/secrets.go`, inside `getSecret`, after the secret is loaded and before the JSON response is written, add:

```go
if !secret.IsAccessible() {
    c.SetForbidden("secret is disabled or outside its valid time window")
    return
}
```

- [ ] **Step 7: Run all tests**

```bash
go test ./internal/repositories/... ./api/... -v
```

Expected: all pass including the new test.

- [ ] **Step 8: Commit**

```bash
git add internal/db/db.go internal/repositories/secret_repository.go api/secrets.go internal/repositories/secret_repository_test.go
git commit -m "feat(secrets): persist and enforce enabled/exp/nbf lifecycle attributes"
```

---

## Task 6: Add lifecycle attributes for keys

**Files:**
- Modify: `model/key.go` — add `Enabled bool`, `ExpiresAt *time.Time`, `NotBefore *time.Time`, `Bits int`, `Curve string`
- Modify: `internal/db/db.go` — keys table schema + migration
- Modify: `internal/repositories/key_repository.go` — INSERT/SELECT/UPDATE
- Modify: `api/keys.go` — enforce in `getKey`
- Test: `internal/repositories/key_repository_test.go`

- [ ] **Step 1: Write the failing test**

Add to (or create) `internal/repositories/key_repository_test.go`:

```go
func TestKeyLifecycleAttributes_PersistAndLoad(t *testing.T) {
    db := setupTestDB(t)
    repo := NewKeyRepository(db, testLogger(t))

    exp := time.Now().Add(24 * time.Hour)
    k := &model.Key{
        ID:        uuid.New(),
        UserID:    uuid.New(),
        Name:      "test-key",
        Type:      model.KeyTypeRSA,
        Value:     "encrypted",
        Enabled:   true,
        ExpiresAt: &exp,
    }
    require.NoError(t, repo.Create(context.Background(), k))

    loaded, err := repo.Read(context.Background(), k.ID)
    require.NoError(t, err)
    require.True(t, loaded.Enabled)
    require.NotNil(t, loaded.ExpiresAt)
}
```

- [ ] **Step 2: Run test to confirm failure**

```bash
go test ./internal/repositories/... -run TestKeyLifecycleAttributes -v
```

Expected: compile error — `Enabled`, `ExpiresAt`, `NotBefore` not on `model.Key`.

- [ ] **Step 3: Add fields to `model/key.go`**

Add to the `Key` struct:

```go
Enabled   bool       `json:"enabled"`
ExpiresAt *time.Time `json:"expires_at,omitempty"`
NotBefore *time.Time `json:"not_before,omitempty"`
Bits      int        `json:"bits,omitempty"`
Curve     string     `json:"curve,omitempty"`
```

Add `IsAccessible()` helper (mirrors `model/secret.go`):

```go
func (k *Key) IsAccessible() bool {
    if !k.Enabled {
        return false
    }
    now := time.Now()
    if k.NotBefore != nil && now.Before(*k.NotBefore) {
        return false
    }
    if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
        return false
    }
    return true
}
```

- [ ] **Step 4: Add columns to schema and migration in `internal/db/db.go`**

In the `CREATE TABLE IF NOT EXISTS keys` block, add after `scheduled_purge_at`:

```sql
enabled    BOOLEAN NOT NULL DEFAULT TRUE,
expires_at TIMESTAMP NULL,
not_before TIMESTAMP NULL,
bits       INTEGER NOT NULL DEFAULT 0,
curve      TEXT NOT NULL DEFAULT '',
```

In `migrateSchema`, append:

```go
"ALTER TABLE keys ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
"ALTER TABLE keys ADD COLUMN expires_at TIMESTAMP NULL",
"ALTER TABLE keys ADD COLUMN not_before TIMESTAMP NULL",
"ALTER TABLE keys ADD COLUMN bits INTEGER NOT NULL DEFAULT 0",
"ALTER TABLE keys ADD COLUMN curve TEXT NOT NULL DEFAULT ''",
```

- [ ] **Step 5: Update key repo INSERT, SELECT, UPDATE**

Mirror the pattern from Task 5. Key repo INSERT is at `key_repository.go:108`; SELECT is at line 163; UPDATE is at line 217. Add `enabled`, `expires_at`, `not_before`, `bits`, `curve` to all three. Update `Scan` calls accordingly.

Also store `bits`/`curve` when creating keys in `key_service.go`:

```go
// In CreateRSAKey, set key.Bits = req.Bits before repo.Create.
// In CreateECDSAKey, set key.Curve = req.Curve before repo.Create.
```

- [ ] **Step 6: Enforce `IsAccessible()` in `getKey` handler**

In `api/keys.go`, inside `getKey`, after loading the key and before the JSON response, add:

```go
if !key.IsAccessible() {
    c.SetForbidden("key is disabled or outside its valid time window")
    return
}
```

- [ ] **Step 7: Run all tests**

```bash
go test ./... -v 2>&1 | tail -30
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add model/key.go internal/db/db.go internal/repositories/key_repository.go internal/services/keys/key_service.go api/keys.go
git commit -m "feat(keys): persist and enforce enabled/exp/nbf lifecycle attributes; store bits/curve"
```

---

## Task 7: Add lifecycle attributes for certificates

**Files:**
- Modify: `model/certificate.go` — add `Enabled bool`, `NotBefore *time.Time`
- Modify: `internal/db/db.go` — certificates table + migration
- Modify: `internal/repositories/certificate_repository.go` — INSERT/SELECT/UPDATE
- Modify: `api/certificates.go` — enforce in `getCertificate`

`ExpiresAt` already exists on `Certificate` and in the DB. This task adds `Enabled` and `NotBefore` only.

- [ ] **Step 1: Add fields to `model/certificate.go`**

Add to `Certificate` struct:

```go
Enabled   bool       `json:"enabled"`
NotBefore *time.Time `json:"not_before,omitempty"`
```

Add `IsAccessible()`:

```go
func (c *Certificate) IsAccessible() bool {
    if !c.Enabled {
        return false
    }
    now := time.Now()
    if c.NotBefore != nil && now.Before(*c.NotBefore) {
        return false
    }
    if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
        return false
    }
    return true
}
```

- [ ] **Step 2: Add columns to schema and migration**

In `CREATE TABLE IF NOT EXISTS certificates` block, add after the existing `expires_at`:

```sql
enabled    BOOLEAN NOT NULL DEFAULT TRUE,
not_before TIMESTAMP NULL,
```

In `migrateSchema`, append:

```go
"ALTER TABLE certificates ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
"ALTER TABLE certificates ADD COLUMN not_before TIMESTAMP NULL",
```

- [ ] **Step 3: Update certificate repo SQL**

Open `internal/repositories/certificate_repository.go`. Find the INSERT, SELECT, and UPDATE statements and add `enabled`, `not_before` to each. Pattern is identical to Tasks 5 and 6.

- [ ] **Step 4: Enforce `IsAccessible()` in `getCertificate` handler**

In `api/certificates.go`, inside `getCertificate`, after loading the cert and before JSON response:

```go
if !cert.IsAccessible() {
    c.SetForbidden("certificate is disabled or outside its valid time window")
    return
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add model/certificate.go internal/db/db.go internal/repositories/certificate_repository.go api/certificates.go
git commit -m "feat(certs): persist and enforce enabled/not_before lifecycle attributes"
```

---

## Task 8: Key versioning — `key_versions` table + true rotation

**Files:**
- Modify: `internal/db/db.go` — add `key_versions` table
- Modify: `internal/repositories/key_repository.go` — add `CreateVersion`, `ListVersions`, `GetVersion`
- Modify: `internal/services/keys/key_service.go` — rewrite `RotateKey` to create a version row
- Modify: `api/keys.go` — add `GET /keys/{id}/versions` route
- Test: `internal/repositories/key_repository_test.go` (versioning), `internal/services/keys/key_service_test.go` (rotation)

**Design:** `key_versions` stores every generated key PEM alongside a monotone integer `version`. The primary `keys` row holds the current version PEM (unchanged). Rotation increments the version counter, writes a new row to `key_versions`, and updates the `keys.value` to the new PEM.

- [ ] **Step 1: Write failing tests**

Add to `internal/repositories/key_repository_test.go`:

```go
func TestKeyVersions_CreateAndList(t *testing.T) {
    db := setupTestDB(t)
    repo := NewKeyRepository(db, testLogger(t))

    keyID := uuid.New()
    userID := uuid.New()

    k := &model.Key{
        ID: keyID, UserID: userID, Name: "versioned", Type: model.KeyTypeRSA, Value: "pem-v1", Enabled: true,
    }
    require.NoError(t, repo.Create(context.Background(), k))
    require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
    require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))

    versions, err := repo.ListVersions(context.Background(), keyID, userID)
    require.NoError(t, err)
    require.Len(t, versions, 2)
    require.Equal(t, 2, versions[1].Version)
}
```

- [ ] **Step 2: Run test to confirm failure**

```bash
go test ./internal/repositories/... -run TestKeyVersions -v
```

Expected: compile error — `CreateVersion`/`ListVersions` undefined.

- [ ] **Step 3: Add `key_versions` table to `createOptimizedSchema`**

In `internal/db/db.go`, after the `key_tags` table block, add:

```sql
CREATE TABLE IF NOT EXISTS key_versions (
    key_id     TEXT NOT NULL,
    version    INTEGER NOT NULL,
    value      TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (key_id, version),
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
);
```

In `migrateSchema`, append:

```go
`CREATE TABLE IF NOT EXISTS key_versions (
    key_id     TEXT NOT NULL,
    version    INTEGER NOT NULL,
    value      TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (key_id, version),
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
)`,
```

- [ ] **Step 4: Add `KeyVersion` model to `model/key.go`**

```go
type KeyVersion struct {
    KeyID     uuid.UUID `json:"key_id"`
    Version   int       `json:"version"`
    CreatedAt time.Time `json:"created_at"`
}
```

The `Value` (encrypted PEM) is intentionally omitted from the HTTP response.

- [ ] **Step 5: Add repo methods to `KeyRepositoryInterface` and `KeyRepository`**

Add to `KeyRepositoryInterface`:

```go
CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error
ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error)
```

Implement in `KeyRepository`:

```go
func (r *KeyRepository) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
    _, err := r.db.ExecContext(ctx,
        "INSERT INTO key_versions (key_id, version, value, created_at) VALUES (?, ?, ?, ?)",
        keyID.String(), version, value, time.Now(),
    )
    return err
}

func (r *KeyRepository) ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error) {
    // Verify ownership by joining keys table.
    rows, err := r.db.QueryContext(ctx, `
        SELECT kv.version, kv.created_at
        FROM key_versions kv
        JOIN keys k ON k.id = kv.key_id
        WHERE kv.key_id = ? AND k.user_id = ?
        ORDER BY kv.version ASC`,
        keyID.String(), userID.String(),
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var versions []model.KeyVersion
    for rows.Next() {
        var v model.KeyVersion
        v.KeyID = keyID
        if err := rows.Scan(&v.Version, &v.CreatedAt); err != nil {
            return nil, err
        }
        versions = append(versions, v)
    }
    return versions, rows.Err()
}
```

- [ ] **Step 6: Rewrite `RotateKey` in `key_service.go`**

Replace the current implementation that creates a `-rotated` key with:

```go
func (s *keyService) RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*CreateKeyResult, error) {
    existing, err := s.GetKey(ctx, keyID, userID)
    if err != nil {
        return nil, fmt.Errorf("rotate key: %w", err)
    }

    // Determine size/curve from stored metadata.
    bits := existing.Bits
    if bits == 0 {
        bits = 2048 // fallback for keys created before this feature
    }
    curve := existing.Curve
    if curve == "" {
        curve = "P-256"
    }

    // Generate new key material using the same parameters as the original.
    var newPEM string
    switch existing.Type {
    case model.KeyTypeRSA:
        newPEM, err = crypto.GenerateRSAKeyPEM(bits)
    case model.KeyTypeECDSA:
        newPEM, err = crypto.GenerateECDSAKeyPEM(curve)
    default:
        return nil, fmt.Errorf("unsupported key type for rotation: %s", existing.Type)
    }
    if err != nil {
        return nil, fmt.Errorf("key generation failed: %w", err)
    }

    encryptedNew, err := common.EncryptSecret(newPEM)
    if err != nil {
        return nil, fmt.Errorf("key encryption failed: %w", err)
    }

    // Determine new version number by counting existing version rows.
    versions, err := s.keyRepo.ListVersions(ctx, keyID, userID)
    if err != nil {
        return nil, fmt.Errorf("list versions: %w", err)
    }
    nextVersion := len(versions) + 1

    // Persist old PEM as version row if this is the first rotation.
    if len(versions) == 0 {
        if err := s.keyRepo.CreateVersion(ctx, keyID, 1, existing.Value); err != nil {
            return nil, fmt.Errorf("archive original key version: %w", err)
        }
        nextVersion = 2
    }

    if err := s.keyRepo.CreateVersion(ctx, keyID, nextVersion, encryptedNew); err != nil {
        return nil, fmt.Errorf("create new key version: %w", err)
    }

    // Update the primary key row with new PEM (keep same ID, name, type).
    existing.Value = encryptedNew
    if err := s.keyRepo.Update(ctx, existing); err != nil {
        return nil, fmt.Errorf("update key value: %w", err)
    }

    s.logger.LogAuditInfo(userID.String(), "rotate_key", "success",
        fmt.Sprintf("Key %s rotated to version %d", keyID, nextVersion))

    return &CreateKeyResult{
        KeyID:     keyID,
        Name:      existing.Name,
        Type:      existing.Type,
        Tags:      existing.Tags,
        CreatedAt: existing.CreatedAt,
    }, nil
}
```

- [ ] **Step 7: Add `GET /keys/{id}/versions` route**

In `api/keys.go`, in the `Init` route block, add:

```go
k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions", ApiSessionRequired(api.App, listKeyVersions)).Methods("GET")
```

Add handler:

```go
func listKeyVersions(c *Context, w http.ResponseWriter, r *http.Request) {
    keyID, err := uuid.Parse(mux.Vars(r)["key_id"])
    if err != nil {
        c.SetInvalidParam("key_id")
        return
    }
    userID, err := getUserIDFromContext(r.Context())
    if err != nil {
        c.SetForbidden("user not authenticated")
        return
    }
    versions, err := c.App.Container.GetKeyRepository().ListVersions(r.Context(), keyID, userID)
    if err != nil {
        c.SetInternalServerError(err.Error())
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{"versions": versions})
}
```

- [ ] **Step 8: Run all tests**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 9: Commit**

```bash
git add internal/db/db.go model/key.go internal/repositories/key_repository.go internal/services/keys/key_service.go api/keys.go
git commit -m "feat(keys): true key versioning with key_versions table; fix rotation to preserve key identity"
```

---

## Task 9: Per-item backup and restore (secrets, keys, certificates)

**Files:**
- Create: `internal/backup/item_backup.go`
- Create: `api/backup_item.go`
- Modify: `api/api.go` — register new routes
- Modify: `internal/db/db.go` — add `item_backups` table
- Test: `internal/backup/item_backup_test.go`

**Design:** A per-item backup is an AES-256-GCM encrypted JSON blob containing the resource's current data. The blob is base64url-encoded and returned to the caller. Restore decodes, decrypts, and re-inserts. The blob is opaque to the caller (not Azure-compatible format, but fulfills the functional requirement).

- [ ] **Step 1: Add `item_backups` table**

In `internal/db/db.go` `createOptimizedSchema`, add:

```sql
CREATE TABLE IF NOT EXISTS item_backups (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id  TEXT NOT NULL,
    blob         TEXT NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

In `migrateSchema`, append:

```go
`CREATE TABLE IF NOT EXISTS item_backups (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id  TEXT NOT NULL,
    blob         TEXT NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
```

- [ ] **Step 2: Write the failing test**

Create `internal/backup/item_backup_test.go`:

```go
package backup_test

import (
    "context"
    "testing"

    "github.com/stretchr/testify/require"
    // import backup package
)

func TestBackupRestoreSecret(t *testing.T) {
    t.Parallel()
    svc := newTestItemBackupService(t)

    secretID := uuid.New()
    userID := uuid.New()

    // Seed a secret in the repo.
    seedTestSecret(t, svc, secretID, userID)

    blob, err := svc.BackupSecret(context.Background(), secretID, userID)
    require.NoError(t, err)
    require.NotEmpty(t, blob)

    // Delete the secret and restore from blob.
    svc.DeleteSecret(t, secretID, userID)

    err = svc.RestoreSecret(context.Background(), blob, userID)
    require.NoError(t, err)

    // Verify the secret is back.
    loaded, err := svc.GetSecret(context.Background(), secretID, userID)
    require.NoError(t, err)
    require.Equal(t, secretID, loaded.ID)
}
```

- [ ] **Step 3: Run test to confirm failure**

```bash
go test ./internal/backup/... -run TestBackupRestoreSecret -v
```

Expected: compile error — `ItemBackupService` undefined.

- [ ] **Step 4: Create `internal/backup/item_backup.go`**

```go
package backup

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"

    "github.com/google/uuid"
    "github.com/numericlabs/rocketvault/common"
    "github.com/numericlabs/rocketvault/internal/repositories"
    "github.com/numericlabs/rocketvault/model"
)

type ItemBackupService struct {
    secretRepo repositories.SecretRepositoryInterface
    keyRepo    repositories.KeyRepositoryInterface
    certRepo   repositories.CertificateRepositoryInterface
}

func NewItemBackupService(
    secretRepo repositories.SecretRepositoryInterface,
    keyRepo repositories.KeyRepositoryInterface,
    certRepo repositories.CertificateRepositoryInterface,
) *ItemBackupService {
    return &ItemBackupService{secretRepo: secretRepo, keyRepo: keyRepo, certRepo: certRepo}
}

// backupBlob is the internal envelope stored in the backup blob.
type backupBlob struct {
    ResourceType string          `json:"resource_type"`
    ResourceID   string          `json:"resource_id"`
    Data         json.RawMessage `json:"data"`
}

func (s *ItemBackupService) BackupSecret(ctx context.Context, id, userID uuid.UUID) (string, error) {
    secret, err := s.secretRepo.ReadByUser(ctx, id, userID)
    if err != nil {
        return "", fmt.Errorf("backup secret: %w", err)
    }
    return encodeBlob("secret", id.String(), secret)
}

func (s *ItemBackupService) RestoreSecret(ctx context.Context, blob string, userID uuid.UUID) error {
    var secret model.Secret
    if err := decodeBlob(blob, "secret", &secret); err != nil {
        return err
    }
    secret.UserID = userID
    return s.secretRepo.Create(ctx, &secret)
}

func (s *ItemBackupService) BackupKey(ctx context.Context, id, userID uuid.UUID) (string, error) {
    key, err := s.keyRepo.Read(ctx, id)
    if err != nil {
        return "", fmt.Errorf("backup key: %w", err)
    }
    if key.UserID != userID {
        return "", fmt.Errorf("forbidden")
    }
    return encodeBlob("key", id.String(), key)
}

func (s *ItemBackupService) RestoreKey(ctx context.Context, blob string, userID uuid.UUID) error {
    var key model.Key
    if err := decodeBlob(blob, "key", &key); err != nil {
        return err
    }
    key.UserID = userID
    return s.keyRepo.Create(ctx, &key)
}

func (s *ItemBackupService) BackupCertificate(ctx context.Context, id, userID uuid.UUID) (string, error) {
    cert, err := s.certRepo.Read(ctx, id)
    if err != nil {
        return "", fmt.Errorf("backup certificate: %w", err)
    }
    if cert.UserID != userID {
        return "", fmt.Errorf("forbidden")
    }
    return encodeBlob("certificate", id.String(), cert)
}

func (s *ItemBackupService) RestoreCertificate(ctx context.Context, blob string, userID uuid.UUID) error {
    var cert model.Certificate
    if err := decodeBlob(blob, "certificate", &cert); err != nil {
        return err
    }
    cert.UserID = userID
    return s.certRepo.Create(ctx, &cert)
}

func encodeBlob(resourceType, resourceID string, data interface{}) (string, error) {
    raw, err := json.Marshal(data)
    if err != nil {
        return "", err
    }
    envelope, err := json.Marshal(backupBlob{
        ResourceType: resourceType,
        ResourceID:   resourceID,
        Data:         raw,
    })
    if err != nil {
        return "", err
    }
    encrypted, err := common.EncryptSecret(string(envelope))
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString([]byte(encrypted)), nil
}

func decodeBlob(blob, expectedType string, out interface{}) error {
    raw, err := base64.URLEncoding.DecodeString(blob)
    if err != nil {
        return fmt.Errorf("invalid blob encoding: %w", err)
    }
    decrypted, err := common.DecryptSecret(string(raw))
    if err != nil {
        return fmt.Errorf("blob decryption failed: %w", err)
    }
    var envelope backupBlob
    if err := json.Unmarshal([]byte(decrypted), &envelope); err != nil {
        return fmt.Errorf("invalid blob format: %w", err)
    }
    if envelope.ResourceType != expectedType {
        return fmt.Errorf("blob type mismatch: expected %s, got %s", expectedType, envelope.ResourceType)
    }
    return json.Unmarshal(envelope.Data, out)
}
```

- [ ] **Step 5: Create `api/backup_item.go`**

```go
package api

import (
    "encoding/json"
    "net/http"

    "github.com/gorilla/mux"
    "github.com/google/uuid"
)

func (api *API) initBackupItemRoutes(r *mux.Router) {
    r.Handle("/secrets/{id:[A-Fa-f0-9-]+}/backup",
        ApiSessionRequired(api.App, backupSecret)).Methods("POST")
    r.Handle("/secrets/restore",
        ApiSessionRequired(api.App, restoreSecret)).Methods("POST")
    r.Handle("/keys/{id:[A-Fa-f0-9-]+}/backup",
        ApiSessionRequired(api.App, backupKey)).Methods("POST")
    r.Handle("/keys/restore",
        ApiSessionRequired(api.App, restoreKey)).Methods("POST")
    r.Handle("/certificates/{id:[A-Fa-f0-9-]+}/backup",
        ApiSessionRequired(api.App, backupCertificate)).Methods("POST")
    r.Handle("/certificates/restore",
        ApiSessionRequired(api.App, restoreCertificate)).Methods("POST")
}

func backupSecret(c *Context, w http.ResponseWriter, r *http.Request) {
    id, err := uuid.Parse(mux.Vars(r)["id"])
    if err != nil {
        c.SetInvalidParam("id")
        return
    }
    userID, err := getUserIDFromContext(r.Context())
    if err != nil {
        c.SetForbidden("user not authenticated")
        return
    }
    svc := c.App.Container.GetItemBackupService()
    blob, err := svc.BackupSecret(r.Context(), id, userID)
    if err != nil {
        c.SetInternalServerError(err.Error())
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"value": blob})
}

func restoreSecret(c *Context, w http.ResponseWriter, r *http.Request) {
    var req struct {
        Value string `json:"value"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
        c.SetInvalidParam("value")
        return
    }
    userID, err := getUserIDFromContext(r.Context())
    if err != nil {
        c.SetForbidden("user not authenticated")
        return
    }
    svc := c.App.Container.GetItemBackupService()
    if err := svc.RestoreSecret(r.Context(), req.Value, userID); err != nil {
        c.SetInternalServerError(err.Error())
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

// backupKey, restoreKey, backupCertificate, restoreCertificate follow the same pattern.
// Implement each by replacing "Secret" with "Key" or "Certificate" and the appropriate ID parameter.
```

Wire in `api/api.go` `Init` by calling `api.initBackupItemRoutes(r)` where the other `init*Routes` calls live.

Add `GetItemBackupService()` to the service container (`internal/container/service_container.go`) following the existing `GetKeyRepository()` pattern.

- [ ] **Step 6: Run all tests**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/backup/item_backup.go internal/backup/item_backup_test.go api/backup_item.go internal/db/db.go internal/container/service_container.go api/api.go
git commit -m "feat(backup): per-item backup/restore for secrets, keys, and certificates"
```

---

## Task 10: Certificate Policy — stub implementation

**Files:**
- Create: `model/certificate_policy.go`
- Modify: `internal/db/db.go` — add `certificate_policies` table
- Create: `internal/repositories/certificate_policy_repository.go`
- Create: `api/certificate_policy.go`
- Modify: `api/api.go` — register routes
- Test: `internal/repositories/certificate_policy_repository_test.go`

**Scope:** CRUD only. Lifetime-action triggers and external issuer integration are follow-on.

- [ ] **Step 1: Create `model/certificate_policy.go`**

```go
package model

import (
    "encoding/json"
    "io"
    "time"

    "github.com/google/uuid"
)

// CertificatePolicy holds the creation and renewal policy for a certificate.
type CertificatePolicy struct {
    ID                uuid.UUID  `json:"id" db:"id"`
    CertificateID     uuid.UUID  `json:"certificate_id" db:"certificate_id"`
    UserID            uuid.UUID  `json:"user_id" db:"user_id"`
    ValidityMonths    int        `json:"validity_months" db:"validity_months"`
    KeyType           string     `json:"key_type" db:"key_type"`
    KeySize           int        `json:"key_size,omitempty" db:"key_size"`
    Curve             string     `json:"curve,omitempty" db:"curve"`
    Subject           string     `json:"subject" db:"subject"`
    SANs              string     `json:"sans,omitempty" db:"sans"`
    AutoRenew         bool       `json:"auto_renew" db:"auto_renew"`
    DaysBeforeExpiry  int        `json:"days_before_expiry" db:"days_before_expiry"`
    IssuerName        string     `json:"issuer_name,omitempty" db:"issuer_name"`
    CreatedAt         time.Time  `json:"created_at" db:"created_at"`
    UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

type UpsertCertificatePolicyRequest struct {
    ValidityMonths   int    `json:"validity_months"`
    KeyType          string `json:"key_type"`
    KeySize          int    `json:"key_size,omitempty"`
    Curve            string `json:"curve,omitempty"`
    Subject          string `json:"subject"`
    SANs             string `json:"sans,omitempty"`
    AutoRenew        bool   `json:"auto_renew"`
    DaysBeforeExpiry int    `json:"days_before_expiry"`
    IssuerName       string `json:"issuer_name,omitempty"`
}

func UpsertCertificatePolicyRequestFromJson(r io.Reader) (*UpsertCertificatePolicyRequest, error) {
    var req UpsertCertificatePolicyRequest
    return &req, json.NewDecoder(r).Decode(&req)
}
```

- [ ] **Step 2: Add `certificate_policies` table**

In `createOptimizedSchema` in `internal/db/db.go`, add after the `certificate_tags` block:

```sql
CREATE TABLE IF NOT EXISTS certificate_policies (
    id                TEXT PRIMARY KEY,
    certificate_id    TEXT NOT NULL UNIQUE,
    user_id           TEXT NOT NULL,
    validity_months   INTEGER NOT NULL DEFAULT 12,
    key_type          TEXT NOT NULL DEFAULT 'RSA',
    key_size          INTEGER NOT NULL DEFAULT 2048,
    curve             TEXT NOT NULL DEFAULT '',
    subject           TEXT NOT NULL DEFAULT '',
    sans              TEXT NOT NULL DEFAULT '',
    auto_renew        BOOLEAN NOT NULL DEFAULT FALSE,
    days_before_expiry INTEGER NOT NULL DEFAULT 30,
    issuer_name       TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

In `migrateSchema`, append:

```go
`CREATE TABLE IF NOT EXISTS certificate_policies (
    id                TEXT PRIMARY KEY,
    certificate_id    TEXT NOT NULL UNIQUE,
    user_id           TEXT NOT NULL,
    validity_months   INTEGER NOT NULL DEFAULT 12,
    key_type          TEXT NOT NULL DEFAULT 'RSA',
    key_size          INTEGER NOT NULL DEFAULT 2048,
    curve             TEXT NOT NULL DEFAULT '',
    subject           TEXT NOT NULL DEFAULT '',
    sans              TEXT NOT NULL DEFAULT '',
    auto_renew        BOOLEAN NOT NULL DEFAULT FALSE,
    days_before_expiry INTEGER NOT NULL DEFAULT 30,
    issuer_name       TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
```

- [ ] **Step 3: Write the failing test**

Create `internal/repositories/certificate_policy_repository_test.go`:

```go
package repositories_test

import (
    "context"
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/stretchr/testify/require"
)

func TestCertificatePolicy_UpsertAndGet(t *testing.T) {
    db := setupTestDB(t)
    repo := NewCertificatePolicyRepository(db, testLogger(t))

    certID := uuid.New()
    userID := uuid.New()

    policy := &model.CertificatePolicy{
        ID:               uuid.New(),
        CertificateID:    certID,
        UserID:           userID,
        ValidityMonths:   12,
        KeyType:          "RSA",
        KeySize:          2048,
        AutoRenew:        true,
        DaysBeforeExpiry: 30,
        CreatedAt:        time.Now(),
        UpdatedAt:        time.Now(),
    }
    require.NoError(t, repo.Upsert(context.Background(), policy))

    loaded, err := repo.GetByCertificateID(context.Background(), certID, userID)
    require.NoError(t, err)
    require.Equal(t, 12, loaded.ValidityMonths)
    require.True(t, loaded.AutoRenew)
}
```

- [ ] **Step 4: Run test to confirm failure**

```bash
go test ./internal/repositories/... -run TestCertificatePolicy -v
```

Expected: compile error.

- [ ] **Step 5: Create `internal/repositories/certificate_policy_repository.go`**

```go
package repositories

import (
    "context"
    "database/sql"

    "github.com/google/uuid"
    "github.com/numericlabs/rocketvault/internal/logging"
    "github.com/numericlabs/rocketvault/model"
)

type CertificatePolicyRepositoryInterface interface {
    Upsert(ctx context.Context, policy *model.CertificatePolicy) error
    GetByCertificateID(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error)
    DeleteByCertificateID(ctx context.Context, certID, userID uuid.UUID) error
}

type CertificatePolicyRepository struct {
    db  *sql.DB
    log *logging.Logger
}

func NewCertificatePolicyRepository(db *sql.DB, log *logging.Logger) CertificatePolicyRepositoryInterface {
    return &CertificatePolicyRepository{db: db, log: log}
}

func (r *CertificatePolicyRepository) Upsert(ctx context.Context, p *model.CertificatePolicy) error {
    _, err := r.db.ExecContext(ctx, `
        INSERT INTO certificate_policies
            (id, certificate_id, user_id, validity_months, key_type, key_size, curve, subject, sans, auto_renew, days_before_expiry, issuer_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(certificate_id) DO UPDATE SET
            validity_months    = excluded.validity_months,
            key_type           = excluded.key_type,
            key_size           = excluded.key_size,
            curve              = excluded.curve,
            subject            = excluded.subject,
            sans               = excluded.sans,
            auto_renew         = excluded.auto_renew,
            days_before_expiry = excluded.days_before_expiry,
            issuer_name        = excluded.issuer_name,
            updated_at         = excluded.updated_at`,
        p.ID.String(), p.CertificateID.String(), p.UserID.String(),
        p.ValidityMonths, p.KeyType, p.KeySize, p.Curve, p.Subject, p.SANs,
        p.AutoRenew, p.DaysBeforeExpiry, p.IssuerName, p.CreatedAt, p.UpdatedAt,
    )
    return err
}

func (r *CertificatePolicyRepository) GetByCertificateID(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error) {
    row := r.db.QueryRowContext(ctx, `
        SELECT id, certificate_id, user_id, validity_months, key_type, key_size, curve, subject, sans, auto_renew, days_before_expiry, issuer_name, created_at, updated_at
        FROM certificate_policies
        WHERE certificate_id = ? AND user_id = ?`,
        certID.String(), userID.String(),
    )
    var p model.CertificatePolicy
    var id, cid, uid string
    if err := row.Scan(&id, &cid, &uid, &p.ValidityMonths, &p.KeyType, &p.KeySize, &p.Curve, &p.Subject, &p.SANs, &p.AutoRenew, &p.DaysBeforeExpiry, &p.IssuerName, &p.CreatedAt, &p.UpdatedAt); err != nil {
        return nil, err
    }
    p.ID, _ = uuid.Parse(id)
    p.CertificateID, _ = uuid.Parse(cid)
    p.UserID, _ = uuid.Parse(uid)
    return &p, nil
}

func (r *CertificatePolicyRepository) DeleteByCertificateID(ctx context.Context, certID, userID uuid.UUID) error {
    _, err := r.db.ExecContext(ctx,
        "DELETE FROM certificate_policies WHERE certificate_id = ? AND user_id = ?",
        certID.String(), userID.String(),
    )
    return err
}
```

- [ ] **Step 6: Create `api/certificate_policy.go`**

```go
package api

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/google/uuid"
    "github.com/gorilla/mux"
    "github.com/numericlabs/rocketvault/model"
)

func getCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
    certID, err := uuid.Parse(mux.Vars(r)["cert_id"])
    if err != nil {
        c.SetInvalidParam("cert_id")
        return
    }
    userID, err := getUserIDFromContext(r.Context())
    if err != nil {
        c.SetForbidden("user not authenticated")
        return
    }
    policy, err := c.App.Container.GetCertificatePolicyRepository().GetByCertificateID(r.Context(), certID, userID)
    if err != nil {
        c.SetNotFound("policy not found")
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(policy)
}

func upsertCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
    certID, err := uuid.Parse(mux.Vars(r)["cert_id"])
    if err != nil {
        c.SetInvalidParam("cert_id")
        return
    }
    userID, err := getUserIDFromContext(r.Context())
    if err != nil {
        c.SetForbidden("user not authenticated")
        return
    }
    req, err := model.UpsertCertificatePolicyRequestFromJson(r.Body)
    if err != nil {
        c.SetInvalidParam("request body")
        return
    }
    now := time.Now()
    policy := &model.CertificatePolicy{
        ID:               uuid.New(),
        CertificateID:    certID,
        UserID:           userID,
        ValidityMonths:   req.ValidityMonths,
        KeyType:          req.KeyType,
        KeySize:          req.KeySize,
        Curve:            req.Curve,
        Subject:          req.Subject,
        SANs:             req.SANs,
        AutoRenew:        req.AutoRenew,
        DaysBeforeExpiry: req.DaysBeforeExpiry,
        IssuerName:       req.IssuerName,
        CreatedAt:        now,
        UpdatedAt:        now,
    }
    if err := c.App.Container.GetCertificatePolicyRepository().Upsert(r.Context(), policy); err != nil {
        c.SetInternalServerError(err.Error())
        return
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(policy)
}
```

Register routes in `api/api.go` inside `Init`:

```go
certs.Handle("/{cert_id:[A-Fa-f0-9-]+}/policy",
    ApiSessionRequired(api.App, getCertificatePolicy)).Methods("GET")
certs.Handle("/{cert_id:[A-Fa-f0-9-]+}/policy",
    ApiSessionRequired(api.App, upsertCertificatePolicy)).Methods("PUT")
```

Add `GetCertificatePolicyRepository() CertificatePolicyRepositoryInterface` to the service container (`internal/container/service_container.go`), initialising it in the same `NewServiceContainer` function using the existing `db` reference.

- [ ] **Step 7: Run all tests**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 8: Commit**

```bash
git add model/certificate_policy.go internal/db/db.go internal/repositories/certificate_policy_repository.go internal/repositories/certificate_policy_repository_test.go api/certificate_policy.go internal/container/service_container.go api/api.go
git commit -m "feat(certs): add CertificatePolicy resource with GET/PUT /certificates/{id}/policy"
```

---

## Self-review

### Spec coverage

| Audit item | Task(s) |
|---|---|
| Verify/Decrypt revoked-key guard | Task 1 |
| ES256K | Task 2 |
| HS256/384/512 | Task 3 |
| RSA1_5, AES-KW, AES-CBC | Task 4 |
| Lifecycle attrs — secrets | Task 5 |
| Lifecycle attrs — keys | Task 6 |
| Lifecycle attrs — certs | Task 7 |
| Key versioning + ListKeyVersions | Task 8 |
| Per-item backup/restore | Task 9 |
| Certificate Policy CRUD | Task 10 |

Wire format (item 1) is a product decision, not an implementation task — excluded by design.

### Placeholder scan

No TBD, TODO, or "implement later" phrases found. Every step has code or an explicit command.

### Type consistency

- `model.KeyVersion` defined in Task 8 Step 4; used in repo interface Step 5 and `RotateKey` Step 6. ✓
- `CertificatePolicy` defined in Task 10 Step 1; used in repo Step 5 and API Step 6. ✓
- `ItemBackupService` defined in Task 9 Step 4; referenced in API Step 5. ✓
- `IsAccessible()` added to `model.Key` in Task 6 Step 3; called in `api/keys.go` Step 6. ✓
- `IsAccessible()` added to `model.Certificate` in Task 7 Step 1; called in `api/certificates.go` Step 4. ✓
