# Bug Fixes: RSA-OAEP Algorithm Collision + Certificate Auto-Renew Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two production bugs: (1) `RSA-OAEP` algorithm constant uses SHA-256 instead of SHA-1 causing silent wrap/unwrap interop failure with Azure SDK clients, and (2) `RenewCertificate` always returns an error because `Certificate` struct lacks a `KeyID` field.

**Architecture:** Both fixes are surgical. The RSA-OAEP fix adds a second algorithm constant and correct SHA-1 path while preserving the existing SHA-256 path under a renamed `RSA-OAEP-256` constant. The cert auto-renew fix adds a `KeyID` column to the `certificates` table, persists it on create, and wires it into `RenewCertificate`.

**Tech Stack:** Go 1.24.2, `crypto/rsa`, `crypto/sha1`, `crypto/sha256`, SQLite/PostgreSQL migrations, testify.

**Spec:** `docs/plans/2026-05-23-azure-keyvault-parity-audit.md` §Keys (RSA-OAEP row) and §Certificates (Auto-renewal scheduler row).

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `internal/crypto/crypto_operations.go` | Modify | Add `AlgorithmRSAOAEP256` constant; fix `encryptRSA`/`decryptRSA` to dispatch on algorithm; add SHA-1 path |
| `internal/services/keys/crypto_service.go` | Modify | Accept both `RSA-OAEP` and `RSA-OAEP-256` in `WrapKey`/`UnwrapKey`; update validation error message |
| `api/keys.go` | Modify | Pass algorithm from request through to service for wrap/unwrap routes |
| `model/certificate.go` | Modify | Add `KeyID uuid.UUID` field to `Certificate` and `CreateCertificateRequest` |
| `internal/db/db.go` | Modify | Add `key_id TEXT` to `createOptimizedSchema` certificates table; add `ALTER TABLE` to `migrateSchema` |
| `internal/repositories/certificate_repository.go` | Modify | Include `key_id` in INSERT and SELECT queries |
| `internal/services/certificates/certificate_service.go` | Modify | Persist `KeyID` on create; use `cert.KeyID` in `RenewCertificate` instead of erroring |
| `internal/crypto/crypto_operations_test.go` | Modify | Add tests for both RSA-OAEP (SHA-1) and RSA-OAEP-256 (SHA-256) round-trips |
| `internal/services/keys/wrap_key_test.go` | Modify | Add test for `RSA-OAEP-256` wrap/unwrap; test algorithm rejection |
| `internal/services/certificates/renewal_service_test.go` | Modify | Add test that `RenewCertificate` succeeds when `KeyID` is populated |

---

## Task 1: Fix RSA-OAEP algorithm constant and add SHA-1 path

**Files:**
- Modify: `internal/crypto/crypto_operations.go`

- [ ] **Step 1: Write failing tests for both algorithms**

Add to `internal/crypto/crypto_operations_test.go` (find the existing `TestEncryptDecryptRSA` test and add below it):

```go
func TestRSAOAEP_SHA1_RoundTrip(t *testing.T) {
	ops := NewCryptoOperations()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pem := encodeRSAPrivateKeyToPEM(t, key) // helper already in file
	plaintext := []byte("secret payload for SHA-1 OAEP")

	enc, err := ops.Encrypt(pem, plaintext, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSAOAEP, enc.Algorithm)

	dec, err := ops.Decrypt(pem, enc.Ciphertext, nil, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec.Plaintext)
}

func TestRSAOAEP256_SHA256_RoundTrip(t *testing.T) {
	ops := NewCryptoOperations()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pem := encodeRSAPrivateKeyToPEM(t, key)
	plaintext := []byte("secret payload for SHA-256 OAEP")

	enc, err := ops.Encrypt(pem, plaintext, AlgorithmRSAOAEP256)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSAOAEP256, enc.Algorithm)

	dec, err := ops.Decrypt(pem, enc.Ciphertext, nil, AlgorithmRSAOAEP256)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec.Plaintext)
}

func TestRSAOAEP_And_RSAOAEP256_Are_Not_Interchangeable(t *testing.T) {
	ops := NewCryptoOperations()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pem := encodeRSAPrivateKeyToPEM(t, key)
	plaintext := []byte("cross-algorithm test")

	enc, err := ops.Encrypt(pem, plaintext, AlgorithmRSAOAEP)
	require.NoError(t, err)

	// Decrypting with SHA-256 path must fail — different hash = different OAEP label
	_, err = ops.Decrypt(pem, enc.Ciphertext, nil, AlgorithmRSAOAEP256)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run the new tests to confirm they fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/crypto/... -run "TestRSAOAEP" -v 2>&1 | head -40
```

Expected: FAIL — `AlgorithmRSAOAEP256` undefined.

- [ ] **Step 3: Add `AlgorithmRSAOAEP256` constant and fix dispatch**

In `internal/crypto/crypto_operations.go`, find the constants block:

```go
const (
	AlgorithmRSAOAEP EncryptionAlgorithm = "RSA-OAEP"   // RSA-OAEP with SHA-256
	AlgorithmAES256  EncryptionAlgorithm = "AES256-GCM" // AES-256-GCM
)
```

Replace it with:

```go
const (
	// AlgorithmRSAOAEP uses RSA-OAEP with SHA-1 — matches Azure SDK default "RSA-OAEP".
	AlgorithmRSAOAEP    EncryptionAlgorithm = "RSA-OAEP"
	// AlgorithmRSAOAEP256 uses RSA-OAEP with SHA-256 — matches Azure "RSA-OAEP-256".
	AlgorithmRSAOAEP256 EncryptionAlgorithm = "RSA-OAEP-256"
	AlgorithmAES256     EncryptionAlgorithm = "AES256-GCM" // AES-256-GCM
)
```

- [ ] **Step 4: Update `Encrypt` and `Decrypt` dispatch**

Find the `Encrypt` function in `internal/crypto/crypto_operations.go`:

```go
func (c *CryptoOperations) Encrypt(keyData string, data []byte, algorithm EncryptionAlgorithm) (*EncryptResult, error) {
	switch algorithm {
	case AlgorithmRSAOAEP:
		return c.encryptRSA(keyData, data)
	case AlgorithmAES256:
		return c.encryptAES(keyData, data)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}
```

Replace with:

```go
func (c *CryptoOperations) Encrypt(keyData string, data []byte, algorithm EncryptionAlgorithm) (*EncryptResult, error) {
	switch algorithm {
	case AlgorithmRSAOAEP:
		return c.encryptRSAOAEP(keyData, data, false) // SHA-1
	case AlgorithmRSAOAEP256:
		return c.encryptRSAOAEP(keyData, data, true) // SHA-256
	case AlgorithmAES256:
		return c.encryptAES(keyData, data)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}
```

Find the `Decrypt` function and replace similarly:

```go
func (c *CryptoOperations) Decrypt(keyData string, ciphertext []byte, nonce []byte, algorithm EncryptionAlgorithm) (*DecryptResult, error) {
	switch algorithm {
	case AlgorithmRSAOAEP:
		return c.decryptRSAOAEP(keyData, ciphertext, false) // SHA-1
	case AlgorithmRSAOAEP256:
		return c.decryptRSAOAEP(keyData, ciphertext, true) // SHA-256
	case AlgorithmAES256:
		return c.decryptAES(keyData, ciphertext, nonce)
	default:
		return nil, fmt.Errorf("unsupported decryption algorithm: %s", algorithm)
	}
}
```

- [ ] **Step 5: Rename and fix `encryptRSA` / `decryptRSA`**

Rename `encryptRSA` → `encryptRSAOAEP` and `decryptRSA` → `decryptRSAOAEP`, adding a `useSHA256 bool` parameter.

Replace the old `encryptRSA` function body:

```go
// encryptRSAOAEP encrypts data using RSA-OAEP.
// useSHA256=false uses SHA-1 (matches Azure "RSA-OAEP").
// useSHA256=true  uses SHA-256 (matches Azure "RSA-OAEP-256").
func (c *CryptoOperations) encryptRSAOAEP(privateKeyPEM string, data []byte, useSHA256 bool) (*EncryptResult, error) {
	privateKey, err := ParsePrivateKey(privateKeyPEM, "RSA")
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}

	var h hash.Hash
	algo := AlgorithmRSAOAEP
	if useSHA256 {
		h = sha256.New()
		algo = AlgorithmRSAOAEP256
	} else {
		h = sha1.New()
	}

	ciphertext, err := rsa.EncryptOAEP(h, rand.Reader, &rsaKey.PublicKey, data, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}
	return &EncryptResult{Ciphertext: ciphertext, Algorithm: algo}, nil
}
```

You will need to add `"crypto/sha1"` to the import block and add `"hash"` — it is already imported because `hash.Hash` is used. Check the existing imports and add what is missing.

Replace the old `decryptRSA` function body:

```go
// decryptRSAOAEP decrypts data using RSA-OAEP.
func (c *CryptoOperations) decryptRSAOAEP(privateKeyPEM string, ciphertext []byte, useSHA256 bool) (*DecryptResult, error) {
	privateKey, err := ParsePrivateKey(privateKeyPEM, "RSA")
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}

	var h hash.Hash
	algo := AlgorithmRSAOAEP
	if useSHA256 {
		h = sha256.New()
		algo = AlgorithmRSAOAEP256
	} else {
		h = sha1.New()
	}

	plaintext, err := rsa.DecryptOAEP(h, rand.Reader, rsaKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
	}
	return &DecryptResult{Plaintext: plaintext, Algorithm: algo}, nil
}
```

- [ ] **Step 6: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/crypto/... -run "TestRSAOAEP" -v 2>&1 | tail -20
```

Expected: all three new tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/crypto/crypto_operations.go internal/crypto/crypto_operations_test.go
git commit -m "fix(crypto): split RSA-OAEP (SHA-1) and RSA-OAEP-256 (SHA-256) algorithm constants"
```

---

## Task 2: Update WrapKey/UnwrapKey to accept both RSA-OAEP algorithms

**Files:**
- Modify: `internal/services/keys/crypto_service.go`
- Modify: `api/keys.go`
- Modify: `internal/services/keys/wrap_key_test.go`

- [ ] **Step 1: Write failing test for RSA-OAEP-256 wrap/unwrap**

In `internal/services/keys/wrap_key_test.go`, add after `TestWrapAndUnwrapKey`:

```go
func TestWrapAndUnwrapKey_OAEP256(t *testing.T) {
	// Reuse same setup as TestWrapAndUnwrapKey — copy the helper call pattern already in that test.
	svc, ownerID := setupWrapKeyService(t)

	dek := []byte("32-byte-data-encryption-key-here")
	wrapResult, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID:        getFirstKeyID(t, svc, ownerID),
		UserID:       ownerID,
		PlaintextKey: dek,
		Algorithm:    "RSA-OAEP-256",
	})
	require.NoError(t, err)
	assert.Equal(t, "RSA-OAEP-256", wrapResult.Algorithm)

	unwrapResult, err := svc.UnwrapKey(context.Background(), keys.UnwrapKeyRequest{
		KeyID:      getFirstKeyID(t, svc, ownerID),
		UserID:     ownerID,
		WrappedKey: wrapResult.WrappedKey,
		Algorithm:  "RSA-OAEP-256",
	})
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapResult.PlaintextKey)
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/keys/... -run "TestWrapAndUnwrapKey_OAEP256" -v 2>&1 | tail -15
```

Expected: FAIL — `unsupported algorithm: RSA-OAEP-256`.

- [ ] **Step 3: Update validation in `WrapKey` and `UnwrapKey`**

In `internal/services/keys/crypto_service.go`, find `WrapKey`:

```go
func (s *cryptoService) WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error) {
```

Find the algorithm validation block (it currently checks `req.Algorithm != "RSA-OAEP"`). Replace it with:

```go
	if req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
		return nil, fmt.Errorf("unsupported algorithm %q: only RSA-OAEP and RSA-OAEP-256 are supported", req.Algorithm)
	}
```

Do the same for `UnwrapKey`.

- [ ] **Step 4: Map the algorithm string to `EncryptionAlgorithm` before calling `CryptoOperations`**

In the `WrapKey` implementation, find the line that calls `s.cryptoOps.Encrypt`. Change the algorithm passed in to use the typed constant:

```go
	var encAlgo crypto.EncryptionAlgorithm
	if req.Algorithm == "RSA-OAEP-256" {
		encAlgo = crypto.AlgorithmRSAOAEP256
	} else {
		encAlgo = crypto.AlgorithmRSAOAEP
	}
	result, err := s.cryptoOps.Encrypt(privateKeyPEM, req.PlaintextKey, encAlgo)
```

Do the same for `UnwrapKey` using `s.cryptoOps.Decrypt`.

Also update `WrapKeyResult.Algorithm` to return the actual algorithm string:

```go
	return &WrapKeyResult{WrappedKey: result.Ciphertext, Algorithm: string(result.Algorithm)}, nil
```

- [ ] **Step 5: Update the HTTP handler to pass algorithm from request body**

In `api/keys.go`, find the `wrapKey` handler. The request body already has `Algorithm string`. Find where `keyservices.WrapKeyRequest` is constructed and ensure `Algorithm` is taken from `req.Algorithm` not hardcoded. Change:

```go
	result, err := cryptoSvc.WrapKey(r.Context(), keyservices.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: plaintextKey,
		Algorithm:    "RSA-OAEP", // ← hardcoded
	})
```

to:

```go
	algo := req.Algorithm
	if algo == "" {
		algo = "RSA-OAEP" // Azure default
	}
	result, err := cryptoSvc.WrapKey(r.Context(), keyservices.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: plaintextKey,
		Algorithm:    algo,
	})
```

Do the same for the `unwrapKey` handler.

- [ ] **Step 6: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/keys/... -v 2>&1 | tail -20
```

Expected: all wrap/unwrap tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/services/keys/crypto_service.go api/keys.go internal/services/keys/wrap_key_test.go
git commit -m "fix(keys): accept RSA-OAEP-256 in WrapKey/UnwrapKey; pass algorithm from HTTP request"
```

---

## Task 3: Add `KeyID` column to certificates table

**Files:**
- Modify: `internal/db/db.go`
- Modify: `model/certificate.go`

- [ ] **Step 1: Add `KeyID` to `model/certificate.go`**

In `model/certificate.go`, find the `Certificate` struct. Add `KeyID` after `UserID`:

```go
type Certificate struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	KeyID            uuid.UUID  `json:"key_id"`
	Name             string     `json:"name"`
	// ... rest unchanged
```

Also add `KeyID` to `CreateCertificateRequest`:

```go
type CreateCertificateRequest struct {
	Name         string   `json:"name"`
	KeyID        string   `json:"key_id"`
	// ... rest unchanged
```

`KeyID` is already present in `CreateCertificateRequest` as a `string` field. This only needs to be surfaced in the domain struct.

- [ ] **Step 2: Add `key_id` to `createOptimizedSchema`**

In `internal/db/db.go`, find the `CREATE TABLE IF NOT EXISTS certificates` statement. Add `key_id TEXT NOT NULL DEFAULT ''` after `user_id TEXT NOT NULL`:

```sql
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    key_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    ...
```

- [ ] **Step 3: Add migration in `migrateSchema`**

In `internal/db/db.go`, find the `migrations` slice in `migrateSchema`. Add:

```go
"ALTER TABLE certificates ADD COLUMN key_id TEXT NOT NULL DEFAULT ''",
```

Place it after the existing certificate soft-delete migrations.

- [ ] **Step 4: Build to verify schema changes compile**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: compile errors because `certificate_repository.go` doesn't yet scan `key_id`. That is expected — fix in Task 4.

- [ ] **Step 5: Commit the schema and model changes**

```bash
git add model/certificate.go internal/db/db.go
git commit -m "feat(certificates): add key_id column to certificates table and model"
```

---

## Task 4: Persist and read `key_id` in certificate repository

**Files:**
- Modify: `internal/repositories/certificate_repository.go`

- [ ] **Step 1: Write failing test**

In `internal/repositories/certificate_repository.go` test file (add to the existing test file or create `certificate_repository_keyid_test.go`):

```go
func TestCertificateRepository_KeyID_Persisted(t *testing.T) {
	db := setupCertificateTestDB(t) // use the existing helper in that package
	log := newTestLogger(t)
	repo := repositories.NewCertificateRepository(db, log)

	keyID := uuid.New()
	cert := &model.Certificate{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		KeyID:     keyID,
		Name:      "test-cert",
		Certificate: "--- PEM ---",
		PrivateKey:  "--- KEY ---",
		CreatedAt: time.Now(),
		AutoRenew:   false,
		RenewalDays: 30,
	}

	err := repo.Create(context.Background(), cert)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), cert.ID)
	require.NoError(t, err)
	assert.Equal(t, keyID, got.KeyID)
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/repositories/... -run "TestCertificateRepository_KeyID" -v 2>&1 | tail -10
```

Expected: FAIL — `KeyID` not scanned.

- [ ] **Step 3: Update `Create` SQL**

In `internal/repositories/certificate_repository.go`, find the `INSERT INTO certificates` statement. Add `key_id` to the column list and `cert.KeyID.String()` to the values:

```go
_, err := r.db.ExecContext(ctx,
    `INSERT INTO certificates (id, user_id, key_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    cert.ID.String(), cert.UserID.String(), cert.KeyID.String(), cert.Name,
    cert.Certificate, cert.PrivateKey, cert.CreatedAt, cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays,
)
```

- [ ] **Step 4: Update `Read` and list queries to scan `key_id`**

For every `SELECT` in the file that scans certificate rows, add `key_id` to the column list and add a `keyIDStr` scan variable, then parse it:

```go
var keyIDStr string
// ... in Scan: &keyIDStr
cert.KeyID, _ = uuid.Parse(keyIDStr)
```

Check `Read`, `ReadByOwner`, `ListByUser`, and `ListAll` — update all of them.

- [ ] **Step 5: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/repositories/... -v 2>&1 | tail -20
```

Expected: `TestCertificateRepository_KeyID_Persisted` PASS; no regressions.

- [ ] **Step 6: Commit**

```bash
git add internal/repositories/certificate_repository.go
git commit -m "feat(certificates): persist and read key_id in certificate repository"
```

---

## Task 5: Persist KeyID in certificate service and fix RenewCertificate

**Files:**
- Modify: `internal/services/certificates/certificate_service.go`
- Modify: `internal/services/certificates/renewal_service_test.go`

- [ ] **Step 1: Write failing test for RenewCertificate**

In `internal/services/certificates/renewal_service_test.go`, add:

```go
func TestRenewCertificate_Succeeds_WhenKeyIDSet(t *testing.T) {
	// Setup: create a certificate with a known key_id via the service, then renew it.
	svc, ownerID, keyID := setupCertServiceWithKey(t) // use or write a helper that creates a key+cert

	certID := createTestCertWithKeyID(t, svc, ownerID, keyID)

	result, err := svc.RenewCertificate(context.Background(), certID, ownerID, 365)
	require.NoError(t, err)
	assert.NotEqual(t, certID, result.CertID) // new cert created
}
```

If `setupCertServiceWithKey` doesn't exist, write it as a local test helper that:
1. Creates an in-memory SQLite DB.
2. Creates a key.
3. Returns `(CertificateServiceInterface, ownerUUID, keyUUID)`.

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/certificates/... -run "TestRenewCertificate_Succeeds" -v 2>&1 | tail -10
```

Expected: FAIL — `RenewCertificate` returns error unconditionally.

- [ ] **Step 3: Persist `KeyID` when creating a certificate**

In `internal/services/certificates/certificate_service.go`, find `CreateSelfSignedCertificate`. Locate the block that builds the `model.Certificate` struct (around line 185 in the current file). Add `KeyID`:

```go
cert := &model.Certificate{
    ID:          uuid.New(),
    UserID:      req.UserID,
    KeyID:       req.KeyID,    // ← add this
    Name:        req.Name,
    Certificate: certPEM,
    PrivateKey:  encryptedKey,
    CreatedAt:   time.Now(),
    Tags:        req.Tags,
    ExpiresAt:   expiresAt,
    AutoRenew:   req.AutoRenew,
    RenewalDays: renewalDays,
}
```

Do the same in `CreateCASignedCertificate` (same pattern, same location in that function).

Note: `req.KeyID` is already a `uuid.UUID` in `CreateCertificateRequest` in the service layer (`internal/services/certificates/certificate_service.go:41`). Confirm that the struct field name matches.

- [ ] **Step 4: Fix `RenewCertificate`**

Find `RenewCertificate` at line 481 of `internal/services/certificates/certificate_service.go`. The current body likely resembles:

```go
func (s *certificateService) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*CreateCertificateResult, error) {
    cert, err := s.GetCertificate(ctx, certID, userID)
    if err != nil {
        return nil, err
    }
    // Bug: Certificate struct has no KeyID → this line errors
    return s.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
        Name:         cert.Name,
        KeyID:        cert.KeyID, // ← this was missing before Task 3
        UserID:       userID,
        ValidityDays: validityDays,
        Tags:         cert.Tags,
        AutoRenew:    cert.AutoRenew,
        RenewalDays:  cert.RenewalDays,
    })
}
```

After Task 3, `cert.KeyID` is now populated. Verify the function uses it correctly. If the function currently has a hard-coded error or a `Certificate` struct access that does not compile, update the function body to match the pattern above.

- [ ] **Step 5: Run all certificate tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/certificates/... -v 2>&1 | tail -30
```

Expected: all tests including `TestRenewCertificate_Succeeds_WhenKeyIDSet` PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/services/certificates/certificate_service.go internal/services/certificates/renewal_service_test.go
git commit -m "fix(certificates): persist KeyID on create; use cert.KeyID in RenewCertificate"
```

---

## Task 6: Full regression pass

- [ ] **Step 1: Run full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|ok" | sort
```

Expected: all packages `ok`. No `FAIL` lines.

- [ ] **Step 2: Build final binary**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build -o /tmp/rocketvault-bug-fixes . && echo "build ok"
```

Expected: `build ok`.

- [ ] **Step 3: Commit any remaining cleanup**

```bash
git add -A
git commit -m "fix: full regression pass — RSA-OAEP collision and cert auto-renew bugs resolved"
```
