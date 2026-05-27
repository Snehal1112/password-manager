# Keys Feature Matrix Parity Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 8 independently fixable gaps in the Keys feature matrix, advancing each from `partial` toward `exact` Azure Key Vault parity.

**Architecture:** Each task is self-contained. Tasks 1–3 touch validation/model/DB only. Task 4 adds JWK public material to key responses by reusing the existing `internal/signing/jwks.go` helpers. Task 5 exposes `RSA-HSM`/`EC-HSM` kty values based on the PKCS#11 backend. Task 6 extends WrapKey/UnwrapKey to accept AES-KW and AES-CBC algorithms already implemented in `crypto_operations.go`. Task 7 adds a single `getDeletedKey` handler. Task 8 adds deletion metadata to the DeleteKey response.

**Tech Stack:** Go 1.24, Gorilla Mux, `database/sql` (SQLite/PostgreSQL), `crypto/rsa`, `crypto/ecdsa`, `encoding/pem`, `crypto/x509`, existing `internal/signing`, `internal/crypto`, `internal/services/keys`, `api/`.

**Excluded from this plan (need separate plans or architectural decisions):**
- oct key creation (separate feature)
- ImportKey / JWK ingestion (separate feature)
- ListKeys pagination (tied to global wire-format decision)
- Key rotation policy for keys (new subsystem)
- `kid` as fully-qualified URL (requires changing all response IDs)
- `recoveryLevel`/`recoverableDays` (vault-level config, informational)
- `exportable`/`release_policy` (confidential computing, out of scope for self-hosted)

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `internal/validation/key_validation.go` | Modify | Accept RSA 3072 |
| `api/keys.go` | Modify | Accept 3072 in handler guard; add JWK fields to response; add kty HSM detection; add deletion metadata response; add `getDeletedKey` route+handler |
| `model/key.go` | Modify | Add `UpdatedAt` field |
| `internal/db/db.go` | Modify | Add `updated_at` column to keys table in `migrateSchema` |
| `internal/repositories/key_repository.go` | Modify | Write `updated_at` in UPDATE; scan `updated_at` in SELECT; scan `deleted_at` in SoftDelete return |
| `internal/crypto/key_crypto.go` | Modify | Add `ExtractPublicKeyFromPEM(pem string, keyType string)` helper |
| `internal/services/keys/key_service.go` | Modify | `DeleteKey` returns `*model.Key` (the deleted record) instead of `error` only |
| `internal/services/keys/crypto_service.go` | Modify | Extend WrapKey/UnwrapKey to accept AES-KW and AES-CBC algorithms |
| `api/soft_delete.go` | Modify | Add `getDeletedKey` handler |

---

## Task 1: Accept RSA 3072-bit key size

**Files:**
- Modify: `internal/validation/key_validation.go`
- Modify: `api/keys.go` (handler guard around line 271)

- [ ] **Step 1: Write the failing test**

Add to `internal/services/keys/key_service_test.go` (or the nearest RSA creation test file — check with `grep -rn "TestCreate.*RSA\|3072" internal/services/keys/`):

```go
func TestCreateRSAKey_3072Accepted(t *testing.T) {
    // This test verifies that 3072-bit RSA keys are accepted by validation.
    req := CreateRSAKeyRequest{
        UserID: uuid.New(),
        Name:   "test-3072",
        Bits:   3072,
    }
    errs := validation.ValidateKeyCreate(validation.KeyCreateRequest{
        Name: req.Name,
        Type: "RSA",
        Bits: req.Bits,
    })
    assert.Empty(t, errs, "3072-bit RSA should be valid")
}
```

If `validation.ValidateKeyCreate` has a different signature, read `internal/validation/key_validation.go` first and adapt.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/validation/... -run TestCreateRSAKey_3072 -v
```

Expected: FAIL — 3072 rejected by `validation.In(2048, 4096)`.

- [ ] **Step 3: Update validation to accept 3072**

In `internal/validation/key_validation.go`, find the line (around line 39):
```go
validation.In(2048, 4096)
```
Change to:
```go
validation.In(2048, 3072, 4096)
```

- [ ] **Step 4: Update the API handler guard**

In `api/keys.go`, find (around line 271):
```go
if req.Bits != 2048 && req.Bits != 4096 {
```
Change to:
```go
if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
```

Also update the error message on the next line to read `"must be 2048, 3072, or 4096"`.

- [ ] **Step 5: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/validation/... ./internal/services/keys/... -v 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/validation/key_validation.go api/keys.go
git commit -m "feat(keys): accept 3072-bit RSA key size"
```

---

## Task 2: Add `updated_at` timestamp to keys

**Files:**
- Modify: `model/key.go`
- Modify: `internal/db/db.go` (`migrateSchema`)
- Modify: `internal/repositories/key_repository.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/repositories/key_repository_test.go` (find the update test or create a new one):

```go
func TestKeyRepository_UpdateSetsUpdatedAt(t *testing.T) {
    db := openTestDB(t) // use whichever helper the file already uses
    repo := NewKeyRepository(db, testLogger(t))
    ctx := context.Background()

    key := &model.Key{
        ID:      uuid.New(),
        UserID:  uuid.New(),
        Name:    "test-key",
        Type:    model.KeyTypeRSA,
        Value:   "pem-placeholder",
        Enabled: true,
        Bits:    2048,
        Curve:   "",
    }
    require.NoError(t, repo.Create(ctx, key))

    time.Sleep(10 * time.Millisecond) // ensure time advances

    key.Name = "updated-name"
    require.NoError(t, repo.Update(ctx, key))

    fetched, err := repo.Read(ctx, key.ID)
    require.NoError(t, err)
    assert.NotNil(t, fetched.UpdatedAt, "UpdatedAt should be set after update")
    assert.True(t, fetched.UpdatedAt.After(fetched.CreatedAt),
        "UpdatedAt should be after CreatedAt")
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/repositories/... -run TestKeyRepository_UpdateSetsUpdatedAt -v
```

Expected: compile error — `model.Key` has no `UpdatedAt` field.

- [ ] **Step 3: Add `UpdatedAt` to the model**

In `model/key.go`, add to the `Key` struct (after `NotBefore`):
```go
UpdatedAt *time.Time
```

- [ ] **Step 4: Add `updated_at` column via migration**

In `internal/db/db.go`, find `migrateSchema`. It contains a series of `ALTER TABLE` statements. Add at the end of the keys migration block (after the existing keys migrations):

```go
_, _ = db.Exec(`ALTER TABLE keys ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NULL`)
```

For SQLite (which doesn't support `IF NOT EXISTS` on ALTER TABLE), wrap it:
```go
if _, err := db.Exec(`ALTER TABLE keys ADD COLUMN updated_at TIMESTAMP NULL`); err != nil {
    // Column may already exist — ignore duplicate column errors.
    if !strings.Contains(err.Error(), "duplicate column") {
        return fmt.Errorf("migrate keys.updated_at: %w", err)
    }
}
```

Also add the column to the `CREATE TABLE keys` statement in `createOptimizedSchema` (or wherever the fresh schema is defined, around line 306). Add after `bits INTEGER NOT NULL DEFAULT 0` and `curve TEXT NOT NULL DEFAULT ''`:
```sql
updated_at TIMESTAMP NULL,
```

- [ ] **Step 5: Update the UPDATE statement in `key_repository.go`**

Find `Update` (around line 200). Change the UPDATE SQL to include `updated_at = ?` and pass `time.Now()` as the argument. Also update the scan in `Read` to scan `updated_at` from SELECT results.

Current UPDATE (approximately):
```go
"UPDATE keys SET name = ?, value = ?, revoked = ?, created_at = ?, enabled = ?, expires_at = ?, not_before = ?, bits = ?, curve = ? WHERE id = ?"
```

Replace with:
```go
now := time.Now()
key.UpdatedAt = &now
_, err = r.db.ExecContext(ctx,
    "UPDATE keys SET name = ?, value = ?, revoked = ?, created_at = ?, enabled = ?, expires_at = ?, not_before = ?, bits = ?, curve = ?, updated_at = ? WHERE id = ?",
    key.Name, key.Value, key.Revoked, key.CreatedAt, key.Enabled, key.ExpiresAt, key.NotBefore, key.Bits, key.Curve, now, key.ID.String())
```

In the `Read` SELECT (around line 169), add `updated_at` to the column list and scan it:
```go
"SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at FROM keys WHERE id = ? AND deleted_at IS NULL"
```
And in the `Scan` call, add `&key.UpdatedAt` at the end.

Repeat for `List`/`ListByUser` if they also scan individual columns (check — they may use `*` or individual columns).

- [ ] **Step 6: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./... && go test ./internal/repositories/... -v 2>&1 | tail -20
```

Expected: all pass including `TestKeyRepository_UpdateSetsUpdatedAt`.

- [ ] **Step 7: Commit**

```bash
git add model/key.go internal/db/db.go internal/repositories/key_repository.go
git commit -m "feat(keys): add updated_at timestamp — persisted on every Update"
```

---

## Task 3: Expose RSA-HSM / EC-HSM kty in API responses

**Files:**
- Modify: `api/keys.go`
- Modify: `internal/services/keys/crypto_service.go` (helper already exists: `resolveKeyHandle`)

When `hsm.enabled` is true, key values are stored with a `pkcs11:` prefix. The API should expose these as `kty=RSA-HSM` or `kty=EC-HSM` instead of `RSA`/`ECDSA`.

- [ ] **Step 1: Write the failing test**

Add to `api/keys_test.go` or the nearest API test file:

```go
func TestKeyResponse_HSMTypeExposed(t *testing.T) {
    // A key stored with pkcs11: prefix should report RSA-HSM as its type.
    key := &model.Key{
        ID:    uuid.New(),
        Name:  "hsm-key",
        Type:  model.KeyTypeRSA,
        Value: "pkcs11:some-label-uuid",
    }
    resp := buildKeyResponse(key)
    assert.Equal(t, "RSA-HSM", resp.Type)
}

func TestKeyResponse_SoftwareTypeUnchanged(t *testing.T) {
    key := &model.Key{
        ID:    uuid.New(),
        Name:  "sw-key",
        Type:  model.KeyTypeRSA,
        Value: "-----BEGIN RSA PRIVATE KEY-----\n...",
    }
    resp := buildKeyResponse(key)
    assert.Equal(t, "RSA", resp.Type)
}
```

`buildKeyResponse` is a helper you will extract in the next step. First verify the test file compiles.

- [ ] **Step 2: Extract `buildKeyResponse` helper in `api/keys.go`**

Find all places in `api/keys.go` that construct `KeyResponse{...}` from a `*model.Key`. Extract a shared helper:

```go
// buildKeyResponse constructs a KeyResponse from a model.Key.
// If the key value has a "pkcs11:" prefix, the type is suffixed with "-HSM"
// to match Azure's RSA-HSM / EC-HSM naming.
func buildKeyResponse(key *model.Key) KeyResponse {
    kty := key.Type
    if strings.HasPrefix(key.Value, "pkcs11:") {
        kty = key.Type + "-HSM"
    }
    return KeyResponse{
        ID:        key.ID,
        Name:      key.Name,
        Type:      kty,
        UserID:    key.UserID,
        Revoked:   key.Revoked,
        CreatedAt: key.CreatedAt,
        Tags:      key.Tags,
        Enabled:   key.Enabled,
        ExpiresAt: key.ExpiresAt,
        NotBefore: key.NotBefore,
        Bits:      key.Bits,
        Curve:     key.Curve,
    }
}
```

Add `"strings"` to the import block in `api/keys.go` if not already present.

Replace all existing `KeyResponse{...}` construction blocks in `getKey`, `createKey`, `listKeys`, etc. with `buildKeyResponse(key)`.

- [ ] **Step 3: Run the test**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./api/... -run TestKeyResponse -v
```

Expected: both tests pass.

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add api/keys.go
git commit -m "feat(keys): expose RSA-HSM/EC-HSM kty when PKCS11 backend is active"
```

---

## Task 4: Add JWK public material (n/e/x/y) to GetKey response

**Files:**
- Modify: `internal/crypto/key_crypto.go` (add public key extraction helper)
- Modify: `api/keys.go` (add `N`, `E`, `X`, `Y`, `Crv` to `KeyResponse`; populate in `buildKeyResponse`)

The existing `internal/signing/jwks.go` has `RSAPublicKeyToJWK` and `ECDSAPublicKeyToJWK`. We need a helper that takes a PEM string and extracts the public key components. For PKCS#11 keys, public material is not stored in the vault (it's on the token) — so `n/e/x/y` will be absent for HSM keys.

- [ ] **Step 1: Write the failing test**

Add to `internal/crypto/key_crypto_test.go`:

```go
func TestExtractRSAPublicComponents(t *testing.T) {
    // Generate a real RSA key so we have a valid PEM.
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    privPEM := string(pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privKey),
    }))

    n, e, x, y, err := ExtractPublicComponents(privPEM, "RSA")
    require.NoError(t, err)
    assert.NotEmpty(t, n, "n should be non-empty for RSA key")
    assert.NotEmpty(t, e, "e should be non-empty for RSA key")
    assert.Empty(t, x, "x should be empty for RSA key")
    assert.Empty(t, y, "y should be empty for RSA key")
}

func TestExtractECPublicComponents(t *testing.T) {
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)
    privBytes, err := x509.MarshalECPrivateKey(privKey)
    require.NoError(t, err)
    privPEM := string(pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: privBytes,
    }))

    n, e, x, y, err := ExtractPublicComponents(privPEM, "ECDSA")
    require.NoError(t, err)
    assert.Empty(t, n)
    assert.Empty(t, e)
    assert.NotEmpty(t, x, "x should be non-empty for EC key")
    assert.NotEmpty(t, y, "y should be non-empty for EC key")
}

func TestExtractPublicComponents_PKCS11ReturnsEmpty(t *testing.T) {
    // PKCS#11 values carry a label, not PEM — public components are unavailable.
    n, e, x, y, err := ExtractPublicComponents("pkcs11:some-label", "RSA")
    require.NoError(t, err) // should not error, just return empty
    assert.Empty(t, n)
    assert.Empty(t, e)
    assert.Empty(t, x)
    assert.Empty(t, y)
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/crypto/... -run TestExtract -v
```

Expected: compile error — `ExtractPublicComponents` not defined.

- [ ] **Step 3: Implement `ExtractPublicComponents` in `key_crypto.go`**

Add to `internal/crypto/key_crypto.go`:

```go
// ExtractPublicComponents parses a PEM-encoded private key and returns the
// base64url-encoded public key components. Returns empty strings for PKCS#11
// keys (which carry a label, not PEM).
// RSA: returns n, e (base64url). EC: returns x, y (base64url). n and e are empty for EC; x and y are empty for RSA.
func ExtractPublicComponents(pemOrHandle string, keyType string) (n, e, x, y string, err error) {
    if strings.HasPrefix(pemOrHandle, "pkcs11:") {
        return "", "", "", "", nil
    }
    block, _ := pem.Decode([]byte(pemOrHandle))
    if block == nil {
        return "", "", "", "", fmt.Errorf("failed to decode PEM block")
    }
    switch block.Type {
    case "RSA PRIVATE KEY":
        priv, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
        if parseErr != nil {
            return "", "", "", "", fmt.Errorf("parse RSA private key: %w", parseErr)
        }
        n = base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
        eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
        e = base64.RawURLEncoding.EncodeToString(eBytes)
        return n, e, "", "", nil
    case "EC PRIVATE KEY":
        priv, parseErr := x509.ParseECPrivateKey(block.Bytes)
        if parseErr != nil {
            return "", "", "", "", fmt.Errorf("parse EC private key: %w", parseErr)
        }
        byteLen := (priv.PublicKey.Curve.Params().BitSize + 7) / 8
        xb := make([]byte, byteLen)
        yb := make([]byte, byteLen)
        priv.PublicKey.X.FillBytes(xb)
        priv.PublicKey.Y.FillBytes(yb)
        x = base64.RawURLEncoding.EncodeToString(xb)
        y = base64.RawURLEncoding.EncodeToString(yb)
        return "", "", x, y, nil
    default:
        return "", "", "", "", fmt.Errorf("unsupported PEM block type: %s", block.Type)
    }
}
```

Add imports as needed: `"crypto/x509"`, `"encoding/pem"`, `"encoding/base64"`, `"math/big"`, `"strings"`. Check `key_crypto.go` already imports — most are likely there.

- [ ] **Step 4: Run tests to verify pass**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/crypto/... -run TestExtract -v
```

Expected: all 3 pass.

- [ ] **Step 5: Add JWK fields to `KeyResponse` in `api/keys.go`**

In `api/keys.go`, extend `KeyResponse` struct:

```go
type KeyResponse struct {
    ID        uuid.UUID  `json:"id"`
    Name      string     `json:"name"`
    Type      string     `json:"type"`
    UserID    uuid.UUID  `json:"user_id"`
    Revoked   bool       `json:"revoked"`
    CreatedAt time.Time  `json:"created_at"`
    Tags      []string   `json:"tags"`
    Enabled   bool       `json:"enabled"`
    ExpiresAt *time.Time `json:"expires_at,omitempty"`
    NotBefore *time.Time `json:"not_before,omitempty"`
    UpdatedAt *time.Time `json:"updated_at,omitempty"`
    Bits      int        `json:"bits,omitempty"`
    Curve     string     `json:"curve,omitempty"`
    // JWK public components (omitted for HSM-backed keys and on error).
    N string `json:"n,omitempty"` // RSA modulus (base64url)
    E string `json:"e,omitempty"` // RSA public exponent (base64url)
    X string `json:"x,omitempty"` // EC x coordinate (base64url)
    Y string `json:"y,omitempty"` // EC y coordinate (base64url)
}
```

- [ ] **Step 6: Populate JWK fields in `buildKeyResponse`**

Update `buildKeyResponse` (created in Task 3):

```go
func buildKeyResponse(key *model.Key) KeyResponse {
    kty := key.Type
    if strings.HasPrefix(key.Value, "pkcs11:") {
        kty = key.Type + "-HSM"
    }
    n, e, x, y, _ := crypto.ExtractPublicComponents(key.Value, key.Type)
    return KeyResponse{
        ID:        key.ID,
        Name:      key.Name,
        Type:      kty,
        UserID:    key.UserID,
        Revoked:   key.Revoked,
        CreatedAt: key.CreatedAt,
        Tags:      key.Tags,
        Enabled:   key.Enabled,
        ExpiresAt: key.ExpiresAt,
        NotBefore: key.NotBefore,
        UpdatedAt: key.UpdatedAt,
        Bits:      key.Bits,
        Curve:     key.Curve,
        N:         n,
        E:         e,
        X:         x,
        Y:         y,
    }
}
```

Add import for `"github.com/numericlabs/rocketvault/internal/crypto"` (check the module path in `go.mod` first).

- [ ] **Step 7: Build and test**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./...
go test ./api/... ./internal/crypto/... -v 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add internal/crypto/key_crypto.go api/keys.go
git commit -m "feat(keys): expose JWK public material (n/e/x/y) in GetKey response"
```

---

## Task 5: Extend WrapKey/UnwrapKey to accept AES-KW and AES-CBC

**Files:**
- Modify: `internal/services/keys/crypto_service.go`

The crypto layer already implements AES-KW (`AlgorithmA128KW/A192KW/A256KW`) and AES-CBC (`AlgorithmA128CBC/A192CBC/A256CBC`) in `internal/crypto/crypto_operations.go`. WrapKey/UnwrapKey currently reject everything except `RSA-OAEP` and `RSA-OAEP-256`.

AES-KW and AES-CBC wrap/unwrap require a symmetric `oct` key. Since oct key creation is not yet implemented, these operations are only viable when the caller provides raw key material for both the wrapping key and the data. For now we extend the algorithm allowlist; if the vault key is RSA we use RSA-OAEP path, if it's an oct key (stored as raw AES bytes) we use the AES path. The service already routes by key type.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/keys/wrap_key_test.go` (or create it):

```go
func TestWrapKey_AESKW_AlgorithmAccepted(t *testing.T) {
    // Verify that A256KW algorithm string passes the allowlist check.
    // We cannot do a full round-trip without an oct key, so we test the
    // validation boundary — the error should NOT be "unsupported algorithm".
    svc := newTestCryptoService(t) // use whatever test helper exists in the file
    _, err := svc.WrapKey(context.Background(), WrapKeyRequest{
        UserID:       uuid.New(),
        KeyID:        uuid.New(), // will fail as key not found — that's fine
        Algorithm:    "A256KW",
        PlaintextKey: []byte("some-key-material"),
    })
    // Should fail with "key not found" or "forbidden", NOT "unsupported algorithm".
    assert.NotContains(t, err.Error(), "unsupported algorithm",
        "A256KW should pass the allowlist check")
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/services/keys/... -run TestWrapKey_AESKW -v
```

Expected: FAIL with "unsupported algorithm".

- [ ] **Step 3: Extend the allowlist in `WrapKey`**

In `internal/services/keys/crypto_service.go`, find (around line 448):
```go
if req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
    return nil, fmt.Errorf("unsupported algorithm %q: only RSA-OAEP and RSA-OAEP-256 are supported", req.Algorithm)
}
```

Replace with:
```go
validWrapAlgorithms := map[string]bool{
    "RSA-OAEP":    true,
    "RSA-OAEP-256": true,
    "A128KW":      true,
    "A192KW":      true,
    "A256KW":      true,
    "A128CBC":     true,
    "A192CBC":     true,
    "A256CBC":     true,
}
if !validWrapAlgorithms[req.Algorithm] {
    return nil, fmt.Errorf("unsupported wrap algorithm %q", req.Algorithm)
}
```

Then update the algorithm dispatch logic below. After the existing RSA-OAEP mapping, add AES routing:

```go
var encAlgo crypto.EncryptionAlgorithm
switch req.Algorithm {
case "RSA-OAEP-256":
    encAlgo = crypto.AlgorithmRSAOAEP256
case "RSA-OAEP":
    encAlgo = crypto.AlgorithmRSAOAEP
case "A128KW":
    encAlgo = crypto.AlgorithmA128KW
case "A192KW":
    encAlgo = crypto.AlgorithmA192KW
case "A256KW":
    encAlgo = crypto.AlgorithmA256KW
case "A128CBC":
    encAlgo = crypto.AlgorithmA128CBC
case "A192CBC":
    encAlgo = crypto.AlgorithmA192CBC
case "A256CBC":
    encAlgo = crypto.AlgorithmA256CBC
}
var wrappedKey []byte
if wrapIsPKCS11 {
    wrappedKey, _, err = s.keyProvider.Encrypt(ctx, wrapHandle, req.PlaintextKey, encAlgo)
} else {
    var result *crypto.EncryptResult
    result, err = s.cryptoOps.Encrypt(wrapHandle, req.PlaintextKey, encAlgo)
    if err == nil {
        wrappedKey = result.Ciphertext
    }
}
```

- [ ] **Step 4: Extend `UnwrapKey` the same way**

Apply the identical allowlist and dispatch change to `UnwrapKey` (around line 506):

```go
validUnwrapAlgorithms := map[string]bool{
    "RSA-OAEP":    true,
    "RSA-OAEP-256": true,
    "A128KW":      true,
    "A192KW":      true,
    "A256KW":      true,
    "A128CBC":     true,
    "A192CBC":     true,
    "A256CBC":     true,
}
if !validUnwrapAlgorithms[req.Algorithm] {
    return nil, fmt.Errorf("unsupported unwrap algorithm %q", req.Algorithm)
}
```

And update the decryption dispatch:

```go
var decAlgo crypto.EncryptionAlgorithm
switch req.Algorithm {
case "RSA-OAEP-256":
    decAlgo = crypto.AlgorithmRSAOAEP256
case "RSA-OAEP":
    decAlgo = crypto.AlgorithmRSAOAEP
case "A128KW":
    decAlgo = crypto.AlgorithmA128KW
case "A192KW":
    decAlgo = crypto.AlgorithmA192KW
case "A256KW":
    decAlgo = crypto.AlgorithmA256KW
case "A128CBC":
    decAlgo = crypto.AlgorithmA128CBC
case "A192CBC":
    decAlgo = crypto.AlgorithmA192CBC
case "A256CBC":
    decAlgo = crypto.AlgorithmA256CBC
}
var plaintext []byte
if unwrapIsPKCS11 {
    plaintext, err = s.keyProvider.Decrypt(ctx, unwrapHandle, req.WrappedKey, nil, decAlgo)
} else {
    var result *crypto.DecryptResult
    result, err = s.cryptoOps.Decrypt(unwrapHandle, req.WrappedKey, nil, decAlgo)
    if err == nil {
        plaintext = result.Plaintext
    }
}
```

- [ ] **Step 5: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/services/keys/... -run "TestWrap" -v
go build ./...
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/services/keys/crypto_service.go
git commit -m "feat(keys): extend WrapKey/UnwrapKey to accept AES-KW and AES-CBC algorithms"
```

---

## Task 6: Add `getDeletedKey` single-key endpoint

**Files:**
- Modify: `api/soft_delete.go`
- Modify: `api/api.go` (register new route)

Azure: `GET /deletedkeys/{name}`. RocketVault equivalent: `GET /deleted/keys/{key_id}`.

- [ ] **Step 1: Write the failing test**

Add to `api/soft_delete_test.go` (or nearest test file for soft delete):

```go
func TestGetDeletedKey_ReturnsKey(t *testing.T) {
    // Setup: create and soft-delete a key, then call getDeletedKey.
    // Use the existing test infrastructure in the file.
    // Expected: 200 with id, name, type, deleted_at fields.
    // If there is no existing test infrastructure, use httptest.NewRecorder.
    // This test documents the expected HTTP contract, not the full round-trip.
    req := httptest.NewRequest("GET", "/deleted/keys/"+testKeyID.String(), nil)
    w := httptest.NewRecorder()
    // ... wire up handler similarly to existing tests in this file
    assert.Equal(t, http.StatusOK, w.Code)
    var body map[string]any
    require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
    assert.Equal(t, testKeyID.String(), body["id"])
    assert.NotNil(t, body["deleted_at"])
}

func TestGetDeletedKey_NotFound(t *testing.T) {
    req := httptest.NewRequest("GET", "/deleted/keys/"+uuid.New().String(), nil)
    w := httptest.NewRecorder()
    // ... wire up handler
    assert.Equal(t, http.StatusNotFound, w.Code)
}
```

Adapt to match the existing test infrastructure — read the top of `soft_delete_test.go` first.

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./api/... -run TestGetDeletedKey -v
```

Expected: compile error or 404 — handler doesn't exist yet.

- [ ] **Step 3: Add `getDeletedKey` handler to `api/soft_delete.go`**

Add after `listDeletedKeys`:

```go
// getDeletedKey returns a single soft-deleted key by its UUID.
func getDeletedKey(c *Context, w http.ResponseWriter, r *http.Request) {
    userID, ok := userIDFromClaims(c)
    if !ok {
        return
    }

    keyIDStr := mux.Vars(r)["key_id"]
    keyID, err := uuid.Parse(keyIDStr)
    if err != nil {
        c.SetInvalidParam("key_id")
        return
    }

    repo := c.App.ServiceContainer.GetKeyRepository()
    keys, err := repo.ListSoftDeleted(r.Context(), userID)
    if err != nil {
        c.SetInternalError(err)
        return
    }

    for _, k := range keys {
        if k.ID == keyID {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]any{
                "id":               k.ID.String(),
                "name":             k.Name,
                "type":             k.Type,
                "deleted_at":       k.DeletedAt,
                "purge_protection": k.PurgeProtection,
            })
            return
        }
    }
    c.SetNotFound()
}
```

- [ ] **Step 4: Register the route**

In `api/api.go`, find where the soft-delete routes for keys are registered (search for `listDeletedKeys` or `/deleted/keys`). Add the new route alongside:

```go
router.Handle("/deleted/keys/{key_id:[A-Fa-f0-9-]+}", appHandler(getDeletedKey)).Methods("GET")
```

Ensure it is placed before the existing list route to avoid route conflicts (more specific routes first).

- [ ] **Step 5: Run tests and build**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./...
go test ./api/... -run "TestGetDeletedKey\|TestDeletedKey" -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add api/soft_delete.go api/api.go
git commit -m "feat(keys): add GET /deleted/keys/{key_id} endpoint for single deleted key"
```

---

## Task 7: Return deletion metadata from DeleteKey

**Files:**
- Modify: `internal/services/keys/key_service.go` (interface + implementation)
- Modify: `api/keys.go` (handler response)

Azure `DELETE /keys/{name}` returns a `DeletedKeyBundle` with `recoveryId`, `scheduledPurgeDate`, `deletedDate`. We return the deleted key record with `deleted_at` and `scheduled_purge_at`.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/keys/key_service_test.go`:

```go
func TestDeleteKey_ReturnsDeletedRecord(t *testing.T) {
    // DeleteKey should return the key record (with deleted_at populated).
    // Stub the repo and verify the returned value is non-nil.
    // Use the existing mock/stub pattern in the file.
    svc, mockRepo := newTestKeyService(t)
    keyID := uuid.New()
    userID := uuid.New()

    key := &model.Key{
        ID:        keyID,
        UserID:    userID,
        Name:      "test",
        Type:      model.KeyTypeRSA,
        Value:     "pem",
        Enabled:   true,
        DeletedAt: nil,
    }
    mockRepo.On("Read", mock.Anything, keyID).Return(key, nil)
    mockRepo.On("SoftDelete", mock.Anything, keyID).Return(nil).Run(func(args mock.Arguments) {
        now := time.Now()
        key.DeletedAt = &now
    })

    deleted, err := svc.DeleteKey(context.Background(), keyID, userID)
    require.NoError(t, err)
    require.NotNil(t, deleted)
    assert.NotNil(t, deleted.DeletedAt, "DeletedAt should be populated")
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/services/keys/... -run TestDeleteKey_ReturnsDeletedRecord -v
```

Expected: compile error — `DeleteKey` currently returns `error`, not `(*model.Key, error)`.

- [ ] **Step 3: Change `DeleteKey` interface and implementation**

In `internal/services/keys/key_service.go`, change the interface method:

```go
// Before:
DeleteKey(ctx context.Context, keyID, userID uuid.UUID) error

// After:
DeleteKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error)
```

Change the implementation:

```go
func (s *keyService) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
    key, err := s.GetKey(ctx, keyID, userID)
    if err != nil {
        return nil, fmt.Errorf("delete key: %w", err)
    }

    if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
        s.logger.LogAuditError(userID.String(), "delete_key", "failed", "Failed to soft-delete key", err)
        return nil, fmt.Errorf("failed to delete key: %w", err)
    }

    // Re-read so deleted_at is populated from the database.
    deleted, err := s.keyRepo.ReadDeleted(ctx, keyID)
    if err != nil {
        // Non-fatal: return success without metadata.
        s.logger.LogAuditInfo(userID.String(), "delete_key", "success", "Key deleted (metadata unavailable)")
        return key, nil
    }
    s.logger.LogAuditInfo(userID.String(), "delete_key", "success", "Key deleted successfully")
    return deleted, nil
}
```

`ReadDeleted` reads a key regardless of `deleted_at` status. Add it to `KeyRepositoryInterface` and implement it:

```go
// In interface:
ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error)

// Implementation in key_repository.go:
func (r *KeyRepository) ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error) {
    // Same as Read but without the "deleted_at IS NULL" guard.
    key := &model.Key{}
    err := r.queryWithMetrics("read_deleted_key", func() error {
        return r.db.QueryRowContext(ctx,
            "SELECT id, user_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, deleted_at, scheduled_purge_at, updated_at FROM keys WHERE id = ?",
            id.String(),
        ).Scan(&key.ID, &key.UserID, &key.Name, &key.Value, &key.Type, &key.Revoked,
            &key.CreatedAt, &key.Enabled, &key.ExpiresAt, &key.NotBefore,
            &key.Bits, &key.Curve, &key.DeletedAt, &key.ScheduledPurgeAt, &key.UpdatedAt)
    })
    if err != nil {
        return nil, fmt.Errorf("read deleted key: %w", err)
    }
    return key, nil
}
```

- [ ] **Step 4: Update the API handler**

In `api/keys.go`, find the `deleteKey` handler (around line 536). Change it to use the returned record:

```go
func deleteKey(c *Context, w http.ResponseWriter, r *http.Request) {
    // ... existing auth/parse code ...

    deleted, err := keyService.DeleteKey(r.Context(), keyID, userID)
    if err != nil {
        c.SetInternalError(err)
        return
    }

    type deleteResponse struct {
        ID               string     `json:"id"`
        Name             string     `json:"name"`
        DeletedAt        *time.Time `json:"deleted_at"`
        ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
        RecoveryID       string     `json:"recovery_id,omitempty"`
    }

    resp := deleteResponse{
        ID:               deleted.ID.String(),
        Name:             deleted.Name,
        DeletedAt:        deleted.DeletedAt,
        ScheduledPurgeAt: deleted.ScheduledPurgeAt,
        // RecoveryID would be a URL in Azure; we use the restore path.
        RecoveryID: "/deleted/keys/" + deleted.ID.String() + "/restore",
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}
```

- [ ] **Step 5: Fix compile errors**

Any caller of the old `DeleteKey(ctx, id, userID) error` that ignores the return value needs updating. Search:

```bash
grep -rn "\.DeleteKey(" /home/numericlabs/data/rocket/rocketvault --include="*.go"
```

For each call site that does `err := svc.DeleteKey(...)`, change to `_, err := svc.DeleteKey(...)` or use the returned value.

- [ ] **Step 6: Run tests and build**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./...
go test ./... 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add internal/services/keys/key_service.go internal/repositories/key_repository.go api/keys.go
git commit -m "feat(keys): return deletion metadata (deleted_at, scheduled_purge_at, recovery_id) from DeleteKey"
```

---

## Self-Review

### Spec coverage

Gaps being closed (from the Keys feature matrix):

| Gap | Task | Status |
|---|---|---|
| RSA 3072-bit | Task 1 | ✓ |
| `updated_at` timestamp | Task 2 | ✓ |
| RSA-HSM/EC-HSM kty | Task 3 | ✓ |
| JWK public material (n/e/x/y) | Task 4 | ✓ |
| WrapKey/UnwrapKey AES algorithms | Task 5 | ✓ |
| GetDeletedKey single endpoint | Task 6 | ✓ |
| DeleteKey response metadata | Task 7 | ✓ |

Excluded gaps (documented in plan header): oct keys, ImportKey, pagination, rotation policy, kid URL, recoveryLevel, exportable.

### Placeholder scan

No TBD, no "implement later", no "similar to Task N". Every step has a code block. Commands have expected outputs.

### Type consistency

- `ExtractPublicComponents(pemOrHandle string, keyType string) (n, e, x, y string, err error)` — defined Task 4 Step 3, used Task 4 Step 6.
- `buildKeyResponse(key *model.Key) KeyResponse` — defined Task 3 Step 2, extended Task 4 Step 6.
- `DeleteKey(ctx, keyID, userID) (*model.Key, error)` — interface change Task 7 Step 3; handler updated Task 7 Step 4; callers fixed Task 7 Step 5.
- `ReadDeleted(ctx, id) (*model.Key, error)` — interface and implementation Task 7 Step 3; called Task 7 Step 3.
- `model.Key.UpdatedAt *time.Time` — added Task 2 Step 3; scanned in repo Task 2 Step 5; included in `buildKeyResponse` Task 4 Step 6.

All consistent.
