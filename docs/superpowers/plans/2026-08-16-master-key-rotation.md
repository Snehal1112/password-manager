# Master Key Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the RocketVault master key rotatable — a `rocketvault master-key rotate` command that re-encrypts every master-key-sealed database column from an old key to a new one, plus a startup guard that refuses to boot on the known-compromised committed default key.

**Architecture:** `common` gains key-parameterized AES-256-GCM primitives (`EncryptWithKey`/`DecryptWithKey`) so one process can decrypt under the old key and re-encrypt under the new one; a new `internal/rekey` package walks the five ciphertext columns (`secrets.value`, `secret_versions.value`, `keys.value`, `key_versions.value`, `certificates.private_key`) with raw dialect-aware SQL, classifying each row as skip-external / already-migrated / re-encrypt, then applying updates in batched transactions guarded by the old ciphertext; a Cobra subcommand drives it with a dry-run mode, and `bootstrap`'s `ConfigurationValidator` gains a weak-key check wired in after vault secret injection.

**Tech Stack:** Go 1.25, Cobra + Viper (CLI/config), `database/sql` via `internal/db` dialect wrapper (SQLite + Postgres), `crypto/aes` + `crypto/cipher` (AES-256-GCM), logrus via `internal/logging`, `testify` for the new package tests, stdlib `testing` for `common` tests (matching that package's existing style).

**Spec:** `docs/superpowers/specs/2026-08-16-master-key-rotation-design.md`

## Global Constraints

- AES-256 master key: exactly **32 raw bytes**, supplied base64-encoded. Both encrypt and decrypt paths enforce the exact length.
- The known-compromised default key is the 32 ASCII bytes `0123456789abcdef0123456789abcdef` (base64 `***SECRET-REMOVED-2026-08-17***`).
- **Never** log, print, or include in an error: either master key, or any decrypted plaintext. Only key *source names* ("environment variable NEW_MASTER_KEY") and row primary keys may appear in output.
- Key material is passed by **environment variable name**, never as a flag value — nothing secret in argv.
- Rows whose value starts with `pkcs11:` are HSM token handles, not ciphertext. Skip them; never attempt to decrypt them.
- Idempotency rule: a row that already decrypts with the **new** key is counted as already-migrated and left untouched. Try the new key *before* the old key on every row.
- No override/bypass flag for the startup guard. It fails closed, always.
- Every `UPDATE` must carry `AND <column> = <old ciphertext>` in its `WHERE` clause and assert `RowsAffected() == 1`.
- Task ordering is load-bearing: the bootstrap startup guard (Task 6) lands **after** the rotation tool (Tasks 3-5), because it makes this repo's committed dev config unbootable.
- Tests never touch a real database file — in-memory SQLite only.

---

### Task 1: Key-parameterized crypto primitives in `common`

**Files:**
- Modify: `common/encrypt.go:32-125`
- Test: `common/encrypt_key_test.go` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `common.ParseMasterKey(encoded string) ([]byte, error)`, `common.EncryptWithKey(value string, key []byte) (string, error)`, `common.DecryptWithKey(encryptedValue string, key []byte) (string, error)`. `common.EncryptSecret(value string) (string, error)` and `common.DecryptSecret(encryptedValue string) (string, error)` keep their exact current signatures and behavior — every existing caller is unaffected.

- [ ] **Step 1: Write the failing tests**

Create `common/encrypt_key_test.go` (stdlib `testing` style, matching `common/encrypt_test.go`):

```go
package common

import (
	"encoding/base64"
	"strings"
	"testing"
)

// rawKey builds a deterministic 32-byte key for tests. Distinct seeds give
// distinct keys.
func rawKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func TestEncryptWithKeyDecryptWithKey_RoundTrip(t *testing.T) {
	key := rawKey(1)
	plaintext := "my secret value"

	ciphertext, err := EncryptWithKey(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	if ciphertext == plaintext {
		t.Fatal("ciphertext must not equal plaintext")
	}

	decrypted, err := DecryptWithKey(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptWithKey failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptWithKey_WrongKeyFails(t *testing.T) {
	ciphertext, err := EncryptWithKey("my secret value", rawKey(1))
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}

	if _, err := DecryptWithKey(ciphertext, rawKey(100)); err == nil {
		t.Error("expected decryption with the wrong key to fail")
	}
}

func TestEncryptWithKey_NonceIsRandomPerCall(t *testing.T) {
	key := rawKey(1)

	first, err := EncryptWithKey("same plaintext", key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	second, err := EncryptWithKey("same plaintext", key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	if first == second {
		t.Error("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestEncryptWithKey_RejectsWrongKeyLength(t *testing.T) {
	if _, err := EncryptWithKey("value", []byte("short")); err == nil {
		t.Error("expected error for a key that is not 32 bytes")
	}
}

func TestDecryptWithKey_RejectsWrongKeyLength(t *testing.T) {
	if _, err := DecryptWithKey("Zm9v", []byte("short")); err == nil {
		t.Error("expected error for a key that is not 32 bytes")
	}
}

func TestParseMasterKey_Valid(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(rawKey(7))

	key, err := ParseMasterKey(encoded)
	if err != nil {
		t.Fatalf("ParseMasterKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}
}

func TestParseMasterKey_Empty(t *testing.T) {
	if _, err := ParseMasterKey(""); err == nil {
		t.Error("expected error for an empty master key")
	}
}

func TestParseMasterKey_NotBase64(t *testing.T) {
	if _, err := ParseMasterKey("not-base64!!"); err == nil {
		t.Error("expected error for a non-base64 master key")
	}
}

func TestParseMasterKey_WrongLength(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("sixteen bytes!!!"))

	_, err := ParseMasterKey(encoded)
	if err == nil {
		t.Fatal("expected error for a 16-byte master key")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Errorf("error should state the required length, got: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./common/ -run 'WithKey|ParseMasterKey' -v`
Expected: FAIL — compile error, `undefined: EncryptWithKey`, `undefined: DecryptWithKey`, `undefined: ParseMasterKey`.

- [ ] **Step 3: Implement the primitives**

In `common/encrypt.go`, replace the whole `EncryptSecret`/`DecryptSecret` block (currently lines 32-125) with this. Keep the file's existing imports — they are all still used.

```go
// masterKeySize is the AES-256 key length in raw bytes.
const masterKeySize = 32

// ParseMasterKey decodes a base64-encoded master key and checks its length.
// It makes no judgement about key quality; use ValidateMasterKey for that.
//
// Parameters:
//
//	encoded: The base64-encoded master key.
//
// Returns:
//
//	The raw 32-byte key and an error if the key is missing or malformed.
func ParseMasterKey(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("master key not configured")
	}

	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode master key: %w", err)
	}
	if len(key) != masterKeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", masterKeySize, len(key))
	}
	return key, nil
}

// EncryptWithKey seals a value with AES-256-GCM under an explicit key. A fresh
// random 12-byte nonce is prepended to the ciphertext and the result is
// base64-encoded. Taking the key as a parameter is what lets the master key
// rotation tool re-encrypt under a second key in the same process.
//
// Parameters:
//
//	value: The plaintext value.
//	key: The raw 32-byte AES-256 key.
//
// Returns:
//
//	The encrypted value (base64-encoded) and an error if encryption fails.
func EncryptWithKey(value string, key []byte) (string, error) {
	if len(key) != masterKeySize {
		return "", fmt.Errorf("master key must be %d bytes, got %d", masterKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithKey opens a value sealed by EncryptWithKey under an explicit key.
// AES-GCM is authenticated, so a wrong key reliably returns an error rather
// than garbage plaintext.
//
// Parameters:
//
//	encryptedValue: The encrypted value (base64-encoded).
//	key: The raw 32-byte AES-256 key.
//
// Returns:
//
//	The decrypted plaintext value and an error if decryption fails.
func DecryptWithKey(encryptedValue string, key []byte) (string, error) {
	if len(key) != masterKeySize {
		return "", fmt.Errorf("master key must be %d bytes, got %d", masterKeySize, len(key))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted value: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// EncryptSecret encrypts a secret value using AES-256-GCM under the master key
// from configuration.
//
// Parameters:
//
//	value: The plaintext secret value.
//
// Returns:
//
//	The encrypted value (base64-encoded) and an error if encryption fails.
func EncryptSecret(value string) (string, error) {
	key, err := ParseMasterKey(viper.GetString("master_key"))
	if err != nil {
		return "", err
	}
	return EncryptWithKey(value, key)
}

// DecryptSecret decrypts a secret value encrypted with AES-256-GCM under the
// master key from configuration.
//
// Parameters:
//
//	encryptedValue: The encrypted value (base64-encoded).
//
// Returns:
//
//	The decrypted plaintext value and an error if decryption fails.
func DecryptSecret(encryptedValue string) (string, error) {
	key, err := ParseMasterKey(viper.GetString("master_key"))
	if err != nil {
		return "", err
	}
	return DecryptWithKey(encryptedValue, key)
}
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `go test ./common/ -run 'WithKey|ParseMasterKey' -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Run the pre-existing `common` suite to prove the refactor changed no behavior**

Run: `go test ./common/ -v`
Expected: PASS, including the untouched `TestEncryptSecretAndDecryptSecret`, `TestEncryptSecret_MissingMasterKey`, `TestEncryptSecret_InvalidMasterKey`, `TestEncryptSecret_ShortMasterKey`, and the four `DecryptSecret` equivalents.

- [ ] **Step 6: Verify no other package regressed**

Run: `go build ./... && go test ./internal/services/secrets/ ./internal/services/keys/ ./internal/services/certificates/ ./internal/backup/`
Expected: PASS. These are the packages that call `EncryptSecret`/`DecryptSecret`.

- [ ] **Step 7: Commit**

```bash
git add common/encrypt.go common/encrypt_key_test.go
git commit -m "refactor(common): extract key-parameterized AES-256-GCM primitives

EncryptWithKey/DecryptWithKey/ParseMasterKey let a single process seal
under one key and open under another, which master key rotation needs.
EncryptSecret/DecryptSecret keep their signatures and become thin
wrappers that read master_key from config. Both directions now require
exactly 32 bytes (previously encrypt accepted >= 32, which aes.NewCipher
rejected one line later anyway)."
```

---

### Task 2: Weak master-key validation (`common.ValidateMasterKey`)

**Files:**
- Create: `common/masterkey.go`
- Test: `common/masterkey_test.go`

**Interfaces:**
- Consumes: `common.ParseMasterKey` (Task 1).
- Produces: `common.ValidateMasterKey(encoded string) error` — returns nil for a key that is safe to seal data with, a descriptive error otherwise.

- [ ] **Step 1: Write the failing tests**

Create `common/masterkey_test.go`:

```go
package common

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidateMasterKey_AcceptsRandomKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	if err := ValidateMasterKey(base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Errorf("expected a CSPRNG key to be accepted, got: %v", err)
	}
}

func TestValidateMasterKey_RejectsCommittedDefault(t *testing.T) {
	// The exact value committed to .rocketvault.yaml.
	const committed = "***SECRET-REMOVED-2026-08-17***"

	err := ValidateMasterKey(committed)
	if err == nil {
		t.Fatal("expected the known-compromised default key to be rejected")
	}
	if !strings.Contains(err.Error(), "known-compromised") {
		t.Errorf("error should identify the key as the compromised default, got: %v", err)
	}
	if !strings.Contains(err.Error(), "master-key rotate") {
		t.Errorf("error should point at the rotation command, got: %v", err)
	}
}

func TestValidateMasterKey_RejectsPrintableASCIIKey(t *testing.T) {
	typed := "correct horse battery staple 32b"
	if len(typed) != 32 {
		t.Fatalf("test fixture must be 32 bytes, got %d", len(typed))
	}

	err := ValidateMasterKey(base64.StdEncoding.EncodeToString([]byte(typed)))
	if err == nil {
		t.Fatal("expected an all-printable-ASCII key to be rejected")
	}
	if !strings.Contains(err.Error(), "openssl rand -base64 32") {
		t.Errorf("error should tell the operator how to generate a key, got: %v", err)
	}
}

func TestValidateMasterKey_RejectsLowDistinctByteKey(t *testing.T) {
	// 32 bytes drawn from only 4 distinct non-printable values.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i % 4)
	}

	if err := ValidateMasterKey(base64.StdEncoding.EncodeToString(key)); err == nil {
		t.Error("expected a low-entropy key to be rejected")
	}
}

func TestValidateMasterKey_RejectsShortKey(t *testing.T) {
	if err := ValidateMasterKey(base64.StdEncoding.EncodeToString([]byte("sixteen bytes!!!"))); err == nil {
		t.Error("expected a 16-byte key to be rejected")
	}
}

func TestValidateMasterKey_RejectsEmptyKey(t *testing.T) {
	if err := ValidateMasterKey(""); err == nil {
		t.Error("expected an empty key to be rejected")
	}
}

func TestValidateMasterKey_RejectsNonBase64Key(t *testing.T) {
	if err := ValidateMasterKey("not-base64!!"); err == nil {
		t.Error("expected a non-base64 key to be rejected")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./common/ -run ValidateMasterKey -v`
Expected: FAIL — compile error, `undefined: ValidateMasterKey`.

- [ ] **Step 3: Implement the validator**

Create `common/masterkey.go`:

```go
package common

import (
	"crypto/subtle"
	"fmt"
)

// compromisedDefaultKey is the placeholder master key that shipped in this
// repository's committed .rocketvault.yaml. It base64-decodes to the ASCII
// string "0123456789abcdef0123456789abcdef". A 2026-08-16 penetration test
// decrypted a live database with it, so any deployment still using it is
// considered breached.
var compromisedDefaultKey = []byte("0123456789abcdef0123456789abcdef")

// minDistinctBytes is the smallest number of distinct byte values a genuine
// 32-byte random key is expected to contain. Random keys average about 31
// distinct values, so the chance of rejecting a real CSPRNG key here is around
// 3e-10, while hand-made filler like "AAAA..." is caught immediately.
const minDistinctBytes = 16

// ValidateMasterKey reports whether a configured master key is safe to seal
// data with. It rejects a missing, malformed, or wrong-length key, the
// known-compromised committed default, keys that are entirely printable ASCII
// (typed by a human rather than produced by a CSPRNG), and keys with too few
// distinct byte values.
//
// The checks run most-specific-first so the operator sees the most actionable
// message. The key itself never appears in any returned error.
//
// Parameters:
//
//	encoded: The base64-encoded master key.
//
// Returns:
//
//	nil if the key is usable, otherwise an error explaining what to do.
func ValidateMasterKey(encoded string) error {
	key, err := ParseMasterKey(encoded)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(key, compromisedDefaultKey) == 1 {
		return fmt.Errorf("master key is the known-compromised default committed to this " +
			"repository (it decodes to \"0123456789abcdef0123456789abcdef\"); generate a new " +
			"key with \"openssl rand -base64 32\" and migrate existing data with " +
			"\"rocketvault master-key rotate\"")
	}

	if allPrintableASCII(key) {
		return fmt.Errorf("master key is entirely printable ASCII, which means it was typed " +
			"rather than generated; generate a new key with \"openssl rand -base64 32\" and " +
			"migrate existing data with \"rocketvault master-key rotate\"")
	}

	if distinctBytes(key) < minDistinctBytes {
		return fmt.Errorf("master key has fewer than %d distinct byte values, which no CSPRNG "+
			"output realistically has; generate a new key with \"openssl rand -base64 32\" and "+
			"migrate existing data with \"rocketvault master-key rotate\"", minDistinctBytes)
	}

	return nil
}

// allPrintableASCII reports whether every byte is a printable ASCII character.
func allPrintableASCII(key []byte) bool {
	for _, b := range key {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// distinctBytes counts how many different byte values appear in key.
func distinctBytes(key []byte) int {
	var seen [256]bool
	count := 0
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			count++
		}
	}
	return count
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./common/ -run ValidateMasterKey -v`
Expected: PASS — all seven tests.

- [ ] **Step 5: Commit**

```bash
git add common/masterkey.go common/masterkey_test.go
git commit -m "feat(common): add ValidateMasterKey weak-key detection

Rejects the known-compromised committed default key, wrong-length keys,
all-printable-ASCII keys, and keys with implausibly few distinct bytes.
Errors name openssl rand -base64 32 and the rotation command; the key
itself is never included in an error."
```

---

### Task 3: Rekey targets and per-row classification

**Files:**
- Create: `internal/rekey/targets.go`
- Create: `internal/rekey/classify.go`
- Test: `internal/rekey/classify_test.go`

**Interfaces:**
- Consumes: `common.EncryptWithKey`, `common.DecryptWithKey` (Task 1).
- Produces: `rekey.Target{Table, Column string; KeyColumns []string}` with methods `SelectSQL() string` and `UpdateSQL() string`; `rekey.Targets() []Target`; unexported `action` constants `actionReEncrypt`, `actionAlreadyNewKey`, `actionSkipExternal`; unexported `classify(value string, oldKey, newKey []byte) (action, string, error)`; exported `rekey.ErrUndecryptable`; exported `rekey.ExternalKeyPrefix`.

- [ ] **Step 1: Write the failing tests**

Create `internal/rekey/classify_test.go`:

```go
package rekey

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

// testKey builds a deterministic 32-byte key. Distinct seeds give distinct keys.
func testKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func TestClassify_ReEncryptsOldKeyValue(t *testing.T) {
	oldKey, newKey := testKey(1), testKey(100)
	sealed, err := common.EncryptWithKey("secret-value", oldKey)
	require.NoError(t, err)

	act, resealed, err := classify(sealed, oldKey, newKey)
	require.NoError(t, err)
	assert.Equal(t, actionReEncrypt, act)
	assert.NotEqual(t, sealed, resealed)

	plaintext, err := common.DecryptWithKey(resealed, newKey)
	require.NoError(t, err)
	assert.Equal(t, "secret-value", plaintext)
}

func TestClassify_DetectsAlreadyMigratedValue(t *testing.T) {
	oldKey, newKey := testKey(1), testKey(100)
	sealed, err := common.EncryptWithKey("secret-value", newKey)
	require.NoError(t, err)

	act, resealed, err := classify(sealed, oldKey, newKey)
	require.NoError(t, err)
	assert.Equal(t, actionAlreadyNewKey, act)
	assert.Empty(t, resealed)
}

func TestClassify_SkipsPKCS11Handle(t *testing.T) {
	act, resealed, err := classify("pkcs11:6f1c0a3e-1c1a-4a5f-9a3e-2b0d5f8c1a77", testKey(1), testKey(100))
	require.NoError(t, err)
	assert.Equal(t, actionSkipExternal, act)
	assert.Empty(t, resealed)
}

func TestClassify_UndecryptableValue(t *testing.T) {
	sealed, err := common.EncryptWithKey("secret-value", testKey(50))
	require.NoError(t, err)

	_, _, err = classify(sealed, testKey(1), testKey(100))
	assert.True(t, errors.Is(err, ErrUndecryptable), "expected ErrUndecryptable, got %v", err)
}

func TestClassify_GarbageValue(t *testing.T) {
	_, _, err := classify("this is not ciphertext", testKey(1), testKey(100))
	assert.True(t, errors.Is(err, ErrUndecryptable), "expected ErrUndecryptable, got %v", err)
}

func TestTargets_CoverEveryMasterKeyColumn(t *testing.T) {
	got := map[string]string{}
	for _, target := range Targets() {
		got[target.Table] = target.Column
	}

	assert.Equal(t, map[string]string{
		"secrets":         "value",
		"secret_versions": "value",
		"keys":            "value",
		"key_versions":    "value",
		"certificates":    "private_key",
	}, got)
}

func TestTarget_SelectSQL(t *testing.T) {
	target := Target{Table: "key_versions", Column: "value", KeyColumns: []string{"key_id", "version"}}
	assert.Equal(t, "SELECT key_id, version, value FROM key_versions", target.SelectSQL())
}

func TestTarget_UpdateSQL(t *testing.T) {
	target := Target{Table: "key_versions", Column: "value", KeyColumns: []string{"key_id", "version"}}
	assert.Equal(t,
		"UPDATE key_versions SET value = ? WHERE key_id = ? AND version = ? AND value = ?",
		target.UpdateSQL())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/rekey/ -v`
Expected: FAIL — the package does not exist yet (`no Go files in .../internal/rekey`).

- [ ] **Step 3: Implement the targets**

Create `internal/rekey/targets.go`:

```go
// Package rekey re-encrypts every master-key-sealed column in the database
// from an old master key to a new one.
//
// It works on raw ciphertext columns rather than through the repository layer
// on purpose: rotation must reach soft-deleted rows and version-history rows
// owned by any user (repository reads are scope- and soft-delete-filtered),
// must write ciphertext verbatim (services re-encrypt on the way through), and
// is a storage-format maintenance operation rather than a domain operation —
// the same category as internal/backup, which talks to the database directly
// for the same reasons.
package rekey

import (
	"fmt"
	"strings"
)

// ExternalKeyPrefix marks a keys/key_versions row whose value is a PKCS#11
// token label rather than master-key-sealed PEM. Mirrors pkcs11Prefix in
// internal/services/keys/crypto_service.go — HSM key material never leaves the
// token, so those rows have nothing to re-encrypt.
const ExternalKeyPrefix = "pkcs11:"

// Target describes one table column that stores AES-256-GCM ciphertext sealed
// with the master key, plus the primary-key columns used to address a row.
type Target struct {
	Table      string
	Column     string
	KeyColumns []string
}

// Targets returns every table column encrypted with the master key. Derived by
// mapping every caller of common.EncryptSecret to the column it writes:
// secrets and their version history, software (non-HSM) key PEMs and their
// version history, and certificate private-key PEMs. The JWT signing key used
// by internal/signing.SelfPKIProvider is an ordinary "keys" row and is covered
// by that entry.
//
// Returns:
//
//	The fixed list of master-key-encrypted columns.
func Targets() []Target {
	return []Target{
		{Table: "secrets", Column: "value", KeyColumns: []string{"id"}},
		{Table: "secret_versions", Column: "value", KeyColumns: []string{"id"}},
		{Table: "keys", Column: "value", KeyColumns: []string{"id"}},
		{Table: "key_versions", Column: "value", KeyColumns: []string{"key_id", "version"}},
		{Table: "certificates", Column: "private_key", KeyColumns: []string{"id"}},
	}
}

// SelectSQL builds the statement that reads every row's primary key and
// ciphertext. Table and column names come from the hardcoded Targets list, not
// from user input, so interpolating them is safe here.
//
// Returns:
//
//	A SELECT statement listing the key columns followed by the value column.
func (t Target) SelectSQL() string {
	return fmt.Sprintf("SELECT %s, %s FROM %s",
		strings.Join(t.KeyColumns, ", "), t.Column, t.Table)
}

// UpdateSQL builds the guarded re-encryption statement. The trailing
// "AND <column> = ?" compares against the ciphertext read during the plan
// phase, so a row rewritten by a still-running server matches zero rows
// instead of being silently clobbered.
//
// Returns:
//
//	An UPDATE statement whose arguments are (new value, key values..., old value).
func (t Target) UpdateSQL() string {
	conditions := make([]string, 0, len(t.KeyColumns)+1)
	for _, column := range t.KeyColumns {
		conditions = append(conditions, column+" = ?")
	}
	conditions = append(conditions, t.Column+" = ?")

	return fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s",
		t.Table, t.Column, strings.Join(conditions, " AND "))
}
```

- [ ] **Step 4: Implement the classifier**

Create `internal/rekey/classify.go`:

```go
package rekey

import (
	"errors"
	"fmt"
	"strings"

	"rocketvault/common"
)

// ErrUndecryptable means a stored value opened with neither the old nor the
// new master key. Almost always a wrong --old-key-env; possibly a row sealed
// with a third, unknown key.
var ErrUndecryptable = errors.New("value decrypts with neither the old nor the new master key")

// action is what a rotation run must do with one stored value.
type action int

const (
	// actionReEncrypt means the value opened with the old key and must be resealed.
	actionReEncrypt action = iota
	// actionAlreadyNewKey means the value already opens with the new key.
	actionAlreadyNewKey
	// actionSkipExternal means the value is a PKCS#11 handle, not ciphertext.
	actionSkipExternal
)

// classify decides what to do with a single stored value.
//
// The new key is tried before the old key, and that ordering is what makes a
// rotation safe to interrupt: AES-GCM is authenticated, so opening with the
// new key succeeding is a reliable "this row was already migrated" signal. No
// marker column or progress file is needed, and re-running after a crash
// simply skips the rows that are already done.
//
// The decrypted plaintext lives only as a local here and is passed straight
// back into EncryptWithKey. It is never logged, returned, or put in an error.
//
// Parameters:
//
//	value: The stored column value.
//	oldKey: The current 32-byte master key.
//	newKey: The replacement 32-byte master key.
//
// Returns:
//
//	The action to take, the resealed value (only for actionReEncrypt), and an
//	error if the value opens with neither key.
func classify(value string, oldKey, newKey []byte) (action, string, error) {
	if strings.HasPrefix(value, ExternalKeyPrefix) {
		return actionSkipExternal, "", nil
	}

	if _, err := common.DecryptWithKey(value, newKey); err == nil {
		return actionAlreadyNewKey, "", nil
	}

	plaintext, err := common.DecryptWithKey(value, oldKey)
	if err != nil {
		return actionReEncrypt, "", ErrUndecryptable
	}

	resealed, err := common.EncryptWithKey(plaintext, newKey)
	if err != nil {
		return actionReEncrypt, "", fmt.Errorf("re-encrypt with the new master key: %w", err)
	}

	return actionReEncrypt, resealed, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/rekey/ -v`
Expected: PASS — all eight tests.

- [ ] **Step 6: Commit**

```bash
git add internal/rekey/targets.go internal/rekey/classify.go internal/rekey/classify_test.go
git commit -m "feat(rekey): add master-key column targets and row classification

Targets() lists the five columns sealed with master_key (secrets,
secret_versions, keys, key_versions, certificates). classify() tries the
new key before the old one so an interrupted rotation resumes without
double-encrypting, and skips pkcs11: HSM handles."
```

---

### Task 4: Rekey engine — plan, apply, report

**Files:**
- Create: `internal/rekey/rekey.go`
- Test: `internal/rekey/rekey_test.go`

**Interfaces:**
- Consumes: `rekey.Target`, `rekey.Targets`, `classify`, `rekey.ErrUndecryptable` (Task 3); `internal/db.DB` / `db.NewConn` / `db.SQLite`; `internal/logging.Logger`.
- Produces: `rekey.Options{OldKey, NewKey []byte; DryRun bool; BatchSize int}`, `rekey.TargetReport{Table, Column string; Total, ReEncrypted, AlreadyNewKey, SkippedExternal int}`, `rekey.Report{Targets []TargetReport; DryRun bool}` with `Report.TotalReEncrypted() int`, `rekey.DefaultBatchSize`, `rekey.New(database rvdb.DB, logger *logging.Logger) *Rekeyer`, `(*Rekeyer).Run(ctx context.Context, opts Options) (*Report, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/rekey/rekey_test.go`:

```go
package rekey

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// newTestDB creates a throwaway in-memory SQLite database with the five
// master-key-encrypted tables, reduced to just the columns rekey touches.
// MaxOpenConns(1) is required: every new connection to ":memory:" would
// otherwise get its own empty database.
func newTestDB(t *testing.T) *rvdb.Conn {
	t.Helper()

	raw, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	raw.SetMaxOpenConns(1)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec

	_, err = raw.Exec(`
		CREATE TABLE secrets (id TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE secret_versions (id TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE keys (id TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE key_versions (
			key_id  TEXT NOT NULL,
			version INTEGER NOT NULL,
			value   TEXT NOT NULL,
			PRIMARY KEY (key_id, version)
		);
		CREATE TABLE certificates (id TEXT PRIMARY KEY, private_key TEXT NOT NULL);
	`)
	require.NoError(t, err)

	return rvdb.NewConn(raw, rvdb.SQLite)
}

func testLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

// seal encrypts a plaintext under key, failing the test if that is not possible.
func seal(t *testing.T, plaintext string, key []byte) string {
	t.Helper()
	value, err := common.EncryptWithKey(plaintext, key)
	require.NoError(t, err)
	return value
}

// exec runs a statement against the test database.
func exec(t *testing.T, conn *rvdb.Conn, query string, args ...any) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(), query, args...)
	require.NoError(t, err)
}

// readValue returns a single column value from the test database.
func readValue(t *testing.T, conn *rvdb.Conn, query string) string {
	t.Helper()
	var value string
	require.NoError(t, conn.QueryRowContext(context.Background(), query).Scan(&value))
	return value
}

// seedAllTargets inserts one row per target, sealed with key.
func seedAllTargets(t *testing.T, conn *rvdb.Conn, key []byte) {
	t.Helper()
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "s1", seal(t, "secret-one", key))
	exec(t, conn, "INSERT INTO secret_versions (id, value) VALUES (?, ?)", "sv1", seal(t, "secret-one-v1", key))
	exec(t, conn, "INSERT INTO keys (id, value) VALUES (?, ?)", "k1", seal(t, "key-pem", key))
	exec(t, conn, "INSERT INTO key_versions (key_id, version, value) VALUES (?, ?, ?)", "k1", 1, seal(t, "key-pem-v1", key))
	exec(t, conn, "INSERT INTO certificates (id, private_key) VALUES (?, ?)", "c1", seal(t, "cert-pem", key))
}

func TestRun_ReEncryptsEveryTarget(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, oldKey)

	report, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)
	assert.Equal(t, 5, report.TotalReEncrypted())
	assert.Len(t, report.Targets, 5)

	for query, want := range map[string]string{
		"SELECT value FROM secrets WHERE id = 's1'":                          "secret-one",
		"SELECT value FROM secret_versions WHERE id = 'sv1'":                 "secret-one-v1",
		"SELECT value FROM keys WHERE id = 'k1'":                             "key-pem",
		"SELECT value FROM key_versions WHERE key_id = 'k1' AND version = 1": "key-pem-v1",
		"SELECT private_key FROM certificates WHERE id = 'c1'":               "cert-pem",
	} {
		stored := readValue(t, conn, query)

		_, err := common.DecryptWithKey(stored, oldKey)
		assert.Error(t, err, "row should no longer open with the old key: %s", query)

		plaintext, err := common.DecryptWithKey(stored, newKey)
		require.NoError(t, err, "row should open with the new key: %s", query)
		assert.Equal(t, want, plaintext)
	}
}

func TestRun_DryRunReportsWithoutWriting(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, oldKey)
	before := readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'")

	report, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: oldKey, NewKey: newKey, DryRun: true,
	})
	require.NoError(t, err)
	assert.True(t, report.DryRun)
	assert.Equal(t, 5, report.TotalReEncrypted())

	assert.Equal(t, before, readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'"),
		"dry run must not modify any row")
	_, err = common.DecryptWithKey(readValue(t, conn, "SELECT value FROM keys WHERE id = 'k1'"), oldKey)
	assert.NoError(t, err, "dry run must leave rows on the old key")
}

func TestRun_SecondRunIsANoOp(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, oldKey)
	rekeyer := New(conn, testLogger())

	_, err := rekeyer.Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)
	afterFirst := readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'")

	report, err := rekeyer.Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)
	assert.Equal(t, 0, report.TotalReEncrypted())
	for _, target := range report.Targets {
		assert.Equal(t, target.Total, target.AlreadyNewKey, "table %s", target.Table)
	}
	assert.Equal(t, afterFirst, readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'"),
		"a second run must not rewrite already-migrated rows")
}

func TestRun_ResumesPartiallyMigratedTable(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "old", seal(t, "still-old", oldKey))
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "new", seal(t, "already-new", newKey))

	report, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)

	secrets := report.Targets[0]
	require.Equal(t, "secrets", secrets.Table)
	assert.Equal(t, 2, secrets.Total)
	assert.Equal(t, 1, secrets.ReEncrypted)
	assert.Equal(t, 1, secrets.AlreadyNewKey)

	plaintext, err := common.DecryptWithKey(readValue(t, conn, "SELECT value FROM secrets WHERE id = 'old'"), newKey)
	require.NoError(t, err)
	assert.Equal(t, "still-old", plaintext)
}

func TestRun_SkipsPKCS11Rows(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	const handle = "pkcs11:6f1c0a3e-1c1a-4a5f-9a3e-2b0d5f8c1a77"
	exec(t, conn, "INSERT INTO keys (id, value) VALUES (?, ?)", "hsm", handle)
	exec(t, conn, "INSERT INTO keys (id, value) VALUES (?, ?)", "soft", seal(t, "key-pem", oldKey))

	report, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)

	var keysReport TargetReport
	for _, target := range report.Targets {
		if target.Table == "keys" {
			keysReport = target
		}
	}
	assert.Equal(t, 1, keysReport.SkippedExternal)
	assert.Equal(t, 1, keysReport.ReEncrypted)
	assert.Equal(t, handle, readValue(t, conn, "SELECT value FROM keys WHERE id = 'hsm'"))
}

func TestRun_WrongOldKeyAbortsWithoutWriting(t *testing.T) {
	conn := newTestDB(t)
	realKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, realKey)
	before := readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'")

	_, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: testKey(200), NewKey: newKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets.value")

	assert.Equal(t, before, readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'"),
		"a failed classification must not write anything")
}

func TestRun_RejectsIdenticalKeys(t *testing.T) {
	conn := newTestDB(t)
	key := testKey(1)

	_, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: key, NewKey: key})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identical")
}

func TestRun_RejectsWrongKeyLength(t *testing.T) {
	conn := newTestDB(t)

	_, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: []byte("short"), NewKey: testKey(100),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32")
}

func TestRun_BatchSizeSmallerThanRowCount(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", id, seal(t, "value-"+id, oldKey))
	}

	report, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: oldKey, NewKey: newKey, BatchSize: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, 5, report.TotalReEncrypted())

	for _, id := range []string{"a", "b", "c", "d", "e"} {
		stored := readValue(t, conn, "SELECT value FROM secrets WHERE id = '"+id+"'")
		plaintext, err := common.DecryptWithKey(stored, newKey)
		require.NoError(t, err)
		assert.Equal(t, "value-"+id, plaintext)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/rekey/ -run TestRun -v`
Expected: FAIL — compile error, `undefined: New`, `undefined: Options`, `undefined: TargetReport`.

- [ ] **Step 3: Implement the engine**

Create `internal/rekey/rekey.go`:

```go
package rekey

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// DefaultBatchSize is how many row updates share one transaction when the
// caller does not choose.
const DefaultBatchSize = 100

// masterKeySize is the AES-256 key length in raw bytes.
const masterKeySize = 32

// Options configures a rotation run.
type Options struct {
	// OldKey is the 32-byte key the stored data is currently sealed with.
	OldKey []byte
	// NewKey is the 32-byte key to reseal the data with.
	NewKey []byte
	// DryRun reports what would change without writing anything.
	DryRun bool
	// BatchSize is the number of row updates per transaction.
	BatchSize int
}

// TargetReport summarises what happened to one table column.
type TargetReport struct {
	Table           string
	Column          string
	Total           int
	ReEncrypted     int
	AlreadyNewKey   int
	SkippedExternal int
}

// Report summarises a whole rotation run.
type Report struct {
	Targets []TargetReport
	DryRun  bool
}

// TotalReEncrypted returns how many rows were resealed across all targets (or,
// for a dry run, how many would be).
func (r Report) TotalReEncrypted() int {
	total := 0
	for _, target := range r.Targets {
		total += target.ReEncrypted
	}
	return total
}

// Rekeyer re-encrypts master-key-sealed columns from one key to another.
type Rekeyer struct {
	db     rvdb.DB
	logger *logging.Logger
}

// pendingUpdate is one planned row rewrite.
type pendingUpdate struct {
	keys     []any
	oldValue string
	newValue string
}

// New creates a Rekeyer bound to a dialect-aware database connection.
//
// Parameters:
//
//	database: The dialect-aware connection whose rows will be rewritten.
//	logger: The logger used for per-batch progress counters.
//
// Returns:
//
//	A Rekeyer ready to Run.
func New(database rvdb.DB, logger *logging.Logger) *Rekeyer {
	return &Rekeyer{db: database, logger: logger}
}

// Run re-encrypts every master-key-sealed column from opts.OldKey to
// opts.NewKey, one target at a time. Each target is fully read and classified
// before any of its rows are written, so a value that opens with neither key
// aborts that target with no partial write. Targets completed before a failure
// stay migrated; re-running with the same key pair resumes safely because
// already-migrated rows are detected and skipped.
//
// Parameters:
//
//	ctx: The context for the run.
//	opts: The keys, dry-run flag, and batch size.
//
// Returns:
//
//	A report covering every target processed so far, and an error if the run
//	could not complete.
func (r *Rekeyer) Run(ctx context.Context, opts Options) (*Report, error) {
	if len(opts.OldKey) != masterKeySize || len(opts.NewKey) != masterKeySize {
		return nil, fmt.Errorf("both master keys must be %d raw bytes", masterKeySize)
	}
	if bytes.Equal(opts.OldKey, opts.NewKey) {
		return nil, fmt.Errorf("the new master key is identical to the old one — nothing to rotate " +
			"(if MASTER_KEY is exported in this shell it takes precedence over the config file, " +
			"so the old key resolved to the new one)")
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultBatchSize
	}

	report := &Report{DryRun: opts.DryRun}
	for _, target := range Targets() {
		targetReport, err := r.processTarget(ctx, target, opts)
		if targetReport != nil {
			report.Targets = append(report.Targets, *targetReport)
		}
		if err != nil {
			return report, fmt.Errorf("%s.%s: %w", target.Table, target.Column, err)
		}
	}
	return report, nil
}

// processTarget plans one target, then applies it unless this is a dry run.
func (r *Rekeyer) processTarget(ctx context.Context, target Target, opts Options) (*TargetReport, error) {
	pending, targetReport, err := r.planTarget(ctx, target, opts)
	if err != nil {
		return nil, err
	}
	if opts.DryRun || len(pending) == 0 {
		return targetReport, nil
	}
	if err := r.applyTarget(ctx, target, pending, opts.BatchSize); err != nil {
		return targetReport, err
	}
	return targetReport, nil
}

// planTarget reads and classifies every row of one target without writing.
func (r *Rekeyer) planTarget(ctx context.Context, target Target, opts Options) ([]pendingUpdate, *TargetReport, error) {
	rows, err := r.db.QueryContext(ctx, target.SelectSQL())
	if err != nil {
		return nil, nil, fmt.Errorf("read rows: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	targetReport := &TargetReport{Table: target.Table, Column: target.Column}
	var pending []pendingUpdate

	for rows.Next() {
		// Key columns are scanned as strings on both dialects: SQLite applies
		// column affinity and Postgres infers the parameter type, so an
		// integer key column such as key_versions.version round-trips
		// correctly as text.
		keyValues := make([]string, len(target.KeyColumns))
		scanTargets := make([]any, 0, len(target.KeyColumns)+1)
		for i := range keyValues {
			scanTargets = append(scanTargets, &keyValues[i])
		}
		var value string
		scanTargets = append(scanTargets, &value)

		if err := rows.Scan(scanTargets...); err != nil {
			return nil, nil, fmt.Errorf("scan row: %w", err)
		}
		targetReport.Total++

		act, resealed, err := classify(value, opts.OldKey, opts.NewKey)
		if err != nil {
			return nil, nil, fmt.Errorf("row %s: %w", strings.Join(keyValues, "/"), err)
		}

		switch act {
		case actionSkipExternal:
			targetReport.SkippedExternal++
		case actionAlreadyNewKey:
			targetReport.AlreadyNewKey++
		case actionReEncrypt:
			targetReport.ReEncrypted++
			pending = append(pending, pendingUpdate{
				keys:     toArgs(keyValues),
				oldValue: value,
				newValue: resealed,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate rows: %w", err)
	}

	return pending, targetReport, nil
}

// applyTarget writes the planned updates in batched transactions.
func (r *Rekeyer) applyTarget(ctx context.Context, target Target, pending []pendingUpdate, batchSize int) error {
	updateSQL := target.UpdateSQL()

	for start := 0; start < len(pending); start += batchSize {
		end := start + batchSize
		if end > len(pending) {
			end = len(pending)
		}
		if err := r.applyBatch(ctx, updateSQL, pending[start:end]); err != nil {
			return err
		}
		r.logger.WithFields(logrus.Fields{
			"table":   target.Table,
			"column":  target.Column,
			"updated": end,
			"total":   len(pending),
		}).Info("Master key rotation progress")
	}
	return nil
}

// applyBatch rewrites one batch of rows inside a single transaction. Each
// update is guarded by the ciphertext read during the plan phase, so a row
// changed by a still-running server aborts the run instead of being clobbered.
func (r *Rekeyer) applyBatch(ctx context.Context, updateSQL string, batch []pendingUpdate) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	for _, update := range batch {
		args := make([]any, 0, len(update.keys)+2)
		args = append(args, update.newValue)
		args = append(args, update.keys...)
		args = append(args, update.oldValue)

		result, err := tx.ExecContext(ctx, updateSQL, args...)
		if err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("update row %v: %w", update.keys, err)
		}

		affected, err := result.RowsAffected()
		if err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("rows affected for row %v: %w", update.keys, err)
		}
		if affected != 1 {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("row %v changed while the rotation was running "+
				"(%d rows updated, expected 1) — stop the RocketVault server and re-run",
				update.keys, affected)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// toArgs converts scanned key-column values into query arguments.
func toArgs(values []string) []any {
	args := make([]any, len(values))
	for i, value := range values {
		args[i] = value
	}
	return args
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/rekey/ -v`
Expected: PASS — the eight classification/target tests from Task 3 plus the nine `TestRun_*` tests.

- [ ] **Step 5: Run the package under the race detector**

Run: `go test ./internal/rekey/ -race`
Expected: PASS, no race reports.

- [ ] **Step 6: Commit**

```bash
git add internal/rekey/rekey.go internal/rekey/rekey_test.go
git commit -m "feat(rekey): add plan-then-apply master key re-encryption engine

Reads and classifies every row of a target before writing any of it, so a
wrong old key aborts with no partial write. Updates run in batched
transactions guarded by the old ciphertext and assert RowsAffected == 1,
turning concurrent writes into a loud failure. Dry-run mode reports the
same counts without writing."
```

---

### Task 5: `rocketvault master-key rotate` CLI command

**Files:**
- Create: `cmd/master_key.go`
- Test: `cmd/master_key_test.go`
- Reference (do not modify): `cmd/backup.go:45-56` (admin gate pattern), `cmd/root.go:220-260` (`persistentPreRun` context keys)

**Interfaces:**
- Consumes: `rekey.New`, `rekey.Options`, `rekey.Report` (Task 4); `common.ParseMasterKey`, `common.ValidateMasterKey` (Tasks 1-2); `common.DBKey`, `common.LogKey`, `common.ClaimsKey` context keys; `db.NewConn`, `db.DialectFromDriver`.
- Produces: the `master-key` command group with the `rotate` subcommand; unexported `requireMasterKeyAdmin(cmd *cobra.Command) (*model.Claims, error)` and `resolveRotationKeys(oldKeyEnv, newKeyEnv string) (oldKey, newKey []byte, oldSource string, err error)`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/master_key_test.go`:

```go
package cmd

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/model"
)

// encodedKey returns a base64 32-byte key built from seed. Distinct seeds give
// distinct keys, and the byte spread passes common.ValidateMasterKey.
func encodedKey(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)*7
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestRequireMasterKeyAdmin_NoClaims(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	_, err := requireMasterKeyAdmin(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestRequireMasterKeyAdmin_NonAdminRole(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{
		UserID: uuid.New(), Username: "bob", Role: model.RoleUser,
	}))

	_, err := requireMasterKeyAdmin(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin")
}

func TestRequireMasterKeyAdmin_Admin(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{
		UserID: uuid.New(), Username: "admin", Role: model.RoleAdmin,
	}))

	claims, err := requireMasterKeyAdmin(cmd)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Username)
}

func TestResolveRotationKeys_OldKeyFromConfig(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", encodedKey(100))

	oldKey, newKey, oldSource, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.NoError(t, err)
	assert.Len(t, oldKey, 32)
	assert.Len(t, newKey, 32)
	assert.Contains(t, oldSource, "config file")
}

func TestResolveRotationKeys_OldKeyFromEnv(t *testing.T) {
	t.Setenv("TEST_OLD_MASTER_KEY", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", encodedKey(100))

	_, _, oldSource, err := resolveRotationKeys("TEST_OLD_MASTER_KEY", "TEST_NEW_MASTER_KEY")
	require.NoError(t, err)
	assert.Contains(t, oldSource, "TEST_OLD_MASTER_KEY")
}

func TestResolveRotationKeys_MissingNewKeyEnvValue(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", "")

	_, _, _, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TEST_NEW_MASTER_KEY")
	assert.Contains(t, err.Error(), "openssl rand -base64 32")
}

func TestResolveRotationKeys_RejectsWeakNewKey(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", "***SECRET-REMOVED-2026-08-17***")

	_, _, _, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "known-compromised")
}

func TestResolveRotationKeys_RejectsIdenticalKeys(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", encodedKey(1))

	_, _, _, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identical")
}

func TestMasterKeyRotateCmd_IsRegistered(t *testing.T) {
	var found *cobra.Command
	for _, sub := range rootCmd.Commands() {
		if sub.Name() == "master-key" {
			found = sub
		}
	}
	require.NotNil(t, found, "master-key command group must be registered on rootCmd")

	var rotate *cobra.Command
	for _, sub := range found.Commands() {
		if sub.Name() == "rotate" {
			rotate = sub
		}
	}
	require.NotNil(t, rotate, "rotate subcommand must be registered")
	assert.NotNil(t, rotate.Flags().Lookup("new-key-env"))
	assert.NotNil(t, rotate.Flags().Lookup("old-key-env"))
	assert.NotNil(t, rotate.Flags().Lookup("dry-run"))
	assert.NotNil(t, rotate.Flags().Lookup("batch-size"))
	assert.NotNil(t, rotate.Flags().Lookup("yes"))
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/ -run 'MasterKey|ResolveRotationKeys' -v`
Expected: FAIL — compile error, `undefined: requireMasterKeyAdmin`, `undefined: resolveRotationKeys`.

- [ ] **Step 3: Implement the command**

Create `cmd/master_key.go`:

```go
package cmd

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/rekey"
	"rocketvault/model"
)

var (
	rotateOldKeyEnv string
	rotateNewKeyEnv string
	rotateDryRun    bool
	rotateBatchSize int
	rotateAssumeYes bool
)

// masterKeyCmd groups master-key maintenance operations. The noun group keeps
// it distinct from the unrelated "rotation" command (scheduled secret
// rotation) and "keys rotate" (per-key material rotation).
var masterKeyCmd = &cobra.Command{
	Use:   "master-key",
	Short: "Manage the master encryption key",
	Long: `Manage the master key that seals secrets, software key PEMs, and
certificate private keys at rest.`,
}

// masterKeyRotateCmd re-encrypts all master-key-sealed data onto a new key.
var masterKeyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Re-encrypt all stored data onto a new master key",
	Long: `Re-encrypt every master-key-sealed database column onto a new key.

Both keys are read from environment variables by name so no key material ever
appears in the command line. The old key defaults to the master_key currently
in the configuration file.

Stop the RocketVault server and take a database backup before running this.
Interrupting the command is safe: re-running it skips rows that are already on
the new key.`,
	Example: `  # Preview what would be re-encrypted, without writing
  export NEW_MASTER_KEY="$(openssl rand -base64 32)"
  rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run

  # Perform the rotation
  rocketvault master-key rotate --new-key-env NEW_MASTER_KEY

  # Take the old key from an environment variable instead of the config file
  rocketvault master-key rotate --old-key-env OLD_MASTER_KEY --new-key-env NEW_MASTER_KEY`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMasterKeyRotate(cmd)
	},
}

func init() {
	rootCmd.AddCommand(masterKeyCmd)
	masterKeyCmd.AddCommand(masterKeyRotateCmd)

	masterKeyRotateCmd.Flags().StringVar(&rotateNewKeyEnv, "new-key-env", "",
		"Name of the environment variable holding the new base64 master key (required)")
	masterKeyRotateCmd.Flags().StringVar(&rotateOldKeyEnv, "old-key-env", "",
		"Name of the environment variable holding the old base64 master key (default: master_key from config)")
	masterKeyRotateCmd.Flags().BoolVar(&rotateDryRun, "dry-run", false,
		"Report what would be re-encrypted without writing anything")
	masterKeyRotateCmd.Flags().IntVar(&rotateBatchSize, "batch-size", rekey.DefaultBatchSize,
		"Number of row updates per transaction")
	masterKeyRotateCmd.Flags().BoolVar(&rotateAssumeYes, "yes", false,
		"Skip the confirmation prompt on a real run")
	masterKeyRotateCmd.MarkFlagRequired("new-key-env") //nolint:errcheck,gosec
}

// requireMasterKeyAdmin returns the caller's claims if they are logged in as
// admin. Rotation rewrites every vault's data, so there is no vault to scope
// it to -- the global admin role is the only applicable gate, same as backup.
//
// Parameters:
//
//	cmd: The running command, carrying the authenticated context.
//
// Returns:
//
//	The caller's claims, or an error if they are missing or not an admin.
func requireMasterKeyAdmin(cmd *cobra.Command) (*model.Claims, error) {
	claims, ok := cmd.Context().Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("unauthorized: missing authentication claims")
	}
	if claims.Role != model.RoleAdmin {
		return nil, fmt.Errorf("forbidden: requires admin role")
	}
	return claims, nil
}

// resolveRotationKeys reads and validates both master keys. Keys are taken
// from environment variables by name (or, for the old key, from the running
// configuration) so no key material reaches the process argument list. The new
// key must pass the full weak-key validation; the old key only needs to be
// structurally valid, because it is by definition the key being retired.
//
// Parameters:
//
//	oldKeyEnv: Name of the environment variable holding the old key, or "" to use the config value.
//	newKeyEnv: Name of the environment variable holding the new key.
//
// Returns:
//
//	The raw old and new keys, a human-readable description of where the old key
//	came from, and an error if either key is missing, invalid, or identical to
//	the other.
func resolveRotationKeys(oldKeyEnv, newKeyEnv string) (oldKey, newKey []byte, oldSource string, err error) {
	oldEncoded := viper.GetString("master_key")
	oldSource = "config file (master_key)"
	if oldKeyEnv != "" {
		oldEncoded = os.Getenv(oldKeyEnv)
		oldSource = "environment variable " + oldKeyEnv
	}
	if oldEncoded == "" {
		return nil, nil, "", fmt.Errorf("the old master key is empty (source: %s)", oldSource)
	}

	if newKeyEnv == "" {
		return nil, nil, "", errors.New("--new-key-env is required")
	}
	newEncoded := os.Getenv(newKeyEnv)
	if newEncoded == "" {
		return nil, nil, "", fmt.Errorf("environment variable %s is empty — generate a key with "+
			"\"openssl rand -base64 32\" and export it", newKeyEnv)
	}

	if newEncoded == oldEncoded {
		return nil, nil, "", fmt.Errorf("the new master key is identical to the old one (old key "+
			"source: %s); note that an exported MASTER_KEY environment variable takes precedence "+
			"over the config file", oldSource)
	}

	oldKey, err = common.ParseMasterKey(oldEncoded)
	if err != nil {
		return nil, nil, "", fmt.Errorf("old master key: %w", err)
	}
	if err := common.ValidateMasterKey(newEncoded); err != nil {
		return nil, nil, "", fmt.Errorf("new master key: %w", err)
	}
	newKey, err = common.ParseMasterKey(newEncoded)
	if err != nil {
		return nil, nil, "", fmt.Errorf("new master key: %w", err)
	}

	return oldKey, newKey, oldSource, nil
}

// runMasterKeyRotate drives a dry run or a real master key rotation.
func runMasterKeyRotate(cmd *cobra.Command) error {
	if _, err := requireMasterKeyAdmin(cmd); err != nil {
		return err
	}

	ctx := cmd.Context()
	rawDB, ok := ctx.Value(common.DBKey).(*sql.DB)
	if !ok || rawDB == nil {
		return errors.New("database connection not available")
	}
	logger, ok := ctx.Value(common.LogKey).(*logging.Logger)
	if !ok || logger == nil {
		return errors.New("logger not available")
	}

	oldKey, newKey, oldSource, err := resolveRotationKeys(rotateOldKeyEnv, rotateNewKeyEnv)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	mode := "REAL RUN (rows will be rewritten)"
	if rotateDryRun {
		mode = "DRY RUN (no rows will be written)"
	}
	fmt.Fprintf(out, "Old master key source: %s\n", oldSource)
	fmt.Fprintf(out, "New master key source: environment variable %s\n", rotateNewKeyEnv)
	fmt.Fprintf(out, "Mode: %s\n\n", mode)

	if !rotateDryRun && !rotateAssumeYes {
		fmt.Fprintln(out, "This rewrites every master-key-encrypted row in the database.")
		fmt.Fprintln(out, "Stop the RocketVault server and take a database backup before continuing.")
		fmt.Fprint(out, "Type 'yes' to continue: ")

		var confirmation string
		if _, scanErr := fmt.Scanln(&confirmation); scanErr != nil || confirmation != "yes" {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
	}

	conn := db.NewConn(rawDB, db.DialectFromDriver(viper.GetString("database.driver")))
	report, runErr := rekey.New(conn, logger).Run(ctx, rekey.Options{
		OldKey:    oldKey,
		NewKey:    newKey,
		DryRun:    rotateDryRun,
		BatchSize: rotateBatchSize,
	})
	if report != nil {
		printRotationReport(out, report)
	}
	if runErr != nil {
		return fmt.Errorf("master key rotation failed: %w", runErr)
	}

	if rotateDryRun {
		fmt.Fprintln(out, "Dry run complete. No rows were modified.")
		return nil
	}
	fmt.Fprintln(out, "Rotation complete. Set the new key as master_key in the configuration "+
		"(or as the MASTER_KEY environment variable) and restart the server.")
	return nil
}

// printRotationReport writes the per-table result table. It prints counters
// only -- never a key, a row value, or a secret name.
func printRotationReport(out io.Writer, report *rekey.Report) {
	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "TABLE\tCOLUMN\tROWS\tRE-ENCRYPTED\tALREADY NEW KEY\tSKIPPED (HSM)") //nolint:errcheck
	for _, target := range report.Targets {
		fmt.Fprintf(writer, "%s\t%s\t%d\t%d\t%d\t%d\n", //nolint:errcheck
			target.Table, target.Column, target.Total,
			target.ReEncrypted, target.AlreadyNewKey, target.SkippedExternal)
	}
	writer.Flush() //nolint:errcheck,gosec
	fmt.Fprintf(out, "\nTotal rows re-encrypted: %d\n\n", report.TotalReEncrypted())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/ -run 'MasterKey|ResolveRotationKeys' -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Verify the command builds and its help renders**

Run: `go build -o /tmp/rocketvault-plan-check . && /tmp/rocketvault-plan-check master-key rotate --help`
Expected: The help text lists `--new-key-env`, `--old-key-env`, `--dry-run`, `--batch-size`, `--yes`, and the examples. No key material appears anywhere.

- [ ] **Step 6: Verify the rest of the `cmd` package still passes**

Run: `go test ./cmd/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/master_key.go cmd/master_key_test.go
git commit -m "feat(cmd): add 'master-key rotate' re-encryption command

Admin-only Cobra subcommand driving internal/rekey. Both keys are read
from named environment variables (old key defaults to the config value)
so no key material reaches argv; the new key must pass ValidateMasterKey.
Supports --dry-run, --batch-size, and --yes, and prints per-table counters
only."
```

---

### Task 6: Startup guard — refuse to boot on a weak master key

**Files:**
- Modify: `bootstrap/bootstrap.go:96-115` (add a method after `Validate`), `bootstrap/bootstrap.go:225-247` (call it in `setup` after Step 1b)
- Test: `bootstrap/bootstrap_test.go` (append)

**Interfaces:**
- Consumes: `common.ValidateMasterKey` (Task 2), `rocketvault master-key rotate` (Task 5) — referenced by name in the error message.
- Produces: `(*ConfigurationValidator).ValidateMasterKey(encoded string) error`. The existing `Validate(cfg *Config, serverCfg *config.Config) error` is unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `bootstrap/bootstrap_test.go`:

```go
// ----- ConfigurationValidator.ValidateMasterKey -----

func TestValidateMasterKey_AcceptsStrongKey(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	cv := NewConfigurationValidator(newTestLogger())
	assert.NoError(t, cv.ValidateMasterKey(base64.StdEncoding.EncodeToString(key)))
}

func TestValidateMasterKey_RejectsCompromisedDefault(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())

	err := cv.ValidateMasterKey("***SECRET-REMOVED-2026-08-17***")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "master_key")
	assert.Contains(t, err.Error(), "master-key rotate")
}

func TestValidateMasterKey_RejectsMissingKey(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())

	assert.Error(t, cv.ValidateMasterKey(""))
}
```

Add `"crypto/rand"` and `"encoding/base64"` to that file's import block if they are not already present, and `"github.com/stretchr/testify/require"` if missing.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./bootstrap/ -run ValidateMasterKey -v`
Expected: FAIL — `cv.ValidateMasterKey undefined`.

- [ ] **Step 3: Implement the validator method**

In `bootstrap/bootstrap.go`, insert this immediately after the existing `Validate` method (which ends with `return nil` after `c.logger.Info("Configuration validation successful")`):

```go
// ValidateMasterKey fails startup when the configured master_key is missing,
// malformed, or known-weak. A 2026-08-16 penetration test decrypted a live
// database using the placeholder key committed to this repository, so booting
// on it is treated as a fatal misconfiguration rather than a warning.
//
// This is a separate method from Validate, and called later in setup, because
// it must run after vault-sourced secrets are injected into Viper — that
// injection can supply master_key itself, so validating alongside the other
// static config would read a value that is about to be replaced.
//
// There is deliberately no override flag: a guard with a documented bypass is
// the same guard the penetration test already walked through.
//
// Parameters:
//
//	encoded: The base64-encoded master key from configuration.
//
// Returns:
//
//	An error if the key must not be used, otherwise nil.
func (c *ConfigurationValidator) ValidateMasterKey(encoded string) error {
	if err := common.ValidateMasterKey(encoded); err != nil {
		return fmt.Errorf("refusing to start: configured master_key is not usable: %w", err)
	}

	c.logger.Info("Master key validation successful")
	return nil
}
```

Add `"rocketvault/common"` to the file's import block (grouped with the other `rocketvault/...` imports).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./bootstrap/ -run ValidateMasterKey -v`
Expected: PASS — all three tests.

- [ ] **Step 5: Wire the check into the boot sequence**

In `bootstrap/bootstrap.go`'s `setup`, insert this between the end of the Step 1b vault-secret block (the closing brace after `logrus.Info("Vault secrets injected into config")`) and the `// Step 2: Initialize database` comment:

```go
	// Step 1c: Refuse to start on a weak or known-compromised master key. This
	// runs after Step 1b because vault-injected secrets can supply master_key.
	if err := b.configValidator.ValidateMasterKey(viper.GetString("master_key")); err != nil {
		return err
	}

```

- [ ] **Step 6: Verify the guard actually fires against the committed config**

Run: `go build -o /tmp/rocketvault-plan-check . && /tmp/rocketvault-plan-check serve`
Expected: The process exits with the error naming `master_key`, `openssl rand -base64 32`, and `rocketvault master-key rotate`. **This failure is the intended outcome** — the committed `.rocketvault.yaml` still holds the compromised key, and rotating it is plan H4's job. Do not "fix" it by editing `.rocketvault.yaml`.

- [ ] **Step 7: Verify the rest of the bootstrap suite still passes**

Run: `go test ./bootstrap/ -v`
Expected: PASS, including the pre-existing `TestValidate_*` cases, which are untouched because the master-key check lives in its own method.

- [ ] **Step 8: Commit**

```bash
git add bootstrap/bootstrap.go bootstrap/bootstrap_test.go
git commit -m "feat(bootstrap): refuse to start on a weak or compromised master key

ConfigurationValidator.ValidateMasterKey runs as setup Step 1c, after
vault-sourced secrets are injected into Viper (that injection can supply
master_key itself). No override flag by design. The server now refuses to
boot on the placeholder key a 2026-08-16 pentest used to decrypt a live
database; the fix is 'rocketvault master-key rotate'."
```

---

### Task 7: Operator runbook

**Files:**
- Create: `docs/runbooks/master-key-rotation.md`
- Modify: `scripts/docsgen/docs.go:29-41` (`docsList`)

**Interfaces:**
- Consumes: the CLI surface from Task 5 — the runbook's commands must match the implemented flags exactly.
- Produces: `docs/runbooks/master-key-rotation.md`, rendered to `docs/runbooks/master-key-rotation.html` by `./scripts/docs.sh build`.

- [ ] **Step 1: Write the runbook**

Create `docs/runbooks/master-key-rotation.md`:

````markdown
# Runbook: Rotating the RocketVault Master Key

The master key seals, with AES-256-GCM, everything RocketVault stores as a secret:

| Table | Column | Contents |
|---|---|---|
| `secrets` | `value` | Secret values |
| `secret_versions` | `value` | Secret version history |
| `keys` | `value` | Software (non-HSM) RSA/ECDSA private key PEMs, including the JWT signing key |
| `key_versions` | `value` | Key rotation history |
| `certificates` | `private_key` | Certificate private key PEMs, including CA keys |

Changing `master_key` in the configuration **without** running this procedure makes every one of
those rows permanently undecryptable. PKCS#11/HSM keys (`pkcs11:`-prefixed values) are unaffected —
their material never leaves the token. User passwords and OAuth2 client secrets are bcrypt hashes
and are also unaffected.

Rotation is an **offline** operation. Plan a maintenance window.

## 1. Generate the new key

```bash
export NEW_MASTER_KEY="$(openssl rand -base64 32)"
```

Store it in your secret store **now**. If it is lost after step 5, every secret in the vault is
unrecoverable.

Do not name this variable `MASTER_KEY`: Viper gives environment variables precedence over the
configuration file, so an exported `MASTER_KEY` would make the tool's "old key from config" default
resolve to the new key. The command detects this and refuses to run, but naming it clearly avoids
the detour.

## 2. Stop the server

Concurrent writes are detected and abort the run. Stop RocketVault first.

## 3. Back up the database

```bash
cp ./dev-rocketvault.db ./dev-rocketvault.db.pre-rotation   # SQLite
pg_dump "$DATABASE_URL" > rocketvault-pre-rotation.sql      # PostgreSQL
```

This backup plus the old key is your rollback.

## 4. Log in and dry-run

```bash
./rocketvault users login --username admin --password '<password>' --totp-code <code>
./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
```

Check the report before continuing:

- Per-table row counts match what you expect for this deployment.
- `ALREADY NEW KEY` is `0` on a first run.
- `SKIPPED (HSM)` is `0` unless the deployment uses PKCS#11.
- No errors.

## 5. Run the rotation

```bash
./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
```

Confirm at the prompt (or pass `--yes` in scripted maintenance). If the command is interrupted, run
it again with the same keys — rows already on the new key are detected and skipped, and nothing is
double-encrypted.

## 6. Update the configuration

Either set `master_key` in `.rocketvault.yaml` to the value of `$NEW_MASTER_KEY`, or — preferred —
export it as the `MASTER_KEY` environment variable of the server process and remove the key from the
file entirely. The environment value takes precedence over the file.

## 7. Restart and verify

```bash
./rocketvault serve
./rocketvault secrets get <name> --vault default
./rocketvault certificates list --vault default
```

A successful read proves the rotation and the configuration agree. The server refuses to start at
all on a key that fails validation (wrong length, the old committed placeholder, or obviously
non-random), so a successful start is itself part of the verification.

## 8. Deal with old backups

Backup files created by `rocketvault backup create` before the rotation are encrypted with the
**old** key and can only be restored with it. Either archive the old key for the backups' retention
period, clearly labelled restore-only and compromised, or take a fresh backup now and delete the
old ones.

## If something goes wrong

| Symptom | Cause | Action |
|---|---|---|
| `value decrypts with neither the old nor the new master key` | Wrong old key | No rows in that table were written. Fix `--old-key-env` and re-run. |
| `row ... changed while the rotation was running` | The server is still running | Stop it and re-run; already-migrated rows are skipped. |
| `the new master key is identical to the old one` | `MASTER_KEY` exported in the shell shadows the config value | Unset it, use a differently named variable. |
| Server logs "could not decrypt stored key, regenerating" after restart | The configuration was updated **before** the rotation ran, on a `jwt.key_source: self_pki` deployment — a new JWT signing key was generated and all sessions were invalidated | Restore the old key in the configuration, restart from step 4, then update the configuration again. |
| Secret reads fail after restart | Configuration and database disagree on the key | Confirm the configuration holds the same key the rotation used; re-run the rotation if it was interrupted before completing. |
````

- [ ] **Step 2: Register the runbook with the docs generator**

In `scripts/docsgen/docs.go`, add this entry to `docsList`, keeping the list's alphabetical-by-path ordering (after the `docs/release-notes/...` entry, before `docs/usage-guide.md`):

```go
	{"docs/runbooks/master-key-rotation.md", "docs/runbooks/master-key-rotation.html"},
```

- [ ] **Step 3: Verify the docs site builds**

Run: `./scripts/docs.sh build`
Expected: Completes without error and creates `docs/runbooks/master-key-rotation.html`.

- [ ] **Step 4: Verify the runbook's commands match the implementation**

Run: `go build -o /tmp/rocketvault-plan-check . && /tmp/rocketvault-plan-check master-key rotate --help`
Expected: Every flag the runbook uses (`--new-key-env`, `--old-key-env`, `--dry-run`, `--yes`) appears in the help output with the meaning the runbook describes.

- [ ] **Step 5: Commit**

```bash
git add docs/runbooks/master-key-rotation.md docs/runbooks/master-key-rotation.html scripts/docsgen/docs.go
git commit -m "docs: add master key rotation runbook

Step-by-step offline rotation procedure (generate, stop, back up, dry-run,
rotate, reconfigure, verify, re-create backups) plus a troubleshooting
table. Registered with the docsgen HTML pipeline."
```

---

### Task 8: Record the finding and fix in `.claude/known-bugs.md`

**Files:**
- Modify: `.claude/known-bugs.md` (append a new entry to the "Open Bugs" section, after the B8 entry and before the `## Deferred Refactors` heading)

**Interfaces:**
- Consumes: everything from Tasks 1-7 — the entry documents the shipped fix.
- Produces: entry `B12` in the project's bug log. No code.

- [ ] **Step 1: Add the entry**

Insert this into `.claude/known-bugs.md`, immediately before the `---` that precedes `## Deferred Refactors`:

```markdown
### B12 — All secrets and software key PEMs sealed with a predictable, git-committed master key

**Status**: Fixed on branch `v-4.0.0` (2026-08-16) — tool and startup guard landed; the
rotation itself against the real dev/prod databases is tracked separately as H4
**Severity**: High — confirmed by live exploitation during the 2026-08-16 penetration test
**File**: `common/encrypt.go`, `common/masterkey.go`, `bootstrap/bootstrap.go`,
`internal/rekey/`, `cmd/master_key.go`, `.rocketvault.yaml`

**Root cause**: Secret values, software (non-HSM) key PEMs, and certificate private keys are all
sealed with AES-256-GCM under a single key read from `viper.GetString("master_key")`. The AES-GCM
construction is correct (fresh random 12-byte nonce per seal, prepended, real AEAD). The defect was
the key *value*: the committed `.rocketvault.yaml` shipped
`master_key: "***SECRET-REMOVED-2026-08-17***"`, which base64-decodes to the ASCII
string `0123456789abcdef0123456789abcdef` — a placeholder, in git, identical in every deployment
that never changed it. Anyone holding a copy of the database (stolen backup, snapshot,
decommissioned disk, or the repository itself) decrypted every secret offline. Nothing in the
codebase checked key quality, and the two length checks even disagreed: `EncryptSecret` accepted
`len(key) >= 32` while `DecryptSecret` required `== 32`.

Rotating the key was not a one-line config change either: with no re-encryption path anywhere in
the codebase, changing `master_key` made every existing row permanently undecryptable. That is why
the fix is a migration tool, not just a guard.

**Blast radius** (every column sealed with this key, established by mapping all nine callers of
`common.EncryptSecret`/`DecryptSecret` to the columns they write): `secrets.value`,
`secret_versions.value`, `keys.value`, `key_versions.value`, `certificates.private_key`. The
`keys` entry includes `internal/signing.SelfPKIProvider`'s JWT signing key, which is stored as an
ordinary `keys` row. PKCS#11/HSM key rows (`pkcs11:` prefix) hold token handles, not ciphertext,
and are unaffected. User passwords and OAuth2 client secrets are bcrypt hashes; TOTP secrets are
stored in plaintext (a separate issue) — none of those are touched by rotation.

**Fix**:
1. `common.EncryptWithKey`/`DecryptWithKey`/`ParseMasterKey` — key-parameterized AES-256-GCM
   primitives, so one process can open under the old key and seal under the new one.
   `EncryptSecret`/`DecryptSecret` keep their signatures and now agree on requiring exactly 32
   bytes.
2. `common.ValidateMasterKey` — rejects a missing/malformed/wrong-length key, the known-compromised
   committed default (constant-time compare), all-printable-ASCII keys, and keys with fewer than 16
   distinct byte values.
3. `bootstrap.ConfigurationValidator.ValidateMasterKey`, called as `setup` Step 1c (after Step 1b
   injects vault-sourced secrets into Viper, since that injection can supply `master_key` itself) —
   the server now refuses to start on a weak key, with no override flag.
4. `internal/rekey` — plan-then-apply re-encryption over the five columns above using raw
   dialect-aware SQL (repositories are scope- and soft-delete-filtered and would re-encrypt on the
   way through, so they are the wrong layer). Each row is classified by trying the **new** key
   first, which makes an interrupted run safe to resume without double-encrypting; `pkcs11:` rows
   are skipped; updates run in batched transactions guarded by `AND <column> = <old ciphertext>`
   with `RowsAffected() == 1` asserted, so a still-running server causes a loud abort instead of
   silent data loss.
5. `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY [--old-key-env ...] [--dry-run]` —
   admin-only CLI driving the engine. Keys are passed by environment-variable *name*, never in
   argv; the new key must pass `ValidateMasterKey`; neither key nor any plaintext is ever logged.

**Regression tests**: `common/masterkey_test.go` (weak-key rejection, including the exact committed
value), `common/encrypt_key_test.go` (key-parameterized round-trip, wrong-key failure),
`internal/rekey/classify_test.go` and `internal/rekey/rekey_test.go` (dry-run writes nothing,
full re-encryption round-trips under the new key, second run is a no-op, partial migration resumes,
`pkcs11:` rows untouched, wrong old key aborts with no writes), `bootstrap/bootstrap_test.go`
(startup guard), `cmd/master_key_test.go` (admin gate, key resolution).

**Operational note**: after this landed, the server refuses to boot against the repository's
committed `.rocketvault.yaml` until the key is rotated — intended. The procedure is
`docs/runbooks/master-key-rotation.md`. Backups taken before a rotation remain encrypted with the
old key and need the old key to restore.

**Related**: H4 (removing the committed key from `.rocketvault.yaml` and moving custody to the
environment/secret store) invokes this tool to perform the actual rotation. Envelope encryption
(per-secret data keys wrapped by a KEK, making future rotations O(1) instead of O(rows)) was
considered and deliberately deferred — it is a storage-format change touching every read path.
```

- [ ] **Step 2: Verify the entry renders and reads correctly**

Run: `grep -n "^### B12" .claude/known-bugs.md`
Expected: One match, positioned after the B8 entry and before `## Deferred Refactors`.

- [ ] **Step 3: Commit**

```bash
git add .claude/known-bugs.md
git commit -m "docs(known-bugs): record B12 predictable committed master key

Root cause, blast radius across all five sealed columns, the five-part
fix (key-parameterized primitives, weak-key validation, startup guard,
internal/rekey engine, master-key rotate CLI), regression tests, and the
relationship to H4."
```

---

### Task 9: Full verification pass

**Files:**
- No changes expected. This task is the gate before the branch is offered for review.

**Interfaces:**
- Consumes: everything from Tasks 1-8.
- Produces: evidence that the build, vet, lint, and full test suite are green.

- [ ] **Step 1: Build everything**

Run: `go build ./...`
Expected: No output, exit code 0.

- [ ] **Step 2: Vet everything**

Run: `go vet ./...`
Expected: No findings.

- [ ] **Step 3: Check formatting on the changed files**

Run:

```bash
gofmt -l common/encrypt.go common/masterkey.go common/encrypt_key_test.go common/masterkey_test.go \
  bootstrap/bootstrap.go bootstrap/bootstrap_test.go \
  internal/rekey/targets.go internal/rekey/classify.go internal/rekey/rekey.go \
  internal/rekey/classify_test.go internal/rekey/rekey_test.go \
  cmd/master_key.go cmd/master_key_test.go scripts/docsgen/docs.go
```

Expected: No output (no file needs reformatting).

- [ ] **Step 4: Lint the changed packages**

Run: `golangci-lint run ./common/... ./bootstrap/... ./internal/rekey/... ./cmd/...`
Expected: No issues. Fix anything reported before continuing — the project bar is zero new lint findings.

- [ ] **Step 5: Run the full test suite**

Run: `go test ./...`
Expected: PASS across all packages.

- [ ] **Step 6: Audit for leaked key material and plaintext**

Run:

```bash
grep -rn "oldKey\|newKey\|OldKey\|NewKey\|plaintext" \
  internal/rekey/rekey.go internal/rekey/classify.go cmd/master_key.go \
  | grep -i "log\|print\|Errorf\|Sprintf"
```

Expected: Every hit is a *length* or *source-name* reference — the "both master keys must be 32 raw
bytes" message, the "identical to the old one" message, and the environment-variable-name output.
No hit passes a key or a plaintext value into a log, a print, or an error. If any does, remove it.

- [ ] **Step 7: Confirm the guard's intended failure is still intended**

Run: `go build -o /tmp/rocketvault-plan-check . && /tmp/rocketvault-plan-check serve; echo "exit=$?"`
Expected: A non-zero exit with the master-key error. `.rocketvault.yaml` must still contain the
original committed key — this plan does not change it. Rotating the real key is plan H4's work,
performed with the tool this plan delivered.
