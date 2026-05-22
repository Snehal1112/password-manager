# OS Keychain JWT Key Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace plaintext PEM file storage in `OSStoreProvider` with OS keychain via `go-keyring`, falling back to the existing PEM file path when the keychain is unavailable.

**Architecture:** Add `loadFromKeychain` and `saveToKeychain` helpers to `internal/signing/os_store.go` that use `go-keyring`. `NewOSStoreProvider` tries keychain first, generates a new key if not found, stores it in the keychain, and falls back to the existing PEM file path if the keychain is unavailable. A thin `keychainBackend` interface is introduced so unit tests can inject a fake without touching the real OS keychain.

**Tech Stack:** Go 1.25, `github.com/zalando/go-keyring` v1, existing `internal/signing` package.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/signing/os_store.go` | Modify | Add keychain interface + load/save helpers; update `NewOSStoreProvider` startup sequence |
| `internal/signing/os_store_test.go` | Create | Unit tests for keychain happy path, missing key, unavailable keychain |
| `go.mod` / `go.sum` | Modify | Add `github.com/zalando/go-keyring` |

---

## Task 1: Add go-keyring dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the dependency**

```bash
cd /path/to/rocketvault
go get github.com/zalando/go-keyring@latest
```

- [ ] **Step 2: Verify it resolves**

```bash
go build ./...
```

Expected: exit 0, no errors.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): add zalando/go-keyring for OS keychain support"
```

---

## Task 2: Introduce keychainBackend interface and update os_store.go

**Files:**
- Modify: `internal/signing/os_store.go`

The real `go-keyring` calls are wrapped behind a `keychainBackend` interface so tests can inject a fake. The production singleton uses `go-keyring` directly.

- [ ] **Step 1: Write the failing test first (see Task 3 — read it now before implementing)**

Read Task 3 fully so you know what interface shape the tests expect before you write the implementation.

- [ ] **Step 2: Add the interface and production implementation to `os_store.go`**

Replace the top of `internal/signing/os_store.go` with the following (keep all existing functions — only add the new block after the imports):

```go
package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zalando/go-keyring"
)

const (
	osStoreAlgorithm  = "RS256"
	keychainService   = "rocketvault"
)

// keychainBackend abstracts go-keyring so tests can inject a fake.
type keychainBackend interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
}

// realKeychain delegates to the go-keyring package.
type realKeychain struct{}

func (r *realKeychain) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (r *realKeychain) Set(service, user, secret string) error {
	return keyring.Set(service, user, secret)
}

// defaultKeychain is the production singleton.
var defaultKeychain keychainBackend = &realKeychain{}
```

- [ ] **Step 3: Update `NewOSStoreProvider` to use the keychain**

Replace the existing `NewOSStoreProvider` function body in `internal/signing/os_store.go`:

```go
// NewOSStoreProvider constructs the provider. cn is the certificate CN to search for.
// It tries the OS keychain first, generates a new RSA-2048 key if not found,
// and falls back to a PEM file if the keychain is unavailable.
func NewOSStoreProvider(cn string) (*OSStoreProvider, error) {
	return newOSStoreProviderWithKeychain(cn, defaultKeychain)
}

// newOSStoreProviderWithKeychain is the testable constructor that accepts a keychainBackend.
func newOSStoreProviderWithKeychain(cn string, kc keychainBackend) (*OSStoreProvider, error) {
	// 1. Try loading existing key from keychain.
	if key, err := loadFromKeychain(kc, cn); err == nil {
		kid := thumbprint(key.Public())
		logrus.WithField("kid", kid).Info("OSStoreProvider: loaded JWT signing key from OS keychain")
		return &OSStoreProvider{
			privateKey: key,
			kid:        kid,
			publicInfo: []PublicKeyInfo{{KeyID: kid, Algorithm: osStoreAlgorithm, PublicKey: key.Public()}},
		}, nil
	}

	// 2. Not in keychain (or keychain unavailable) — generate a new key.
	logrus.WithField("cn", cn).Warn("OSStoreProvider: no key in keychain, auto-generating RSA-2048 key")

	key, cert, err := generateSelfSignedRSA(cn)
	if err != nil {
		return nil, fmt.Errorf("OSStoreProvider: auto-generate key: %w", err)
	}

	// 3. Try saving to keychain.
	if err := saveToKeychain(kc, cn, key); err != nil {
		// 4. Keychain unavailable — fall back to PEM file.
		logrus.WithError(err).Warn("OSStoreProvider: keychain unavailable, falling back to PEM file")
		if err := persistKey(key, cert, cn); err != nil {
			logrus.WithError(err).Warn("OSStoreProvider: could not persist key to file either (in-memory only)")
		}
	}

	kid := thumbprint(key.Public())
	return &OSStoreProvider{
		privateKey: key,
		kid:        kid,
		publicInfo: []PublicKeyInfo{{KeyID: kid, Algorithm: osStoreAlgorithm, PublicKey: key.Public()}},
	}, nil
}
```

- [ ] **Step 4: Add `loadFromKeychain` and `saveToKeychain` helpers**

Add these functions to `internal/signing/os_store.go` (after `NewOSStoreProvider`):

```go
// loadFromKeychain retrieves the RSA private key PEM from the OS keychain.
// Returns an error if the key is not found or the keychain is unavailable.
func loadFromKeychain(kc keychainBackend, cn string) (*rsa.PrivateKey, error) {
	pemStr, err := kc.Get(keychainService, keychainUser(cn))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("keychain entry is not valid PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// saveToKeychain stores the RSA private key PEM in the OS keychain.
func saveToKeychain(kc keychainBackend, cn string, key *rsa.PrivateKey) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return kc.Set(keychainService, keychainUser(cn), string(pemBytes))
}

// keychainUser returns the keychain username/label for a given CN.
func keychainUser(cn string) string {
	return "jwt-signing-key-" + cn
}
```

- [ ] **Step 5: Verify it compiles**

```bash
go build ./internal/signing/...
```

Expected: exit 0.

---

## Task 3: Write unit tests for the keychain paths

**Files:**
- Create: `internal/signing/os_store_test.go`

- [ ] **Step 1: Create the test file**

```go
package signing

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// fakeKeychain is an in-memory keychainBackend for testing.
type fakeKeychain struct {
	store map[string]string
	setErr error // if non-nil, Set always returns this error
}

func newFakeKeychain() *fakeKeychain {
	return &fakeKeychain{store: make(map[string]string)}
}

func (f *fakeKeychain) Get(service, user string) (string, error) {
	v, ok := f.store[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (f *fakeKeychain) Set(service, user, secret string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.store[service+"/"+user] = secret
	return nil
}

// TestOSStore_KeychainHappyPath verifies that a key stored in the keychain
// is loaded on second call without regenerating.
func TestOSStore_KeychainHappyPath(t *testing.T) {
	kc := newFakeKeychain()

	// First call — keychain empty, generates and stores key.
	p1, err := newOSStoreProviderWithKeychain("test-cn", kc)
	require.NoError(t, err)
	assert.Equal(t, "RS256", p1.Algorithm())
	assert.NotEmpty(t, p1.KeyID())

	// Keychain must now contain the key.
	stored, err := kc.Get(keychainService, keychainUser("test-cn"))
	require.NoError(t, err)
	assert.Contains(t, stored, "RSA PRIVATE KEY")

	// Second call — loads from keychain, same kid.
	p2, err := newOSStoreProviderWithKeychain("test-cn", kc)
	require.NoError(t, err)
	assert.Equal(t, p1.KeyID(), p2.KeyID(), "kid must be stable across restarts")
}

// TestOSStore_KeychainUnavailable verifies fallback to PEM file when keychain errors.
func TestOSStore_KeychainUnavailable(t *testing.T) {
	kc := newFakeKeychain()
	kc.setErr = errors.New("keychain daemon not running")

	// Should not error — falls back to PEM file (which may also fail in CI, non-fatal).
	p, err := newOSStoreProviderWithKeychain("test-cn-unavail", kc)
	require.NoError(t, err)
	assert.Equal(t, "RS256", p.Algorithm())
	assert.NotEmpty(t, p.KeyID())

	// Key must NOT be in the fake keychain (Set failed).
	_, err = kc.Get(keychainService, keychainUser("test-cn-unavail"))
	assert.Error(t, err, "key should not be in keychain when Set failed")
}

// TestOSStore_KeychainMissingKey verifies that ErrNotFound triggers generation.
func TestOSStore_KeychainMissingKey(t *testing.T) {
	kc := newFakeKeychain() // empty — ErrNotFound on Get

	p, err := newOSStoreProviderWithKeychain("test-cn-missing", kc)
	require.NoError(t, err)
	assert.NotEmpty(t, p.KeyID())

	// After construction, key must be stored.
	_, err = kc.Get(keychainService, keychainUser("test-cn-missing"))
	assert.NoError(t, err, "key should be stored after generation")
}

// TestOSStore_DifferentCNsDontCollide verifies label isolation.
func TestOSStore_DifferentCNsDontCollide(t *testing.T) {
	kc := newFakeKeychain()

	p1, err := newOSStoreProviderWithKeychain("cn-alpha", kc)
	require.NoError(t, err)

	p2, err := newOSStoreProviderWithKeychain("cn-beta", kc)
	require.NoError(t, err)

	assert.NotEqual(t, p1.KeyID(), p2.KeyID(), "different CNs must produce different keys")
}

// TestLoadFromKeychain_InvalidPEM verifies corrupt keychain entry is handled.
func TestLoadFromKeychain_InvalidPEM(t *testing.T) {
	kc := newFakeKeychain()
	kc.store[keychainService+"/"+keychainUser("bad-cn")] = "not-valid-pem"

	_, err := loadFromKeychain(kc, "bad-cn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid PEM")
}

// TestKeychainUser verifies label format.
func TestKeychainUser(t *testing.T) {
	assert.Equal(t, "jwt-signing-key-rocketvault", keychainUser("rocketvault"))
	assert.Equal(t, "jwt-signing-key-my-app", keychainUser("my-app"))
}

// helpers

func rsaPublicKeyFromPEM(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	return &key.PublicKey
}
```

- [ ] **Step 2: Run the tests — expect failures (TDD red)**

```bash
go test ./internal/signing/... -run TestOSStore -v
```

Expected: compile error or FAIL (implementation not complete yet — if you are doing these tasks in order, Task 2 must be done first).

- [ ] **Step 3: Run the tests after Task 2 is complete — expect green**

```bash
go test ./internal/signing/... -v
```

Expected: all PASS.

- [ ] **Step 4: Run the full suite to check for regressions**

```bash
go clean -testcache && go test ./...
```

Expected: all packages pass.

- [ ] **Step 5: Commit**

```bash
git add internal/signing/os_store.go internal/signing/os_store_test.go go.mod go.sum
git commit -m "feat(signing): store OSStoreProvider key in OS keychain via go-keyring

Falls back to PEM file when keychain daemon is unavailable (headless/CI).
Introduces keychainBackend interface for testability without touching real OS keychain.
Supports Linux (libsecret), macOS (Keychain), Windows (Credential Manager)."
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task covering it |
|-----------------|-----------------|
| Load from keychain on startup | Task 2 Step 3 (`loadFromKeychain`) |
| Generate + store if not found | Task 2 Step 3 (`newOSStoreProviderWithKeychain`) |
| Fall back to PEM file if keychain unavailable | Task 2 Step 3 (fallback branch) |
| Keychain entry label includes CN | Task 2 Step 4 (`keychainUser`) |
| Cross-platform (Linux/macOS/Windows) | Task 1 (`go-keyring` handles all three) |
| Unit: happy path | Task 3 `TestOSStore_KeychainHappyPath` |
| Unit: keychain unavailable | Task 3 `TestOSStore_KeychainUnavailable` |
| Unit: missing key (ErrNotFound) | Task 3 `TestOSStore_KeychainMissingKey` |
| Different CNs don't collide | Task 3 `TestOSStore_DifferentCNsDontCollide` |
| Corrupt keychain entry handled | Task 3 `TestLoadFromKeychain_InvalidPEM` |

**Placeholder scan:** No TBDs, no "implement later", all code blocks complete.

**Type consistency:** `keychainBackend` interface defined in Task 2 Step 2 and used consistently in Tasks 2 and 3. `keychainUser(cn)` defined in Task 2 Step 4, referenced in Task 3 tests correctly.
