# Key JWK Public Components Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the JWK public components (`n`/`e`/`x`/`y`) actually appear on key responses — they are silently empty on every software key today — and add them to `GET /keys/{key_id}/versions/{version}`, matching Azure Key Vault's `GET /keys/{name}/{version}`.

**Architecture:** JWK extraction moves out of the API layer into `KeyService`. The handler cannot do this work: the material is master-key-encrypted in `keys.value`, and `api/` has no decryption precedent (`grep -rn "common.DecryptSecret" api/` returns nothing). A new `KeyService.GetPublicJWK(ctx, keyID, version, scope)` resolves the version's stored material, decrypts it, and parses it; handlers just call it and copy the result onto their response struct.

**Tech Stack:** Go 1.24, Gorilla Mux, testify/mock, `internal/crypto` (PEM/JWK parsing), `common` (AES-256-GCM master-key encryption).

**Spec:** No separate design doc — the source finding is `.claude/azure-keyvault-parity.md` §2, the `Get / List / List versions` row (line 41), which reads *"the response is `model.KeyVersion{KeyID, Version, CreatedAt}` only, no public JWK components at all, thinner than even the current-key `GET /keys/{id}` (which does emit them via `buildKeyResponse`)"*. The **Root cause** section below corrects that row: the current-key route does not emit them either. The design decisions this plan encodes are stated inline in that section and in each task.

## Root cause (verified, not assumed)

`api/keys.go:201` calls:

```go
n, e, x, y, _ := crypto.ExtractPublicComponents(key.Value, key.Type)
```

`key.Value` is the value as stored, and every software key is stored master-key-encrypted — `key_service.go:241` and `:333` both do `storedValue, err = common.EncryptSecret(handle)` before `keyRepo.Create`. `crypto.ExtractPublicComponents` (`internal/crypto/key_crypto.go:138`) begins with `pem.Decode`, which returns a nil block for base64 ciphertext, so the function returns `"", "", "", "", fmt.Errorf("failed to decode PEM block")`. **That error is discarded into `_`**, so all four components come back empty and are dropped by their `omitempty` tags.

Verified empirically with a throwaway test in `api/` (deleted after the run):

```
PLAINTEXT -> len(n)=342 e="AQAB" err=<nil>
ENCRYPTED -> len(n)=0   e=""     err=failed to decode PEM block
buildKeyResponse(N="", E="")
```

So `GET /keys/{id}`, `POST /keys`, `PUT /keys/{id}`, and `POST /keys/{id}/rotate` all advertise `n`/`e`/`x`/`y` fields that never populate. This plan fixes that first, then extends the same capability to the version route.

## Global Constraints

- **Never return private material.** `GetPublicJWK` returns only the four public components. No task may add a `Value`, PEM, or private-scalar field to any response struct. `model.KeyVersion`'s existing no-material guarantee (`model/key.go:55-62`) stands unchanged.
- **HSM keys have no public components and that is not an error.** A value prefixed `pkcs11:` means the material never left the token. `ExtractPublicComponents` already returns four empty strings and a nil error for that case (`key_crypto.go:139-141`, pinned by `TestExtractPublicComponents_PKCS11ReturnsEmpty`). `GetPublicJWK` must return an empty `*model.PublicJWK` with a nil error, never a 500.
- **List stays JWK-free.** `listKeys` must not fetch a JWK per key — that would be an N-way decrypt on a list endpoint, and Azure's own list response carries identifiers and attributes only, not public material. It passes `nil`.
- **Errors propagate, never get discarded.** The bug being fixed is a swallowed error. No task may write `_` for an error returned by `ExtractPublicComponents` or `DecryptSecret`.
- **Layering:** decryption and parsing live in `internal/services/keys`. `api/` must not import `common` for decryption. See the `service-layer-conventions` skill.
- **Go 1.24, existing dependencies only.** No new module requirements.

## File structure

| File | Responsibility |
|---|---|
| `model/key.go` (modify) | New `PublicJWK` value type carrying the four components |
| `internal/services/keys/key_service.go` (modify) | `GetPublicJWK` on the `KeyService` interface + `keyService` implementation |
| `internal/services/keys/key_jwk_test.go` (new) | Unit tests for `GetPublicJWK` across software / HSM / archived-version / error paths |
| `api/keys.go` (modify) | `buildKeyResponse` signature change; four single-key handlers fetch a JWK; new `KeyVersionResponse`; `getKeyVersion` returns it |
| `api/keys_jwk_test.go` (new) | Handler-level tests that a real key's response carries non-empty `n`/`e` |
| `.claude/azure-keyvault-parity.md` (modify) | §2 row correction |
| `.claude/known-bugs.md` (modify) | New root-cause entry |

---

### Task 1: `model.PublicJWK` and `KeyService.GetPublicJWK`

**Files:**
- Modify: `model/key.go` (append after the `KeyVersionRecord` block, currently ending at line 78)
- Modify: `internal/services/keys/key_service.go` (interface near line 134; implementation after `GetKeyVersion`, which ends at line 528)
- Test: `internal/services/keys/key_jwk_test.go` (create)

**Interfaces:**
- Consumes: `KeyService.GetKey(ctx, keyID, scope) (*model.Key, error)` (`key_service.go:464`); `KeyRepositoryInterface.CurrentVersion(ctx, keyID, userID) (int, error)` and `.ReadVersionValue(ctx, keyID, version, userID) (string, error)` (`internal/repositories/key_repository.go:51,63`); `common.DecryptSecret(string) (string, error)`; `crypto.ExtractPublicComponents(pemOrHandle, keyType string) (n, e, x, y string, err error)`; the package-local `pkcs11Prefix` constant declared in `internal/services/keys/crypto_service.go`.
- Produces: `model.PublicJWK{N, E, X, Y string}` and `KeyService.GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error)`. Tasks 2 and 3 call exactly this signature. `version == 0` means "the current version".

- [ ] **Step 1: Write the failing test**

Create `internal/services/keys/key_jwk_test.go`. It reuses `mockKeyRepository` from `key_soft_delete_test.go` (same package), which already has `Read`, `CurrentVersion`, and `ReadVersionValue` methods.

```go
package keys

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// setTestMasterKey installs a random master key so common.EncryptSecret and
// common.DecryptSecret round-trip inside this test binary.
func setTestMasterKey(t *testing.T) {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	viper.Set("master_key", base64.StdEncoding.EncodeToString(raw))
}

// newJWKService builds a keyService over the given mock repository.
func newJWKService(repo *mockKeyRepository) KeyService {
	return NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})
}

func TestGetPublicJWK_RSACurrentVersion(t *testing.T) {
	setTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	pemKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	stored, err := common.EncryptSecret(pemKey)
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: stored, Enabled: true,
	}, nil)

	jwk, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.NoError(t, err)
	assert.NotEmpty(t, jwk.N, "RSA modulus must be populated")
	assert.Equal(t, "AQAB", jwk.E)
	assert.Empty(t, jwk.X)
	assert.Empty(t, jwk.Y)
	repo.AssertNotCalled(t, "CurrentVersion", mock.Anything, mock.Anything, mock.Anything)
}

func TestGetPublicJWK_ECDSACurrentVersion(t *testing.T) {
	setTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	pemKey, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	stored, err := common.EncryptSecret(pemKey)
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeECDSA, Value: stored, Enabled: true,
	}, nil)

	jwk, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.NoError(t, err)
	assert.NotEmpty(t, jwk.X)
	assert.NotEmpty(t, jwk.Y)
	assert.Empty(t, jwk.N)
}

func TestGetPublicJWK_HSMKeyReturnsEmptyNotError(t *testing.T) {
	setTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "pkcs11:token-label", Enabled: true,
	}, nil)

	jwk, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.NoError(t, err, "an HSM key has no public material to parse; that is not an error")
	assert.Equal(t, &model.PublicJWK{}, jwk)
}

func TestGetPublicJWK_ArchivedVersionReadsVersionValue(t *testing.T) {
	setTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	currentPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	currentStored, err := common.EncryptSecret(currentPEM)
	require.NoError(t, err)

	archivedPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	archivedStored, err := common.EncryptSecret(archivedPEM)
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: currentStored, Enabled: true,
	}, nil)
	repo.On("CurrentVersion", mock.Anything, keyID, userID).Return(2, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 1, userID).Return(archivedStored, nil)

	svc := newJWKService(repo)

	v1, err := svc.GetPublicJWK(context.Background(), keyID, 1, scope)
	require.NoError(t, err)

	v2, err := svc.GetPublicJWK(context.Background(), keyID, 2, scope)
	require.NoError(t, err)

	assert.NotEmpty(t, v1.N)
	assert.NotEmpty(t, v2.N)
	assert.NotEqual(t, v1.N, v2.N, "version 1 must resolve the archived material, not keys.value")
	repo.AssertExpectations(t)
}

func TestGetPublicJWK_DecryptFailurePropagates(t *testing.T) {
	setTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "not-valid-ciphertext", Enabled: true,
	}, nil)

	_, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.Error(t, err, "a decrypt failure must surface, not be swallowed into an empty JWK")
	assert.Contains(t, err.Error(), "decrypt key material")
}

func TestGetPublicJWK_KeyNotFoundPropagates(t *testing.T) {
	setTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(nil, errors.New("no rows"))

	_, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeyNotFound), "must wrap ErrKeyNotFound so writeKeyError maps it to 404")
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/keys/ -run TestGetPublicJWK -v`

Expected: **build failure**, `undefined: model.PublicJWK` and `svc.GetPublicJWK undefined (type KeyService has no field or method GetPublicJWK)`.

- [ ] **Step 3: Add `model.PublicJWK`**

In `model/key.go`, immediately after the `KeyVersionRecord` struct (which closes at line 78) and before the `// --- HTTP request/response types ---` comment:

```go
// PublicJWK carries the public components of a key, extracted from its
// decrypted private material. RSA keys populate N and E; EC keys populate X
// and Y. Every field is empty for an HSM-backed key, whose material never
// leaves the token — that is a valid result, not an error.
//
// This type deliberately carries no private component. It is the only shape
// in which key material derived data reaches an HTTP response.
type PublicJWK struct {
	N string `json:"n,omitempty"` // RSA modulus (base64url).
	E string `json:"e,omitempty"` // RSA public exponent (base64url).
	X string `json:"x,omitempty"` // EC x coordinate (base64url).
	Y string `json:"y,omitempty"` // EC y coordinate (base64url).
}
```

- [ ] **Step 4: Declare `GetPublicJWK` on the `KeyService` interface**

In `internal/services/keys/key_service.go`, directly after the `GetKeyVersion` declaration (line 134):

```go
	// GetPublicJWK returns the public components of keyID's material at the
	// given version, authorized by scope. A version of 0 means the current
	// version. Every component is empty for an HSM-backed key.
	GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error)
```

- [ ] **Step 5: Implement `GetPublicJWK`**

In the same file, after `GetKeyVersion` (which ends at line 528). Add `"strings"` to the import block — the current block (lines 6-22) does not have it.

```go
// GetPublicJWK returns the public components of keyID's material at version,
// authorized by scope. A version of 0, or a version equal to the current one,
// reads keys.value; any older version reads its archived key_versions row via
// ReadVersionValue, the same resolution cryptoService.resolveVersionValue
// performs for the six crypto operations.
//
// The stored material is master-key-encrypted, so it must be decrypted before
// it can be PEM-parsed. api.buildKeyResponse previously called
// crypto.ExtractPublicComponents on the encrypted value directly and discarded
// the resulting "failed to decode PEM block" error, which is why every key
// response carried empty n/e/x/y components.
func (s *keyService) GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}

	value := key.Value
	if version > 0 {
		current, curErr := s.keyRepo.CurrentVersion(ctx, keyID, key.UserID)
		if curErr != nil {
			return nil, fmt.Errorf("resolve current key version: %w", curErr)
		}
		if version != current {
			value, err = s.keyRepo.ReadVersionValue(ctx, keyID, version, key.UserID)
			if err != nil {
				return nil, err
			}
		}
	}

	// An HSM key stores a token handle, not PEM. There is no public material
	// to return and that is a valid result, not an error.
	if strings.HasPrefix(value, pkcs11Prefix) {
		return &model.PublicJWK{}, nil
	}

	decrypted, err := common.DecryptSecret(value)
	if err != nil {
		return nil, fmt.Errorf("decrypt key material: %w", err)
	}

	n, e, x, y, err := crypto.ExtractPublicComponents(decrypted, key.Type)
	if err != nil {
		return nil, fmt.Errorf("extract public components: %w", err)
	}
	return &model.PublicJWK{N: n, E: e, X: x, Y: y}, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/services/keys/ -run TestGetPublicJWK -v`
Expected: PASS, all seven test functions.

Then confirm nothing else broke — every implementer of `KeyService` must now carry the new method:

Run: `go build ./... && go test ./internal/services/keys/ ./api/ ./cmd/... 2>&1 | tail -30`
Expected: PASS. If a mock in `api/` or `cmd/` implements `KeyService` and now fails to satisfy the interface, add a `GetPublicJWK` method to that mock returning `(&model.PublicJWK{}, nil)`; do not change the interface.

- [ ] **Step 7: Commit**

```bash
git add model/key.go internal/services/keys/key_service.go internal/services/keys/key_jwk_test.go
git commit -m "feat(keys): add KeyService.GetPublicJWK for version-aware public components"
```

---

### Task 2: Populate JWK components on the four single-key responses

**Files:**
- Modify: `api/keys.go:191-222` (`buildKeyResponse`), `:402` (`createKey`), `:464` (`getKey`), `:530` (`updateKey`), `:612` (`rotateKey`), `:432` (`listKeys`)
- Test: `api/keys_jwk_test.go` (create)

**Interfaces:**
- Consumes: `KeyService.GetPublicJWK(ctx, keyID, version, scope)` from Task 1.
- Produces: `buildKeyResponse(key *model.Key, jwk *model.PublicJWK) KeyResponse` — Task 3 does not call it, but any future handler must pass both arguments; `nil` means "omit the components".

- [ ] **Step 1: Write the failing test**

Create `api/keys_jwk_test.go`. This asserts on `buildKeyResponse` directly, which is the unit that carried the bug.

```go
package api

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

func TestBuildKeyResponse_CarriesSuppliedJWK(t *testing.T) {
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	viper.Set("master_key", base64.StdEncoding.EncodeToString(raw))

	pemKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	stored, err := common.EncryptSecret(pemKey)
	require.NoError(t, err)

	n, e, _, _, err := crypto.ExtractPublicComponents(pemKey, "RSA")
	require.NoError(t, err)
	require.NotEmpty(t, n)

	key := &model.Key{Type: model.KeyTypeRSA, Value: stored}

	resp := buildKeyResponse(key, &model.PublicJWK{N: n, E: e})
	assert.Equal(t, n, resp.N, "the supplied modulus must reach the response")
	assert.Equal(t, e, resp.E)
}

func TestBuildKeyResponse_NilJWKOmitsComponents(t *testing.T) {
	key := &model.Key{Type: model.KeyTypeRSA, Value: "anything"}

	resp := buildKeyResponse(key, nil)
	assert.Empty(t, resp.N)
	assert.Empty(t, resp.E)
	assert.Empty(t, resp.X)
	assert.Empty(t, resp.Y)
}

func TestBuildKeyResponse_HSMTypeSuffixUnchanged(t *testing.T) {
	rsa := buildKeyResponse(&model.Key{Type: model.KeyTypeRSA, Value: "pkcs11:label"}, &model.PublicJWK{})
	assert.Equal(t, "RSA-HSM", rsa.Type)

	ec := buildKeyResponse(&model.Key{Type: model.KeyTypeECDSA, Value: "pkcs11:label"}, &model.PublicJWK{})
	assert.Equal(t, "EC-HSM", ec.Type)

	k256 := buildKeyResponse(&model.Key{Type: model.KeyTypeES256K, Value: "pkcs11:label"}, &model.PublicJWK{})
	assert.Equal(t, "EC-HSM", k256.Type)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./api/ -run TestBuildKeyResponse -v`
Expected: **build failure**, `too many arguments in call to buildKeyResponse`.

- [ ] **Step 3: Change `buildKeyResponse` to take the JWK**

In `api/keys.go`, replace the function at lines 191-222. Delete the `crypto.ExtractPublicComponents` line entirely — that call is the bug.

```go
// buildKeyResponse converts a model.Key to a KeyResponse. When the key's value
// carries a "pkcs11:" prefix the type is suffixed with "-HSM" (e.g. "RSA" →
// "RSA-HSM", "ECDSA" → "EC-HSM") to match Azure Key Vault's convention for
// hardware-backed keys.
//
// jwk supplies the public components and may be nil, which omits them. It is
// passed in rather than derived here: key.Value is master-key-encrypted, so
// parsing it in this layer is impossible. This function used to call
// crypto.ExtractPublicComponents(key.Value, ...) and discard its error, which
// silently emitted empty n/e/x/y on every software key.
func buildKeyResponse(key *model.Key, jwk *model.PublicJWK) KeyResponse {
	kty := key.Type
	if strings.HasPrefix(key.Value, "pkcs11:") {
		switch kty {
		case "ECDSA", "ES256K":
			kty = "EC-HSM"
		default:
			kty = kty + "-HSM"
		}
	}
	resp := KeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Type:      kty,
		UserID:    key.UserID,
		Revoked:   key.Revoked,
		CreatedAt: key.CreatedAt,
		UpdatedAt: key.UpdatedAt,
		Tags:      key.Tags,
		Enabled:   key.Enabled,
		ExpiresAt: key.ExpiresAt,
		NotBefore: key.NotBefore,
		Bits:      key.Bits,
		Curve:     key.Curve,
	}
	if jwk != nil {
		resp.N, resp.E, resp.X, resp.Y = jwk.N, jwk.E, jwk.X, jwk.Y
	}
	return resp
}
```

- [ ] **Step 4: Update the five call sites**

`listKeys` (`api/keys.go:432`) — pass `nil`, per the Global Constraints:

```go
		response.Keys[i] = buildKeyResponse(&keysList[i], nil)
```

`createKey` (`api/keys.go:393-402`) — the scope is built inline here:

```go
	// Fetch the full key record so buildKeyResponse can report the stored
	// value's HSM prefix, and its public components for the response body.
	scope := model.NewVaultScope(vaultID, userID)
	key, err := keyService.GetKey(r.Context(), result.KeyID, scope)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	jwk, err := keyService.GetPublicJWK(r.Context(), key.ID, 0, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(buildKeyResponse(key, jwk)) //nolint:errcheck,gosec
```

`getKey` (`api/keys.go:464`), `updateKey` (`:530`), and `rotateKey` (`:612`) each already have a `scope` variable in place (`getKey` at `:452`, `updateKey` at `:499`, and `rotateKey` inside its own body). In each, replace the single encode line with:

```go
	jwk, err := keyService.GetPublicJWK(r.Context(), key.ID, 0, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildKeyResponse(key, jwk)) //nolint:errcheck,gosec
```

For `rotateKey`, keep the existing `w.Header().Set` / status-code lines as they already are and insert only the `jwk` lookup above the encode; do not change its status code.

If `rotateKey`'s local key-service variable is named something other than `keyService`, use that name — do not introduce a second lookup.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./api/ -run TestBuildKeyResponse -v`
Expected: PASS (3 tests).

Run: `go build ./... && go test ./api/ 2>&1 | tail -20`
Expected: PASS. Any existing API test that mocks `KeyService` needs the `GetPublicJWK` method added (returning `(&model.PublicJWK{}, nil)`); any test calling `buildKeyResponse` with one argument needs `, nil` appended.

- [ ] **Step 6: Commit**

```bash
git add api/keys.go api/keys_jwk_test.go
git commit -m "fix(keys): emit real JWK public components instead of parsing encrypted material"
```

---

### Task 3: Return JWK components from `GET /keys/{key_id}/versions/{version}`

**Files:**
- Modify: `api/keys.go` (new `KeyVersionResponse` type next to `KeyResponse` at `:70-89`; `getKeyVersion` handler at `:652-678`)
- Test: `api/keys_jwk_test.go` (extend the file created in Task 2)

**Interfaces:**
- Consumes: `KeyService.GetKeyVersion(ctx, keyID, version, scope) (*model.KeyVersion, error)` (`key_service.go:522`); `KeyService.GetPublicJWK(ctx, keyID, version, scope)` from Task 1; `c.Params.Version int` (`api/params.go:25`, already parsed from the `{version}` path variable, 0 if absent).
- Produces: `api.KeyVersionResponse` — the wire shape of the version-get route.

- [ ] **Step 1: Write the failing test**

Append to `api/keys_jwk_test.go`:

```go
func TestBuildKeyVersionResponse_CarriesMetadataAndJWK(t *testing.T) {
	keyID := uuid.New()
	created := time.Now().UTC().Truncate(time.Second)

	resp := buildKeyVersionResponse(
		&model.KeyVersion{KeyID: keyID, Version: 3, CreatedAt: created},
		&model.PublicJWK{N: "modulus", E: "AQAB"},
	)

	assert.Equal(t, keyID, resp.KeyID)
	assert.Equal(t, 3, resp.Version)
	assert.Equal(t, created, resp.CreatedAt)
	assert.Equal(t, "modulus", resp.N)
	assert.Equal(t, "AQAB", resp.E)
}

func TestKeyVersionResponse_NeverCarriesMaterial(t *testing.T) {
	resp := buildKeyVersionResponse(
		&model.KeyVersion{KeyID: uuid.New(), Version: 1},
		&model.PublicJWK{N: "modulus"},
	)

	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	// The response must expose no private-material field under any name.
	for _, forbidden := range []string{`"value"`, `"private`, `"pem"`, `"d"`} {
		assert.NotContains(t, string(raw), forbidden,
			"key version response must never carry private material")
	}
}
```

Add `"encoding/json"`, `"time"`, and `"github.com/google/uuid"` to that file's import block.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./api/ -run 'TestBuildKeyVersionResponse|TestKeyVersionResponse' -v`
Expected: **build failure**, `undefined: buildKeyVersionResponse`.

- [ ] **Step 3: Add the response type and builder**

In `api/keys.go`, immediately after the `KeyListResponse` type (which closes at line 94):

```go
// KeyVersionResponse is the wire shape of GET /keys/{key_id}/versions/{version}.
// It carries the version's bookkeeping metadata plus that version's public JWK
// components, matching Azure Key Vault's GET /keys/{name}/{version}, which
// returns the version's public key.
//
// It deliberately embeds no model.KeyVersionRecord and no Value field: the
// archived material stays internal to the backup service.
type KeyVersionResponse struct {
	KeyID     uuid.UUID `json:"key_id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	// JWK public components (omitted for HSM-backed keys).
	N string `json:"n,omitempty"` // RSA modulus (base64url).
	E string `json:"e,omitempty"` // RSA public exponent (base64url).
	X string `json:"x,omitempty"` // EC x coordinate (base64url).
	Y string `json:"y,omitempty"` // EC y coordinate (base64url).
}

// buildKeyVersionResponse merges a version's metadata with its public
// components. jwk may be nil, which omits the components.
func buildKeyVersionResponse(v *model.KeyVersion, jwk *model.PublicJWK) KeyVersionResponse {
	resp := KeyVersionResponse{
		KeyID:     v.KeyID,
		Version:   v.Version,
		CreatedAt: v.CreatedAt,
	}
	if jwk != nil {
		resp.N, resp.E, resp.X, resp.Y = jwk.N, jwk.E, jwk.X, jwk.Y
	}
	return resp
}
```

- [ ] **Step 4: Return it from the handler**

In `api/keys.go`, replace the tail of `getKeyVersion` (currently lines 671-678, from the `version, err := keyService.GetKeyVersion(...)` call to the end of the function):

```go
	version, err := keyService.GetKeyVersion(r.Context(), keyID, c.Params.Version, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	// Azure's GET /keys/{name}/{version} returns the version's public key, so
	// this route resolves that version's material rather than the current
	// key's. An HSM-backed key yields an empty JWK and no error.
	jwk, err := keyService.GetPublicJWK(r.Context(), keyID, c.Params.Version, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildKeyVersionResponse(version, jwk)) //nolint:errcheck,gosec
```

`writeKeyError` (`api/errors_key.go:39`) already maps `repositories.ErrKeyVersionNotFound` to a 404, so a request for a version that does not exist keeps its current status code.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./api/ -run 'TestBuildKeyVersionResponse|TestKeyVersionResponse|TestBuildKeyResponse' -v`
Expected: PASS (5 tests).

Run: `go build ./... && go test ./... 2>&1 | grep -v "^ok" | head -20`
Expected: no failures.

- [ ] **Step 6: Commit**

```bash
git add api/keys.go api/keys_jwk_test.go
git commit -m "feat(keys): return public JWK components from the key-version route"
```

---

### Task 4: Correct the parity doc and record the root cause

**Files:**
- Modify: `.claude/azure-keyvault-parity.md` (the `Get / List / List versions` row at line 41; the §2 Partial bullet in the Summary at lines 468-489)
- Modify: `.claude/known-bugs.md` (append a new numbered entry)

**Interfaces:**
- Consumes: nothing — documentation only.
- Produces: nothing consumed by other tasks.

- [ ] **Step 1: Correct the §2 row**

In `.claude/azure-keyvault-parity.md`, replace the RocketVault cell and Status of the `Get / List / List versions` row (line 41) with:

```
| Get / List / List versions | ✅ (`GET /keys/{name}/{version}` returns the version's public JWK — `n`/`e` for RSA, `x`/`y`/`crv` for EC) | ✅ `GET /keys`, `/keys/{id}`, `/keys/{id}/versions`, `/keys/{id}/versions/{version}`. The version route returns `api.KeyVersionResponse` — metadata plus that version's public JWK components, resolved through `KeyService.GetPublicJWK`. `crv` is not emitted on the version route (the archived `key_versions` row carries no curve name; the current-key response carries it as `curve`) | 🟡 (public JWK now returned per version; `crv` still absent from the version response) |
```

- [ ] **Step 2: Add the dated correction note**

Append to the §2 note block (after the paragraph ending at line 98):

```
*Corrected 2026-08-19 (fourth pass): the note above claimed the version route was
"thinner than even the current-key `GET /keys/{id}` (which does emit them via
`buildKeyResponse`)". The parenthetical was wrong — **no** key route emitted JWK
components. `buildKeyResponse` passed the master-key-encrypted `keys.value`
straight to `crypto.ExtractPublicComponents`, whose first act is `pem.Decode`;
that returned `failed to decode PEM block`, and the error was discarded into `_`
(`api/keys.go:201`), so `n`/`e`/`x`/`y` were empty on every software key and
dropped by `omitempty`. Fixed by moving extraction into
`KeyService.GetPublicJWK`, which decrypts before parsing and resolves an
archived version through `ReadVersionValue`. Both the four single-key responses
and the new `api.KeyVersionResponse` now carry real components. `listKeys`
deliberately does not — Azure's list response carries identifiers and attributes
only, and a per-key decrypt on a list endpoint is not worth the cost.*
```

- [ ] **Step 3: Correct the Summary bullet**

In the `**Partial (🟡):**` section, in the `Key operations beyond CRUD` bullet, replace the sentence beginning *"The new `GET /keys/{id}/versions/{version}` route closes the missing-route gap..."* through *"...via a crypto op with `version` set."* with:

```
  The `GET /keys/{id}/versions/{version}` route now returns that version's
  public JWK components alongside its metadata, matching Azure's real
  response; the remaining difference is `crv`, which the archived version row
  does not carry. This also fixed a latent defect the earlier passes missed:
  no key route emitted JWK components at all, because the encrypted stored
  value was being handed to a PEM parser and the failure discarded.
```

- [ ] **Step 4: Add a known-bugs entry**

Append to `.claude/known-bugs.md`, using the next free section number (check the file for the highest existing `§ Bnn` and increment):

```markdown
## B28 — JWK public components silently empty on every key response

**Status:** Fixed 2026-08-19.

**Symptom:** `GET /keys/{id}`, `POST /keys`, `PUT /keys/{id}` and
`POST /keys/{id}/rotate` all declared `n`/`e`/`x`/`y` fields in
`api.KeyResponse` and never populated them for any software-backed key.
Because all four carry `omitempty`, the fields simply vanished from the JSON
and no client could distinguish "this key has no public material" (a genuine
HSM result) from "extraction failed".

**Root cause:** `buildKeyResponse` (`api/keys.go:201`) called
`crypto.ExtractPublicComponents(key.Value, key.Type)`. `key.Value` is the
value as stored, and `KeyService` encrypts it with `common.EncryptSecret`
before `keyRepo.Create` (`key_service.go:241`, `:333`).
`ExtractPublicComponents` starts with `pem.Decode`, which returns a nil block
for base64 ciphertext, so the function returned four empty strings and
`failed to decode PEM block`. That error was assigned to `_`.

**Why it survived review:** the discarded error made the failure
indistinguishable from the legitimate HSM path, which also returns four empty
strings — but with a nil error (`key_crypto.go:139-141`). No test asserted a
non-empty `n` at the handler level; `internal/crypto/key_crypto_test.go` only
exercised `ExtractPublicComponents` with plaintext PEM, where it works
correctly.

**Fix:** extraction moved to `KeyService.GetPublicJWK`, which decrypts with
`common.DecryptSecret` before parsing and propagates both failures.
`buildKeyResponse` now receives the components rather than deriving them.
The same method resolves an archived version's material through
`KeyRepository.ReadVersionValue`, which is what let
`GET /keys/{id}/versions/{version}` gain a real public JWK.

**Pinned by:** `TestGetPublicJWK_*`
(`internal/services/keys/key_jwk_test.go`) and
`TestBuildKeyResponse_CarriesSuppliedJWK` / `TestKeyVersionResponse_NeverCarriesMaterial`
(`api/keys_jwk_test.go`).
```

- [ ] **Step 5: Commit**

```bash
git add .claude/azure-keyvault-parity.md .claude/known-bugs.md
git commit -m "docs: correct the JWK parity claim and record the discarded-error root cause"
```
