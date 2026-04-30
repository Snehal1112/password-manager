# Azure KV Feature Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Secret Content Types, Key Wrapping/Unwrapping, and Certificate Auto-Renewal to RocketVault, closing the gap with Azure Key Vault.

**Architecture:** Layered delivery — Content Types (schema + metadata only), then Key Wrapping (new crypto ops on existing CryptoService), then Certificate Auto-Renewal (new domain fields + scheduler). Each feature follows the existing DDD pattern: domain → repository → service → API → CLI.

**Tech Stack:** Go 1.24.2, Gorilla Mux, SQLite/PostgreSQL, `crypto/rsa` (RSA-OAEP), `crypto/x509` (cert parsing), testify/mock.

**Spec:** `docs/superpowers/specs/2026-04-30-azure-kv-features-design.md`

---

## Files Created or Modified

### Feature 1 — Secret Content Types
| File | Action | Purpose |
|---|---|---|
| `internal/domain/secret.go` | Modify | Add `ContentType string` field |
| `internal/db/db.go` | Modify | Add `content_type` column to schema + migration |
| `internal/repositories/secret_repository.go` | Modify | Persist/read `content_type` in SQL |
| `internal/services/secrets/secret_service.go` | Modify | Add `ContentType` to request types; validate allowlist |
| `api/secrets.go` | Modify | Accept/return `content_type` in create/update/get handlers |
| `cmd/secrets/create.go` | Modify | Add `--content-type` flag |
| `cmd/secrets/update.go` | Modify | Add `--content-type` flag |

### Feature 2 — Key Wrapping / Unwrapping
| File | Action | Purpose |
|---|---|---|
| `internal/services/keys/crypto_service.go` | Modify | Add `WrapKey`/`UnwrapKey` types + methods to interface and impl |
| `api/keys.go` | Modify | Add `wrapKey`/`unwrapKey` handlers + routes |
| `cmd/keys/wrap.go` | Create | `rocketvault keys wrap` CLI subcommand |
| `cmd/keys/unwrap.go` | Create | `rocketvault keys unwrap` CLI subcommand |

### Feature 3 — Certificate Auto-Renewal
| File | Action | Purpose |
|---|---|---|
| `internal/domain/certificate.go` | Modify | Add `ExpiresAt`, `AutoRenew`, `RenewalDays` |
| `internal/db/db.go` | Modify | Add three columns to certificates schema + migration |
| `internal/repositories/certificate_repository.go` | Modify | Persist/read new fields; add `ListAll` for scheduler |
| `internal/services/certificates/certificate_service.go` | Modify | Populate `ExpiresAt` from X.509 `NotAfter` on create/renew |
| `internal/services/certificates/renewal_service.go` | Create | `CertificateRenewalService` — check and auto-renew |
| `internal/services/certificates/renewal_scheduler.go` | Create | Daily ticker calling `CheckAndRenewCertificates` |
| `internal/container/service_container.go` | Modify | Wire renewal service into container |
| `bootstrap/bootstrap.go` | Modify | Start/stop `CertificateRenewalScheduler` |
| `api/certificates.go` | Create | HTTP handlers for certificates (currently CLI-only) |
| `cmd/certificates/create.go` | Modify | Add `--auto-renew`, `--renewal-days` flags |
| `cmd/certificates/update.go` | Modify | Add `--auto-renew`, `--renewal-days` flags |

---

## Task 1: Add `content_type` to Secret domain and schema

**Files:**
- Modify: `internal/domain/secret.go`
- Modify: `internal/db/db.go`

- [ ] **Step 1: Add `ContentType` field to `domain.Secret`**

In `internal/domain/secret.go`, add after the `Enabled` field:

```go
ContentType     string     `json:"content_type,omitempty"`     // Media type of the secret value
```

- [ ] **Step 2: Add `content_type` column to `createOptimizedSchema`**

In `internal/db/db.go`, in the `CREATE TABLE IF NOT EXISTS secrets` block (around line 297), change:

```sql
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
```
to:
```sql
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			content_type TEXT NOT NULL DEFAULT '',
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
```

- [ ] **Step 3: Add migration for `content_type` in `migrateSchema`**

In `internal/db/db.go`, add to the `migrations` slice in `migrateSchema`:

```go
// Feature: secret content types
"ALTER TABLE secrets ADD COLUMN content_type TEXT NOT NULL DEFAULT ''",
```

- [ ] **Step 4: Verify the project builds**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add internal/domain/secret.go internal/db/db.go
git commit -m "feat(content-type): add ContentType field to Secret domain and schema"
```

---

## Task 2: Persist and read `content_type` in the secret repository

**Files:**
- Modify: `internal/repositories/secret_repository.go`

- [ ] **Step 1: Write a failing test**

In `internal/repositories/secret_repository.go`, add a test file `internal/repositories/secret_repository_content_type_test.go`:

```go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type TEXT NOT NULL DEFAULT ''
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secret_tags (
		secret_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (secret_id, tag)
	)`)
	require.NoError(t, err)
	return db
}

func TestSecretRepositoryContentType(t *testing.T) {
	db := setupTestDB(t)
	log := logging.NewLogger()
	repo := repositories.NewSecretRepository(db, log)

	userID := uuid.New()
	secret := &domain.Secret{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        "my-secret",
		Value:       "encrypted-value",
		Version:     1,
		CreatedAt:   time.Now(),
		ContentType: "application/json",
	}

	err := repo.Create(context.Background(), secret)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), secret.ID)
	require.NoError(t, err)
	assert.Equal(t, "application/json", got.ContentType)
}
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/repositories/... -run TestSecretRepositoryContentType -v
```
Expected: FAIL — `ContentType` not persisted (empty string returned).

- [ ] **Step 3: Update `Create` SQL to include `content_type`**

In `internal/repositories/secret_repository.go`, change the `INSERT` in `Create` (around line 102):

```go
	_, err := r.db.ExecContext(
		ctx,
		"INSERT INTO secrets (id, user_id, name, value, version, created_at, content_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
		secret.ID.String(), secret.UserID.String(), secret.Name, secret.Value, secret.Version, secret.CreatedAt, secret.ContentType,
	)
```

- [ ] **Step 4: Update `Read` SQL to scan `content_type`**

In `internal/repositories/secret_repository.go`, change the `SELECT` in `Read` (around line 150):

```go
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type FROM secrets WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType)
```

Do the same for any other `SELECT` in the file that scans secret rows (check `ReadByNameAndUser`, list queries, etc.) — add `content_type` to the column list and `&secret.ContentType` to the Scan call for each.

- [ ] **Step 5: Update `Update` SQL to include `content_type`**

In `internal/repositories/secret_repository.go`, change the `UPDATE` in `Update` (around line 247):

```go
	result, err := r.db.ExecContext(
		ctx,
		"UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ? WHERE id = ? AND user_id = ?",
		secret.Name, secret.Value, secret.Version, secret.ContentType, secret.ID.String(), secret.UserID.String(),
	)
```

- [ ] **Step 6: Run the test to confirm it passes**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/repositories/... -run TestSecretRepositoryContentType -v
```
Expected: PASS.

- [ ] **Step 7: Run full test suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 8: Commit**

```bash
git add internal/repositories/secret_repository_content_type_test.go internal/repositories/secret_repository.go
git commit -m "feat(content-type): persist and read content_type in secret repository"
```

---

## Task 3: Validate `content_type` in the secret service

**Files:**
- Modify: `internal/services/secrets/secret_service.go`

- [ ] **Step 1: Write a failing test**

Add `internal/services/secrets/content_type_test.go`:

```go
package secrets_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/secrets"
)

type mockSecretRepoForContentType struct{ mock.Mock }

func (m *mockSecretRepoForContentType) Create(ctx context.Context, s *domain.Secret) error {
	return m.Called(ctx, s).Error(0)
}
func (m *mockSecretRepoForContentType) Read(ctx context.Context, id uuid.UUID) (*domain.Secret, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*domain.Secret), args.Error(1)
}
func (m *mockSecretRepoForContentType) Update(ctx context.Context, s *domain.Secret) error {
	return m.Called(ctx, s).Error(0)
}
func (m *mockSecretRepoForContentType) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockSecretRepoForContentType) List(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	args := m.Called(ctx, userID, tags)
	return args.Get(0).([]domain.Secret), args.Error(1)
}
func (m *mockSecretRepoForContentType) ReadByNameAndUser(ctx context.Context, name string, userID uuid.UUID) (*domain.Secret, error) {
	args := m.Called(ctx, name, userID)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*domain.Secret), args.Error(1)
}

func TestCreateSecretRejectsUnknownContentType(t *testing.T) {
	// Use the real SecretService wired with a minimal mock repo.
	// We only need to verify that an unknown content_type is rejected
	// before any repo call is made.
	svc := secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: &mockSecretRepoForContentType{},
		Logger:           logging.NewLogger(),
	})

	_, err := svc.CreateSecret(context.Background(), secrets.CreateSecretRequest{
		UserID:      uuid.New(),
		Name:        "test",
		Value:       "value",
		ContentType: "application/unknown-type",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported content type")
}

func TestCreateSecretAcceptsValidContentType(t *testing.T) {
	repo := &mockSecretRepoForContentType{}
	repo.On("ReadByNameAndUser", mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(s *domain.Secret) bool {
		return s.ContentType == "application/json"
	})).Return(nil)

	svc := secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: repo,
		Logger:           logging.NewLogger(),
	})

	_, err := svc.CreateSecret(context.Background(), secrets.CreateSecretRequest{
		UserID:      uuid.New(),
		Name:        "test",
		Value:       "value",
		ContentType: "application/json",
	})
	assert.NoError(t, err)
}
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/secrets/... -run TestCreateSecretRejectsUnknownContentType -v
```
Expected: compile error or FAIL.

- [ ] **Step 3: Add `ContentType` to `CreateSecretRequest` and `UpdateSecretRequest`**

In `internal/services/secrets/secret_service.go`:

```go
// CreateSecretRequest represents a request to create a new secret.
type CreateSecretRequest struct {
	UserID      uuid.UUID
	Name        string
	Value       string
	Tags        []string
	ContentType string // Optional media type (e.g. "application/json")
}

// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	SecretID    uuid.UUID
	UserID      uuid.UUID
	Name        *string
	Value       *string
	Tags        *[]string
	ContentType *string // Optional — nil means no change
}
```

- [ ] **Step 4: Add content type allowlist and validation helper**

In `internal/services/secrets/secret_service.go`, add after the `import` block:

```go
// validContentTypes is the set of accepted content_type values.
var validContentTypes = map[string]struct{}{
	"":                        {}, // empty = unset, always valid
	"text/plain":              {},
	"application/json":        {},
	"application/xml":         {},
	"application/x-pem-file":  {},
	"application/x-pkcs12":    {},
	"application/octet-stream": {},
}

func validateContentType(ct string) error {
	if _, ok := validContentTypes[ct]; !ok {
		return fmt.Errorf("unsupported content type: %q", ct)
	}
	return nil
}
```

- [ ] **Step 5: Call `validateContentType` in `CreateSecret` before any repo call**

In `internal/services/secrets/secret_service.go`, in `CreateSecret`, add after the name/value validation:

```go
	if err := validateContentType(req.ContentType); err != nil {
		return nil, err
	}
```

Then set `ContentType` on the domain object before calling `repo.Create`:

```go
	secret.ContentType = req.ContentType
```

- [ ] **Step 6: Apply validation and update in `UpdateSecret`**

In `UpdateSecret`, after loading the existing secret:

```go
	if req.ContentType != nil {
		if err := validateContentType(*req.ContentType); err != nil {
			return err
		}
		existing.ContentType = *req.ContentType
	}
```

- [ ] **Step 7: Run tests**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/secrets/... -run "TestCreateSecretRejectsUnknownContentType|TestCreateSecretAcceptsValidContentType" -v
```
Expected: both PASS.

- [ ] **Step 8: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 9: Commit**

```bash
git add internal/services/secrets/content_type_test.go internal/services/secrets/secret_service.go
git commit -m "feat(content-type): validate content_type in SecretService"
```

---

## Task 4: Expose `content_type` in the secrets API and CLI

**Files:**
- Modify: `api/secrets.go`
- Modify: `cmd/secrets/create.go`
- Modify: `cmd/secrets/update.go`

- [ ] **Step 1: Add `ContentType` to API request/response structs in `api/secrets.go`**

Change `CreateSecretRequest`:
```go
type CreateSecretRequest struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Tags        []string `json:"tags,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
}
```

Change `UpdateSecretRequest`:
```go
type UpdateSecretRequest struct {
	Name        string   `json:"name,omitempty"`
	Value       string   `json:"value,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	ContentType *string  `json:"content_type,omitempty"`
}
```

Change `SecretResponse`:
```go
type SecretResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Value       string   `json:"value,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Version     int      `json:"version"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
}
```

- [ ] **Step 2: Pass `ContentType` from request to service in `createSecret` handler**

In `createSecret` (around line 493), change the service call:
```go
	createReq := secrets.CreateSecretRequest{
		UserID:      userID,
		Name:        req.Name,
		Value:       req.Value,
		Tags:        req.Tags,
		ContentType: req.ContentType,
	}
```

And include it in the response:
```go
	response := SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Tags:        secret.Tags,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
		ContentType: secret.ContentType,
	}
```

- [ ] **Step 3: Pass `ContentType` in `updateSecret` handler**

Find the `updateSecret` handler in `api/secrets.go`. Add to the service call:
```go
	updateReq := secretssvc.UpdateSecretRequest{
		SecretID:    secretID,
		UserID:      userID,
		// ... existing fields ...
		ContentType: req.ContentType,
	}
```

- [ ] **Step 4: Include `ContentType` in `getSecret` response**

Find `getSecret` handler, ensure the response includes:
```go
	response := SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Value:       decryptedValue,
		Tags:        secret.Tags,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
		ContentType: secret.ContentType,
	}
```

- [ ] **Step 5: Add `--content-type` flag to `cmd/secrets/create.go`**

In the `init()` or `NewCreateCommand()` function, add:
```go
createCmd.Flags().String("content-type", "", "Media type of the secret value (e.g. application/json)")
```

In the run function, read it and pass to the service:
```go
contentType, _ := cmd.Flags().GetString("content-type")
// ... include in CreateSecretRequest:
req := secrets.CreateSecretRequest{
    // ... existing fields ...
    ContentType: contentType,
}
```

- [ ] **Step 6: Add `--content-type` flag to `cmd/secrets/update.go`**

```go
updateCmd.Flags().String("content-type", "", "Media type of the secret value")
```

In run function:
```go
contentType, _ := cmd.Flags().GetString("content-type")
var contentTypePtr *string
if cmd.Flags().Changed("content-type") {
    contentTypePtr = &contentType
}
// include ContentType: contentTypePtr in UpdateSecretRequest
```

- [ ] **Step 7: Build and verify**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 8: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 9: Commit**

```bash
git add api/secrets.go cmd/secrets/create.go cmd/secrets/update.go
git commit -m "feat(content-type): expose content_type in secrets API and CLI"
```

---

## Task 5: Add `WrapKey`/`UnwrapKey` to `CryptoService`

**Files:**
- Modify: `internal/services/keys/crypto_service.go`

- [ ] **Step 1: Write failing tests**

Add `internal/services/keys/wrap_key_test.go`:

```go
package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/keys"
)

// generateTestRSAPEM returns a 2048-bit RSA private key as PEM string.
func generateTestRSAPEM(t *testing.T) string {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	}))
}

type mockKeyRepoForWrap struct{ mock.Mock }

func (m *mockKeyRepoForWrap) Read(ctx context.Context, id uuid.UUID) (*domain.Key, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*domain.Key), args.Error(1)
}
func (m *mockKeyRepoForWrap) Create(ctx context.Context, k *domain.Key) error { return nil }
func (m *mockKeyRepoForWrap) Update(ctx context.Context, k *domain.Key) error { return nil }
func (m *mockKeyRepoForWrap) Delete(ctx context.Context, id uuid.UUID) error  { return nil }
func (m *mockKeyRepoForWrap) List(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]domain.Key, error) {
	return nil, nil
}

func TestWrapAndUnwrapKey(t *testing.T) {
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &domain.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    "RSA",
		Value:   encryptedPEM,
		Revoked: false,
	}

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(vaultKey, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        logging.NewLogger(),
	})

	plaintext := []byte("super-secret-dek-32-bytes-padded")

	wrapResult, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: plaintext,
		Algorithm:    "RSA-OAEP",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, wrapResult.WrappedKey)
	assert.Equal(t, "RSA-OAEP", wrapResult.Algorithm)

	// Set up repo mock for unwrap call too.
	repo.On("Read", mock.Anything, keyID).Return(vaultKey, nil)

	unwrapResult, err := svc.UnwrapKey(context.Background(), keys.UnwrapKeyRequest{
		KeyID:      keyID,
		UserID:     userID,
		WrappedKey: wrapResult.WrappedKey,
		Algorithm:  "RSA-OAEP",
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapResult.PlaintextKey)
}

func TestWrapKeyForbiddenForWrongUser(t *testing.T) {
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, _ := common.EncryptSecret(privateKeyPEM)

	ownerID := uuid.New()
	callerID := uuid.New()
	keyID := uuid.New()

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(&domain.Key{
		ID: keyID, UserID: ownerID, Type: "RSA", Value: encryptedPEM,
	}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        logging.NewLogger(),
	})

	_, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       callerID,
		PlaintextKey: []byte("dek"),
		Algorithm:    "RSA-OAEP",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestWrapKeyRejectsUnsupportedAlgorithm(t *testing.T) {
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, _ := common.EncryptSecret(privateKeyPEM)
	userID := uuid.New()
	keyID := uuid.New()

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(&domain.Key{
		ID: keyID, UserID: userID, Type: "RSA", Value: encryptedPEM,
	}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        logging.NewLogger(),
	})

	_, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID: keyID, UserID: userID,
		PlaintextKey: []byte("dek"),
		Algorithm:    "ECDH-ES",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/keys/... -run "TestWrapAndUnwrapKey|TestWrapKeyForbidden|TestWrapKeyRejects" -v
```
Expected: compile error — `WrapKey`/`UnwrapKey` not defined.

- [ ] **Step 3: Add request/result types and extend the interface**

In `internal/services/keys/crypto_service.go`, after the `DecryptResult` type, add:

```go
// WrapKeyRequest is a request to wrap key material with an RSA vault key.
type WrapKeyRequest struct {
	KeyID        uuid.UUID
	UserID       uuid.UUID
	PlaintextKey []byte
	Algorithm    string // must be "RSA-OAEP"
}

// WrapKeyResult holds the wrapped key bytes.
type WrapKeyResult struct {
	WrappedKey []byte
	Algorithm  string
}

// UnwrapKeyRequest is a request to unwrap key material with an RSA vault key.
type UnwrapKeyRequest struct {
	KeyID      uuid.UUID
	UserID     uuid.UUID
	WrappedKey []byte
	Algorithm  string // must be "RSA-OAEP"
}

// UnwrapKeyResult holds the recovered plaintext key bytes.
type UnwrapKeyResult struct {
	PlaintextKey []byte
	Algorithm    string
}
```

Add to `CryptoService` interface:

```go
	WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error)
	UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error)
```

- [ ] **Step 4: Implement `WrapKey`**

Add to the `cryptoService` struct in `internal/services/keys/crypto_service.go`:

```go
// WrapKey encrypts plaintext key material using the vault RSA key (RSA-OAEP).
func (s *cryptoService) WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error) {
	if req.Algorithm != "RSA-OAEP" {
		return nil, fmt.Errorf("unsupported algorithm %q: only RSA-OAEP is supported", req.Algorithm)
	}

	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "forbidden",
			fmt.Sprintf("unauthorized wrap attempt with key %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed",
			fmt.Sprintf("attempted wrap with revoked key %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot wrap with revoked key")
	}

	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "failed to decrypt vault key", err)
		return nil, fmt.Errorf("failed to decrypt vault key: %w", err)
	}

	result, err := s.cryptoOps.Encrypt(decryptedKey, req.PlaintextKey, crypto.AlgorithmRSAOAEP)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "RSA-OAEP wrap failed", err)
		return nil, fmt.Errorf("wrap failed: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "wrap_key", "success",
		fmt.Sprintf("key material wrapped with vault key %s", req.KeyID))

	return &WrapKeyResult{WrappedKey: result.Ciphertext, Algorithm: "RSA-OAEP"}, nil
}
```

- [ ] **Step 5: Implement `UnwrapKey`**

```go
// UnwrapKey decrypts wrapped key material using the vault RSA key (RSA-OAEP).
func (s *cryptoService) UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error) {
	if req.Algorithm != "RSA-OAEP" {
		return nil, fmt.Errorf("unsupported algorithm %q: only RSA-OAEP is supported", req.Algorithm)
	}

	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "forbidden",
			fmt.Sprintf("unauthorized unwrap attempt with key %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed",
			fmt.Sprintf("attempted unwrap with revoked key %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot unwrap with revoked key")
	}

	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "failed to decrypt vault key", err)
		return nil, fmt.Errorf("failed to decrypt vault key: %w", err)
	}

	result, err := s.cryptoOps.Decrypt(decryptedKey, req.WrappedKey, nil, crypto.AlgorithmRSAOAEP)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "RSA-OAEP unwrap failed", err)
		return nil, fmt.Errorf("unwrap failed: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "unwrap_key", "success",
		fmt.Sprintf("key material unwrapped with vault key %s", req.KeyID))

	return &UnwrapKeyResult{PlaintextKey: result.Plaintext, Algorithm: "RSA-OAEP"}, nil
}
```

- [ ] **Step 6: Run tests**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/keys/... -run "TestWrapAndUnwrapKey|TestWrapKeyForbidden|TestWrapKeyRejects" -v
```
Expected: all PASS.

- [ ] **Step 7: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 8: Commit**

```bash
git add internal/services/keys/wrap_key_test.go internal/services/keys/crypto_service.go
git commit -m "feat(key-wrap): add WrapKey and UnwrapKey to CryptoService"
```

---

## Task 6: Add wrap/unwrap HTTP handlers and routes

**Files:**
- Modify: `api/keys.go`

- [ ] **Step 1: Add request/response types to `api/keys.go`**

After the existing type declarations, add:

```go
// WrapKeyRequest is the HTTP request body for POST /keys/{id}/wrap.
type WrapKeyRequest struct {
	PlaintextKey string `json:"plaintext_key"` // base64-encoded key material
	Algorithm    string `json:"algorithm"`     // "RSA-OAEP"
}

// WrapKeyResponse is the HTTP response for a successful wrap.
type WrapKeyResponse struct {
	WrappedKey string `json:"wrapped_key"` // base64-encoded wrapped bytes
	Algorithm  string `json:"algorithm"`
}

// UnwrapKeyRequest is the HTTP request body for POST /keys/{id}/unwrap.
type UnwrapKeyRequest struct {
	WrappedKey string `json:"wrapped_key"` // base64-encoded wrapped bytes
	Algorithm  string `json:"algorithm"`
}

// UnwrapKeyResponse is the HTTP response for a successful unwrap.
type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"` // base64-encoded recovered key
	Algorithm    string `json:"algorithm"`
}
```

- [ ] **Step 2: Register routes in `InitKeys`**

In `InitKeys`, add after the `rotate` route:

```go
	keys.Handle("/{id:[A-Fa-f0-9-]+}/wrap", SessionRequired(api.App, wrapKey)).Methods("POST")
	keys.Handle("/{id:[A-Fa-f0-9-]+}/unwrap", SessionRequired(api.App, unwrapKey)).Methods("POST")
```

- [ ] **Step 3: Implement `wrapKey` handler**

Add to `api/keys.go`:

```go
// wrapKey handles POST /keys/{id}/wrap.
func wrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("wrapKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("wrapKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("wrapKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req WrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("wrapKey", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlaintextKey == "" {
		c.Err = common.NewAppError("wrapKey", "plaintext_key is required", nil, "", http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	plaintextBytes, err := base64.StdEncoding.DecodeString(req.PlaintextKey)
	if err != nil {
		c.Err = common.NewAppError("wrapKey", "plaintext_key must be valid base64", nil, err.Error(), http.StatusBadRequest)
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.WrapKey(r.Context(), keyservices.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: plaintextBytes,
		Algorithm:    req.Algorithm,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "forbidden") {
			status = http.StatusForbidden
		} else if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "unsupported algorithm") {
			status = http.StatusBadRequest
		}
		c.Err = common.NewAppError("wrapKey", "Wrap operation failed", nil, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WrapKeyResponse{
		WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
		Algorithm:  result.Algorithm,
	})
}
```

- [ ] **Step 4: Implement `unwrapKey` handler**

```go
// unwrapKey handles POST /keys/{id}/unwrap.
func unwrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("unwrapKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("unwrapKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("unwrapKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req UnwrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("unwrapKey", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	if req.WrappedKey == "" {
		c.Err = common.NewAppError("unwrapKey", "wrapped_key is required", nil, "", http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	wrappedBytes, err := base64.StdEncoding.DecodeString(req.WrappedKey)
	if err != nil {
		c.Err = common.NewAppError("unwrapKey", "wrapped_key must be valid base64", nil, err.Error(), http.StatusBadRequest)
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.UnwrapKey(r.Context(), keyservices.UnwrapKeyRequest{
		KeyID:      keyID,
		UserID:     userID,
		WrappedKey: wrappedBytes,
		Algorithm:  req.Algorithm,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "forbidden") {
			status = http.StatusForbidden
		} else if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "unsupported algorithm") {
			status = http.StatusBadRequest
		}
		c.Err = common.NewAppError("unwrapKey", "Unwrap operation failed", nil, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UnwrapKeyResponse{
		PlaintextKey: base64.StdEncoding.EncodeToString(result.PlaintextKey),
		Algorithm:    result.Algorithm,
	})
}
```

- [ ] **Step 5: Add missing import `encoding/base64` to `api/keys.go`**

Ensure the import block in `api/keys.go` includes:
```go
	"encoding/base64"
```

- [ ] **Step 6: Check for `c.cryptoSvc()` context accessor**

Run:
```bash
grep -n "cryptoSvc\|CryptoSvc" /home/numericlabs/data/Golang/rocketvault/api/context.go
```

If it does not exist, add to `api/context.go`:
```go
func (c *Context) cryptoSvc() keyservices.CryptoService {
	svc := GetCryptoService(c.App)
	if svc == nil {
		c.Err = common.NewAppError("cryptoSvc", "Crypto service unavailable", nil, "", http.StatusInternalServerError)
	}
	return svc
}
```

Also add the corresponding getter to `api/context_accessors` or wherever `secretSvc()` and `keySvc()` are defined — follow the exact same pattern.

- [ ] **Step 7: Build**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 8: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 9: Commit**

```bash
git add api/keys.go api/context.go
git commit -m "feat(key-wrap): add wrap and unwrap HTTP endpoints to keys API"
```

---

## Task 7: Add `wrap` and `unwrap` CLI subcommands

**Files:**
- Create: `cmd/keys/wrap.go`
- Create: `cmd/keys/unwrap.go`

- [ ] **Step 1: Create `cmd/keys/wrap.go`**

```go
/*
Copyright © 2025 Snehal Dangroshiya
...license header...
*/
package keys

import (
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/internal/services/keys"
)

// NewWrapCmd returns the cobra command for wrapping key material.
func NewWrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wrap",
		Short: "Wrap key material with a vault RSA key (RSA-OAEP)",
		RunE:  runWrap,
	}
	cmd.Flags().String("key-id", "", "UUID of the vault key (KEK) to use for wrapping (required)")
	cmd.Flags().String("key-material", "", "Base64-encoded key material to wrap (required)")
	cmd.MarkFlagRequired("key-id")
	cmd.MarkFlagRequired("key-material")
	return cmd
}

func runWrap(cmd *cobra.Command, args []string) error {
	keyIDStr, _ := cmd.Flags().GetString("key-id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		return fmt.Errorf("invalid key-id: %w", err)
	}

	keyMaterialB64, _ := cmd.Flags().GetString("key-material")
	plaintext, err := base64.StdEncoding.DecodeString(keyMaterialB64)
	if err != nil {
		return fmt.Errorf("key-material must be valid base64: %w", err)
	}

	container, err := getServiceContainer(cmd)
	if err != nil {
		return err
	}
	userID, err := getCallerUserID(cmd)
	if err != nil {
		return err
	}

	cryptoSvc := container.GetCryptoService()
	result, err := cryptoSvc.WrapKey(cmd.Context(), keys.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: plaintext,
		Algorithm:    "RSA-OAEP",
	})
	if err != nil {
		return fmt.Errorf("wrap failed: %w", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(result.WrappedKey))
	return nil
}
```

- [ ] **Step 2: Create `cmd/keys/unwrap.go`**

```go
/*
Copyright © 2025 Snehal Dangroshiya
...license header...
*/
package keys

import (
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/internal/services/keys"
)

// NewUnwrapCmd returns the cobra command for unwrapping key material.
func NewUnwrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unwrap",
		Short: "Unwrap key material with a vault RSA key (RSA-OAEP)",
		RunE:  runUnwrap,
	}
	cmd.Flags().String("key-id", "", "UUID of the vault key (KEK) to use for unwrapping (required)")
	cmd.Flags().String("wrapped-key", "", "Base64-encoded wrapped key to unwrap (required)")
	cmd.MarkFlagRequired("key-id")
	cmd.MarkFlagRequired("wrapped-key")
	return cmd
}

func runUnwrap(cmd *cobra.Command, args []string) error {
	keyIDStr, _ := cmd.Flags().GetString("key-id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		return fmt.Errorf("invalid key-id: %w", err)
	}

	wrappedB64, _ := cmd.Flags().GetString("wrapped-key")
	wrappedBytes, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return fmt.Errorf("wrapped-key must be valid base64: %w", err)
	}

	container, err := getServiceContainer(cmd)
	if err != nil {
		return err
	}
	userID, err := getCallerUserID(cmd)
	if err != nil {
		return err
	}

	cryptoSvc := container.GetCryptoService()
	result, err := cryptoSvc.UnwrapKey(cmd.Context(), keys.UnwrapKeyRequest{
		KeyID:      keyID,
		UserID:     userID,
		WrappedKey: wrappedBytes,
		Algorithm:  "RSA-OAEP",
	})
	if err != nil {
		return fmt.Errorf("unwrap failed: %w", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(result.PlaintextKey))
	return nil
}
```

- [ ] **Step 3: Register commands in the keys root command**

Find where `cmd/keys/` subcommands are registered (check `cmd/keys.go` or `cmd/certificate.go` for pattern). Add:

```go
keysCmd.AddCommand(NewWrapCmd())
keysCmd.AddCommand(NewUnwrapCmd())
```

Note: Check that `getServiceContainer` and `getCallerUserID` are helpers already defined in the keys package (e.g., in `cmd/keys/create.go` or a shared `helpers.go`). Use the exact same function names as the other subcommands in that package.

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add cmd/keys/wrap.go cmd/keys/unwrap.go cmd/keys.go
git commit -m "feat(key-wrap): add rocketvault keys wrap and unwrap CLI subcommands"
```

---

## Task 8: Add `ExpiresAt`, `AutoRenew`, `RenewalDays` to Certificate domain and schema

**Files:**
- Modify: `internal/domain/certificate.go`
- Modify: `internal/db/db.go`

- [ ] **Step 1: Add three fields to `domain.Certificate`**

In `internal/domain/certificate.go`, add after `ScheduledPurgeAt`:

```go
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // populated from X.509 NotAfter; read-only via API
	AutoRenew   bool       `json:"auto_renew"`            // if true, scheduler renews before expiry
	RenewalDays int        `json:"renewal_days"`          // days before expiry to trigger renewal
```

- [ ] **Step 2: Add columns to `createOptimizedSchema`**

In `internal/db/db.go`, in the `CREATE TABLE IF NOT EXISTS certificates` block, add before the `FOREIGN KEY` line:

```sql
			expires_at DATETIME,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30,
```

- [ ] **Step 3: Add migrations in `migrateSchema`**

Add to the `migrations` slice:

```go
// Feature: certificate auto-renewal
"ALTER TABLE certificates ADD COLUMN expires_at DATETIME",
"ALTER TABLE certificates ADD COLUMN auto_renew BOOLEAN NOT NULL DEFAULT FALSE",
"ALTER TABLE certificates ADD COLUMN renewal_days INTEGER NOT NULL DEFAULT 30",
```

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add internal/domain/certificate.go internal/db/db.go
git commit -m "feat(cert-renewal): add ExpiresAt, AutoRenew, RenewalDays to Certificate domain and schema"
```

---

## Task 9: Persist and read new certificate fields in repository

**Files:**
- Modify: `internal/repositories/certificate_repository.go`

- [ ] **Step 1: Write a failing test**

Add `internal/repositories/certificate_renewal_repo_test.go`:

```go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

func setupCertTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		expires_at DATETIME,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificate_tags (
		certificate_id TEXT NOT NULL, tag TEXT NOT NULL,
		PRIMARY KEY (certificate_id, tag))`)
	require.NoError(t, err)
	return db
}

func TestCertificateRepositoryRenewalFields(t *testing.T) {
	db := setupCertTestDB(t)
	log := logging.NewLogger()
	repo := repositories.NewCertificateRepository(db, log)

	expires := time.Now().Add(90 * 24 * time.Hour)
	cert := &domain.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "test-cert",
		Certificate: "PEM",
		PrivateKey:  "ENCRYPTED",
		CreatedAt:   time.Now(),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 14,
	}

	err := repo.Create(context.Background(), cert)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), cert.ID)
	require.NoError(t, err)
	assert.True(t, got.AutoRenew)
	assert.Equal(t, 14, got.RenewalDays)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, expires, *got.ExpiresAt, time.Second)
}
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/repositories/... -run TestCertificateRepositoryRenewalFields -v
```
Expected: FAIL — fields not persisted.

- [ ] **Step 3: Update `Create` SQL in certificate repository**

In `internal/repositories/certificate_repository.go`, change the INSERT (around line 112):

```go
		_, err = tx.ExecContext(
			ctx,
			"INSERT INTO certificates (id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			cert.ID.String(), cert.UserID.String(), cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
			cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays,
		)
```

- [ ] **Step 4: Update `Read` SQL to scan new fields**

In `internal/repositories/certificate_repository.go`, change the SELECT in `Read` (around line 167):

```go
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days FROM certificates WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
		&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays)
```

- [ ] **Step 5: Update `Update` SQL**

In `Update` (around line 227):

```go
		_, err := tx.ExecContext(
			ctx,
			"UPDATE certificates SET name = ?, certificate = ?, private_key = ?, created_at = ?, expires_at = ?, auto_renew = ?, renewal_days = ? WHERE id = ?",
			cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
			cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays, cert.ID.String(),
		)
```

- [ ] **Step 6: Update `ListByUser` scan to include new fields**

In `ListByUser` (around line 421), change:

```go
			if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
				&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays); err != nil {
```

Update the SELECT query correspondingly:

```sql
SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days
FROM certificates WHERE user_id = ? AND deleted_at IS NULL
```

- [ ] **Step 7: Add `ListAll` method for the scheduler**

Add to the `CertificateRepositoryInterface`:

```go
	ListAll(ctx context.Context) ([]domain.Certificate, error)
```

Add implementation:

```go
func (r *CertificateRepository) ListAll(ctx context.Context) ([]domain.Certificate, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days FROM certificates WHERE deleted_at IS NULL")
	if err != nil {
		return nil, fmt.Errorf("failed to list all certificates: %w", err)
	}
	defer rows.Close()

	var certs []domain.Certificate
	for rows.Next() {
		var cert domain.Certificate
		var idStr, userIDStr string
		if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
			&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays); err != nil {
			return nil, fmt.Errorf("failed to scan certificate row: %w", err)
		}
		cert.ID = uuid.MustParse(idStr)
		cert.UserID = uuid.MustParse(userIDStr)
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}
```

- [ ] **Step 8: Run tests**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/repositories/... -run TestCertificateRepositoryRenewalFields -v
```
Expected: PASS.

- [ ] **Step 9: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 10: Commit**

```bash
git add internal/repositories/certificate_renewal_repo_test.go internal/repositories/certificate_repository.go
git commit -m "feat(cert-renewal): persist and read renewal fields in certificate repository"
```

---

## Task 10: Populate `ExpiresAt` from X.509 NotAfter in CertificateService

**Files:**
- Modify: `internal/services/certificates/certificate_service.go`

- [ ] **Step 1: Write a failing test**

Add `internal/services/certificates/expires_at_test.go`:

```go
package certificates_test

import (
	"testing"
	"time"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseCertNotAfter parses the NotAfter from a PEM-encoded certificate.
func parseCertNotAfter(t *testing.T, certPEM string) time.Time {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert.NotAfter
}

func TestExtractExpiresAt(t *testing.T) {
	// Generate a self-signed cert valid for 30 days.
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &pk.PublicKey, pk)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	got := parseCertNotAfter(t, certPEM)
	assert.WithinDuration(t, notAfter, got, time.Second)
}
```

This test validates the X.509 parse logic we'll extract into a helper.

- [ ] **Step 2: Run to confirm PASS** (the parsing logic already exists in `crypto/x509_helper.go`; this test just validates the pattern)

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/certificates/... -run TestExtractExpiresAt -v
```

- [ ] **Step 3: Add `extractExpiresAt` helper in `certificate_service.go`**

Add a private helper at the bottom of `internal/services/certificates/certificate_service.go`:

```go
// extractExpiresAt parses the NotAfter field from a PEM-encoded X.509 certificate.
func extractExpiresAt(certPEM string) (*time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}
	t := cert.NotAfter
	return &t, nil
}
```

Add required imports if not already present:
```go
	"crypto/x509"
	"encoding/pem"
```

- [ ] **Step 4: Populate `ExpiresAt` in `CreateSelfSignedCertificate`**

In `CreateSelfSignedCertificate`, after `certPEM` is generated and before `cert` is constructed:

```go
	expiresAt, err := extractExpiresAt(certPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to parse certificate expiry", err)
		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
	}
```

And in the `domain.Certificate` literal:
```go
	cert := &domain.Certificate{
		// ... existing fields ...
		ExpiresAt:   expiresAt,
		AutoRenew:   req.AutoRenew,
		RenewalDays: req.RenewalDays,
	}
```

- [ ] **Step 5: Add `AutoRenew` and `RenewalDays` to `CreateCertificateRequest`**

In `internal/services/certificates/certificate_service.go`, add to `CreateCertificateRequest`:

```go
	AutoRenew   bool
	RenewalDays int // 0 defaults to 30
```

- [ ] **Step 6: Populate `ExpiresAt` in `CreateCASignedCertificate` and `RenewCertificate`**

Apply the same `extractExpiresAt` call and field assignment in both functions, identical to step 4. In `RenewCertificate`, also copy `AutoRenew` and `RenewalDays` from the original cert to the renewed cert.

- [ ] **Step 7: Build**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 8: Run tests**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/certificates/... -v 2>&1 | tail -30
```
Expected: no failures.

- [ ] **Step 9: Commit**

```bash
git add internal/services/certificates/certificate_service.go internal/services/certificates/expires_at_test.go
git commit -m "feat(cert-renewal): populate ExpiresAt from X.509 NotAfter in CertificateService"
```

---

## Task 11: Implement `CertificateRenewalService`

**Files:**
- Create: `internal/services/certificates/renewal_service.go`

- [ ] **Step 1: Write a failing test**

Create `internal/services/certificates/renewal_service_test.go`:

```go
package certificates_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/certificates"
)

type mockCertRepoForRenewal struct{ mock.Mock }

func (m *mockCertRepoForRenewal) ListAll(ctx context.Context) ([]domain.Certificate, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Certificate), args.Error(1)
}

type mockCertServiceForRenewal struct{ mock.Mock }

func (m *mockCertServiceForRenewal) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*certificates.CreateCertificateResult, error) {
	args := m.Called(ctx, certID, userID, validityDays)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*certificates.CreateCertificateResult), args.Error(1)
}

func TestCheckAndRenewCertificates_AutoRenew(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour) // expires in 10 days
	certID := uuid.New()
	userID := uuid.New()
	cert := domain.Certificate{
		ID:          certID,
		UserID:      userID,
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]domain.Certificate{cert}, nil)

	certSvc := &mockCertServiceForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, certID, userID, mock.AnythingOfType("int")).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             logging.NewLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

func TestCheckAndRenewCertificates_WarnOnly(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	cert := domain.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   false,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]domain.Certificate{cert}, nil)

	certSvc := &mockCertServiceForRenewal{}
	// RenewCertificate must NOT be called.

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             logging.NewLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 1, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate")
}
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/certificates/... -run "TestCheckAndRenew" -v
```
Expected: compile error — package doesn't exist yet.

- [ ] **Step 3: Create `internal/services/certificates/renewal_service.go`**

```go
package certificates

import (
	"context"
	"time"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// RenewalCertServiceInterface is the subset of CertificateService used by the renewal service.
type RenewalCertServiceInterface interface {
	RenewCertificate(ctx context.Context, certID, userID interface{ String() string }, validityDays int) (*CreateCertificateResult, error)
}

// CertificateRenewalService checks all certificates and renews or warns based on the auto_renew flag.
type CertificateRenewalService interface {
	CheckAndRenewCertificates(ctx context.Context) (renewed int, warned int, err error)
}

// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
}

type certRenewalService struct {
	certRepo repositories.CertificateRepositoryInterface
	certSvc  CertificateService
	logger   *logging.Logger
}

// NewCertificateRenewalService constructs the renewal service.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo: cfg.CertRepository,
		certSvc:  cfg.CertificateService,
		logger:   cfg.Logger,
	}
}

// CheckAndRenewCertificates scans all certificates and either renews or warns.
func (s *certRenewalService) CheckAndRenewCertificates(ctx context.Context) (int, int, error) {
	certs, err := s.certRepo.ListAll(ctx)
	if err != nil {
		return 0, 0, err
	}

	var renewed, warned int
	now := time.Now()

	for _, cert := range certs {
		if cert.ExpiresAt == nil {
			continue
		}
		if cert.ExpiresAt.Before(now) {
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_expiry_warning", "warning",
				"Certificate already expired: "+cert.Name)
			continue
		}

		daysUntilExpiry := int(cert.ExpiresAt.Sub(now).Hours() / 24)
		renewalDays := cert.RenewalDays
		if renewalDays <= 0 {
			renewalDays = 30
		}

		if daysUntilExpiry > renewalDays {
			continue
		}

		if cert.AutoRenew {
			validityDays := 365
			if !cert.CreatedAt.IsZero() && cert.ExpiresAt != nil {
				validityDays = int(cert.ExpiresAt.Sub(cert.CreatedAt).Hours() / 24)
			}
			if validityDays <= 0 {
				validityDays = 365
			}

			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, cert.UserID, validityDays)
			if err != nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal failed for: "+cert.Name, err)
				continue
			}
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_auto_renew", "success",
				"Auto-renewed certificate: "+cert.Name)
			renewed++
		} else {
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_expiry_warning", "warning",
				"Certificate expiring soon (auto_renew disabled): "+cert.Name)
			warned++
		}
	}

	return renewed, warned, nil
}
```

- [ ] **Step 4: Run tests**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./internal/services/certificates/... -run "TestCheckAndRenew" -v
```
Expected: both PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add internal/services/certificates/renewal_service.go internal/services/certificates/renewal_service_test.go
git commit -m "feat(cert-renewal): implement CertificateRenewalService"
```

---

## Task 12: Implement `CertificateRenewalScheduler`

**Files:**
- Create: `internal/services/certificates/renewal_scheduler.go`

- [ ] **Step 1: Create `renewal_scheduler.go`**

```go
package certificates

import (
	"context"
	"time"

	"rocketvault/internal/logging"
)

// CertificateRenewalScheduler runs CertificateRenewalService on a configurable interval.
type CertificateRenewalScheduler struct {
	svc    CertificateRenewalService
	log    *logging.Logger
	done   chan struct{}
	interval time.Duration
}

// NewCertificateRenewalScheduler creates a scheduler with the given interval.
func NewCertificateRenewalScheduler(svc CertificateRenewalService, log *logging.Logger, interval time.Duration) *CertificateRenewalScheduler {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &CertificateRenewalScheduler{svc: svc, log: log, done: make(chan struct{}), interval: interval}
}

// Start launches the scheduler in a background goroutine.
func (s *CertificateRenewalScheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop signals the scheduler to stop.
func (s *CertificateRenewalScheduler) Stop() {
	close(s.done)
}

func (s *CertificateRenewalScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run once immediately on startup.
	s.check(ctx)

	for {
		select {
		case <-ticker.C:
			s.check(ctx)
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *CertificateRenewalScheduler) check(ctx context.Context) {
	renewed, warned, err := s.svc.CheckAndRenewCertificates(ctx)
	if err != nil {
		s.log.WithError(err).Error("certificate renewal check failed")
		return
	}
	if renewed > 0 || warned > 0 {
		s.log.Infof("certificate renewal check: %d renewed, %d warned", renewed, warned)
	}
}
```

- [ ] **Step 2: Build**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/services/certificates/renewal_scheduler.go
git commit -m "feat(cert-renewal): implement CertificateRenewalScheduler"
```

---

## Task 13: Wire renewal service into the container and bootstrap

**Files:**
- Modify: `internal/container/service_container.go`
- Modify: `bootstrap/bootstrap.go`

- [ ] **Step 1: Check how `CertificateService` is exposed in the container**

```bash
grep -n "CertificateService\|GetCertificate\|certService" /home/numericlabs/data/Golang/rocketvault/internal/container/service_container.go | head -20
```

- [ ] **Step 2: Add `CertificateRenewalService` to the container**

In `internal/container/service_container.go`, add a field to the container struct:

```go
	certRenewalService certificates.CertificateRenewalService
```

In the container initialization (wherever `CertificateService` is created), add after it:

```go
	container.certRenewalService = certificates.NewCertificateRenewalService(
		certificates.RenewalServiceConfig{
			CertRepository:     container.certRepo,
			CertificateService: container.certService,
			Logger:             container.logger,
		},
	)
```

Add a getter:

```go
func (c *ServiceContainer) GetCertificateRenewalService() certificates.CertificateRenewalService {
	return c.certRenewalService
}
```

- [ ] **Step 3: Add `renewalScheduler` to `bootstrap.go`**

In `bootstrap/bootstrap.go`, add a field alongside `purgeScheduler`:

```go
	renewalScheduler *certificates.CertificateRenewalScheduler
```

In the `Bootstrap` method, after the purge scheduler start (Step 2b), add:

```go
	// Step 2c: Start certificate renewal scheduler.
	renewalSvc := container.GetCertificateRenewalService()
	b.renewalScheduler = certificates.NewCertificateRenewalScheduler(renewalSvc, b.cfg.Logger, 24*time.Hour)
	b.renewalScheduler.Start(ctx)
```

In the shutdown function, alongside `b.purgeScheduler.Stop()`, add:

```go
	if b.renewalScheduler != nil {
		b.renewalScheduler.Stop()
	}
```

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 5: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add internal/container/service_container.go bootstrap/bootstrap.go
git commit -m "feat(cert-renewal): wire CertificateRenewalService into container and start scheduler in bootstrap"
```

---

## Task 14: Add `auto_renew` and `renewal_days` to certificates API and CLI

**Files:**
- Create: `api/certificates.go`
- Modify: `cmd/certificates/create.go`
- Modify: `cmd/certificates/update.go`

- [ ] **Step 1: Create `api/certificates.go` with request/response types and routes**

```go
/*
Copyright © 2025 Snehal Dangroshiya
...license header...
*/
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/common"
	certservices "rocketvault/internal/services/certificates"
)

// CreateCertificateRequest is the HTTP request body for POST /certificates.
type CreateCertificateRequest struct {
	Name         string   `json:"name"`
	KeyID        string   `json:"key_id"`
	ValidityDays int      `json:"validity_days"`
	Tags         []string `json:"tags,omitempty"`
	AutoRenew    bool     `json:"auto_renew"`
	RenewalDays  int      `json:"renewal_days"`
	CAKeyID      string   `json:"ca_key_id,omitempty"`
	CACertID     string   `json:"ca_cert_id,omitempty"`
}

// CertificateResponse is the HTTP response for certificate operations.
type CertificateResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	UserID      uuid.UUID  `json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Tags        []string   `json:"tags,omitempty"`
	AutoRenew   bool       `json:"auto_renew"`
	RenewalDays int        `json:"renewal_days"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// InitCertificates registers HTTP routes for certificate management.
func (api *API) InitCertificates(certs *mux.Router) {
	certs.Handle("", SessionRequired(api.App, createCertificate)).Methods("POST")
	certs.Handle("", SessionRequired(api.App, listCertificates)).Methods("GET")
	certs.Handle("/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, getCertificate)).Methods("GET")
	certs.Handle("/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, updateCertificate)).Methods("PUT")
	certs.Handle("/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, deleteCertificate)).Methods("DELETE")
	api.Logger.Infoln("Certificates API routes initialized")
}

func createCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	var req CreateCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("createCertificate", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.KeyID == "" {
		c.Err = common.NewAppError("createCertificate", "name and key_id are required", nil, "", http.StatusBadRequest)
		return
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}
	if req.RenewalDays <= 0 {
		req.RenewalDays = 30
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("createCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("createCertificate", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}
	keyID, err := uuid.Parse(req.KeyID)
	if err != nil {
		c.Err = common.NewAppError("createCertificate", "Invalid key_id", nil, err.Error(), http.StatusBadRequest)
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	createReq := certservices.CreateCertificateRequest{
		Name:         req.Name,
		KeyID:        keyID,
		UserID:       userID,
		ValidityDays: req.ValidityDays,
		Tags:         req.Tags,
		AutoRenew:    req.AutoRenew,
		RenewalDays:  req.RenewalDays,
	}

	var result *certservices.CreateCertificateResult
	if req.CAKeyID != "" && req.CACertID != "" {
		caKeyID, _ := uuid.Parse(req.CAKeyID)
		caCertID, _ := uuid.Parse(req.CACertID)
		createReq.CAKeyID = caKeyID
		createReq.CACertID = caCertID
		result, err = certSvc.CreateCASignedCertificate(r.Context(), createReq)
	} else {
		result, err = certSvc.CreateSelfSignedCertificate(r.Context(), createReq)
	}
	if err != nil {
		c.Err = common.NewAppError("createCertificate", "Failed to create certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CertificateResponse{
		ID:          result.CertID,
		Name:        result.Name,
		UserID:      userID,
		CreatedAt:   result.CreatedAt,
		Tags:        result.Tags,
		AutoRenew:   req.AutoRenew,
		RenewalDays: req.RenewalDays,
		ExpiresAt:   result.ExpiresAt,
	})
}

func getCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("getCertificate", "Invalid certificate ID", nil, err.Error(), http.StatusBadRequest)
		return
	}
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("getCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	cert, err := certSvc.GetCertificate(r.Context(), certID, userID)
	if err != nil {
		c.Err = common.NewAppError("getCertificate", "Certificate not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CertificateResponse{
		ID:          cert.ID,
		Name:        cert.Name,
		UserID:      cert.UserID,
		CreatedAt:   cert.CreatedAt,
		Tags:        cert.Tags,
		AutoRenew:   cert.AutoRenew,
		RenewalDays: cert.RenewalDays,
		ExpiresAt:   cert.ExpiresAt,
	})
}

func listCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("listCertificates", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	certs, err := certSvc.ListCertificates(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("listCertificates", "Failed to list certificates", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := make([]CertificateResponse, len(certs))
	for i, cert := range certs {
		resp[i] = CertificateResponse{
			ID:          cert.ID,
			Name:        cert.Name,
			UserID:      cert.UserID,
			CreatedAt:   cert.CreatedAt,
			Tags:        cert.Tags,
			AutoRenew:   cert.AutoRenew,
			RenewalDays: cert.RenewalDays,
			ExpiresAt:   cert.ExpiresAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func updateCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("updateCertificate", "Invalid certificate ID", nil, err.Error(), http.StatusBadRequest)
		return
	}
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("updateCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	var body struct {
		Name        *string   `json:"name,omitempty"`
		Tags        []string  `json:"tags,omitempty"`
		AutoRenew   *bool     `json:"auto_renew,omitempty"`
		RenewalDays *int      `json:"renewal_days,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		c.Err = common.NewAppError("updateCertificate", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	updateReq := certservices.UpdateCertificateRequest{
		CertID:      certID,
		UserID:      userID,
		Name:        body.Name,
		Tags:        body.Tags,
		AutoRenew:   body.AutoRenew,
		RenewalDays: body.RenewalDays,
	}
	if err := certSvc.UpdateCertificate(r.Context(), updateReq); err != nil {
		c.Err = common.NewAppError("updateCertificate", "Failed to update certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("deleteCertificate", "Invalid certificate ID", nil, err.Error(), http.StatusBadRequest)
		return
	}
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("deleteCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	if err := certSvc.DeleteCertificate(r.Context(), certID, userID); err != nil {
		c.Err = common.NewAppError("deleteCertificate", "Failed to delete certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

Note: Check that `c.certSvc()` and `UpdateCertificateRequest.AutoRenew`/`RenewalDays` fields exist. If `UpdateCertificateRequest` does not have `AutoRenew`/`RenewalDays`, add them in `certificate_service.go` and update `UpdateCertificate` to apply them to the domain object.

Also check that `CreateCertificateResult` includes `ExpiresAt *time.Time` — if not, add it and populate it from the certificate.

- [ ] **Step 2: Register `InitCertificates` in the API router**

In `api/api.go` (or wherever `InitSecrets`, `InitKeys` are called), add:

```go
	certsRouter := apiRouter.PathPrefix("/certificates").Subrouter()
	api.InitCertificates(certsRouter)
```

- [ ] **Step 3: Add `--auto-renew` and `--renewal-days` to `cmd/certificates/create.go`**

```go
createCmd.Flags().Bool("auto-renew", false, "Automatically renew certificate before expiry")
createCmd.Flags().Int("renewal-days", 30, "Days before expiry to trigger renewal")
```

In the run function:
```go
autoRenew, _ := cmd.Flags().GetBool("auto-renew")
renewalDays, _ := cmd.Flags().GetInt("renewal-days")
// Include in CreateCertificateRequest:
// AutoRenew: autoRenew, RenewalDays: renewalDays
```

- [ ] **Step 4: Add the same flags to `cmd/certificates/update.go`**

```go
updateCmd.Flags().Bool("auto-renew", false, "Enable or disable auto-renewal")
updateCmd.Flags().Int("renewal-days", 0, "Days before expiry to trigger renewal (0 = no change)")
```

In the run function, only include if the flag was explicitly set:
```go
var autoRenewPtr *bool
if cmd.Flags().Changed("auto-renew") {
    v, _ := cmd.Flags().GetBool("auto-renew")
    autoRenewPtr = &v
}
var renewalDaysPtr *int
if cmd.Flags().Changed("renewal-days") {
    v, _ := cmd.Flags().GetInt("renewal-days")
    renewalDaysPtr = &v
}
// Include AutoRenew: autoRenewPtr, RenewalDays: renewalDaysPtr in UpdateCertificateRequest
```

- [ ] **Step 5: Build**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: no errors.

- [ ] **Step 6: Run full suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... 2>&1 | tail -20
```
Expected: no new failures.

- [ ] **Step 7: Commit**

```bash
git add api/certificates.go api/api.go cmd/certificates/create.go cmd/certificates/update.go
git commit -m "feat(cert-renewal): add certificates API with auto_renew/renewal_days; add CLI flags"
```

---

## Final Verification

- [ ] **Build the entire project**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go build ./...
```
Expected: zero errors.

- [ ] **Run the complete test suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go test ./... -count=1 2>&1 | tail -30
```
Expected: all PASS, no failures.

- [ ] **Smoke-check the three features compile correctly**

```bash
cd /home/numericlabs/data/Golang/rocketvault && go vet ./...
```
Expected: no issues.
