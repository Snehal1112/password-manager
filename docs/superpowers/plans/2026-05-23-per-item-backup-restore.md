# Per-item Backup/Restore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-item backup and restore endpoints for secrets, keys, and certificates, matching Azure Key Vault's `BackupSecret`/`RestoreSecret` (and equivalent for keys/certs). A backup produces an opaque, encrypted, self-describing blob containing all versions of the item. A restore imports that blob, creating (or recreating) the item with all its version history. These are distinct from the existing full-vault backup in `internal/backup/`.

**Architecture:** Each backup operation:
1. Reads all versions of the item from the repository.
2. Serialises them into a JSON envelope (`BackupEnvelope`).
3. Encrypts the envelope with AES-256-GCM using a key derived from a per-vault backup master key (stored in config or the vault's own AES key).
4. Returns a base64-encoded opaque blob as `{"value": "<base64>"}`.

Restore reverses this: decrypt the blob → deserialise → create the item and all versions if absent.

The encryption uses the existing `common.EncryptSecret` / `common.DecryptSecret` pattern (`common/encrypt.go`). No new crypto primitives are required.

**Tech Stack:** Go 1.24.2, `encoding/json`, `encoding/base64`, `crypto/aes`, AES-256-GCM (via `common/encrypt.go`), testify.

**Spec:** `docs/plans/2026-05-23-azure-keyvault-parity-audit.md` §Backup & Restore — "per-item BackupSecret/Key/Cert" row.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `model/backup.go` | Create | `BackupEnvelope`, `SecretBackupBlob`, `KeyBackupBlob`, `CertBackupBlob` types |
| `internal/services/secrets/backup_service.go` | Create | `BackupSecret`, `RestoreSecret` |
| `internal/services/keys/backup_service.go` | Create | `BackupKey`, `RestoreKey` |
| `internal/services/certificates/backup_service.go` | Create | `BackupCertificate`, `RestoreCertificate` |
| `internal/services/secrets/backup_service_test.go` | Create | Round-trip backup/restore tests for secrets |
| `internal/services/keys/backup_service_test.go` | Create | Round-trip tests for keys |
| `internal/services/certificates/backup_service_test.go` | Create | Round-trip tests for certs |
| `api/secrets.go` | Modify | Add `POST /secrets/{name}/backup` and `POST /secrets/restore` routes |
| `api/keys.go` | Modify | Add `POST /keys/{id}/backup` and `POST /keys/restore` routes |
| `api/certificates.go` | Modify | Add `POST /certificates/{id}/backup` and `POST /certificates/restore` routes |

---

## Task 1: Define backup envelope types

**Files:**
- Create: `model/backup.go`

- [ ] **Step 1: Create `model/backup.go`**

```go
package model

import "time"

// BackupFormat is the version identifier embedded in every backup blob.
// Increment this if the envelope schema changes; reject unknown versions on restore.
const BackupFormat = "rocketvault/v1"

// SecretBackupPayload holds the data for a single secret backup.
type SecretBackupPayload struct {
	Format    string    `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	Secret    Secret    `json:"secret"`
}

// KeyBackupPayload holds the data for a single key backup, including all versions.
type KeyBackupPayload struct {
	Format    string       `json:"format"`
	CreatedAt time.Time    `json:"created_at"`
	Key       Key          `json:"key"`
	Versions  []KeyVersion `json:"versions,omitempty"`
}

// CertificateBackupPayload holds the data for a single certificate backup.
type CertificateBackupPayload struct {
	Format      string      `json:"format"`
	CreatedAt   time.Time   `json:"created_at"`
	Certificate Certificate `json:"certificate"`
}

// BackupResponse is returned by all backup endpoints.
// The Value field is an opaque base64-encoded encrypted blob.
type BackupResponse struct {
	Value string `json:"value"`
}

// RestoreRequest is the body sent to restore endpoints.
type RestoreRequest struct {
	Value string `json:"value"` // the opaque blob from BackupResponse
}
```

- [ ] **Step 2: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -10
```

- [ ] **Step 3: Commit**

```bash
git add model/backup.go
git commit -m "feat(model): add backup envelope types for per-item backup/restore"
```

---

## Task 2: Implement `BackupSecret` and `RestoreSecret`

**Files:**
- Create: `internal/services/secrets/backup_service.go`
- Create: `internal/services/secrets/backup_service_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/services/secrets/backup_service_test.go`:

```go
package secrets_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupAndRestoreSecret_RoundTrip(t *testing.T) {
	svc, ownerID := setupSecretService(t)

	// Create a secret
	original, err := svc.CreateSecret(context.Background(), CreateSecretRequest{
		Name:   "backup-test",
		Value:  "super-secret-value",
		UserID: ownerID,
		Tags:   []string{"env:test"},
	})
	require.NoError(t, err)

	// Backup it
	blob, err := svc.BackupSecret(context.Background(), original.SecretID, ownerID)
	require.NoError(t, err)
	assert.NotEmpty(t, blob)

	// Delete the original
	require.NoError(t, svc.DeleteSecret(context.Background(), original.SecretID, ownerID))

	// Restore from blob
	restored, err := svc.RestoreSecret(context.Background(), blob, ownerID)
	require.NoError(t, err)
	assert.Equal(t, "backup-test", restored.Name)
}

func TestBackupSecret_FailsForOtherUser(t *testing.T) {
	svc, ownerID := setupSecretService(t)
	otherID := uuid.New()

	original, _ := svc.CreateSecret(context.Background(), CreateSecretRequest{
		Name:   "not-mine",
		Value:  "value",
		UserID: ownerID,
	})

	_, err := svc.BackupSecret(context.Background(), original.SecretID, otherID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestRestoreSecret_FailsForCorruptBlob(t *testing.T) {
	svc, ownerID := setupSecretService(t)
	_, err := svc.RestoreSecret(context.Background(), "not-valid-base64!!!!", ownerID)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/secrets/... -run "TestBackup|TestRestore" -v 2>&1 | tail -10
```

Expected: FAIL — `BackupSecret`/`RestoreSecret` undefined.

- [ ] **Step 3: Implement `backup_service.go` for secrets**

Create `internal/services/secrets/backup_service.go`:

```go
package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// BackupSecret creates an opaque encrypted blob containing a complete backup of the secret.
// The blob is base64-encoded and suitable for safe long-term storage.
// Returns the blob string or an error.
func (s *secretService) BackupSecret(ctx context.Context, secretID, userID uuid.UUID) (string, error) {
	secret, err := s.GetSecret(ctx, secretID, userID)
	if err != nil {
		return "", fmt.Errorf("backup failed: %w", err)
	}
	// Access control already enforced by GetSecret.

	payload := model.SecretBackupPayload{
		Format:    model.BackupFormat,
		CreatedAt: time.Now().UTC(),
		Secret:    *secret,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to serialise backup payload: %w", err)
	}

	// Encrypt with the vault's AES-256-GCM scheme (same as secret value encryption)
	encrypted, err := common.EncryptSecret(string(jsonBytes))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt backup: %w", err)
	}

	// Return as base64-encoded opaque blob
	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}

// RestoreSecret decrypts a backup blob and recreates the secret.
// If a secret with the same name already exists (and is not soft-deleted), it returns an error.
// The restored secret is owned by the requesting user.
func (s *secretService) RestoreSecret(ctx context.Context, blob string, ownerID uuid.UUID) (*model.Secret, error) {
	// Decode base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("invalid backup blob: base64 decode failed: %w", err)
	}

	// Decrypt
	jsonStr, err := common.DecryptSecret(string(encryptedBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid backup blob: decryption failed: %w", err)
	}

	// Deserialise
	var payload model.SecretBackupPayload
	if err := json.Unmarshal([]byte(jsonStr), &payload); err != nil {
		return nil, fmt.Errorf("invalid backup blob: JSON parse failed: %w", err)
	}
	if payload.Format != model.BackupFormat {
		return nil, fmt.Errorf("unsupported backup format %q", payload.Format)
	}

	// Reassign to requesting user and assign new ID to avoid conflicts
	restoredSecret := payload.Secret
	restoredSecret.ID = uuid.New()
	restoredSecret.UserID = ownerID
	restoredSecret.DeletedAt = nil // clear any soft-delete state

	if err := s.secretRepo.Create(ctx, &restoredSecret); err != nil {
		return nil, fmt.Errorf("failed to restore secret: %w", err)
	}

	s.logger.LogAuditInfo(ownerID.String(), "restore_secret", "success",
		fmt.Sprintf("secret %q restored from backup as ID %s", restoredSecret.Name, restoredSecret.ID))
	return &restoredSecret, nil
}
```

- [ ] **Step 4: Add interface methods**

In `SecretService` interface (in the same file or `secret_service.go`), add:

```go
BackupSecret(ctx context.Context, secretID, userID uuid.UUID) (string, error)
RestoreSecret(ctx context.Context, blob string, ownerID uuid.UUID) (*model.Secret, error)
```

- [ ] **Step 5: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/secrets/... -run "TestBackup|TestRestore" -v 2>&1 | tail -20
```

Expected: all three tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/services/secrets/backup_service.go internal/services/secrets/backup_service_test.go
git commit -m "feat(services): BackupSecret and RestoreSecret with AES-256-GCM encrypted blobs"
```

---

## Task 3: Implement `BackupKey`/`RestoreKey` (with version history)

**Files:**
- Create: `internal/services/keys/backup_service.go`
- Create: `internal/services/keys/backup_service_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/services/keys/backup_service_test.go`:

```go
package keys_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupAndRestoreKey_RoundTrip(t *testing.T) {
	svc, ownerID := setupKeyService(t)
	keyID := createTestRSAKey(t, svc, ownerID)

	// Rotate once to produce v1 and v2
	require.NoError(t, svc.RotateKey(context.Background(), keyID, ownerID))

	blob, err := svc.BackupKey(context.Background(), keyID, ownerID)
	require.NoError(t, err)
	assert.NotEmpty(t, blob)

	// Delete and restore
	require.NoError(t, svc.DeleteKey(context.Background(), keyID, ownerID))
	restored, err := svc.RestoreKey(context.Background(), blob, ownerID)
	require.NoError(t, err)
	assert.NotNil(t, restored)
}
```

- [ ] **Step 2: Implement `backup_service.go` for keys**

Create `internal/services/keys/backup_service.go`:

```go
package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// BackupKey creates an opaque encrypted blob containing the key and all its versions.
func (s *keyService) BackupKey(ctx context.Context, keyID, userID uuid.UUID) (string, error) {
	key, err := s.GetKey(ctx, keyID, userID)
	if err != nil {
		return "", fmt.Errorf("backup failed: %w", err)
	}

	var versions []model.KeyVersion
	if s.keyVersionRepo != nil {
		versions, _ = s.keyVersionRepo.ListByKey(ctx, keyID)
	}

	payload := model.KeyBackupPayload{
		Format:    model.BackupFormat,
		CreatedAt: time.Now().UTC(),
		Key:       *key,
		Versions:  versions,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to serialise key backup: %w", err)
	}

	encrypted, err := common.EncryptSecret(string(jsonBytes))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key backup: %w", err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}

// RestoreKey decrypts a backup blob and recreates the key along with all version history.
func (s *keyService) RestoreKey(ctx context.Context, blob string, ownerID uuid.UUID) (*model.Key, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("invalid key backup blob: base64 decode failed: %w", err)
	}

	jsonStr, err := common.DecryptSecret(string(encryptedBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid key backup blob: decryption failed: %w", err)
	}

	var payload model.KeyBackupPayload
	if err := json.Unmarshal([]byte(jsonStr), &payload); err != nil {
		return nil, fmt.Errorf("invalid key backup blob: JSON parse failed: %w", err)
	}
	if payload.Format != model.BackupFormat {
		return nil, fmt.Errorf("unsupported backup format %q", payload.Format)
	}

	restoredKey := payload.Key
	restoredKey.ID = uuid.New()
	restoredKey.UserID = ownerID
	restoredKey.DeletedAt = nil

	if err := s.keyRepo.Create(ctx, &restoredKey); err != nil {
		return nil, fmt.Errorf("failed to restore key: %w", err)
	}

	// Restore version history if available
	if s.keyVersionRepo != nil {
		for _, v := range payload.Versions {
			v.KeyID = restoredKey.ID
			_ = s.keyVersionRepo.Create(ctx, &v) // best-effort; don't fail restore on version errors
		}
	}

	s.logger.LogAuditInfo(ownerID.String(), "restore_key", "success",
		fmt.Sprintf("key %q restored from backup as ID %s", restoredKey.Name, restoredKey.ID))
	return &restoredKey, nil
}
```

- [ ] **Step 3: Add interface methods to `KeyService`**

```go
BackupKey(ctx context.Context, keyID, userID uuid.UUID) (string, error)
RestoreKey(ctx context.Context, blob string, ownerID uuid.UUID) (*model.Key, error)
```

- [ ] **Step 4: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/keys/... -run "TestBackup|TestRestore" -v 2>&1 | tail -15
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/keys/backup_service.go internal/services/keys/backup_service_test.go
git commit -m "feat(services): BackupKey and RestoreKey including version history"
```

---

## Task 4: Implement `BackupCertificate`/`RestoreCertificate`

**Files:**
- Create: `internal/services/certificates/backup_service.go`
- Create: `internal/services/certificates/backup_service_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/services/certificates/backup_service_test.go`:

```go
package certificates_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupAndRestoreCertificate_RoundTrip(t *testing.T) {
	svc, ownerID, _ := setupCertServiceWithKey(t)
	certID := createTestCert(t, svc, ownerID)

	blob, err := svc.BackupCertificate(context.Background(), certID, ownerID)
	require.NoError(t, err)
	assert.NotEmpty(t, blob)

	require.NoError(t, svc.DeleteCertificate(context.Background(), certID, ownerID))

	restored, err := svc.RestoreCertificate(context.Background(), blob, ownerID)
	require.NoError(t, err)
	assert.NotNil(t, restored)
}
```

- [ ] **Step 2: Implement `backup_service.go` for certificates**

Create `internal/services/certificates/backup_service.go`:

```go
package certificates

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// BackupCertificate creates an opaque encrypted blob for the certificate.
func (s *certificateService) BackupCertificate(ctx context.Context, certID, userID uuid.UUID) (string, error) {
	cert, err := s.GetCertificate(ctx, certID, userID)
	if err != nil {
		return "", fmt.Errorf("backup failed: %w", err)
	}

	payload := model.CertificateBackupPayload{
		Format:      model.BackupFormat,
		CreatedAt:   time.Now().UTC(),
		Certificate: *cert,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to serialise certificate backup: %w", err)
	}

	encrypted, err := common.EncryptSecret(string(jsonBytes))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt certificate backup: %w", err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}

// RestoreCertificate recreates a certificate from a backup blob.
func (s *certificateService) RestoreCertificate(ctx context.Context, blob string, ownerID uuid.UUID) (*model.Certificate, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate backup blob: base64 decode failed: %w", err)
	}

	jsonStr, err := common.DecryptSecret(string(encryptedBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid certificate backup blob: decryption failed: %w", err)
	}

	var payload model.CertificateBackupPayload
	if err := json.Unmarshal([]byte(jsonStr), &payload); err != nil {
		return nil, fmt.Errorf("invalid certificate backup blob: JSON parse failed: %w", err)
	}
	if payload.Format != model.BackupFormat {
		return nil, fmt.Errorf("unsupported backup format %q", payload.Format)
	}

	restoredCert := payload.Certificate
	restoredCert.ID = uuid.New()
	restoredCert.UserID = ownerID
	restoredCert.DeletedAt = nil

	if err := s.certRepo.Create(ctx, &restoredCert); err != nil {
		return nil, fmt.Errorf("failed to restore certificate: %w", err)
	}

	s.logger.LogAuditInfo(ownerID.String(), "restore_certificate", "success",
		fmt.Sprintf("certificate %q restored from backup as ID %s", restoredCert.Name, restoredCert.ID))
	return &restoredCert, nil
}
```

- [ ] **Step 3: Add interface methods to `CertificateService`**

```go
BackupCertificate(ctx context.Context, certID, userID uuid.UUID) (string, error)
RestoreCertificate(ctx context.Context, blob string, ownerID uuid.UUID) (*model.Certificate, error)
```

- [ ] **Step 4: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/certificates/... -run "TestBackup|TestRestore" -v 2>&1 | tail -15
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/certificates/backup_service.go internal/services/certificates/backup_service_test.go
git commit -m "feat(services): BackupCertificate and RestoreCertificate"
```

---

## Task 5: Add HTTP backup/restore endpoints

**Files:**
- Modify: `api/secrets.go`, `api/keys.go`, `api/certificates.go`

All three follow the same pattern; the secrets implementation is shown in full. Key and certificate handlers are identical except for service type.

- [ ] **Step 1: Add secret backup/restore routes**

In `api/secrets.go`, find the route registration function (e.g., `InitSecrets`). Add:

```go
s.Handle("/{secret_id:[A-Fa-f0-9-]+}/backup", ApiSessionRequired(api.App, backupSecret)).Methods("POST")
s.Handle("/restore", ApiSessionRequired(api.App, restoreSecret)).Methods("POST")
```

- [ ] **Step 2: Implement `backupSecret` handler**

```go
func backupSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	secretID, err := uuid.Parse(vars["secret_id"])
	if err != nil {
		c.SetInvalidParamError("secret_id")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	secretSvc := c.App.GetServiceContainer().GetSecretService()
	blob, err := secretSvc.BackupSecret(r.Context(), secretID, userID)
	if err != nil {
		c.SetError(err.Error(), http.StatusForbidden)
		c.HandleError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.BackupResponse{Value: blob})
}
```

- [ ] **Step 3: Implement `restoreSecret` handler**

```go
func restoreSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	var req model.RestoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		c.SetInvalidParamError("value")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	secretSvc := c.App.GetServiceContainer().GetSecretService()
	secret, err := secretSvc.RestoreSecret(r.Context(), req.Value, userID)
	if err != nil {
		c.SetError(err.Error(), http.StatusBadRequest)
		c.HandleError(w, r)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret)
}
```

- [ ] **Step 4: Repeat for `api/keys.go`**

Add routes:

```go
k.Handle("/{key_id:[A-Fa-f0-9-]+}/backup", ApiSessionRequired(api.App, backupKey)).Methods("POST")
k.Handle("/restore", ApiSessionRequired(api.App, restoreKey)).Methods("POST")
```

Add handlers `backupKey` and `restoreKey` following the same pattern as secrets — calling `keySvc.BackupKey(...)` and `keySvc.RestoreKey(...)`.

- [ ] **Step 5: Repeat for `api/certificates.go`**

Add routes:

```go
cert.Handle("/{cert_id:[A-Fa-f0-9-]+}/backup", ApiSessionRequired(api.App, backupCertificate)).Methods("POST")
cert.Handle("/restore", ApiSessionRequired(api.App, restoreCertificate)).Methods("POST")
```

Add handlers `backupCertificate` and `restoreCertificate`.

- [ ] **Step 6: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

- [ ] **Step 7: Commit**

```bash
git add api/secrets.go api/keys.go api/certificates.go
git commit -m "feat(api): add POST /secrets|keys|certificates/{id}/backup and /restore endpoints"
```

---

## Task 6: Full regression pass

- [ ] **Step 1: Run full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|ok" | sort
```

Expected: all packages `ok`.

- [ ] **Step 2: Build binary**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build -o /tmp/rocketvault-backup . && echo "build ok"
```

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: per-item backup/restore for secrets, keys, and certificates"
```
