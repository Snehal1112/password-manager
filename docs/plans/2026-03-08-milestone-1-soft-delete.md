# Milestone 1: Soft-Delete & Purge Protection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add full Azure Key Vault-compatible soft-delete and purge protection to secrets, keys, and certificates, with recovery API endpoints, a configurable retention period, and a background auto-purge job.

**Architecture:** Secrets already have full soft-delete infrastructure (`SoftDelete`, `PurgeSecret`, `ListByUserIncludeDeleted` in repository; `DeleteSecret` calls `SoftDelete` in service). This milestone mirrors that pattern for keys and certificates, adds the new `/deleted/*` API routes, wires up soft-delete config, and adds a background scheduler that auto-purges expired items.

**Tech Stack:** Go stdlib (`context`, `time`, `sync`), existing Gorilla Mux router, SQLite/PostgreSQL via `database/sql`, testify for tests, existing Cobra + Viper config pattern.

---

## Context: What Already Exists (Do Not Rebuild)

- `internal/repositories/secret_repository.go` — `SoftDelete`, `PurgeSecret`, `ListByUserIncludeDeleted` already implemented
- `internal/services/secrets/secret_service.go` — `DeleteSecret` already calls `SoftDelete`
- `internal/domain/secret.go` — `Secret` struct already has `DeletedAt *time.Time` and `PurgeProtection bool`
- Migration `20241025000001_add_soft_delete.sql` already added `deleted_at` and `purge_protection` to `secrets`

**What is missing:**
- `deleted_at`, `purge_protection`, `scheduled_purge_at` columns on `keys` and `certificates` tables
- `SoftDelete` / `PurgeKey` / `ListSoftDeleted` on key repository
- `SoftDelete` / `PurgeCertificate` / `ListSoftDeleted` on certificate repository
- Key and certificate services updated to call `SoftDelete` instead of hard-delete
- Soft-delete config block in `config/config.go`
- New API routes: `GET /deleted/{secrets|keys|certificates}`, `POST /deleted/{id}/recover`, `DELETE /deleted/{id}` (purge)
- Background purge scheduler

---

### Task 1: Migration — add soft-delete columns to keys and certificates

**Files:**
- Create: `internal/db/migrations/20260308000001_add_soft_delete_keys_certs.sql`

#### Step 1: Create the migration file

```sql
-- Migration: Add soft-delete columns to keys and certificates tables
-- Description: Mirrors the soft-delete pattern already on the secrets table.
--              Adds deleted_at, purge_protection, and scheduled_purge_at to keys
--              and certificates so they support AKV-style soft-delete.
-- Version: 20260308000001

ALTER TABLE keys ADD COLUMN deleted_at        TIMESTAMP NULL;
ALTER TABLE keys ADD COLUMN purge_protection   BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE keys ADD COLUMN scheduled_purge_at TIMESTAMP NULL;

ALTER TABLE certificates ADD COLUMN deleted_at        TIMESTAMP NULL;
ALTER TABLE certificates ADD COLUMN purge_protection   BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE certificates ADD COLUMN scheduled_purge_at TIMESTAMP NULL;
```

#### Step 2: Build to verify the embed picks up the new file

```bash
cd /home/numericlabs/data/Golang/password-manager
go build -o rocketvault .
```

Expected: no errors.

#### Step 3: Run migrate:status to confirm the new migration is listed

```bash
./rocketvault migrate:status
```

Expected: `[ ] 20260308000001 - add_soft_delete_keys_certs (Pending)` in the output.

#### Step 4: Apply the migration

```bash
./rocketvault migrate
```

Expected: `All migrations completed successfully`

#### Step 5: Commit

```bash
git add internal/db/migrations/20260308000001_add_soft_delete_keys_certs.sql
git commit -m "feat(db): add soft-delete columns to keys and certificates tables"
```

---

### Task 2: Soft-delete config block

**Files:**
- Modify: `config/config.go`

#### Step 1: Add the SoftDeleteConfig struct and wire it into Config

Open `config/config.go` and add after the existing struct fields:

```go
// SoftDeleteConfig controls soft-delete and purge protection behaviour.
type SoftDeleteConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	RetentionDays  int  `mapstructure:"retention_days"`
	PurgeProtection bool `mapstructure:"purge_protection"`
}
```

Then add the field to the `Config` struct:

```go
SoftDelete SoftDeleteConfig `mapstructure:"soft_delete"`
```

#### Step 2: Add defaults in `.rocketvault.yaml`

Append to `.rocketvault.yaml`:

```yaml
soft_delete:
  enabled: true
  retention_days: 30
  purge_protection: false
```

#### Step 3: Build to verify

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 4: Commit

```bash
git add config/config.go .rocketvault.yaml
git commit -m "feat(config): add soft_delete configuration block"
```

---

### Task 3: Key repository — add SoftDelete, PurgeKey, ListSoftDeleted (TDD)

**Files:**
- Modify: `internal/repositories/key_repository.go`
- Create: `internal/repositories/key_soft_delete_test.go`

#### Step 1: Write the failing tests

Create `internal/repositories/key_soft_delete_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/repositories"
)

func TestKeySoftDelete(t *testing.T) {
	db := setupTestDB(t) // reuse existing test helper
	repo := repositories.NewKeyRepository(db)
	ctx := context.Background()
	userID := uuid.New()

	key := &domain.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "test-key",
		Type:      "rsa",
		PublicKey: "pub",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))

	// SoftDelete sets deleted_at, leaves row in table.
	require.NoError(t, repo.SoftDelete(ctx, key.ID))

	// Normal Get should return error (soft-deleted item not visible).
	_, err := repo.GetByID(ctx, key.ID)
	assert.Error(t, err)

	// ListSoftDeleted should include it.
	deleted, err := repo.ListSoftDeleted(ctx, userID)
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, key.ID, deleted[0].ID)
	assert.NotNil(t, deleted[0].DeletedAt)
}

func TestKeyPurge(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewKeyRepository(db)
	ctx := context.Background()
	userID := uuid.New()

	key := &domain.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "purge-key",
		Type:      "rsa",
		PublicKey: "pub",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))
	require.NoError(t, repo.SoftDelete(ctx, key.ID))

	// Purge should permanently remove it.
	require.NoError(t, repo.PurgeKey(ctx, key.ID))

	deleted, err := repo.ListSoftDeleted(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, deleted)
}

func TestKeyPurgeProtection(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewKeyRepository(db)
	ctx := context.Background()
	userID := uuid.New()

	key := &domain.Key{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "protected-key",
		Type:      "rsa",
		PublicKey: "pub",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, key))
	require.NoError(t, repo.SoftDelete(ctx, key.ID))
	require.NoError(t, repo.SetPurgeProtection(ctx, key.ID, true))

	// Purge should fail when purge_protection = true.
	err := repo.PurgeKey(ctx, key.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "purge protection")
}
```

#### Step 2: Run to verify they fail

```bash
go test ./internal/repositories/... -run TestKeySoftDelete -v 2>&1
go test ./internal/repositories/... -run TestKeyPurge -v 2>&1
go test ./internal/repositories/... -run TestKeyPurgeProtection -v 2>&1
```

Expected: compile errors — `SoftDelete`, `PurgeKey`, `ListSoftDeleted`, `SetPurgeProtection` undefined.

#### Step 3: Update KeyRepositoryInterface and add domain fields

In `internal/repositories/key_repository.go`, add to the interface:

```go
SoftDelete(ctx context.Context, id uuid.UUID) error
PurgeKey(ctx context.Context, id uuid.UUID) error
SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*domain.Key, error)
```

In `internal/domain/key.go`, add to the `Key` struct:

```go
DeletedAt       *time.Time
PurgeProtection bool
ScheduledPurgeAt *time.Time
```

In `internal/repositories/key_repository.go`, add these implementations after the existing `Delete` method:

```go
// SoftDelete marks a key as deleted without removing it from the database.
func (r *keyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE keys SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to soft delete key: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("key not found or already deleted")
	}
	return nil
}

// PurgeKey permanently deletes a soft-deleted key if purge_protection is false.
func (r *keyRepository) PurgeKey(ctx context.Context, id uuid.UUID) error {
	// Check purge protection.
	var protected bool
	err := r.db.QueryRowContext(ctx,
		`SELECT purge_protection FROM keys WHERE id = ? AND deleted_at IS NOT NULL`, id,
	).Scan(&protected)
	if err != nil {
		return fmt.Errorf("key not found in deleted state: %w", err)
	}
	if protected {
		return fmt.Errorf("cannot purge key: purge protection is enabled")
	}
	_, err = r.db.ExecContext(ctx, `DELETE FROM keys WHERE id = ?`, id)
	return err
}

// SetPurgeProtection enables or disables purge protection on a key.
func (r *keyRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE keys SET purge_protection = ? WHERE id = ?`, enabled, id,
	)
	return err
}

// ListSoftDeleted returns all soft-deleted keys for a user.
func (r *keyRepository) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*domain.Key, error) {
	query := `SELECT id, user_id, name, type, public_key, created_at, deleted_at, purge_protection
	          FROM keys WHERE user_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list soft-deleted keys: %w", err)
	}
	defer rows.Close()

	var keys []*domain.Key
	for rows.Next() {
		k := &domain.Key{}
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Type, &k.PublicKey,
			&k.CreatedAt, &k.DeletedAt, &k.PurgeProtection); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
```

Also update the existing `List` and `GetByID` queries to add `AND deleted_at IS NULL` filters where missing.

#### Step 4: Run tests to verify they pass

```bash
go test ./internal/repositories/... -run TestKeySoftDelete -v
go test ./internal/repositories/... -run TestKeyPurge -v
go test ./internal/repositories/... -run TestKeyPurgeProtection -v
```

Expected: all 3 tests PASS.

#### Step 5: Commit

```bash
git add internal/repositories/key_repository.go \
        internal/repositories/key_soft_delete_test.go \
        internal/domain/key.go
git commit -m "feat(keys): add SoftDelete, PurgeKey, ListSoftDeleted to key repository"
```

---

### Task 4: Update KeyService to use soft-delete (TDD)

**Files:**
- Modify: `internal/services/keys/key_service.go`
- Create: `internal/services/keys/key_soft_delete_test.go`

#### Step 1: Write the failing test

Create `internal/services/keys/key_soft_delete_test.go`:

```go
package keys_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	keyservice "rocketvault/internal/services/keys"
)

func TestDeleteKeySoftDeletes(t *testing.T) {
	mockRepo := new(MockKeyRepository)
	svc := keyservice.NewKeyService(mockRepo, nil)
	ctx := context.Background()
	keyID := uuid.New()
	userID := uuid.New()

	// GetByID returns the key (authorization check).
	mockRepo.On("GetByID", ctx, keyID).Return(&domain.Key{ID: keyID, UserID: userID}, nil)
	// SoftDelete should be called — NOT Delete.
	mockRepo.On("SoftDelete", ctx, keyID).Return(nil)

	err := svc.DeleteKey(ctx, keyID, userID)
	require.NoError(t, err)
	mockRepo.AssertCalled(t, "SoftDelete", ctx, keyID)
	mockRepo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}
```

#### Step 2: Run to verify it fails

```bash
go test ./internal/services/keys/... -run TestDeleteKeySoftDeletes -v
```

Expected: FAIL — `SoftDelete` not called; `Delete` called instead.

#### Step 3: Update DeleteKey in key_service.go

In `internal/services/keys/key_service.go`, find `DeleteKey` (around line 390) and change:

```go
// Before:
if err := s.keyRepo.Delete(ctx, keyID); err != nil {

// After:
if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
```

#### Step 4: Run test to verify it passes

```bash
go test ./internal/services/keys/... -run TestDeleteKeySoftDeletes -v
```

Expected: PASS.

#### Step 5: Run full key service tests

```bash
go test ./internal/services/keys/... -count=1 -v
```

Expected: all tests pass.

#### Step 6: Commit

```bash
git add internal/services/keys/key_service.go \
        internal/services/keys/key_soft_delete_test.go
git commit -m "feat(keys): change DeleteKey to use soft-delete instead of hard delete"
```

---

### Task 5: Mirror soft-delete for certificate repository and service

**Files:**
- Modify: `internal/repositories/certificate_repository.go`
- Modify: `internal/services/certificates/certificate_service.go`
- Modify: `internal/domain/certificate.go`
- Create: `internal/repositories/certificate_soft_delete_test.go`

#### Step 1: Add domain fields to Certificate

In `internal/domain/certificate.go`, add:

```go
DeletedAt        *time.Time
PurgeProtection  bool
ScheduledPurgeAt *time.Time
```

#### Step 2: Add interface methods and implementations to certificate repository

Mirror the exact pattern from Task 3 — add `SoftDelete`, `PurgeCertificate`, `SetPurgeProtection`, `ListSoftDeleted` to `CertificateRepositoryInterface` and implement them.

Update `GetByID` and `List` queries to filter `AND deleted_at IS NULL`.

#### Step 3: Write and run tests (mirror key_soft_delete_test.go pattern)

Create `internal/repositories/certificate_soft_delete_test.go` following the same 3-test pattern as Task 3.

```bash
go test ./internal/repositories/... -run TestCertificateSoftDelete -v
go test ./internal/repositories/... -run TestCertificatePurge -v
go test ./internal/repositories/... -run TestCertificatePurgeProtection -v
```

Expected: all PASS.

#### Step 4: Update CertificateService DeleteCertificate to call SoftDelete

Mirror Task 4 exactly — change `Delete` call to `SoftDelete` in `internal/services/certificates/certificate_service.go`.

#### Step 5: Run full test suite

```bash
go test ./internal/... -count=1
```

Expected: all pass.

#### Step 6: Commit

```bash
git add internal/repositories/certificate_repository.go \
        internal/repositories/certificate_soft_delete_test.go \
        internal/services/certificates/certificate_service.go \
        internal/domain/certificate.go
git commit -m "feat(certs): add soft-delete to certificate repository and service"
```

---

### Task 6: New API handlers for deleted resources

**Files:**
- Create: `api/soft_delete.go`
- Modify: `api/api.go`

#### Step 1: Create `api/soft_delete.go`

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/google/uuid"
)

// listDeletedSecrets returns all soft-deleted secrets for the authenticated user.
func (a *API) listDeletedSecrets(w http.ResponseWriter, r *http.Request) {
	userID := getUserIDFromContext(r.Context())
	secrets, err := a.container.GetSecretRepository().ListByUserIncludeDeleted(r.Context(), userID)
	if err != nil {
		http.Error(w, "failed to list deleted secrets", http.StatusInternalServerError)
		return
	}
	// Filter to only deleted items.
	var deleted []interface{}
	for _, s := range secrets {
		if s.DeletedAt != nil {
			deleted = append(deleted, s)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deleted)
}

// recoverSecret restores a soft-deleted secret.
func (a *API) recoverSecret(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "invalid secret ID", http.StatusBadRequest)
		return
	}
	if err := a.container.GetSecretRepository().RecoverSecret(r.Context(), id); err != nil {
		http.Error(w, "failed to recover secret: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "recovered"})
}

// purgeSecret permanently deletes a soft-deleted secret.
func (a *API) purgeSecret(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "invalid secret ID", http.StatusBadRequest)
		return
	}
	if err := a.container.GetSecretRepository().PurgeSecret(r.Context(), id); err != nil {
		http.Error(w, "failed to purge secret: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listDeletedKeys returns all soft-deleted keys for the authenticated user.
func (a *API) listDeletedKeys(w http.ResponseWriter, r *http.Request) {
	userID := getUserIDFromContext(r.Context())
	keys, err := a.container.GetKeyRepository().ListSoftDeleted(r.Context(), userID)
	if err != nil {
		http.Error(w, "failed to list deleted keys", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

// recoverKey restores a soft-deleted key.
func (a *API) recoverKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}
	if err := a.container.GetKeyRepository().RecoverKey(r.Context(), id); err != nil {
		http.Error(w, "failed to recover key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "recovered"})
}

// purgeKey permanently deletes a soft-deleted key.
func (a *API) purgeKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}
	if err := a.container.GetKeyRepository().PurgeKey(r.Context(), id); err != nil {
		http.Error(w, "failed to purge key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listDeletedCertificates, recoverCertificate, purgeCertificate
// follow the exact same pattern as keys above.
```

#### Step 2: Register new routes in `api/api.go`

Inside the authenticated route block, add:

```go
// Soft-delete recovery and purge routes
r.Handle("/api/v1/deleted/secrets", authMiddleware(http.HandlerFunc(a.listDeletedSecrets))).Methods("GET")
r.Handle("/api/v1/deleted/secrets/{id}/recover", authMiddleware(http.HandlerFunc(a.recoverSecret))).Methods("POST")
r.Handle("/api/v1/deleted/secrets/{id}", authMiddleware(http.HandlerFunc(a.purgeSecret))).Methods("DELETE")

r.Handle("/api/v1/deleted/keys", authMiddleware(http.HandlerFunc(a.listDeletedKeys))).Methods("GET")
r.Handle("/api/v1/deleted/keys/{id}/recover", authMiddleware(http.HandlerFunc(a.recoverKey))).Methods("POST")
r.Handle("/api/v1/deleted/keys/{id}", authMiddleware(http.HandlerFunc(a.purgeKey))).Methods("DELETE")

r.Handle("/api/v1/deleted/certificates", authMiddleware(http.HandlerFunc(a.listDeletedCertificates))).Methods("GET")
r.Handle("/api/v1/deleted/certificates/{id}/recover", authMiddleware(http.HandlerFunc(a.recoverCertificate))).Methods("POST")
r.Handle("/api/v1/deleted/certificates/{id}", authMiddleware(http.HandlerFunc(a.purgeCertificate))).Methods("DELETE")
```

#### Step 3: Build to verify

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 4: Commit

```bash
git add api/soft_delete.go api/api.go
git commit -m "feat(api): add soft-delete recovery and purge endpoints"
```

---

### Task 7: Background auto-purge scheduler

**Files:**
- Create: `internal/services/softdelete/purge_scheduler.go`
- Modify: `bootstrap/bootstrap.go`

#### Step 1: Create the scheduler

```go
package softdelete

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"rocketvault/config"
	"rocketvault/internal/logging"
)

// PurgeScheduler runs daily and permanently deletes soft-deleted items
// whose retention period has expired and purge_protection is false.
type PurgeScheduler struct {
	db     *sql.DB
	cfg    config.SoftDeleteConfig
	log    *logging.Logger
	done   chan struct{}
}

// NewPurgeScheduler creates a new scheduler.
func NewPurgeScheduler(db *sql.DB, cfg config.SoftDeleteConfig, log *logging.Logger) *PurgeScheduler {
	return &PurgeScheduler{db: db, cfg: cfg, log: log, done: make(chan struct{})}
}

// Start runs the purge scheduler in a background goroutine.
func (s *PurgeScheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop signals the scheduler to stop.
func (s *PurgeScheduler) Stop() {
	close(s.done)
}

func (s *PurgeScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run once on startup, then every 24h.
	s.purgeExpired(ctx)

	for {
		select {
		case <-ticker.C:
			s.purgeExpired(ctx)
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// purgeExpired permanently deletes items past their retention period.
func (s *PurgeScheduler) purgeExpired(ctx context.Context) {
	cutoff := time.Now().AddDate(0, 0, -s.cfg.RetentionDays)

	tables := []string{"secrets", "keys", "certificates"}
	for _, table := range tables {
		query := fmt.Sprintf(
			`DELETE FROM %s WHERE deleted_at IS NOT NULL AND deleted_at < ? AND purge_protection = FALSE`,
			table,
		)
		result, err := s.db.ExecContext(ctx, query, cutoff)
		if err != nil {
			s.log.WithError(err).Errorf("auto-purge failed for %s", table)
			continue
		}
		n, _ := result.RowsAffected()
		if n > 0 {
			s.log.Infof("auto-purged %d expired %s", n, table)
		}
	}
}
```

#### Step 2: Wire scheduler into bootstrap

In `bootstrap/bootstrap.go`, after the database is initialised, add:

```go
if cfg.SoftDelete.Enabled {
    scheduler := softdelete.NewPurgeScheduler(db, cfg.SoftDelete, log)
    scheduler.Start(ctx)
    // Register stop with shutdown hook.
    shutdown.Register(func() { scheduler.Stop() })
}
```

#### Step 3: Build and verify

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 4: Commit

```bash
git add internal/services/softdelete/purge_scheduler.go bootstrap/bootstrap.go
git commit -m "feat(softdelete): add background auto-purge scheduler"
```

---

### Task 8: Full verification

#### Step 1: Run full test suite

```bash
go test ./... -count=1
```

Expected: all packages pass.

#### Step 2: Smoke-test soft-delete via API

Start the server:
```bash
./rocketvault serve
```

Create a secret, delete it, confirm it appears in deleted list, recover it:
```bash
# Create
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/users/login \
  -d '{"username":"admin","password":"admin123","totp_code":"<code>"}' | jq -r .token)

SECRET_ID=$(curl -s -X POST http://localhost:8080/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test-soft-delete","value":"hunter2"}' | jq -r .id)

# Delete (should soft-delete now)
curl -X DELETE http://localhost:8080/api/v1/secrets/$SECRET_ID \
  -H "Authorization: Bearer $TOKEN"

# Confirm it appears in deleted list
curl http://localhost:8080/api/v1/deleted/secrets \
  -H "Authorization: Bearer $TOKEN"

# Recover it
curl -X POST http://localhost:8080/api/v1/deleted/secrets/$SECRET_ID/recover \
  -H "Authorization: Bearer $TOKEN"

# Confirm it's back
curl http://localhost:8080/api/v1/secrets/$SECRET_ID \
  -H "Authorization: Bearer $TOKEN"
```

Expected: secret disappears from main list after delete, appears in `/deleted/secrets`, reappears in main list after recover.

#### Step 3: Push

```bash
git push origin v-4.0.0
```

---

## Summary

| Task | What | Commit |
|---|---|---|
| 1 | DB migration for keys + certs soft-delete columns | `feat(db): add soft-delete columns to keys and certificates tables` |
| 2 | Soft-delete config block | `feat(config): add soft_delete configuration block` |
| 3 | Key repository SoftDelete/PurgeKey/ListSoftDeleted | `feat(keys): add SoftDelete, PurgeKey, ListSoftDeleted to key repository` |
| 4 | KeyService uses SoftDelete | `feat(keys): change DeleteKey to use soft-delete instead of hard delete` |
| 5 | Certificate repository + service soft-delete | `feat(certs): add soft-delete to certificate repository and service` |
| 6 | New API handlers + routes | `feat(api): add soft-delete recovery and purge endpoints` |
| 7 | Background auto-purge scheduler | `feat(softdelete): add background auto-purge scheduler` |
| 8 | Verification + push | — |
