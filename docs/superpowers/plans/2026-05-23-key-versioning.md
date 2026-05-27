# Key Versioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current "rotate = rename with `-rotated` suffix" hack with a real versioning model. After this plan: every key has a monotonically increasing version counter; `RotateKey` creates a new version instead of renaming; `GET /keys/{id}/versions` lists all versions; `GET /keys/{id}/versions/{version}` retrieves a specific version. Old key material is preserved and retrievable.

**Architecture:** New `key_versions` table stores each version as a row linked back to the parent key. The parent `keys` row stores the current (`latest`) version number. `RotateKey` inserts a new `key_versions` row, increments the counter, and archives the old key material in that row. A `KeyVersionRepository` interface + implementation mirrors the existing repository pattern.

**Tech Stack:** Go 1.24.2, SQLite/PostgreSQL, Gorilla Mux, testify.

**Spec:** `docs/plans/2026-05-23-azure-keyvault-parity-audit.md` §Keys — "Key versioning / ListKeyVersions" row.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `model/key.go` | Modify | Add `Version int`, `LatestVersion int` fields to `Key`; add `KeyVersion` struct; add `ListKeyVersionsResponse` |
| `internal/db/db.go` | Modify | Add `key_versions` table to `createOptimizedSchema`; add `version` column to `keys` table via `migrateSchema` |
| `internal/repositories/key_version_repository.go` | Create | `KeyVersionRepository` interface + SQLite/PG implementation |
| `internal/repositories/key_version_repository_test.go` | Create | Repository tests |
| `internal/services/keys/key_service.go` | Modify | Update `RotateKey` to use versioned pattern; add `ListKeyVersions`, `GetKeyVersion` |
| `internal/services/keys/key_version_service_test.go` | Create | Service tests for versioning |
| `internal/container/service_container.go` | Modify | Wire `KeyVersionRepository` into container |
| `api/keys.go` | Modify | Add `GET /{key_id}/versions` and `GET /{key_id}/versions/{version}` routes + handlers |
| `api/keys_version_test.go` | Create | HTTP-layer tests for versioning endpoints |

---

## Task 1: Add versioning model types

**Files:**
- Modify: `model/key.go`

- [ ] **Step 1: Add `Version` and `LatestVersion` to `Key` struct**

In `model/key.go`, find the `Key` struct. Add after `PurgeProtection bool`:

```go
Version       int `json:"version"`        // current version of this key (set during create, 1-based)
LatestVersion int `json:"latest_version"` // latest version across all rotations
```

- [ ] **Step 2: Add `KeyVersion` struct**

Append to `model/key.go`:

```go
// KeyVersion represents a single immutable version of a key, created on each rotation.
type KeyVersion struct {
	KeyID     uuid.UUID `json:"key_id"`
	Version   int       `json:"version"`   // 1-based version number
	Value     string    `json:"-"`         // encrypted key material (never returned in API)
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"` // true when this version was superseded
}

type KeyVersionResponse struct {
	KeyID     string `json:"key_id"`
	Version   int    `json:"version"`
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
	Revoked   bool   `json:"revoked"`
}

type ListKeyVersionsResponse struct {
	Versions []KeyVersionResponse `json:"versions"`
}
```

- [ ] **Step 3: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -10
```

- [ ] **Step 4: Commit**

```bash
git add model/key.go
git commit -m "feat(model): add Version/LatestVersion to Key, add KeyVersion and ListKeyVersions types"
```

---

## Task 2: Add `key_versions` table and `version` column to schema

**Files:**
- Modify: `internal/db/db.go`

- [ ] **Step 1: Add `key_versions` table to `createOptimizedSchema`**

In `internal/db/db.go`, find `createOptimizedSchema`. After the `keys` table, add:

```sql
CREATE TABLE IF NOT EXISTS key_versions (
    key_id TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (key_id, version)
);
CREATE INDEX IF NOT EXISTS idx_key_versions_key_id ON key_versions(key_id);
```

- [ ] **Step 2: Add `version` and `latest_version` columns to `keys` table in `createOptimizedSchema`**

Find `CREATE TABLE IF NOT EXISTS keys`. Add after existing columns:

```sql
version INTEGER NOT NULL DEFAULT 1,
latest_version INTEGER NOT NULL DEFAULT 1,
```

- [ ] **Step 3: Add `migrateSchema` migrations**

Add to the migrations slice:

```go
"ALTER TABLE keys ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
"ALTER TABLE keys ADD COLUMN latest_version INTEGER NOT NULL DEFAULT 1",
```

Note: `key_versions` table migration is handled by the `CREATE TABLE IF NOT EXISTS` in `createOptimizedSchema` — no separate migration needed for a new table.

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -10
```

- [ ] **Step 5: Commit**

```bash
git add internal/db/db.go
git commit -m "feat(db): add key_versions table and version/latest_version columns to keys table"
```

---

## Task 3: Implement `KeyVersionRepository`

**Files:**
- Create: `internal/repositories/key_version_repository.go`
- Create: `internal/repositories/key_version_repository_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/repositories/key_version_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestKeyVersionRepository_CreateAndList(t *testing.T) {
	db := setupKeyTestDB(t)
	repo := repositories.NewKeyVersionRepository(db, newTestLogger(t))

	keyID := uuid.New()

	v1 := &model.KeyVersion{
		KeyID:     keyID,
		Version:   1,
		Value:     "encrypted-material-v1",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Revoked:   false,
	}
	require.NoError(t, repo.Create(context.Background(), v1))

	v2 := &model.KeyVersion{
		KeyID:     keyID,
		Version:   2,
		Value:     "encrypted-material-v2",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Revoked:   false,
	}
	require.NoError(t, repo.Create(context.Background(), v2))

	versions, err := repo.ListByKey(context.Background(), keyID)
	require.NoError(t, err)
	assert.Len(t, versions, 2)
	assert.Equal(t, 1, versions[0].Version)
	assert.Equal(t, 2, versions[1].Version)
}

func TestKeyVersionRepository_GetByVersion(t *testing.T) {
	db := setupKeyTestDB(t)
	repo := repositories.NewKeyVersionRepository(db, newTestLogger(t))

	keyID := uuid.New()
	require.NoError(t, repo.Create(context.Background(), &model.KeyVersion{
		KeyID: keyID, Version: 1, Value: "v1", Type: "RSA", CreatedAt: time.Now(),
	}))

	got, err := repo.GetByVersion(context.Background(), keyID, 1)
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

func TestKeyVersionRepository_MarkRevoked(t *testing.T) {
	db := setupKeyTestDB(t)
	repo := repositories.NewKeyVersionRepository(db, newTestLogger(t))

	keyID := uuid.New()
	require.NoError(t, repo.Create(context.Background(), &model.KeyVersion{
		KeyID: keyID, Version: 1, Value: "v1", Type: "RSA", CreatedAt: time.Now(),
	}))
	require.NoError(t, repo.MarkRevoked(context.Background(), keyID, 1))

	got, err := repo.GetByVersion(context.Background(), keyID, 1)
	require.NoError(t, err)
	assert.True(t, got.Revoked)
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/repositories/... -run "TestKeyVersionRepository" -v 2>&1 | tail -10
```

Expected: FAIL — `NewKeyVersionRepository` undefined.

- [ ] **Step 3: Implement `KeyVersionRepository`**

Create `internal/repositories/key_version_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// KeyVersionRepository manages immutable key version records.
type KeyVersionRepository interface {
	Create(ctx context.Context, kv *model.KeyVersion) error
	GetByVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error)
	ListByKey(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error)
	MarkRevoked(ctx context.Context, keyID uuid.UUID, version int) error
}

type keyVersionRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewKeyVersionRepository creates a new KeyVersionRepository.
func NewKeyVersionRepository(db *sql.DB, log *logging.Logger) KeyVersionRepository {
	return &keyVersionRepository{db: db, log: log}
}

func (r *keyVersionRepository) Create(ctx context.Context, kv *model.KeyVersion) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO key_versions (key_id, version, value, type, created_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		kv.KeyID.String(), kv.Version, kv.Value, kv.Type, kv.CreatedAt, kv.Revoked,
	)
	if err != nil {
		return fmt.Errorf("failed to create key version: %w", err)
	}
	return nil
}

func (r *keyVersionRepository) GetByVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT key_id, version, value, type, created_at, revoked
		 FROM key_versions WHERE key_id = ? AND version = ?`,
		keyID.String(), version,
	)
	return scanKeyVersion(row)
}

func (r *keyVersionRepository) ListByKey(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT key_id, version, value, type, created_at, revoked
		 FROM key_versions WHERE key_id = ? ORDER BY version ASC`,
		keyID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list key versions: %w", err)
	}
	defer rows.Close()

	var versions []model.KeyVersion
	for rows.Next() {
		kv, err := scanKeyVersionRow(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, *kv)
	}
	return versions, rows.Err()
}

func (r *keyVersionRepository) MarkRevoked(ctx context.Context, keyID uuid.UUID, version int) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE key_versions SET revoked = TRUE WHERE key_id = ? AND version = ?`,
		keyID.String(), version,
	)
	if err != nil {
		return fmt.Errorf("failed to mark key version revoked: %w", err)
	}
	return nil
}

func scanKeyVersion(row *sql.Row) (*model.KeyVersion, error) {
	var kv model.KeyVersion
	var keyIDStr string
	var createdAt time.Time
	err := row.Scan(&keyIDStr, &kv.Version, &kv.Value, &kv.Type, &createdAt, &kv.Revoked)
	if err != nil {
		return nil, fmt.Errorf("failed to scan key version: %w", err)
	}
	kv.KeyID, _ = uuid.Parse(keyIDStr)
	kv.CreatedAt = createdAt
	return &kv, nil
}

func scanKeyVersionRow(rows *sql.Rows) (*model.KeyVersion, error) {
	var kv model.KeyVersion
	var keyIDStr string
	var createdAt time.Time
	err := rows.Scan(&keyIDStr, &kv.Version, &kv.Value, &kv.Type, &createdAt, &kv.Revoked)
	if err != nil {
		return nil, fmt.Errorf("failed to scan key version row: %w", err)
	}
	kv.KeyID, _ = uuid.Parse(keyIDStr)
	kv.CreatedAt = createdAt
	return &kv, nil
}
```

- [ ] **Step 4: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/repositories/... -run "TestKeyVersionRepository" -v 2>&1 | tail -20
```

Expected: all three tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/key_version_repository.go internal/repositories/key_version_repository_test.go
git commit -m "feat(repositories): add KeyVersionRepository for key version storage"
```

---

## Task 4: Wire `KeyVersionRepository` into service container

**Files:**
- Modify: `internal/container/service_container.go`

- [ ] **Step 1: Add `KeyVersionRepository` to container struct**

In `internal/container/service_container.go`, find the struct fields section. Add:

```go
keyVersionRepo repositories.KeyVersionRepository
```

- [ ] **Step 2: Initialize it in the container setup**

Find where `keyRepo` is initialized (near `repositories.NewKeyRepository`). Add directly after:

```go
container.keyVersionRepo = repositories.NewKeyVersionRepository(db, logger)
```

- [ ] **Step 3: Add accessor method**

```go
func (c *ServiceContainer) GetKeyVersionRepository() repositories.KeyVersionRepository {
    return c.keyVersionRepo
}
```

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -10
```

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): wire KeyVersionRepository into service container"
```

---

## Task 5: Update `RotateKey` and add `ListKeyVersions`/`GetKeyVersion` to service

**Files:**
- Modify: `internal/services/keys/key_service.go`
- Create: `internal/services/keys/key_version_service_test.go`

- [ ] **Step 1: Write failing service tests**

Create `internal/services/keys/key_version_service_test.go`:

```go
package keys_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotateKey_CreatesNewVersion(t *testing.T) {
	svc, ownerID := setupKeyService(t)
	keyID := createTestRSAKey(t, svc, ownerID)

	// After create, version should be 1
	key, err := svc.GetKey(context.Background(), keyID, ownerID)
	require.NoError(t, err)
	assert.Equal(t, 1, key.Version)
	assert.Equal(t, 1, key.LatestVersion)

	// Rotate
	require.NoError(t, svc.RotateKey(context.Background(), keyID, ownerID))

	// After rotate, latest_version should be 2, current key material is v2
	rotated, err := svc.GetKey(context.Background(), keyID, ownerID)
	require.NoError(t, err)
	assert.Equal(t, 2, rotated.LatestVersion)
}

func TestListKeyVersions_ReturnsAllVersions(t *testing.T) {
	svc, ownerID := setupKeyService(t)
	keyID := createTestRSAKey(t, svc, ownerID)
	require.NoError(t, svc.RotateKey(context.Background(), keyID, ownerID))
	require.NoError(t, svc.RotateKey(context.Background(), keyID, ownerID))

	versions, err := svc.ListKeyVersions(context.Background(), keyID, ownerID)
	require.NoError(t, err)
	assert.Len(t, versions, 3) // v1, v2, v3
}

func TestGetKeyVersion_ReturnsSpecificVersion(t *testing.T) {
	svc, ownerID := setupKeyService(t)
	keyID := createTestRSAKey(t, svc, ownerID)
	require.NoError(t, svc.RotateKey(context.Background(), keyID, ownerID))

	v1, err := svc.GetKeyVersion(context.Background(), keyID, 1, ownerID)
	require.NoError(t, err)
	assert.Equal(t, 1, v1.Version)
	assert.True(t, v1.Revoked) // v1 was revoked when v2 was created
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/keys/... -run "TestRotateKey|TestListKeyVersions|TestGetKeyVersion" -v 2>&1 | tail -15
```

Expected: FAIL — `ListKeyVersions`, `GetKeyVersion` undefined; `RotateKey` creates `-rotated` suffix.

- [ ] **Step 3: Update `RotateKey` in `key_service.go`**

Find the current `RotateKey` implementation. It likely renames the key to `{name}-rotated` and creates a new key. Replace the body with the versioned approach:

```go
func (s *keyService) RotateKey(ctx context.Context, keyID, userID uuid.UUID) error {
	// 1. Load current key
	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to read key: %w", err)
	}
	if key.UserID != userID {
		return fmt.Errorf("forbidden: cannot rotate another user's key")
	}

	// 2. Archive current key material as the current version (if not already stored)
	currentVersion := key.LatestVersion
	if currentVersion == 0 {
		currentVersion = 1
	}

	// Check if this version already exists (idempotent rotate guard)
	existing, _ := s.keyVersionRepo.GetByVersion(ctx, keyID, currentVersion)
	if existing == nil {
		if err := s.keyVersionRepo.Create(ctx, &model.KeyVersion{
			KeyID:     keyID,
			Version:   currentVersion,
			Value:     key.Value, // already encrypted
			Type:      key.Type,
			CreatedAt: key.CreatedAt,
			Revoked:   false,
		}); err != nil {
			return fmt.Errorf("failed to archive current key version: %w", err)
		}
	}

	// 3. Generate new key material
	newValue, err := s.generateKeyMaterial(key.Type, key.Tags)
	if err != nil {
		return fmt.Errorf("failed to generate new key material: %w", err)
	}

	// 4. Mark old version as revoked
	if err := s.keyVersionRepo.MarkRevoked(ctx, keyID, currentVersion); err != nil {
		return fmt.Errorf("failed to revoke old key version: %w", err)
	}

	// 5. Store new version
	newVersion := currentVersion + 1
	if err := s.keyVersionRepo.Create(ctx, &model.KeyVersion{
		KeyID:     keyID,
		Version:   newVersion,
		Value:     newValue,
		Type:      key.Type,
		CreatedAt: time.Now(),
		Revoked:   false,
	}); err != nil {
		return fmt.Errorf("failed to create new key version: %w", err)
	}

	// 6. Update parent key row with new material and incremented version
	key.Value = newValue
	key.LatestVersion = newVersion
	key.Version = newVersion
	if err := s.keyRepo.Update(ctx, key); err != nil {
		return fmt.Errorf("failed to update key with new version: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "rotate_key", "success",
		fmt.Sprintf("key %s rotated to version %d", keyID, newVersion))
	return nil
}
```

Note: `generateKeyMaterial` should be extracted from the existing `RotateKey` implementation or `CreateKey` — it generates RSA/ECDSA key bytes, encrypts them with `common.EncryptSecret`, and returns the ciphertext string.

- [ ] **Step 4: Add `ListKeyVersions` and `GetKeyVersion` methods**

Add to `key_service.go`:

```go
func (s *keyService) ListKeyVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error) {
	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}
	if key.UserID != userID {
		return nil, fmt.Errorf("forbidden: cannot list versions of another user's key")
	}
	return s.keyVersionRepo.ListByKey(ctx, keyID)
}

func (s *keyService) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (*model.KeyVersion, error) {
	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}
	if key.UserID != userID {
		return nil, fmt.Errorf("forbidden: cannot access another user's key version")
	}
	return s.keyVersionRepo.GetByVersion(ctx, keyID, version)
}
```

Also update the `KeyService` interface to include these two methods:

```go
ListKeyVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error)
GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (*model.KeyVersion, error)
```

- [ ] **Step 5: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/keys/... -run "TestRotateKey|TestListKeyVersions|TestGetKeyVersion" -v 2>&1 | tail -20
```

Expected: all three tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_version_service_test.go
git commit -m "feat(services): RotateKey creates new version; add ListKeyVersions and GetKeyVersion"
```

---

## Task 6: Add HTTP versioning endpoints

**Files:**
- Modify: `api/keys.go`
- Create: `api/keys_version_test.go`

- [ ] **Step 1: Write failing HTTP tests**

Create `api/keys_version_test.go`:

```go
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListKeyVersions_ReturnsVersions(t *testing.T) {
	srv := newTestServer(t)
	keyID := createTestKey(t, srv, "RSA")

	// Rotate twice to generate v1, v2, v3
	doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/rotate", nil)
	doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/rotate", nil)

	resp := doRequest(t, srv, "GET", "/api/v1/keys/"+keyID+"/versions", nil)
	require.Equal(t, http.StatusOK, resp.Code)

	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	versions := out["versions"].([]interface{})
	assert.GreaterOrEqual(t, len(versions), 2)
}

func TestGetKeyVersion_ReturnsSpecificVersion(t *testing.T) {
	srv := newTestServer(t)
	keyID := createTestKey(t, srv, "RSA")
	doRequest(t, srv, "POST", "/api/v1/keys/"+keyID+"/rotate", nil)

	resp := doRequest(t, srv, "GET", "/api/v1/keys/"+keyID+"/versions/1", nil)
	require.Equal(t, http.StatusOK, resp.Code)

	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	assert.Equal(t, float64(1), out["version"])
}
```

- [ ] **Step 2: Run to confirm tests fail (404)**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestListKeyVersions|TestGetKeyVersion" -v 2>&1 | tail -10
```

- [ ] **Step 3: Register versioning routes in `InitKeys`**

In `api/keys.go`, add to `InitKeys` before the log line:

```go
k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions", ApiSessionRequired(api.App, listKeyVersions)).Methods("GET")
k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getKeyVersion)).Methods("GET")
```

- [ ] **Step 4: Implement `listKeyVersions` handler**

```go
func listKeyVersions(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["key_id"])
	if err != nil {
		c.SetInvalidParamError("key_id")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	keySvc := c.App.GetServiceContainer().GetKeyService()
	versions, err := keySvc.ListKeyVersions(r.Context(), keyID, userID)
	if err != nil {
		c.SetError(err.Error(), http.StatusForbidden)
		c.HandleError(w, r)
		return
	}

	resp := model.ListKeyVersionsResponse{}
	for _, v := range versions {
		resp.Versions = append(resp.Versions, model.KeyVersionResponse{
			KeyID:     v.KeyID.String(),
			Version:   v.Version,
			Type:      v.Type,
			CreatedAt: v.CreatedAt.Format(time.RFC3339),
			Revoked:   v.Revoked,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
```

- [ ] **Step 5: Implement `getKeyVersion` handler**

```go
func getKeyVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["key_id"])
	if err != nil {
		c.SetInvalidParamError("key_id")
		c.HandleError(w, r)
		return
	}
	version, err := strconv.Atoi(vars["version"])
	if err != nil || version < 1 {
		c.SetInvalidParamError("version")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	keySvc := c.App.GetServiceContainer().GetKeyService()
	kv, err := keySvc.GetKeyVersion(r.Context(), keyID, version, userID)
	if err != nil {
		c.SetError(err.Error(), http.StatusNotFound)
		c.HandleError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.KeyVersionResponse{
		KeyID:     kv.KeyID.String(),
		Version:   kv.Version,
		Type:      kv.Type,
		CreatedAt: kv.CreatedAt.Format(time.RFC3339),
		Revoked:   kv.Revoked,
	})
}
```

Add `"strconv"` to the import block if not already present.

- [ ] **Step 6: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./api/... -run "TestListKeyVersions|TestGetKeyVersion" -v 2>&1 | tail -20
```

Expected: both tests PASS.

- [ ] **Step 7: Commit**

```bash
git add api/keys.go api/keys_version_test.go
git commit -m "feat(api): add GET /keys/{id}/versions and /keys/{id}/versions/{version} endpoints"
```

---

## Task 7: Full regression pass

- [ ] **Step 1: Run full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|ok" | sort
```

Expected: all packages `ok`.

- [ ] **Step 2: Build binary**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build -o /tmp/rocketvault-versioning . && echo "build ok"
```

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: key versioning — RotateKey creates versions, ListKeyVersions and GetKeyVersion endpoints"
```
