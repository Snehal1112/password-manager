# Per-Key Rotation Policy API — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the parity gap in `.claude/azure-keyvault-parity.md` §2 ("Get/Set rotation policy: 🟡 rotation policies exist; no per-key JWK policy API") by adding `GET/PUT/DELETE /keys/{key_id}/rotationpolicy`, a per-key policy resource distinct from RocketVault's existing named, reusable, secret-scoped `rotation_policies` (which stays as-is — this is an additive feature, not a migration).

**Architecture:** Mirror the existing certificate-policy sub-resource pattern exactly (`model/certificate_policy.go`, `internal/repositories/certificate_policy_repository.go`, `api/certificate_policy.go`): a dedicated 1:1 `key_rotation_policies` table (`key_id UNIQUE`), a small standalone repository (no service-layer indirection — the API handler pre-authorizes via `KeyService.GetKey` before touching the policy repository directly, exactly as the certificate policy handlers pre-authorize via `CertificateService.GetCertificate`), and three handlers registered under the existing `registerKeyRoutes` (so they're vault-scope-aware on both flat and vault-scoped routes for free). Authorization for the new routes plugs into the existing two-tier system from `internal/services/authorization/data_actions.go`: two new data actions (`ActionKeysRotationPolicyRead`/`Write`) are added only to `Key Vault Crypto Officer` and `Key Vault Administrator` (matching Azure's real `keyrotationpolicies/*` grant, which is Officer/Administrator-only — Crypto User does not get it).

**Tech Stack:** Go, SQLite/PostgreSQL (via `internal/db`), gorilla/mux, testify/mock.

## Global Constraints

- `go build ./...` and `go vet ./...` must pass after every task.
- Follow the dual-write migration pattern from CLAUDE.md: the `CREATE TABLE` goes in both `createOptimizedSchema` (fresh installs) and `migrateSchema` (upgrades) in `internal/db/db.go`, mirroring `certificate_policies`' existing dual placement exactly (`internal/db/db.go:465-484` and `:749-768`).
- Mirror `model/certificate_policy.go`, `internal/repositories/certificate_policy_repository.go`, and `api/certificate_policy.go` file-for-file in shape and style — this is a proven, already-reviewed pattern in this codebase; do not invent a different one.
- This is additive: do not modify the existing account-level `rotation_policies` table, `RotationServiceInterface`, or `cmd/rotation.go` — they serve secrets and stay exactly as they are.

---

### Task 1: Add the `key_rotation_policies` table and `KeyRotationPolicy` model

**Files:**
- Modify: `internal/db/db.go` (add `CREATE TABLE` in `createOptimizedSchema`, mirrored in `migrateSchema`)
- Create: `model/key_rotation_policy.go`

**Interfaces:**
- Produces: `model.KeyRotationPolicy` struct, `model.UpsertKeyRotationPolicyRequest` struct, `model.UpsertKeyRotationPolicyRequestFromJson(r io.Reader) (*UpsertKeyRotationPolicyRequest, error)` — consumed by Tasks 2 and 5.

- [ ] **Step 1: Add the table to `createOptimizedSchema`**

In `internal/db/db.go`, immediately after the `certificate_policies` block (ends at line 484, right before the blank line that follows), add:

```sql
		CREATE TABLE IF NOT EXISTS key_rotation_policies (
			id                         TEXT PRIMARY KEY,
			key_id                     TEXT NOT NULL UNIQUE,
			user_id                    TEXT NOT NULL,
			rotate_after_days          INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days  INTEGER NOT NULL DEFAULT 30,
			expiry_days                INTEGER NOT NULL DEFAULT 365,
			enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
			created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_key_id ON key_rotation_policies(key_id);
		CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_user_id ON key_rotation_policies(user_id);
```

- [ ] **Step 2: Mirror the same table into `migrateSchema`**

In `internal/db/db.go`, immediately after the `certificate_policies` block in `migrateSchema`'s statement list (ends at line 768, right before the `// Feature: enriched audit fields...` comment), add:

```go
		`CREATE TABLE IF NOT EXISTS key_rotation_policies (
			id                         TEXT PRIMARY KEY,
			key_id                     TEXT NOT NULL UNIQUE,
			user_id                    TEXT NOT NULL,
			rotate_after_days          INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days  INTEGER NOT NULL DEFAULT 30,
			expiry_days                INTEGER NOT NULL DEFAULT 365,
			enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
			created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_key_id ON key_rotation_policies(key_id)",
		"CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_user_id ON key_rotation_policies(user_id)",
```

- [ ] **Step 3: Create the model file**

Create `model/key_rotation_policy.go`:

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// KeyRotationPolicy holds the per-key rotation policy, matching the shape of
// Azure Key Vault's GET/PUT /keys/{name}/rotationpolicy resource: how long
// after creation a key auto-rotates, how long before a version's expiry a
// notification fires, and how long each new version stays valid.
type KeyRotationPolicy struct {
	ID                     uuid.UUID `json:"id" db:"id"`
	KeyID                  uuid.UUID `json:"key_id" db:"key_id"`
	UserID                 uuid.UUID `json:"user_id" db:"user_id"`
	RotateAfterDays        int       `json:"rotate_after_days" db:"rotate_after_days"`
	NotifyBeforeExpiryDays int       `json:"notify_before_expiry_days" db:"notify_before_expiry_days"`
	ExpiryDays             int       `json:"expiry_days" db:"expiry_days"`
	Enabled                bool      `json:"enabled" db:"enabled"`
	CreatedAt              time.Time `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time `json:"updated_at" db:"updated_at"`
}

// UpsertKeyRotationPolicyRequest is the request body for creating or updating
// a key's rotation policy.
type UpsertKeyRotationPolicyRequest struct {
	RotateAfterDays        int  `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int  `json:"notify_before_expiry_days"`
	ExpiryDays             int  `json:"expiry_days"`
	Enabled                bool `json:"enabled"`
}

// UpsertKeyRotationPolicyRequestFromJson decodes a request body into an upsert request.
func UpsertKeyRotationPolicyRequestFromJson(r io.Reader) (*UpsertKeyRotationPolicyRequest, error) {
	var req UpsertKeyRotationPolicyRequest
	return &req, json.NewDecoder(r).Decode(&req)
}
```

- [ ] **Step 4: Build and commit**

Run: `go build ./... && go vet ./...`

```bash
git add internal/db/db.go model/key_rotation_policy.go
git commit -m "feat(db): add key_rotation_policies table and KeyRotationPolicy model"
```

---

### Task 2: Add `KeyRotationPolicyRepository`

**Files:**
- Create: `internal/repositories/key_rotation_policy_repository.go`
- Create: `internal/repositories/key_rotation_policy_repository_test.go`

**Interfaces:**
- Consumes: `model.KeyRotationPolicy` (Task 1), `db.DB` (`internal/db`).
- Produces: `KeyRotationPolicyRepositoryInterface` with `Upsert`, `GetByKeyID`, `DeleteByKeyID`, `GetByKeyIDAny`, `DeleteByKeyIDAny` — consumed by Tasks 3 and 5.

- [ ] **Step 1: Write the failing repository tests**

Create `internal/repositories/key_rotation_policy_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupKeyRotationPolicyTestDB creates an in-memory SQLite DB for key rotation
// policy tests.
func setupKeyRotationPolicyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT,
		role TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS key_rotation_policies (
		id                         TEXT PRIMARY KEY,
		key_id                     TEXT NOT NULL UNIQUE,
		user_id                    TEXT NOT NULL,
		rotate_after_days          INTEGER NOT NULL DEFAULT 90,
		notify_before_expiry_days  INTEGER NOT NULL DEFAULT 30,
		expiry_days                INTEGER NOT NULL DEFAULT 365,
		enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
		created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

func newKeyRotationPolicyTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func TestKeyRotationPolicy_UpsertAndGet(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))

	keyID := uuid.New()
	userID := uuid.New()

	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 userID,
		RotateAfterDays:        90,
		NotifyBeforeExpiryDays: 30,
		ExpiryDays:             365,
		Enabled:                true,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
	require.NoError(t, repo.Upsert(context.Background(), policy))

	loaded, err := repo.GetByKeyID(context.Background(), keyID, userID)
	require.NoError(t, err)
	require.Equal(t, 90, loaded.RotateAfterDays)
	require.True(t, loaded.Enabled)
}

func TestKeyRotationPolicy_UpsertUpdatesExisting(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))

	keyID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	first := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(context.Background(), first))

	second := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID,
		RotateAfterDays: 30, NotifyBeforeExpiryDays: 7, ExpiryDays: 180, Enabled: false,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(context.Background(), second))

	loaded, err := repo.GetByKeyID(context.Background(), keyID, userID)
	require.NoError(t, err)
	require.Equal(t, 30, loaded.RotateAfterDays)
	require.Equal(t, 7, loaded.NotifyBeforeExpiryDays)
	require.False(t, loaded.Enabled)
}

func TestKeyRotationPolicy_DeleteByKeyID(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))

	keyID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(context.Background(), policy))
	require.NoError(t, repo.DeleteByKeyID(context.Background(), keyID, userID))

	_, err := repo.GetByKeyID(context.Background(), keyID, userID)
	require.Error(t, err)
}

func TestKeyRotationPolicyRepository_GetByKeyIDAny_IgnoresOwner(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))
	ctx := context.Background()

	keyID := uuid.New()
	ownerID := uuid.New()
	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: ownerID,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	got, err := repo.GetByKeyIDAny(ctx, keyID)
	require.NoError(t, err)
	require.Equal(t, keyID, got.KeyID)
}

func TestKeyRotationPolicyRepository_DeleteByKeyIDAny_IgnoresOwner(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))
	ctx := context.Background()

	keyID := uuid.New()
	ownerID := uuid.New()
	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: ownerID,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	require.NoError(t, repo.DeleteByKeyIDAny(ctx, keyID))

	_, err := repo.GetByKeyIDAny(ctx, keyID)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/repositories/... -run TestKeyRotationPolicy -v`

Expected: FAIL (compile error — `repositories.NewKeyRotationPolicyRepository` doesn't exist yet).

- [ ] **Step 3: Implement the repository**

Create `internal/repositories/key_rotation_policy_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// KeyRotationPolicyRepositoryInterface defines CRUD operations for per-key
// rotation policies.
type KeyRotationPolicyRepositoryInterface interface {
	// Upsert inserts or replaces the policy for a key.
	Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error
	// GetByKeyID retrieves the policy for a given key and owner.
	GetByKeyID(ctx context.Context, keyID, userID uuid.UUID) (*model.KeyRotationPolicy, error)
	// DeleteByKeyID removes the policy for a given key and owner.
	DeleteByKeyID(ctx context.Context, keyID, userID uuid.UUID) error
	// GetByKeyIDAny retrieves the policy for a key regardless of owner.
	// Callers must independently verify the caller's access to the key
	// (e.g. vault membership) before calling this.
	GetByKeyIDAny(ctx context.Context, keyID uuid.UUID) (*model.KeyRotationPolicy, error)
	// DeleteByKeyIDAny removes the policy for a key regardless of owner.
	// Callers must independently verify the caller's access to the key
	// before calling this.
	DeleteByKeyIDAny(ctx context.Context, keyID uuid.UUID) error
}

// KeyRotationPolicyRepository is the default database-backed implementation.
type KeyRotationPolicyRepository struct {
	db  db.DB
	log *logging.Logger
}

// NewKeyRotationPolicyRepository creates a new KeyRotationPolicyRepository.
func NewKeyRotationPolicyRepository(db db.DB, log *logging.Logger) KeyRotationPolicyRepositoryInterface {
	return &KeyRotationPolicyRepository{db: db, log: log}
}

// Upsert inserts a new policy or updates the existing one for the same key_id.
func (r *KeyRotationPolicyRepository) Upsert(ctx context.Context, p *model.KeyRotationPolicy) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO key_rotation_policies
			(id, key_id, user_id, rotate_after_days, notify_before_expiry_days,
			 expiry_days, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key_id) DO UPDATE SET
			rotate_after_days         = excluded.rotate_after_days,
			notify_before_expiry_days = excluded.notify_before_expiry_days,
			expiry_days               = excluded.expiry_days,
			enabled                   = excluded.enabled,
			updated_at                = excluded.updated_at`,
		p.ID.String(), p.KeyID.String(), p.UserID.String(),
		p.RotateAfterDays, p.NotifyBeforeExpiryDays, p.ExpiryDays, p.Enabled,
		p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetByKeyID retrieves the policy scoped to a key and its owner.
func (r *KeyRotationPolicyRepository) GetByKeyID(ctx context.Context, keyID, userID uuid.UUID) (*model.KeyRotationPolicy, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, key_id, user_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, created_at, updated_at
		FROM key_rotation_policies
		WHERE key_id = ? AND user_id = ?`,
		keyID.String(), userID.String(),
	)
	return scanKeyRotationPolicyRow(row)
}

// DeleteByKeyID removes the policy owned by userID for the given key.
// Returns sql.ErrNoRows when no matching policy exists.
func (r *KeyRotationPolicyRepository) DeleteByKeyID(ctx context.Context, keyID, userID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM key_rotation_policies WHERE key_id = ? AND user_id = ?",
		keyID.String(), userID.String(),
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetByKeyIDAny retrieves the policy for a key, ignoring owner. Callers are
// responsible for verifying access to the key (e.g. vault membership) before
// calling this.
func (r *KeyRotationPolicyRepository) GetByKeyIDAny(ctx context.Context, keyID uuid.UUID) (*model.KeyRotationPolicy, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, key_id, user_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, created_at, updated_at
		FROM key_rotation_policies
		WHERE key_id = ?`,
		keyID.String(),
	)
	return scanKeyRotationPolicyRow(row)
}

// DeleteByKeyIDAny removes the policy for a key, ignoring owner. Callers are
// responsible for verifying access to the key before calling this. Returns
// sql.ErrNoRows when no matching policy exists.
func (r *KeyRotationPolicyRepository) DeleteByKeyIDAny(ctx context.Context, keyID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM key_rotation_policies WHERE key_id = ?",
		keyID.String(),
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// scanKeyRotationPolicyRow scans one key_rotation_policies row.
func scanKeyRotationPolicyRow(row *sql.Row) (*model.KeyRotationPolicy, error) {
	var p model.KeyRotationPolicy
	var idStr, keyIDStr, userIDStr string
	if err := row.Scan(&idStr, &keyIDStr, &userIDStr,
		&p.RotateAfterDays, &p.NotifyBeforeExpiryDays, &p.ExpiryDays, &p.Enabled,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if p.ID, err = uuid.Parse(idStr); err != nil {
		return nil, err
	}
	if p.KeyID, err = uuid.Parse(keyIDStr); err != nil {
		return nil, err
	}
	if p.UserID, err = uuid.Parse(userIDStr); err != nil {
		return nil, err
	}
	return &p, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/repositories/... -run TestKeyRotationPolicy -v`

Expected: PASS (6 tests).

- [ ] **Step 5: Add to `.mockery.yaml` and regenerate (optional interface, matches certificate policy's own choice not to mock it — skip unless a later task needs a mock)**

`CertificatePolicyRepositoryInterface` is deliberately absent from `.mockery.yaml` — its API-layer tests use a small hand-written `mock.Mock`-based stub instead (see Task 5). Do the same here: do not add `KeyRotationPolicyRepositoryInterface` to `.mockery.yaml`.

- [ ] **Step 6: Build and commit**

Run: `go build ./... && go vet ./...`

```bash
git add internal/repositories/key_rotation_policy_repository.go internal/repositories/key_rotation_policy_repository_test.go
git commit -m "feat(repositories): add KeyRotationPolicyRepository"
```

---

### Task 3: Wire `KeyRotationPolicyRepository` into the service container

**Files:**
- Modify: `internal/container/service_container.go` (interface, field, initialization, getter)
- Modify: `internal/container/container_test.go` (add lifecycle assertions mirroring `GetCertificatePolicyRepository`)
- Modify: `cmd/testutils/test_utils.go` (`MockServiceContainer` stub method)

**Interfaces:**
- Consumes: `repositories.NewKeyRotationPolicyRepository` (Task 2).
- Produces: `ServiceContainerInterface.GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface` — consumed by Task 5's API handlers via a new `Context.keyRotationPolicyRepo()` accessor.

- [ ] **Step 1: Add the interface method**

In `internal/container/service_container.go`, immediately after the existing `GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface` line in the `ServiceContainerInterface` interface (line 50), add:

```go
	GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface
```

- [ ] **Step 2: Add the field**

Immediately after the `certPolicyRepository repositories.CertificatePolicyRepositoryInterface` field declaration (line 145) in the `ServiceContainer` struct, add:

```go
	keyRotationPolicyRepository repositories.KeyRotationPolicyRepositoryInterface
```

- [ ] **Step 3: Initialize it**

Immediately after `c.certPolicyRepository = repositories.NewCertificatePolicyRepository(c.conn, c.logger)` (line 282), add:

```go
	c.keyRotationPolicyRepository = repositories.NewKeyRotationPolicyRepository(c.conn, c.logger)
```

- [ ] **Step 4: Add the getter**

Immediately after the `GetCertificatePolicyRepository` method (ends line 717), add:

```go
// GetKeyRotationPolicyRepository returns the per-key rotation policy repository.
func (c *ServiceContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	return c.keyRotationPolicyRepository
}
```

- [ ] **Step 5: Update `internal/container/container_test.go`**

Find the two existing assertions for `GetCertificatePolicyRepository` (around lines 80 and 222 — one asserting `Nil` before the container is fully built, one asserting `NotNil` after) and add matching assertions for `GetKeyRotationPolicyRepository` immediately after each:

```go
	assert.Nil(t, c.GetKeyRotationPolicyRepository(), "GetKeyRotationPolicyRepository")
```
and
```go
	assert.NotNil(t, container.GetKeyRotationPolicyRepository(), "GetKeyRotationPolicyRepository")
```

- [ ] **Step 6: Update `cmd/testutils/test_utils.go`**

Immediately after the `GetCertificatePolicyRepository` stub method (line ~180), add:

```go
func (m *MockServiceContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	return nil
}
```

- [ ] **Step 7: Add the `Context` accessor**

In `api/context.go`, immediately after `certPolicyRepo()` (line 284), add:

```go
func (c *Context) keyRotationPolicyRepo() repositories.KeyRotationPolicyRepositoryInterface {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetKeyRotationPolicyRepository()
}
```

- [ ] **Step 8: Build and run the container test suite**

Run: `go build ./... && go vet ./... && go test ./internal/container/... -v`

Expected: PASS, including the two new assertions. This step will also surface every other type implementing `ServiceContainerInterface` that now needs the new method (every hand-rolled test-only container in `api/*_test.go` panics at compile time otherwise) — **do not fix those yet**, that happens naturally as Task 5 touches the relevant test files; for now confirm the count of newly-broken test files with:

Run: `go build ./... 2>&1 | grep -c "does not implement"`

Note the count so Task 5's scope is verifiable (every hand-rolled `*TestContainer`/`*testContainer` type across `api/*_test.go` needs one more method — add `panic("unexpected call: GetKeyRotationPolicyRepository")` to each, matching the style of every other unused method in those types).

- [ ] **Step 9: Commit**

```bash
git add internal/container/service_container.go internal/container/container_test.go \
  cmd/testutils/test_utils.go api/context.go
git commit -m "feat(container): wire KeyRotationPolicyRepository into the service container"
```

---

### Task 4: Add rotation-policy data actions and authorize Crypto Officer / Administrator only

**Files:**
- Modify: `model/azure_roles.go` (two new `DataAction` constants, added to two role bundles)
- Modify: `internal/services/authorization/data_actions.go` (`mapKeyAction`)
- Modify: `internal/services/authorization/authorization_matrix_test.go` (two new ops, `allKeyOps`, two count assertions)

**Interfaces:**
- Produces: `model.ActionKeysRotationPolicyRead`, `model.ActionKeysRotationPolicyWrite` — consumed by Task 5's handlers indirectly via `PolicyMiddleware` (no direct handler code references these constants; the middleware resolves them from the route).

- [ ] **Step 1: Add the two data actions**

In `model/azure_roles.go`, in the "Key data actions" const block (ends at line 69 with `ActionKeysVerify`), add before the closing `)`:

```go
	// ActionKeysRotationPolicyRead permits reading a key's rotation policy.
	ActionKeysRotationPolicyRead DataAction = "Microsoft.KeyVault/vaults/keys/rotationpolicy/read"
	// ActionKeysRotationPolicyWrite permits creating, updating, or clearing a
	// key's rotation policy.
	ActionKeysRotationPolicyWrite DataAction = "Microsoft.KeyVault/vaults/keys/rotationpolicy/write"
```

- [ ] **Step 2: Grant them to Crypto Officer and Administrator only**

This matches the real Azure grant — the original parity doc's Crypto Officer row already named `keyrotationpolicies/*` as part of the real Azure Crypto Officer bundle, and Azure does not grant it to Crypto User.

In `model/azure_roles.go`, change:

```go
	RoleKeyVaultAdministrator: {
		ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
		ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
		ActionSecretsRecover, ActionSecretsPurge,
		ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
		ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
		ActionCertificatesRecover, ActionCertificatesPurge,
	},
```

to:

```go
	RoleKeyVaultAdministrator: {
		ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
		ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
		ActionSecretsRecover, ActionSecretsPurge,
		ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
		ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		ActionKeysRotationPolicyRead, ActionKeysRotationPolicyWrite,
		ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
		ActionCertificatesRecover, ActionCertificatesPurge,
	},
```

and change:

```go
	RoleKeyVaultCryptoOfficer: {
		ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
		ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
	},
```

to:

```go
	RoleKeyVaultCryptoOfficer: {
		ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
		ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		ActionKeysRotationPolicyRead, ActionKeysRotationPolicyWrite,
	},
```

- [ ] **Step 3: Map the route in `mapKeyAction`**

In `internal/services/authorization/data_actions.go`, inside `mapKeyAction`'s `if len(seg) == 2` block (lines 169-193), add a new case alongside the existing `method == http.MethodPost` block — this one needs GET and PUT/DELETE, so it can't reuse that block. Change:

```go
	if len(seg) == 2 {
		if seg[1] == "versions" && method == http.MethodGet {
			return model.ActionKeysRead, RouteVaultData
		}
		if method == http.MethodPost {
			switch seg[1] {
			case "rotate":
				return model.ActionKeysRotate, RouteVaultData
			case "backup":
				return model.ActionKeysBackup, RouteVaultData
			case "wrap":
				return model.ActionKeysWrap, RouteVaultData
			case "unwrap":
				return model.ActionKeysUnwrap, RouteVaultData
			case "sign":
				return model.ActionKeysSign, RouteVaultData
			case "verify":
				return model.ActionKeysVerify, RouteVaultData
			case "encrypt":
				return model.ActionKeysEncrypt, RouteVaultData
			case "decrypt":
				return model.ActionKeysDecrypt, RouteVaultData
			}
		}
	}
	return "", RouteVaultData
```

to:

```go
	if len(seg) == 2 {
		if seg[1] == "versions" && method == http.MethodGet {
			return model.ActionKeysRead, RouteVaultData
		}
		if seg[1] == "rotationpolicy" {
			switch method {
			case http.MethodGet:
				return model.ActionKeysRotationPolicyRead, RouteVaultData
			case http.MethodPut, http.MethodDelete:
				return model.ActionKeysRotationPolicyWrite, RouteVaultData
			}
			return "", RouteVaultData
		}
		if method == http.MethodPost {
			switch seg[1] {
			case "rotate":
				return model.ActionKeysRotate, RouteVaultData
			case "backup":
				return model.ActionKeysBackup, RouteVaultData
			case "wrap":
				return model.ActionKeysWrap, RouteVaultData
			case "unwrap":
				return model.ActionKeysUnwrap, RouteVaultData
			case "sign":
				return model.ActionKeysSign, RouteVaultData
			case "verify":
				return model.ActionKeysVerify, RouteVaultData
			case "encrypt":
				return model.ActionKeysEncrypt, RouteVaultData
			case "decrypt":
				return model.ActionKeysDecrypt, RouteVaultData
			}
		}
	}
	return "", RouteVaultData
```

- [ ] **Step 4: Update the authorization matrix test — add the two new operations**

In `internal/services/authorization/authorization_matrix_test.go`, add to `matrixOps` (after the `keys.unwrap` entry, line 65):

```go
	{"keys.getRotationPolicy", http.MethodGet, "/api/v1/vaults/prod/keys/abc/rotationpolicy"},
	{"keys.setRotationPolicy", http.MethodPut, "/api/v1/vaults/prod/keys/abc/rotationpolicy"},
```

- [ ] **Step 5: Add the two operations to `allKeyOps`**

Change:

```go
	allKeyOps = []string{
		"keys.list", "keys.get", "keys.create", "keys.update", "keys.delete",
		"keys.rotate", "keys.listVersions", "keys.sign", "keys.verify",
		"keys.encrypt", "keys.decrypt", "keys.wrap", "keys.unwrap",
		"keys.backup", "keys.restore", "keys.listDeleted", "keys.getDeleted",
		"keys.recover", "keys.purge",
	}
```

to:

```go
	allKeyOps = []string{
		"keys.list", "keys.get", "keys.create", "keys.update", "keys.delete",
		"keys.rotate", "keys.listVersions", "keys.sign", "keys.verify",
		"keys.encrypt", "keys.decrypt", "keys.wrap", "keys.unwrap",
		"keys.getRotationPolicy", "keys.setRotationPolicy",
		"keys.backup", "keys.restore", "keys.listDeleted", "keys.getDeleted",
		"keys.recover", "keys.purge",
	}
```

Since `matrixAllowed[model.RoleKeyVaultCryptoOfficer] = allKeyOps` and `RoleKeyVaultAdministrator`'s entry unions `allKeyOps`, both roles automatically pick up the two new operations — no further change needed there. `RoleKeyVaultCryptoUser`'s explicit list is untouched, so it correctly stays denied for both.

- [ ] **Step 6: Update the two hardcoded operation-count assertions**

In `TestAuthorizationMatrixCoversEveryOperation`, change `assert.Len(t, matrixOps, 48)` to `assert.Len(t, matrixOps, 50)`.

In `TestAuthorizationMatrixNoRoleGrantsEverythingButAdministrator`, change both `assert.Len(t, names, 48)` and `assert.Less(t, len(names), 48, ...)` to `50`.

- [ ] **Step 7: Run the authorization test suite**

Run: `go build ./... && go vet ./... && go test ./internal/services/authorization/... -v`

Expected: PASS, including `TestAuthorizationMatrix`, `TestAuthorizationMatrixCoversEveryOperation`, `TestAuthorizationMatrixNoRoleGrantsEverythingButAdministrator`.

- [ ] **Step 8: Commit**

```bash
git add model/azure_roles.go internal/services/authorization/data_actions.go \
  internal/services/authorization/authorization_matrix_test.go
git commit -m "feat(authz): add key rotation-policy data actions, grant to Crypto Officer and Administrator"
```

---

### Task 5: Add the API handlers, register routes, and update every affected test container

**Files:**
- Create: `api/key_rotation_policy.go`
- Create: `api/key_rotation_policy_test.go`
- Modify: `api/keys.go` (`registerKeyRoutes`)
- Modify: every hand-rolled `*Context`-backing container type across `api/*_test.go` that implements the full `container.ServiceContainerInterface` (add one `GetKeyRotationPolicyRepository` stub method each — Task 3 Step 8 told you how many)

**Interfaces:**
- Consumes: `c.keyRotationPolicyRepo()` (Task 3), `c.keySvc() keyServices.KeyService` (`api/context.go:230`), `scopeFromRequest` (`api/context.go:64`), `model.UpsertKeyRotationPolicyRequestFromJson` (Task 1).
- Produces: `getKeyRotationPolicy`, `upsertKeyRotationPolicy`, `deleteKeyRotationPolicy` handler functions — registered as routes, no other Go code depends on them directly.

- [ ] **Step 1: Write the failing handler tests**

Create `api/key_rotation_policy_test.go`, mirroring `api/certificate_policy_test.go`'s structure exactly:

```go
// Package api — internal tests for key rotation policy handlers.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	oauth2Services "rocketvault/internal/services/oauth2"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
	"rocketvault/model"
)

// --- mock KeyRotationPolicyRepository ---

type mockKeyRotationPolicyRepo struct {
	mock.Mock
}

func (m *mockKeyRotationPolicyRepo) Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *mockKeyRotationPolicyRepo) GetByKeyID(ctx context.Context, keyID, userID uuid.UUID) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyRotationPolicy), args.Error(1)
}

func (m *mockKeyRotationPolicyRepo) DeleteByKeyID(ctx context.Context, keyID, userID uuid.UUID) error {
	args := m.Called(ctx, keyID, userID)
	return args.Error(0)
}

func (m *mockKeyRotationPolicyRepo) GetByKeyIDAny(ctx context.Context, keyID uuid.UUID) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyRotationPolicy), args.Error(1)
}

func (m *mockKeyRotationPolicyRepo) DeleteByKeyIDAny(ctx context.Context, keyID uuid.UUID) error {
	args := m.Called(ctx, keyID)
	return args.Error(0)
}

// --- scopeStubKeyServiceForPolicy: trivial success stub for the pre-check ---

type scopeStubKeyServiceForPolicy struct {
	keyServices.KeyService
	key    *model.Key
	keyErr error
}

func (s *scopeStubKeyServiceForPolicy) GetKey(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Key, error) {
	return s.key, s.keyErr
}

// --- keyRotationPolicyRepoContainer ---

type keyRotationPolicyRepoContainer struct {
	repo   repositories.KeyRotationPolicyRepositoryInterface
	keySvc keyServices.KeyService
}

func (c *keyRotationPolicyRepoContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	return c.repo
}
func (c *keyRotationPolicyRepoContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *keyRotationPolicyRepoContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *keyRotationPolicyRepoContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *keyRotationPolicyRepoContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *keyRotationPolicyRepoContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *keyRotationPolicyRepoContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *keyRotationPolicyRepoContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *keyRotationPolicyRepoContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *keyRotationPolicyRepoContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *keyRotationPolicyRepoContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *keyRotationPolicyRepoContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *keyRotationPolicyRepoContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *keyRotationPolicyRepoContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *keyRotationPolicyRepoContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *keyRotationPolicyRepoContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *keyRotationPolicyRepoContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *keyRotationPolicyRepoContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *keyRotationPolicyRepoContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *keyRotationPolicyRepoContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *keyRotationPolicyRepoContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *keyRotationPolicyRepoContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *keyRotationPolicyRepoContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *keyRotationPolicyRepoContainer) GetKeyService() keyServices.KeyService {
	return c.keySvc
}
func (c *keyRotationPolicyRepoContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *keyRotationPolicyRepoContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *keyRotationPolicyRepoContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *keyRotationPolicyRepoContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *keyRotationPolicyRepoContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *keyRotationPolicyRepoContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *keyRotationPolicyRepoContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *keyRotationPolicyRepoContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *keyRotationPolicyRepoContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *keyRotationPolicyRepoContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *keyRotationPolicyRepoContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *keyRotationPolicyRepoContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *keyRotationPolicyRepoContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *keyRotationPolicyRepoContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *keyRotationPolicyRepoContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *keyRotationPolicyRepoContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *keyRotationPolicyRepoContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *keyRotationPolicyRepoContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *keyRotationPolicyRepoContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *keyRotationPolicyRepoContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *keyRotationPolicyRepoContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *keyRotationPolicyRepoContainer) Close() error { return nil }

const krpTestUserID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

// newKeyRotationPolicyCtx builds a Context backed by the given policy repo
// mock. The key service defaults to a scope stub that reports the key as
// found, since these tests exercise the policy repository, not the key
// pre-check.
func newKeyRotationPolicyCtx(repo repositories.KeyRotationPolicyRepositoryInterface, keyIDStr string) *Context {
	a := &app.App{ServiceContainer: &keyRotationPolicyRepoContainer{repo: repo, keySvc: &scopeStubKeyServiceForPolicy{}}}
	return &Context{
		App:    a,
		Claims: jwt.MapClaims{"user_id": krpTestUserID},
		Params: &ApiParams{KeyID: keyIDStr, PerPage: 60},
	}
}

// ============================================================
// getKeyRotationPolicy
// ============================================================

func TestGetKeyRotationPolicy_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyRotationPolicyCtx(nil, "bad-key-id")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/bad/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetKeyRotationPolicy_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("GetByKeyIDAny", mock.Anything, keyID).Return(nil, errors.New("not found"))

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	repo.AssertExpectations(t)
}

func TestGetKeyRotationPolicy_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(krpTestUserID)
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("GetByKeyIDAny", mock.Anything, keyID).Return(&model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, RotateAfterDays: 90,
	}, nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	getKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

// ============================================================
// upsertKeyRotationPolicy
// ============================================================

func TestUpsertKeyRotationPolicy_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyRotationPolicyCtx(nil, "bad")
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 90})
	r := httptest.NewRequest(http.MethodPut, "/keys/bad/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertKeyRotationPolicy_InvalidBody_Returns400(t *testing.T) {
	keyID := uuid.New()
	c := newKeyRotationPolicyCtx(nil, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader([]byte(`{bad json}`)))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertKeyRotationPolicy_UpsertError_Returns500(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 90, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	repo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(krpTestUserID)
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("Upsert", mock.Anything, mock.Anything).Return(nil)
	repo.On("GetByKeyIDAny", mock.Anything, keyID).Return(&model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, RotateAfterDays: 90, Enabled: true,
	}, nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"rotate_after_days": 90, "enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))

	upsertKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

// ============================================================
// deleteKeyRotationPolicy
// ============================================================

func TestDeleteKeyRotationPolicy_InvalidKeyID_Returns400(t *testing.T) {
	c := newKeyRotationPolicyCtx(nil, "bad")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/bad/rotationpolicy", nil)

	deleteKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteKeyRotationPolicy_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("DeleteByKeyIDAny", mock.Anything, keyID).Return(errors.New("db error"))

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	deleteKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	repo.AssertExpectations(t)
}

func TestDeleteKeyRotationPolicy_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	repo := &mockKeyRotationPolicyRepo{}
	repo.On("DeleteByKeyIDAny", mock.Anything, keyID).Return(nil)

	c := newKeyRotationPolicyCtx(repo, keyID.String())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String()+"/rotationpolicy", nil)

	deleteKeyRotationPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run 'TestGetKeyRotationPolicy|TestUpsertKeyRotationPolicy|TestDeleteKeyRotationPolicy' -v`

Expected: FAIL (compile error — `getKeyRotationPolicy`/`upsertKeyRotationPolicy`/`deleteKeyRotationPolicy` don't exist yet, and every other hand-rolled container type in the `api` package fails to satisfy `ServiceContainerInterface` because of Task 3's new method — this is expected and fixed by Step 4 below).

- [ ] **Step 3: Implement the handlers**

Create `api/key_rotation_policy.go`, mirroring `api/certificate_policy.go`:

```go
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// getKeyRotationPolicy returns the rotation policy for a key.
func getKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	repo := c.keyRotationPolicyRepo()
	if repo == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}
	if _, err := keySvc.GetKey(r.Context(), keyID, scope); err != nil {
		c.SetNotFound("key")
		return
	}

	policy, err := repo.GetByKeyIDAny(r.Context(), keyID)
	if err != nil {
		c.SetNotFound("rotation policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy) //nolint:errcheck,gosec
}

// upsertKeyRotationPolicy creates or replaces the rotation policy for a key.
func upsertKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	req, err := model.UpsertKeyRotationPolicyRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	repo := c.keyRotationPolicyRepo()
	if repo == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}
	if _, err := keySvc.GetKey(r.Context(), keyID, scope); err != nil {
		c.SetNotFound("key")
		return
	}

	now := time.Now()
	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 scope.ActorID(),
		RotateAfterDays:        req.RotateAfterDays,
		NotifyBeforeExpiryDays: req.NotifyBeforeExpiryDays,
		ExpiryDays:             req.ExpiryDays,
		Enabled:                req.Enabled,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	if err := repo.Upsert(r.Context(), policy); err != nil {
		c.SetInternalError(err)
		return
	}

	// Read-after-write so the response reflects the canonical stored ID. The
	// scope has already authorized the parent key, so the owner-agnostic
	// lookup is safe here too.
	stored, err := repo.GetByKeyIDAny(r.Context(), keyID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stored) //nolint:errcheck,gosec
}

// deleteKeyRotationPolicy removes the rotation policy for a key.
func deleteKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	repo := c.keyRotationPolicyRepo()
	if repo == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}
	if _, err := keySvc.GetKey(r.Context(), keyID, scope); err != nil {
		c.SetNotFound("key")
		return
	}

	if err := repo.DeleteByKeyIDAny(r.Context(), keyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.SetNotFound("rotation policy not found")
		} else {
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}
```

- [ ] **Step 4: Register the routes**

In `api/keys.go`, inside `registerKeyRoutes` (after the `/{key_id:[A-Fa-f0-9-]+}/decrypt` line, before `api.Logger.Infoln(...)`), add:

```go
	// Rotation policy sub-resource: GET/PUT/DELETE /keys/{key_id}/rotationpolicy
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotationpolicy", ApiSessionRequired(api.App, getKeyRotationPolicy)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotationpolicy", ApiSessionRequired(api.App, upsertKeyRotationPolicy)).Methods("PUT")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotationpolicy", ApiSessionRequired(api.App, deleteKeyRotationPolicy)).Methods("DELETE")
```

Because `registerKeyRoutes` is called for both `api.BaseRoutes.Keys` (flat) and `api.BaseRoutes.VaultScoped.PathPrefix("/keys")` (vault-scoped) in `InitKeys`, this is vault-scope-aware immediately with no separate registration step.

- [ ] **Step 5: Fix every other hand-rolled container type in `api/*_test.go`**

Every type in the `api` test files that implements the full `ServiceContainerInterface` (found via the build-error count from Task 3 Step 8) needs one more method. Add it next to each type's `GetCertificatePolicyRepository` stub (same file, same pattern):

```go
func (c *<TypeName>) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
```

For containers that use `return nil` instead of `panic(...)` for every method (e.g. `testutils.MockServiceContainer`, already handled in Task 3 Step 6), match that file's existing convention instead.

- [ ] **Step 6: Run the full test suite**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tail -80`

Expected: clean build, all tests pass, including the new `TestGetKeyRotationPolicy_*`/`TestUpsertKeyRotationPolicy_*`/`TestDeleteKeyRotationPolicy_*` and `TestAuthorizationMatrixOpsAreRealRoutes` (which now walks the newly-registered routes and confirms `mapKeyAction` maps them).

- [ ] **Step 7: Commit**

```bash
git add api/key_rotation_policy.go api/key_rotation_policy_test.go api/keys.go
git add -u  # stage every *_test.go file touched by Step 5
git commit -m "feat(api): add GET/PUT/DELETE /keys/{key_id}/rotationpolicy"
```

---

### Task 6: Update the parity doc

**Files:**
- Modify: `.claude/azure-keyvault-parity.md`

- [ ] **Step 1: Update §2's rotation policy row**

Change:
```
| Get/Set rotation policy | ✅ | 🟡 rotation policies exist; no per-key JWK policy API | 🟡 |
```
to:
```
| Get/Set rotation policy | ✅ | ✅ `GET/PUT/DELETE /keys/{key_id}/rotationpolicy`, granted to Crypto Officer + Administrator (matching Azure's `keyrotationpolicies/*`) | ✅ |
```

- [ ] **Step 2: Update the Summary's Partial (🟡) bullet**

Remove the "Rotation policy" bullet from the **Partial (🟡)** list (it no longer applies — the per-key API now exists; the pre-existing account-level `rotation_policies` for secrets is unrelated and unaffected). Add a short note to the **Strong parity (✅)** paragraph mentioning the new per-key rotation policy endpoint.

- [ ] **Step 3: Update §6's Crypto Officer row**

The row already says `no per-key rotation-policy API is a separate, still-open gap (see §1)` (from the 2026-08-13 RBAC correction) — remove that clause now that it's closed.

- [ ] **Step 4: Commit**

```bash
git add .claude/azure-keyvault-parity.md
git commit -m "docs(parity): close the per-key rotation policy gap"
```
