# Vault Tags and Modification Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Azure-parity key/value `tags` map and `updated_at`/`updated_by` modification tracking to RocketVault's Vault resource.

**Architecture:** Tags are stored as a JSON `TEXT` column on the `vaults` table; (de)serialization is confined to the repository layer so a future migration to a normalized table touches only one file. `UpdateVault` gains an `updatedBy uuid.UUID` parameter threaded from the API/CLI callers; the repository stamps `updated_at` on every update.

**Tech Stack:** Go 1.24, Gorilla Mux, SQLite/PostgreSQL, `encoding/json`, `google/uuid`, standard `testing`.

**Spec:** `docs/superpowers/specs/2026-06-02-vault-tags-and-modification-tracking-design.md`

---

## File Structure

- `model/vault.go` — add `Tags`, `UpdatedAt`, `UpdatedBy` to `Vault`/requests/response; add `ValidateVaultTags`.
- `internal/db/db.go` — add columns to `createOptimizedSchema` and `migrateSchema`.
- `internal/db/migrations/20260602000001_add_vault_tags_modtracking.sql` — CLI migrate path.
- `internal/repositories/vault_repository.go` — JSON tag (de)serialization; extended Create/Update SQL; updated `vaultCols`/`scanVault`.
- `internal/services/vaults/vault_service.go` — tag validation; `UpdateVault(...,updatedBy)`.
- `api/vault.go` — pass tags through; read caller UUID in update handler.
- `cmd/vaults/update.go` — pass `uuid.Nil` (no authenticated user in CLI context).
- `cmd/testutils/test_utils.go`, `internal/middleware/middleware_test.go` — update mock/stub signatures.

---

## Task 1: Model — fields, request/response, tag validation

**Files:**
- Modify: `model/vault.go`
- Test: `model/vault_tags_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `model/vault_tags_test.go`:

```go
package model

import "testing"

func TestValidateVaultTags(t *testing.T) {
	if err := ValidateVaultTags(nil); err != nil {
		t.Fatalf("nil tags should be valid, got %v", err)
	}
	if err := ValidateVaultTags(map[string]string{"env": "prod"}); err != nil {
		t.Fatalf("valid tags rejected: %v", err)
	}
	if err := ValidateVaultTags(map[string]string{"": "x"}); err == nil {
		t.Fatal("empty key should be rejected")
	}
	if err := ValidateVaultTags(map[string]string{"k": ""}); err == nil {
		t.Fatal("empty value should be rejected")
	}
	big := make(map[string]string)
	for i := 0; i < 16; i++ {
		big[string(rune('a'+i))] = "v"
	}
	if err := ValidateVaultTags(big); err == nil {
		t.Fatal("more than 15 tags should be rejected")
	}
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateVaultTags(map[string]string{string(long): "v"}); err == nil {
		t.Fatal("over-256-char key should be rejected")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/ -run TestValidateVaultTags -v`
Expected: FAIL — `undefined: ValidateVaultTags`.

- [ ] **Step 3: Add fields and validation to `model/vault.go`**

In the `Vault` struct, after `ScheduledPurgeAt`, add:

```go
	Tags             map[string]string `json:"tags,omitempty"`
	UpdatedAt        *time.Time        `json:"updated_at,omitempty"`
	UpdatedBy        *uuid.UUID        `json:"updated_by,omitempty"`
```

In `CreateVaultRequest`, after `RetentionDays`, add:

```go
	Tags            map[string]string `json:"tags,omitempty"`
```

In `UpdateVaultRequest`, after `RetentionDays`, add:

```go
	Tags            *map[string]string `json:"tags,omitempty"` // nil = unchanged, {} = clear, set = replace
```

In `VaultResponse`, after `ScheduledPurgeAt`, add:

```go
	Tags             map[string]string `json:"tags,omitempty"`
	UpdatedAt        string            `json:"updated_at,omitempty"`
	UpdatedBy        string            `json:"updated_by,omitempty"`
```

In `ToResponse()`, before the `return resp`, add:

```go
	if len(v.Tags) > 0 {
		resp.Tags = v.Tags
	}
	if v.UpdatedAt != nil {
		resp.UpdatedAt = v.UpdatedAt.Format(time.RFC3339)
	}
	if v.UpdatedBy != nil {
		resp.UpdatedBy = v.UpdatedBy.String()
	}
```

After `ValidateVaultName`, add:

```go
// ValidateVaultTags enforces Azure Key Vault tag limits: at most 15 tags, each
// key and value non-empty and at most 256 characters.
func ValidateVaultTags(tags map[string]string) error {
	if len(tags) > 15 {
		return fmt.Errorf("too many tags: %d (max 15)", len(tags))
	}
	for k, val := range tags {
		if k == "" {
			return fmt.Errorf("tag key must not be empty")
		}
		if val == "" {
			return fmt.Errorf("tag value for key %q must not be empty", k)
		}
		if len(k) > 256 {
			return fmt.Errorf("tag key %q exceeds 256 characters", k)
		}
		if len(val) > 256 {
			return fmt.Errorf("tag value for key %q exceeds 256 characters", k)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./model/ -run TestValidateVaultTags -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add model/vault.go model/vault_tags_test.go
git commit -S -m "feat(model): add vault tags and modification-tracking fields"
```

---

## Task 2: Schema — columns on fresh DBs and migrations

**Files:**
- Modify: `internal/db/db.go`
- Create: `internal/db/migrations/20260602000001_add_vault_tags_modtracking.sql`

- [ ] **Step 1: Add columns to `createOptimizedSchema`**

In `internal/db/db.go`, in the `CREATE TABLE IF NOT EXISTS vaults (` block inside
`createOptimizedSchema` (around line 305), change the final field line so the block ends:

```sql
			deleted_at         TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL,
			tags               TEXT NOT NULL DEFAULT '{}',
			updated_at         TIMESTAMP NULL,
			updated_by         TEXT NULL
		);
```

- [ ] **Step 2: Add idempotent ALTERs to `migrateSchema`**

In `internal/db/db.go`, in the `migrations := []string{...}` slice, immediately AFTER the
line `"CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name)",` add:

```go
		// Vault tags + modification tracking (Azure parity). Tags stored as a JSON
		// object; (de)serialization is confined to vault_repository.go.
		"ALTER TABLE vaults ADD COLUMN tags TEXT NOT NULL DEFAULT '{}'",
		"ALTER TABLE vaults ADD COLUMN updated_at TIMESTAMP NULL",
		"ALTER TABLE vaults ADD COLUMN updated_by TEXT NULL",
```

- [ ] **Step 3: Create the migration file**

Create `internal/db/migrations/20260602000001_add_vault_tags_modtracking.sql`:

```sql
-- Vault tags (JSON key/value map) and modification tracking (Azure Key Vault parity).
ALTER TABLE vaults ADD COLUMN tags TEXT NOT NULL DEFAULT '{}';
ALTER TABLE vaults ADD COLUMN updated_at TIMESTAMP NULL;
ALTER TABLE vaults ADD COLUMN updated_by TEXT NULL;
```

- [ ] **Step 4: Verify the DB package builds and existing tests pass**

Run: `go test ./internal/db/... -v`
Expected: PASS (schema string still compiles; migrations apply idempotently).

- [ ] **Step 5: Commit**

```bash
git add internal/db/db.go internal/db/migrations/20260602000001_add_vault_tags_modtracking.sql
git commit -S -m "feat(db): add vaults.tags, updated_at, updated_by columns"
```

---

## Task 3: Repository — JSON tags, extended Create/Update, scan

**Files:**
- Modify: `internal/repositories/vault_repository.go`
- Test: `internal/repositories/vault_repository_tags_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/vault_repository_tags_test.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newVaultTagsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE vaults (
		id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		retention_days INTEGER NOT NULL DEFAULT 90,
		created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL, scheduled_purge_at TIMESTAMP NULL,
		tags TEXT NOT NULL DEFAULT '{}', updated_at TIMESTAMP NULL, updated_by TEXT NULL
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func TestVaultRepository_TagsRoundTripAndUpdateStamps(t *testing.T) {
	db := newVaultTagsTestDB(t)
	defer db.Close()
	repo := NewVaultRepository(db, &logging.Logger{})
	ctx := context.Background()

	creator := uuid.New()
	v := &model.Vault{
		ID: uuid.New(), Name: "tagged", Enabled: true, RetentionDays: 90,
		CreatedBy: creator, Tags: map[string]string{"env": "prod"},
	}
	if err := repo.Create(ctx, v); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.ReadByName(ctx, "tagged")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Tags["env"] != "prod" {
		t.Fatalf("tags not round-tripped: %v", got.Tags)
	}

	updater := uuid.New()
	got.Tags = map[string]string{"team": "billing"}
	got.UpdatedBy = &updater
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}

	after, err := repo.ReadByName(ctx, "tagged")
	if err != nil {
		t.Fatalf("read after update: %v", err)
	}
	if after.Tags["team"] != "billing" || after.Tags["env"] != "" {
		t.Fatalf("update did not replace tags: %v", after.Tags)
	}
	if after.UpdatedAt == nil {
		t.Fatal("updated_at was not stamped")
	}
	if after.UpdatedBy == nil || *after.UpdatedBy != updater {
		t.Fatalf("updated_by not persisted: %v", after.UpdatedBy)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestVaultRepository_TagsRoundTripAndUpdateStamps -v`
Expected: FAIL — `scanVault` scans the wrong number of columns / tags not stored.

- [ ] **Step 3: Update `vault_repository.go`**

Add `"encoding/json"` to the imports.

Change `vaultCols` (line 40) to:

```go
const vaultCols = "id, name, enabled, purge_protection, retention_days, created_by, created_at, deleted_at, scheduled_purge_at, tags, updated_at, updated_by"
```

Replace `scanVault` (lines 45-70) with:

```go
func scanVault(row scanRow) (*model.Vault, error) {
	var v model.Vault
	var idStr, createdByStr string
	var deletedAt, scheduledPurgeAt, updatedAt sql.NullTime
	var tagsJSON string
	var updatedByStr sql.NullString
	if err := row.Scan(&idStr, &v.Name, &v.Enabled, &v.PurgeProtection, &v.RetentionDays,
		&createdByStr, &v.CreatedAt, &deletedAt, &scheduledPurgeAt,
		&tagsJSON, &updatedAt, &updatedByStr); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid vault id: %w", err)
	}
	v.ID = id
	createdBy, err := uuid.Parse(createdByStr)
	if err != nil {
		return nil, fmt.Errorf("invalid created_by id: %w", err)
	}
	v.CreatedBy = createdBy
	if deletedAt.Valid {
		v.DeletedAt = &deletedAt.Time
	}
	if scheduledPurgeAt.Valid {
		v.ScheduledPurgeAt = &scheduledPurgeAt.Time
	}
	if tagsJSON != "" && tagsJSON != "{}" {
		if err := json.Unmarshal([]byte(tagsJSON), &v.Tags); err != nil {
			return nil, fmt.Errorf("invalid vault tags json: %w", err)
		}
	}
	if updatedAt.Valid {
		v.UpdatedAt = &updatedAt.Time
	}
	if updatedByStr.Valid && updatedByStr.String != "" {
		ub, err := uuid.Parse(updatedByStr.String)
		if err != nil {
			return nil, fmt.Errorf("invalid updated_by id: %w", err)
		}
		v.UpdatedBy = &ub
	}
	return &v, nil
}

// marshalTags serializes a tag map to a JSON object string, defaulting to "{}".
func marshalTags(tags map[string]string) (string, error) {
	if len(tags) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return "", fmt.Errorf("marshal vault tags: %w", err)
	}
	return string(b), nil
}
```

Replace `Create` (lines 72-83) with:

```go
func (r *VaultRepository) Create(ctx context.Context, v *model.Vault) error {
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	tagsJSON, err := marshalTags(v.Tags)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO vaults (id, name, enabled, purge_protection, retention_days, created_by, created_at, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		v.ID.String(), v.Name, v.Enabled, v.PurgeProtection, v.RetentionDays, v.CreatedBy.String(), v.CreatedAt, tagsJSON)
	if err != nil {
		return fmt.Errorf("failed to insert vault: %w", err)
	}
	return nil
}
```

Replace `Update` (lines 130-138) with:

```go
func (r *VaultRepository) Update(ctx context.Context, v *model.Vault) error {
	tagsJSON, err := marshalTags(v.Tags)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	v.UpdatedAt = &now
	var updatedBy any
	if v.UpdatedBy != nil && *v.UpdatedBy != uuid.Nil {
		updatedBy = v.UpdatedBy.String()
	}
	_, err = r.db.ExecContext(ctx,
		"UPDATE vaults SET enabled = ?, purge_protection = ?, retention_days = ?, tags = ?, updated_at = ?, updated_by = ? WHERE id = ?",
		v.Enabled, v.PurgeProtection, v.RetentionDays, tagsJSON, now, updatedBy, v.ID.String())
	if err != nil {
		return fmt.Errorf("failed to update vault: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repositories/ -run TestVaultRepository_TagsRoundTripAndUpdateStamps -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/vault_repository.go internal/repositories/vault_repository_tags_test.go
git commit -S -m "feat(repo): persist vault tags as JSON and stamp updated_at/by"
```

---

## Task 4: Service — tag validation and `updatedBy` parameter

**Files:**
- Modify: `internal/services/vaults/vault_service.go`
- Test: `internal/services/vaults/vault_service_test.go` (existing — update call sites)

- [ ] **Step 1: Update the existing test call sites and add a tags test**

In `internal/services/vaults/vault_service_test.go`, update both existing `UpdateVault`
calls (lines ~250 and ~271) to pass a `uuid.UUID` as the final argument:

```go
	updated, err := svc.UpdateVault(context.Background(), "upd", model.UpdateVaultRequest{
		// ... existing fields ...
	}, uuid.New())
```
```go
	_, err := svc.UpdateVault(context.Background(), "missing", model.UpdateVaultRequest{Enabled: boolPtr(true)}, uuid.New())
```

Add a new test (ensure `"github.com/google/uuid"` is imported):

```go
func TestUpdateVault_ReplacesTagsAndSetsUpdatedBy(t *testing.T) {
	svc, _ := newServiceWithVault(t, "tagged") // see existing test helpers
	updater := uuid.New()
	tags := map[string]string{"env": "prod"}
	got, err := svc.UpdateVault(context.Background(), "tagged",
		model.UpdateVaultRequest{Tags: &tags}, updater)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Tags["env"] != "prod" {
		t.Fatalf("tags not applied: %v", got.Tags)
	}
	if got.UpdatedBy == nil || *got.UpdatedBy != updater {
		t.Fatalf("updated_by not set: %v", got.UpdatedBy)
	}
}
```

> Note: if no `newServiceWithVault` helper exists, construct the service the same way the
> existing tests in this file do (they already create a vault before updating it) and
> reuse that setup.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestUpdateVault -v`
Expected: FAIL — too many arguments to `UpdateVault` / `Tags` field unused.

- [ ] **Step 3: Update the service**

In `internal/services/vaults/vault_service.go`:

Change the interface method (line 34) to:

```go
	UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error)
```

In `CreateVault`, after the `ValidateVaultName` check (after line 55), add:

```go
	if err := model.ValidateVaultTags(req.Tags); err != nil {
		return nil, err
	}
```

In the `v := &model.Vault{...}` literal, add `Tags: req.Tags,` (after `CreatedAt`).

Replace the `UpdateVault` signature and body (lines 115-135) with:

```go
// UpdateVault applies the non-nil request overrides to an active vault and persists it.
func (s *vaultService) UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error) {
	v, err := s.getByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		v.Enabled = *req.Enabled
	}
	if req.PurgeProtection != nil {
		v.PurgeProtection = *req.PurgeProtection
	}
	if req.RetentionDays != nil {
		v.RetentionDays = *req.RetentionDays
	}
	if req.Tags != nil {
		if err := model.ValidateVaultTags(*req.Tags); err != nil {
			return nil, err
		}
		v.Tags = *req.Tags
	}
	if updatedBy != uuid.Nil {
		v.UpdatedBy = &updatedBy
	}
	if err := s.repo.Update(ctx, v); err != nil {
		return nil, fmt.Errorf("update vault: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo(updatedBy.String(), "update_vault", "success", fmt.Sprintf("Vault updated: %s", v.Name))
	}
	return v, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/vaults/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/vaults/vault_service.go internal/services/vaults/vault_service_test.go
git commit -S -m "feat(service): validate vault tags; thread updatedBy through UpdateVault"
```

---

## Task 5: Update mock and stub signatures

**Files:**
- Modify: `cmd/testutils/test_utils.go:548`
- Modify: `internal/middleware/middleware_test.go:93`

- [ ] **Step 1: Update the mock in `cmd/testutils/test_utils.go`**

Change `MockVaultService.UpdateVault` (line 548) to:

```go
func (m *MockVaultService) UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error) {
	args := m.Called(ctx, name, req, updatedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
}
```

> If the existing mock body differs, preserve its return logic and only add the
> `updatedBy uuid.UUID` parameter and pass it into `m.Called(...)`. Ensure
> `"github.com/google/uuid"` is imported.

- [ ] **Step 2: Update the stub in `internal/middleware/middleware_test.go`**

Change `stubVaultService.UpdateVault` (line 93) to:

```go
func (s *stubVaultService) UpdateVault(context.Context, string, model.UpdateVaultRequest, uuid.UUID) (*model.Vault, error) {
	return nil, nil
}
```

> Ensure `"github.com/google/uuid"` is imported in that test file.

- [ ] **Step 3: Verify both packages build**

Run: `go vet ./cmd/testutils/... ./internal/middleware/...`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add cmd/testutils/test_utils.go internal/middleware/middleware_test.go
git commit -S -m "test: update VaultService mock/stub for new UpdateVault signature"
```

---

## Task 6: API handler — read caller UUID, pass tags

**Files:**
- Modify: `api/vault.go:132-158`
- Test: `api/vault_tags_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `api/vault_tags_test.go`. Follow the existing vault API test setup in
`api/vault_scoped_routes_test.go` / other `api/*_test.go` for building an authed request.
The test creates a vault, PATCHes tags, and asserts the response carries them:

```go
package api

import (
	"net/http"
	"testing"
)

// TestUpdateVault_WithTags verifies PATCH /vaults/{name} accepts and returns a tags map.
// Uses the same authed-request harness as the other vault API tests in this package.
func TestUpdateVault_WithTags(t *testing.T) {
	env := newVaultAPITestEnv(t)        // existing helper used by vault API tests
	env.createVault(t, "tagged")

	resp := env.patchVault(t, "tagged", `{"tags":{"env":"prod"}}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("patch status = %d, want 200; body=%s", resp.Code, resp.Body.String())
	}
	if got := resp.Body.String(); !contains(got, `"env":"prod"`) {
		t.Fatalf("response missing tags: %s", got)
	}
}
```

> If `newVaultAPITestEnv`/`createVault`/`patchVault`/`contains` helpers do not exist with
> these names, replicate the request-construction pattern from the existing vault API
> tests in this package (they already issue authed requests against the vault routes) and
> assert on `httptest.ResponseRecorder.Code` and `.Body`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/ -run TestUpdateVault_WithTags -v`
Expected: FAIL — tags not echoed (handler not passing them through / signature mismatch).

- [ ] **Step 3: Update `updateVault` in `api/vault.go`**

Replace the `updateVault` body (lines 132-158) with:

```go
// updateVault handles the request to update a vault by name.
func updateVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	req, err := model.UpdateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Identify the acting user from JWT claims for modification tracking.
	var updatedBy uuid.UUID
	if userIDStr, ok := c.Claims["user_id"].(string); ok {
		if parsed, perr := uuid.Parse(userIDStr); perr == nil {
			updatedBy = parsed
		}
	}

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.UpdateVault(r.Context(), name, *req, updatedBy)
	if err != nil {
		if errors.Is(err, vaults.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInvalidParam(err.Error())
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))

	c.Logger.Printf("Vault %s updated", name)
}
```

Ensure `api/vault.go` imports `"errors"`, `"github.com/google/uuid"`, and the vaults
service package (`vaults "rocketvault/internal/services/vaults"`); add any that are missing.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/ -run TestUpdateVault_WithTags -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/vault.go api/vault_tags_test.go
git commit -S -m "feat(api): accept vault tags and record updated_by on update"
```

---

## Task 7: CLI — pass `uuid.Nil` (no authenticated user in CLI context)

**Files:**
- Modify: `cmd/vaults/update.go:47`

- [ ] **Step 1: Update the CLI call**

In `cmd/vaults/update.go`, add `"github.com/google/uuid"` to the imports, and change
line 47 to:

```go
		vault, err := vaultService.UpdateVault(ctx, name, req, uuid.Nil)
```

> The CLI update command has no authenticated user UUID in its context (it talks to the
> service container directly). Passing `uuid.Nil` makes the repository write `updated_by`
> as NULL, while `updated_at` is still stamped.

- [ ] **Step 2: Verify the cmd package builds**

Run: `go build ./cmd/...`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/vaults/update.go
git commit -S -m "feat(cli): pass nil updatedBy for vault update (no CLI user context)"
```

---

## Task 8: Full verification gate and live smoke test

**Files:** none (verification only).

- [ ] **Step 1: Build and vet the whole module**

Run: `go build ./... && go vet ./...`
Expected: exit 0, no output.

- [ ] **Step 2: Run all affected package tests**

Run: `go test ./model/... ./internal/db/... ./internal/repositories/... ./internal/services/vaults/... ./api/... ./cmd/vaults/... ./internal/middleware/...`
Expected: all `ok`.

- [ ] **Step 3: Live smoke test (server already runs on :8774; re-login if token expired)**

```bash
B=http://localhost:8774
CODE=$(oathtool --totp --base32 "$(cat /tmp/admin_totp.txt)")
TOKEN=$(curl -s -X POST $B/api/v1/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$CODE\"}" | jq -r .token)
A="Authorization: Bearer $TOKEN"

# Create with tags
curl -s -X POST $B/api/v1/vaults -H "$A" -H "Content-Type: application/json" \
  -d '{"name":"tag-smoke","enabled":true,"tags":{"env":"prod"}}' | jq '{name,tags}'

# PATCH replaces tags; updated_at/updated_by appear
curl -s -X PATCH $B/api/v1/vaults/tag-smoke -H "$A" -H "Content-Type: application/json" \
  -d '{"tags":{"team":"billing"}}' | jq '{name,tags,updated_at,updated_by}'

# PATCH without tags leaves them unchanged
curl -s -X PATCH $B/api/v1/vaults/tag-smoke -H "$A" -H "Content-Type: application/json" \
  -d '{"purge_protection":true}' | jq '{tags,purge_protection}'

# Over-limit tags -> 400
curl -s -o /dev/null -w "over-limit -> %{http_code} (want 400)\n" \
  -X PATCH $B/api/v1/vaults/tag-smoke -H "$A" -H "Content-Type: application/json" \
  -d '{"tags":{"a":"","":"x"}}'
```

Expected: create echoes `{"env":"prod"}`; PATCH shows `{"team":"billing"}` plus a non-empty `updated_at` and `updated_by`; tags-less PATCH keeps `{"team":"billing"}`; over-limit returns 400.

- [ ] **Step 4: Final commit (if any cleanup needed)**

```bash
git add -A
git commit -S -m "test: verify vault tags + modification tracking end-to-end" || echo "nothing to commit"
```
```

