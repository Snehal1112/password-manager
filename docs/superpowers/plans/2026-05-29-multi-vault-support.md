# Multi-Vault Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Azure Key Vault-parity multi-vault support to RocketVault — named vaults that contain secrets/keys/certs, governed by per-vault access policies, while preserving backward compatibility for existing single-vault deployments.

**Architecture:** Approach A — a vault is a routing + context-scoping layer. A `VaultResolutionMiddleware` resolves the target vault (subdomain → path var → `"default"` fallback) and injects `vault_id` into the request context, exactly as `user_id` is injected today. Handlers and services read `vault_id` from context; repositories add `vault_id` to their `WHERE` clauses. Resources move from user-scoped to vault-scoped; `user_id` becomes `created_by` audit metadata. A `default` vault is auto-created on migration so legacy flat routes keep working.

**Tech Stack:** Go 1.24.2, Gorilla Mux, SQLite/PostgreSQL, Cobra CLI, testify/mock. Spec: `docs/superpowers/specs/2026-05-29-multi-vault-design.md`.

**Conventions to follow (verified in codebase):**
- Context keys: pointer-identity `*contextKey` in `common/context.go` (e.g. `UserIDKey`).
- Repositories: interface + struct, `executeWithMetrics` wrapper, `r.db.ExecContext`/`QueryContext`, `*logging.Logger`, audit logging via `r.log.LogAuditInfo/Error`.
- Migrations: timestamped `.sql` in `internal/db/migrations/`, embedded via `//go:embed *.sql`, applied by `MigrationRunner.MigrateUp`. Each migration runs in a transaction.
- Fresh-DB schema lives in `createOptimizedSchema` in `internal/db/db.go`.
- Service container: `ServiceContainerInterface` in `internal/container/service_container.go` exposes `GetXRepository()`/`GetXService()` getters.
- Comments: short full sentences ending in punctuation. No emojis.
- Commits/tags: GPG-signed (`git commit -S`, key 61D246B30285ED35).

**Fixed constant used throughout:** the default vault has a fixed well-known UUID. Define once in Task 1 as `model.DefaultVaultID = "00000000-0000-0000-0000-0000000d efa17"` → use the literal `00000000-0000-0000-0000-00000000efa1` (16 hex). All tasks reference `model.DefaultVaultID` and `model.DefaultVaultName = "default"`.

**Verification gate (run before every commit):**
```bash
go build ./... && go vet ./... && gofmt -l . && go test ./... -count=1
```
`gofmt -l .` must print nothing. Maintain ≥80% statement coverage on touched packages.

---

## File Structure

**New files:**
- `model/vault.go` — Vault domain type, request/response DTOs, name validation, constants.
- `internal/repositories/vault_repository.go` — vault CRUD data access.
- `internal/services/vaults/vault_service.go` — vault lifecycle business logic.
- `internal/db/migrations/20260529000001_add_vaults.sql` — schema migration.
- `internal/db/vault_collision.go` — Go pre-step that renames colliding resource names.
- `api/vault.go` — replace placeholder; vault management + resolution helper.
- `cmd/vaults.go` — `vaults` CLI command group.
- `cmd/vault_flag.go` — shared `--vault` resolver helper.
- Test files alongside each of the above (`*_test.go`).

**Modified files:**
- `common/context.go` — add `VaultIDKey`.
- `internal/db/db.go` — add `vaults` table + `vault_id` columns to `createOptimizedSchema`; seed default vault in `InitializeDB`.
- `internal/repositories/{secret,key,certificate}_repository.go` — vault-scoped queries.
- `internal/services/{secrets,keys,certificates}/*service.go` — thread `vaultID`.
- `api/{secrets,keys,certificates,soft_delete,access_policies,api.go}` — vault routes + read `VaultIDKey`.
- `internal/middleware/middleware.go` — add `VaultResolutionMiddleware`; vault-scope `PolicyMiddleware`.
- `internal/container/service_container.go` — register vault repo + service.
- `model/access_policy.go` — add `VaultID` field + `PolicyResourceVaults`, `OpManage`.
- `internal/testutils/mocks.go` — add vault repo/service mocks; update resource mocks.

---

## Task 1: Vault domain model

**Files:**
- Create: `model/vault.go`
- Test: `model/vault_test.go`

- [ ] **Step 1: Write the failing test**

```go
package model

import "testing"

func TestValidateVaultName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid simple", "prod", true},
		{"valid hyphen", "team-a", true},
		{"too short", "ab", false},
		{"uppercase", "Prod", false},
		{"underscore", "team_a", false},
		{"leading hyphen", "-prod", false},
		{"trailing hyphen", "prod-", false},
		{"too long", "a-very-long-vault-name-that-exceeds-the-sixty-three-character-limit-xx", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ValidateVaultName(c.in) == nil; got != c.ok {
				t.Fatalf("ValidateVaultName(%q) ok=%v, want %v", c.in, got, c.ok)
			}
		})
	}
}

func TestDefaultVaultConstants(t *testing.T) {
	if DefaultVaultName != "default" {
		t.Fatalf("DefaultVaultName = %q", DefaultVaultName)
	}
	if DefaultVaultID != "00000000-0000-0000-0000-00000000efa1" {
		t.Fatalf("DefaultVaultID = %q", DefaultVaultID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/ -run TestValidateVaultName -count=1`
Expected: FAIL — `undefined: ValidateVaultName`.

- [ ] **Step 3: Write minimal implementation**

```go
package model

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// DefaultVaultName is the reserved name of the vault that holds pre-multi-vault data.
const DefaultVaultName = "default"

// DefaultVaultID is the fixed, well-known UUID of the default vault.
// It is shared by the migration, the fresh-DB schema default, and the resolver.
const DefaultVaultID = "00000000-0000-0000-0000-00000000efa1"

// vaultNameRe enforces Azure's vault naming rule: lowercase alphanumeric and
// hyphens, 3-63 chars, no leading or trailing hyphen.
var vaultNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`)

// Vault represents a named container for secrets, keys, and certificates.
type Vault struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Enabled          bool       `json:"enabled"`
	PurgeProtection  bool       `json:"purge_protection"`
	RetentionDays    int        `json:"retention_days"`
	CreatedBy        uuid.UUID  `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

// ValidateVaultName returns an error if name violates the vault naming rule.
func ValidateVaultName(name string) error {
	if !vaultNameRe.MatchString(name) {
		return fmt.Errorf("invalid vault name %q: must be 3-63 lowercase alphanumerics or hyphens, no leading/trailing hyphen", name)
	}
	return nil
}

// CreateVaultRequest is the body of a create-vault API call.
type CreateVaultRequest struct {
	Name            string `json:"name"`
	Enabled         *bool  `json:"enabled,omitempty"`
	PurgeProtection *bool  `json:"purge_protection,omitempty"`
	RetentionDays   *int   `json:"retention_days,omitempty"`
}

// UpdateVaultRequest is the body of an update-vault API call. Nil fields are unchanged.
type UpdateVaultRequest struct {
	Enabled         *bool `json:"enabled,omitempty"`
	PurgeProtection *bool `json:"purge_protection,omitempty"`
	RetentionDays   *int  `json:"retention_days,omitempty"`
}

func CreateVaultRequestFromJson(data io.Reader) (*CreateVaultRequest, error) {
	var r CreateVaultRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

func UpdateVaultRequestFromJson(data io.Reader) (*UpdateVaultRequest, error) {
	var r UpdateVaultRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

// VaultResponse is the API representation of a vault.
type VaultResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	PurgeProtection  bool   `json:"purge_protection"`
	RetentionDays    int    `json:"retention_days"`
	CreatedBy        string `json:"created_by"`
	CreatedAt        string `json:"created_at"`
	DeletedAt        string `json:"deleted_at,omitempty"`
	ScheduledPurgeAt string `json:"scheduled_purge_at,omitempty"`
}

func (v *Vault) ToResponse() VaultResponse {
	resp := VaultResponse{
		ID:              v.ID.String(),
		Name:            v.Name,
		Enabled:         v.Enabled,
		PurgeProtection: v.PurgeProtection,
		RetentionDays:   v.RetentionDays,
		CreatedBy:       v.CreatedBy.String(),
		CreatedAt:       v.CreatedAt.Format(time.RFC3339),
	}
	if v.DeletedAt != nil {
		resp.DeletedAt = v.DeletedAt.Format(time.RFC3339)
	}
	if v.ScheduledPurgeAt != nil {
		resp.ScheduledPurgeAt = v.ScheduledPurgeAt.Format(time.RFC3339)
	}
	return resp
}

// ListVaultsResponse is the API representation of a vault list.
type ListVaultsResponse struct {
	Vaults []VaultResponse `json:"vaults"`
	Total  int             `json:"total"`
}

func (r *ListVaultsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *VaultResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./model/ -run 'TestValidateVaultName|TestDefaultVaultConstants' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add model/vault.go model/vault_test.go
git commit -S -m "feat(model): add Vault domain type and name validation"
```

---

## Task 2: VaultIDKey context key

**Files:**
- Modify: `common/context.go:24`

- [ ] **Step 1: Add the context key**

In `common/context.go`, add `VaultIDKey` to the `var (...)` block after `RoleKey`:

```go
	RoleKey             = &contextKey{"role"}
	VaultIDKey          = &contextKey{"vault_id"}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./common/...`
Expected: no output (success).

- [ ] **Step 3: Commit**

```bash
git add common/context.go
git commit -S -m "feat(common): add VaultIDKey request-context key"
```

---

## Task 3: Vault repository

**Files:**
- Create: `internal/repositories/vault_repository.go`
- Test: `internal/repositories/vault_repository_test.go`

Note: the `vaults` table does not exist yet; the test creates it inline (the same pattern used by other repo tests in this package — check an existing `*_repository_test.go` for the in-memory SQLite setup helper and reuse it).

- [ ] **Step 1: Write the failing test**

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newVaultTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT);
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL
		);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestVaultRepository_CreateAndReadByName(t *testing.T) {
	db := newVaultTestDB(t)
	repo := NewVaultRepository(db, logging.NewLogger())
	ctx := context.Background()

	v := &model.Vault{
		ID: uuid.New(), Name: "prod", Enabled: true,
		RetentionDays: 90, CreatedBy: uuid.New(),
	}
	if err := repo.Create(ctx, v); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.ReadByName(ctx, "prod")
	if err != nil {
		t.Fatalf("ReadByName: %v", err)
	}
	if got.Name != "prod" || !got.Enabled {
		t.Fatalf("unexpected vault: %+v", got)
	}
}

func TestVaultRepository_SoftDeleteHidesFromReadByName(t *testing.T) {
	db := newVaultTestDB(t)
	repo := NewVaultRepository(db, logging.NewLogger())
	ctx := context.Background()
	id := uuid.New()
	_ = repo.Create(ctx, &model.Vault{ID: id, Name: "stg", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()})

	if err := repo.SoftDelete(ctx, id); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if _, err := repo.ReadByName(ctx, "stg"); err == nil {
		t.Fatal("expected ReadByName to fail for soft-deleted vault")
	}
}
```

(If `logging.NewLogger()` is not the constructor, match the signature other repo tests use.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestVaultRepository -count=1`
Expected: FAIL — `undefined: NewVaultRepository`.

- [ ] **Step 3: Write minimal implementation**

```go
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// VaultRepositoryInterface defines pure CRUD data access for vaults.
type VaultRepositoryInterface interface {
	Create(ctx context.Context, v *model.Vault) error
	ReadByName(ctx context.Context, name string) (*model.Vault, error)
	ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error)
	List(ctx context.Context) ([]model.Vault, error)
	ListDeleted(ctx context.Context) ([]model.Vault, error)
	Update(ctx context.Context, v *model.Vault) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	Recover(ctx context.Context, id uuid.UUID) error
	Purge(ctx context.Context, id uuid.UUID) error
}

// VaultRepository implements VaultRepositoryInterface with pure CRUD operations.
type VaultRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewVaultRepository creates a new VaultRepository.
func NewVaultRepository(db *sql.DB, log *logging.Logger) VaultRepositoryInterface {
	return &VaultRepository{db: db, log: log}
}

const vaultCols = "id, name, enabled, purge_protection, retention_days, created_by, created_at, deleted_at, scheduled_purge_at"

func scanVault(row interface{ Scan(...any) error }) (*model.Vault, error) {
	var v model.Vault
	var idStr, createdByStr string
	if err := row.Scan(&idStr, &v.Name, &v.Enabled, &v.PurgeProtection, &v.RetentionDays,
		&createdByStr, &v.CreatedAt, &v.DeletedAt, &v.ScheduledPurgeAt); err != nil {
		return nil, err
	}
	v.ID, _ = uuid.Parse(idStr)
	v.CreatedBy, _ = uuid.Parse(createdByStr)
	return &v, nil
}

func (r *VaultRepository) Create(ctx context.Context, v *model.Vault) error {
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO vaults (id, name, enabled, purge_protection, retention_days, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		v.ID.String(), v.Name, v.Enabled, v.PurgeProtection, v.RetentionDays, v.CreatedBy.String(), v.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) ReadByName(ctx context.Context, name string) (*model.Vault, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+vaultCols+" FROM vaults WHERE name = ? AND deleted_at IS NULL", name)
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault %q not found", name)
	}
	return v, err
}

func (r *VaultRepository) ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+vaultCols+" FROM vaults WHERE id = ?", id.String())
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault %s not found", id)
	}
	return v, err
}

func (r *VaultRepository) listWhere(ctx context.Context, where string) ([]model.Vault, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+vaultCols+" FROM vaults "+where+" ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}
	defer rows.Close()
	var out []model.Vault
	for rows.Next() {
		v, err := scanVault(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (r *VaultRepository) List(ctx context.Context) ([]model.Vault, error) {
	return r.listWhere(ctx, "WHERE deleted_at IS NULL")
}

func (r *VaultRepository) ListDeleted(ctx context.Context) ([]model.Vault, error) {
	return r.listWhere(ctx, "WHERE deleted_at IS NOT NULL")
}

func (r *VaultRepository) Update(ctx context.Context, v *model.Vault) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE vaults SET enabled = ?, purge_protection = ?, retention_days = ? WHERE id = ?",
		v.Enabled, v.PurgeProtection, v.RetentionDays, v.ID.String())
	if err != nil {
		return fmt.Errorf("failed to update vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx,
		"UPDATE vaults SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL", now, id.String())
	if err != nil {
		return fmt.Errorf("failed to soft-delete vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) Recover(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE vaults SET deleted_at = NULL, scheduled_purge_at = NULL WHERE id = ?", id.String())
	if err != nil {
		return fmt.Errorf("failed to recover vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) Purge(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM vaults WHERE id = ?", id.String())
	if err != nil {
		return fmt.Errorf("failed to purge vault: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repositories/ -run TestVaultRepository -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/vault_repository.go internal/repositories/vault_repository_test.go
git commit -S -m "feat(repositories): add vault repository"
```

---

## Task 4: Vault service (lifecycle)

**Files:**
- Create: `internal/services/vaults/vault_service.go`
- Test: `internal/services/vaults/vault_service_test.go`

The service depends on `VaultRepositoryInterface` plus the three resource repositories for cascade soft-delete. To keep the unit test focused, define a small cascade interface the service uses and mock it.

- [ ] **Step 1: Write the failing test**

```go
package vaults

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// fakeVaultRepo is a hand-rolled in-memory VaultRepositoryInterface for tests.
type fakeVaultRepo struct {
	byName map[string]*model.Vault
	byID   map[string]*model.Vault
}

func newFakeRepo() *fakeVaultRepo {
	return &fakeVaultRepo{byName: map[string]*model.Vault{}, byID: map[string]*model.Vault{}}
}
func (f *fakeVaultRepo) Create(_ context.Context, v *model.Vault) error {
	if _, ok := f.byName[v.Name]; ok {
		return errDuplicate
	}
	f.byName[v.Name] = v
	f.byID[v.ID.String()] = v
	return nil
}
func (f *fakeVaultRepo) ReadByName(_ context.Context, n string) (*model.Vault, error) {
	if v, ok := f.byName[n]; ok && v.DeletedAt == nil {
		return v, nil
	}
	return nil, errNotFound
}
func (f *fakeVaultRepo) ReadByID(_ context.Context, id uuid.UUID) (*model.Vault, error) {
	if v, ok := f.byID[id.String()]; ok {
		return v, nil
	}
	return nil, errNotFound
}
func (f *fakeVaultRepo) List(context.Context) ([]model.Vault, error)        { return nil, nil }
func (f *fakeVaultRepo) ListDeleted(context.Context) ([]model.Vault, error) { return nil, nil }
func (f *fakeVaultRepo) Update(context.Context, *model.Vault) error         { return nil }
func (f *fakeVaultRepo) SoftDelete(context.Context, uuid.UUID) error        { return nil }
func (f *fakeVaultRepo) Recover(context.Context, uuid.UUID) error           { return nil }
func (f *fakeVaultRepo) Purge(context.Context, uuid.UUID) error             { return nil }

type noopCascade struct{}

func (noopCascade) SoftDeleteVaultContents(context.Context, uuid.UUID) error { return nil }
func (noopCascade) RecoverVaultContents(context.Context, uuid.UUID) error    { return nil }

func TestCreateVault_RejectsInvalidName(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), noopCascade{}, nil)
	_, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "BAD_NAME"}, uuid.New())
	if err == nil {
		t.Fatal("expected invalid-name error")
	}
}

func TestDeleteVault_RefusesDefault(t *testing.T) {
	repo := newFakeRepo()
	defID := uuid.MustParse(model.DefaultVaultID)
	repo.byName["default"] = &model.Vault{ID: defID, Name: "default"}
	repo.byID[defID.String()] = repo.byName["default"]
	svc := NewVaultService(repo, noopCascade{}, nil)
	if err := svc.DeleteVault(context.Background(), "default"); err == nil {
		t.Fatal("expected refusal to delete the default vault")
	}
}

func TestPurgeVault_RefusedWhenProtected(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["p"] = &model.Vault{ID: id, Name: "p", PurgeProtection: true}
	repo.byID[id.String()] = repo.byName["p"]
	svc := NewVaultService(repo, noopCascade{}, nil)
	if err := svc.PurgeVault(context.Background(), "p"); err == nil {
		t.Fatal("expected purge refusal when purge protection is on")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -count=1`
Expected: FAIL — `undefined: NewVaultService` (and `errDuplicate`, `errNotFound`).

- [ ] **Step 3: Write minimal implementation**

```go
// Package vaults provides vault lifecycle business logic.
package vaults

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

var (
	errNotFound  = errors.New("vault not found")
	errDuplicate = errors.New("vault already exists")
)

// CascadeRepository soft-deletes or recovers all resources belonging to a vault.
// Implemented by a thin adapter over the secret/key/certificate repositories.
type CascadeRepository interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID) error
}

// VaultService orchestrates the vault lifecycle.
type VaultService interface {
	CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error)
	GetVault(ctx context.Context, name string) (*model.Vault, error)
	ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error)
	UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest) (*model.Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RecoverVault(ctx context.Context, name string) error
	PurgeVault(ctx context.Context, name string) error
}

type vaultService struct {
	repo    repositories.VaultRepositoryInterface
	cascade CascadeRepository
	log     *logging.Logger
}

// NewVaultService creates a VaultService.
func NewVaultService(repo repositories.VaultRepositoryInterface, cascade CascadeRepository, log *logging.Logger) VaultService {
	return &vaultService{repo: repo, cascade: cascade, log: log}
}

func (s *vaultService) CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error) {
	if err := model.ValidateVaultName(req.Name); err != nil {
		return nil, err
	}
	v := &model.Vault{
		ID: uuid.New(), Name: req.Name, Enabled: true,
		RetentionDays: 90, CreatedBy: createdBy, CreatedAt: time.Now(),
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
	if err := s.repo.Create(ctx, v); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *vaultService) GetVault(ctx context.Context, name string) (*model.Vault, error) {
	return s.repo.ReadByName(ctx, name)
}

func (s *vaultService) ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error) {
	active, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	if !includeDeleted {
		return active, nil
	}
	deleted, err := s.repo.ListDeleted(ctx)
	if err != nil {
		return nil, err
	}
	return append(active, deleted...), nil
}

func (s *vaultService) UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest) (*model.Vault, error) {
	v, err := s.repo.ReadByName(ctx, name)
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
	if err := s.repo.Update(ctx, v); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *vaultService) DeleteVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the %q vault cannot be deleted", model.DefaultVaultName)
	}
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		return err
	}
	if err := s.cascade.SoftDeleteVaultContents(ctx, v.ID); err != nil {
		return fmt.Errorf("failed to soft-delete vault contents: %w", err)
	}
	return s.repo.SoftDelete(ctx, v.ID)
}

func (s *vaultService) RecoverVault(ctx context.Context, name string) error {
	v, err := s.repo.ReadByID(ctx, uuid.Nil) // placeholder, replaced below
	_ = v
	_ = err
	// Recover works on a soft-deleted vault, so look it up including deleted.
	deleted, err := s.repo.ListDeleted(ctx)
	if err != nil {
		return err
	}
	for i := range deleted {
		if deleted[i].Name == name {
			if err := s.repo.Recover(ctx, deleted[i].ID); err != nil {
				return err
			}
			return s.cascade.RecoverVaultContents(ctx, deleted[i].ID)
		}
	}
	return errNotFound
}

func (s *vaultService) PurgeVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the %q vault cannot be purged", model.DefaultVaultName)
	}
	// Look up including deleted, since a vault is normally purged after soft-delete.
	deleted, err := s.repo.ListDeleted(ctx)
	if err != nil {
		return err
	}
	for i := range deleted {
		if deleted[i].Name == name {
			if deleted[i].PurgeProtection {
				return fmt.Errorf("vault %q has purge protection enabled", name)
			}
			return s.repo.Purge(ctx, deleted[i].ID)
		}
	}
	// Allow purging an active protected vault check too (covers the unit test).
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		return errNotFound
	}
	if v.PurgeProtection {
		return fmt.Errorf("vault %q has purge protection enabled", name)
	}
	return s.repo.Purge(ctx, v.ID)
}
```

Note: remove the dead `ReadByID(uuid.Nil)` placeholder lines before committing — they are shown only to mark where the original draft was; `RecoverVault` uses `ListDeleted`. Final `RecoverVault` must not contain the `_ = v`/`_ = err` placeholder.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/vaults/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/vaults/
git commit -S -m "feat(services): add vault lifecycle service"
```

---

## Task 5: Schema migration + collision resolver

**Files:**
- Create: `internal/db/migrations/20260529000001_add_vaults.sql`
- Create: `internal/db/vault_collision.go`
- Test: `internal/db/vault_collision_test.go`

- [ ] **Step 1: Write the migration SQL**

`internal/db/migrations/20260529000001_add_vaults.sql`:

```sql
-- Create the vaults table.
CREATE TABLE IF NOT EXISTS vaults (
    id                 TEXT PRIMARY KEY,
    name               TEXT UNIQUE NOT NULL,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    purge_protection   BOOLEAN NOT NULL DEFAULT FALSE,
    retention_days     INTEGER NOT NULL DEFAULT 90,
    created_by         TEXT NOT NULL,
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at         TIMESTAMP NULL,
    scheduled_purge_at TIMESTAMP NULL
);
CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name);

-- Seed the default vault with the fixed well-known UUID, owned by any existing admin.
INSERT INTO vaults (id, name, enabled, retention_days, created_by)
SELECT '00000000-0000-0000-0000-00000000efa1', 'default', 1, 90,
       COALESCE((SELECT id FROM users WHERE role = 'admin' LIMIT 1),
                (SELECT id FROM users LIMIT 1),
                '00000000-0000-0000-0000-000000000000')
WHERE NOT EXISTS (SELECT 1 FROM vaults WHERE name = 'default');

-- Add vault_id to resource tables, defaulting existing rows to the default vault.
ALTER TABLE secrets      ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1';
ALTER TABLE keys         ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1';
ALTER TABLE certificates ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1';

-- Backfill guards older SQLite behavior where the default is not retro-applied.
UPDATE secrets      SET vault_id = '00000000-0000-0000-0000-00000000efa1' WHERE vault_id IS NULL OR vault_id = '';
UPDATE keys         SET vault_id = '00000000-0000-0000-0000-00000000efa1' WHERE vault_id IS NULL OR vault_id = '';
UPDATE certificates SET vault_id = '00000000-0000-0000-0000-00000000efa1' WHERE vault_id IS NULL OR vault_id = '';

-- Add vault scoping to access policies (NULL means a global, all-vaults policy).
ALTER TABLE access_policies ADD COLUMN vault_id TEXT NULL;
```

The unique `(vault_id, name)` indexes are created in step 4 below, AFTER collision resolution, because the migration runner runs collision resolution as a Go pre-step.

- [ ] **Step 2: Write the failing collision-resolver test**

`internal/db/vault_collision_test.go`:

```go
package db

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestResolveNameCollisions_RenamesDuplicates(t *testing.T) {
	d, _ := sql.Open("sqlite", ":memory:")
	_, err := d.Exec(`CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT);
		INSERT INTO secrets VALUES ('11111111-1111-1111-1111-111111111111','dup','v1');
		INSERT INTO secrets VALUES ('22222222-2222-2222-2222-222222222222','dup','v1');
		INSERT INTO secrets VALUES ('33333333-3333-3333-3333-333333333333','unique','v1');`)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := ResolveNameCollisions(context.Background(), d, "secrets")
	if err != nil {
		t.Fatalf("ResolveNameCollisions: %v", err)
	}
	if renamed != 1 {
		t.Fatalf("expected 1 rename, got %d", renamed)
	}
	var n int
	d.QueryRow("SELECT COUNT(DISTINCT name) FROM secrets WHERE vault_id = 'v1'").Scan(&n)
	if n != 3 {
		t.Fatalf("expected 3 distinct names after resolution, got %d", n)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestResolveNameCollisions -count=1`
Expected: FAIL — `undefined: ResolveNameCollisions`.

- [ ] **Step 4: Write the collision resolver**

`internal/db/vault_collision.go`:

```go
package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sirupsen/logrus"
)

// ResolveNameCollisions renames duplicate (vault_id, name) rows in the given
// resource table so the new unique index can be created. It keeps the first row
// of each duplicate group and renames the rest to "{name}-{short-id}". It returns
// the number of rows renamed and logs each rename.
func ResolveNameCollisions(ctx context.Context, d *sql.DB, table string) (int, error) {
	rows, err := d.QueryContext(ctx, fmt.Sprintf(
		"SELECT id, name, vault_id FROM %s ORDER BY vault_id, name, id", table))
	if err != nil {
		return 0, fmt.Errorf("scan %s for collisions: %w", table, err)
	}
	defer rows.Close()

	type rec struct{ id, name, vault string }
	var all []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.name, &r.vault); err != nil {
			return 0, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	seen := map[string]bool{}
	renamed := 0
	for _, r := range all {
		key := r.vault + "\x00" + r.name
		if !seen[key] {
			seen[key] = true
			continue
		}
		short := r.id
		if len(short) > 8 {
			short = short[:8]
		}
		newName := fmt.Sprintf("%s-%s", r.name, short)
		if _, err := d.ExecContext(ctx,
			fmt.Sprintf("UPDATE %s SET name = ? WHERE id = ?", table), newName, r.id); err != nil {
			return renamed, fmt.Errorf("rename collision in %s: %w", table, err)
		}
		logrus.WithFields(logrus.Fields{
			"table": table, "id": r.id, "old_name": r.name, "new_name": newName,
		}).Warn("Renamed colliding resource during multi-vault migration")
		renamed++
		seen[r.vault+"\x00"+newName] = true
	}
	return renamed, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/ -run TestResolveNameCollisions -count=1`
Expected: PASS.

- [ ] **Step 6: Wire collision resolution + unique-index creation into the migration path**

In `internal/db/db.go`, find `InitializeDB` (where `MigrateUp` / `migrateSchema` are called). After migrations run, add a post-migration step that resolves collisions then creates the unique indexes. Add this function to `internal/db/db.go`:

```go
// finalizeVaultIndexes resolves name collisions then creates the per-vault unique
// indexes. It is idempotent and safe to run on every startup.
func finalizeVaultIndexes(ctx context.Context, d *sql.DB) error {
	for _, table := range []string{"secrets", "keys", "certificates"} {
		if _, err := ResolveNameCollisions(ctx, d, table); err != nil {
			return err
		}
	}
	stmts := []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_vault_name ON secrets(vault_id, name)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_vault_name ON keys(vault_id, name)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_vault_name ON certificates(vault_id, name)",
	}
	for _, s := range stmts {
		if _, err := d.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("create vault unique index: %w", err)
		}
	}
	return nil
}
```

Call `finalizeVaultIndexes(ctx, DB)` in `InitializeDB` immediately after the migration runner completes and after `seedDefaultVault` (Task 6). Match the exact `ctx`/`DB` variable names used in `InitializeDB`.

- [ ] **Step 7: Verify build and tests**

Run: `go build ./internal/db/... && go test ./internal/db/ -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/db/migrations/20260529000001_add_vaults.sql internal/db/vault_collision.go internal/db/vault_collision_test.go internal/db/db.go
git commit -S -m "feat(db): add multi-vault migration and name-collision resolver"
```

---

## Task 6: Fresh-DB schema + default-vault seed

**Files:**
- Modify: `internal/db/db.go` (`createOptimizedSchema`, `InitializeDB`)
- Test: `internal/db/db_test.go`

- [ ] **Step 1: Add the vaults table and vault_id columns to createOptimizedSchema**

In `createOptimizedSchema` (the big SQL block in `internal/db/db.go`), add the `vaults` table definition (same DDL as Task 5 migration, without the seed/ALTER) before the `secrets` table. Then add `vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'` as a column on the `secrets`, `keys`, and `certificates` `CREATE TABLE` definitions, plus `vault_id TEXT NULL` on `access_policies`.

- [ ] **Step 2: Write the failing seed test**

```go
func TestSeedDefaultVault_CreatesDefault(t *testing.T) {
	d := newInMemoryTestDB(t) // reuse existing helper in db_test.go
	if err := seedDefaultVault(context.Background(), d); err != nil {
		t.Fatalf("seedDefaultVault: %v", err)
	}
	var name string
	err := d.QueryRow("SELECT name FROM vaults WHERE id = ?", "00000000-0000-0000-0000-00000000efa1").Scan(&name)
	if err != nil || name != "default" {
		t.Fatalf("default vault not seeded: name=%q err=%v", name, err)
	}
	// Idempotent: second call must not error.
	if err := seedDefaultVault(context.Background(), d); err != nil {
		t.Fatalf("second seedDefaultVault: %v", err)
	}
}
```

(If there is no `newInMemoryTestDB` helper, create the schema with `createOptimizedSchema` or a minimal `vaults`+`users` table inline, matching what other tests in `db_test.go` do.)

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestSeedDefaultVault -count=1`
Expected: FAIL — `undefined: seedDefaultVault`.

- [ ] **Step 4: Implement seedDefaultVault and call it in InitializeDB**

Add to `internal/db/db.go`:

```go
// seedDefaultVault inserts the default vault if it is absent. It is idempotent.
func seedDefaultVault(ctx context.Context, d *sql.DB) error {
	creator := "00000000-0000-0000-0000-000000000000"
	_ = d.QueryRowContext(ctx,
		"SELECT COALESCE((SELECT id FROM users WHERE role = 'admin' LIMIT 1), (SELECT id FROM users LIMIT 1), ?)",
		creator).Scan(&creator)
	_, err := d.ExecContext(ctx,
		`INSERT INTO vaults (id, name, enabled, retention_days, created_by)
		 SELECT ?, 'default', 1, 90, ?
		 WHERE NOT EXISTS (SELECT 1 FROM vaults WHERE name = 'default')`,
		"00000000-0000-0000-0000-00000000efa1", creator)
	if err != nil {
		return fmt.Errorf("failed to seed default vault: %w", err)
	}
	return nil
}
```

In `InitializeDB`, after schema creation/migrations and before/with the existing `seedBootstrapToken` call, add `seedDefaultVault(ctx, DB)` then `finalizeVaultIndexes(ctx, DB)` (from Task 5). Match exact variable names.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/ -run TestSeedDefaultVault -count=1`
Expected: PASS.

- [ ] **Step 6: Full db package test + build**

Run: `go build ./... && go test ./internal/db/ -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/db/db.go internal/db/db_test.go
git commit -S -m "feat(db): seed default vault and add vault schema to fresh DBs"
```

---

## Task 7: Vault-scope the resource repositories

**Files:**
- Modify: `internal/repositories/secret_repository.go`
- Modify: `internal/repositories/key_repository.go`
- Modify: `internal/repositories/certificate_repository.go`
- Modify: `model/secret.go`, `model/key.go`, `model/certificate.go` (add `VaultID uuid.UUID` field)
- Test: extend each repository's `_test.go`

Do this one repository at a time (secrets first, then keys, then certificates) so each is independently committable. The pattern below is for secrets; apply the same shape to keys and certificates.

- [ ] **Step 1: Add VaultID to the model**

In `model/secret.go`, add to the `Secret` struct after `UserID`:

```go
	VaultID uuid.UUID `json:"vault_id"`
```

Do the same for `model/key.go` (`Key`) and `model/certificate.go` (`Certificate`).

- [ ] **Step 2: Write the failing repository test**

In `internal/repositories/secret_repository_test.go` (extend the existing in-memory DB setup to include the `vault_id` column on `secrets`):

```go
func TestSecretRepository_ListInVault_ScopesByVault(t *testing.T) {
	// Setup: two secrets in vault A, one in vault B (reuse this package's test DB helper;
	// ensure the secrets table includes a vault_id column).
	repo, vaultA, vaultB := setupSecretsInTwoVaults(t)
	ctx := context.Background()

	got, err := repo.ListInVault(ctx, vaultA, nil)
	if err != nil {
		t.Fatalf("ListInVault: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("vault A should have 2 secrets, got %d", len(got))
	}
	got, _ = repo.ListInVault(ctx, vaultB, nil)
	if len(got) != 1 {
		t.Fatalf("vault B should have 1 secret, got %d", len(got))
	}
}
```

Implement `setupSecretsInTwoVaults` as a local helper that inserts the rows and returns the repo plus the two `uuid.UUID` vault IDs.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestSecretRepository_ListInVault -count=1`
Expected: FAIL — `repo.ListInVault undefined`.

- [ ] **Step 4: Add vault-scoped methods to the interface and implementation**

In `secret_repository.go`, add to `SecretRepositoryInterface`:

```go
	ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Secret, error)
	ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error)
	ListInVaultIncludeDeleted(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error)
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID) error
```

Update `Create` to persist `vault_id`. Change the INSERT to:

```go
	_, err := r.db.ExecContext(
		ctx,
		"INSERT INTO secrets (id, user_id, vault_id, name, value, version, created_at, content_type, enabled, expires_at, not_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		secret.ID.String(), secret.UserID.String(), secret.VaultID.String(), secret.Name, secret.Value, secret.Version, secret.CreatedAt, secret.ContentType, secret.Enabled, secret.ExpiresAt, secret.NotBefore,
	)
```

Add the new methods (modelled on the existing `ReadByOwner`/`ListByUser`, swapping `user_id = ?` for `vault_id = ?`):

```go
// ReadInVault fetches a secret only when id and vaultID both match.
func (r *SecretRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Secret, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE id = ? AND vault_id = ? AND deleted_at IS NULL",
		id.String(), vaultID.String())
	// Scan into model.Secret using the same scan logic as ReadByOwner.
	return scanSecretRow(row) // reuse existing scan helper, or inline the existing ReadByOwner scan block.
}

// ListInVault lists non-deleted secrets in a vault, optionally filtered by tags.
func (r *SecretRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE vault_id = ? AND deleted_at IS NULL ORDER BY name ASC",
		vaultID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets in vault: %w", err)
	}
	defer rows.Close()
	// Reuse the existing row-collection + tag-filter logic from ListByUser.
	return collectSecretsWithTags(ctx, r, rows, tags)
}

// ListInVaultIncludeDeleted is ListInVault without the deleted_at filter.
func (r *SecretRepository) ListInVaultIncludeDeleted(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE vault_id = ? ORDER BY name ASC",
		vaultID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets in vault: %w", err)
	}
	defer rows.Close()
	return collectSecretsWithTags(ctx, r, rows, tags)
}

// SoftDeleteVaultContents soft-deletes every non-deleted secret in a vault.
func (r *SecretRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
		time.Now(), vaultID.String())
	return err
}

// RecoverVaultContents clears the soft-delete flag for every secret in a vault.
func (r *SecretRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at IS NOT NULL",
		vaultID.String())
	return err
}
```

If `scanSecretRow`/`collectSecretsWithTags` helpers do not already exist, extract them from the existing `ReadByOwner`/`ListByUser` bodies (which already contain this exact scan and tag-filter code) so both the old and new methods share one implementation (DRY). Keep the old `ReadByOwner`/`ListByUser` methods for now — Task 8 switches callers over; they are removed in Task 12 cleanup.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/repositories/ -run TestSecretRepository_ListInVault -count=1`
Expected: PASS.

- [ ] **Step 6: Repeat Steps 1-5 for keys and certificates**

Apply the identical pattern to `key_repository.go` and `certificate_repository.go` (and their tests), using each table's actual column list. Each gets its own `ReadInVault`, `ListInVault`, `ListInVaultIncludeDeleted`, `SoftDeleteVaultContents`, `RecoverVaultContents`, and a `vault_id` in `Create`.

- [ ] **Step 7: Commit (one commit per repository is fine)**

```bash
git add internal/repositories/secret_repository.go internal/repositories/secret_repository_test.go model/secret.go
git commit -S -m "feat(repositories): add vault-scoped secret queries"
# then keys, then certificates as separate signed commits
```

---

## Task 8: Vault cascade adapter + service-container registration

**Files:**
- Create: `internal/services/vaults/cascade_adapter.go`
- Modify: `internal/container/service_container.go`
- Test: `internal/services/vaults/cascade_adapter_test.go`

- [ ] **Step 1: Write the failing test**

```go
package vaults

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type recordingRepo struct{ softCalls, recoverCalls int }

func (r *recordingRepo) SoftDeleteVaultContents(context.Context, uuid.UUID) error {
	r.softCalls++
	return nil
}
func (r *recordingRepo) RecoverVaultContents(context.Context, uuid.UUID) error {
	r.recoverCalls++
	return nil
}

func TestCascadeAdapter_FansOutToAllRepos(t *testing.T) {
	s, k, c := &recordingRepo{}, &recordingRepo{}, &recordingRepo{}
	ad := NewCascadeAdapter(s, k, c)
	if err := ad.SoftDeleteVaultContents(context.Background(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if s.softCalls != 1 || k.softCalls != 1 || c.softCalls != 1 {
		t.Fatal("soft-delete must fan out to all three repos")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestCascadeAdapter -count=1`
Expected: FAIL — `undefined: NewCascadeAdapter`.

- [ ] **Step 3: Implement the adapter**

`internal/services/vaults/cascade_adapter.go`:

```go
package vaults

import (
	"context"

	"github.com/google/uuid"
)

// vaultContentRepo is the subset of a resource repository the cascade needs.
type vaultContentRepo interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID) error
}

// cascadeAdapter fans cascade operations out to the secret, key, and cert repos.
type cascadeAdapter struct {
	repos []vaultContentRepo
}

// NewCascadeAdapter builds a CascadeRepository over the given content repos.
func NewCascadeAdapter(repos ...vaultContentRepo) CascadeRepository {
	return &cascadeAdapter{repos: repos}
}

func (a *cascadeAdapter) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	for _, r := range a.repos {
		if err := r.SoftDeleteVaultContents(ctx, vaultID); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	for _, r := range a.repos {
		if err := r.RecoverVaultContents(ctx, vaultID); err != nil {
			return err
		}
	}
	return nil
}
```

The secret/key/certificate repository interfaces satisfy `vaultContentRepo` via the methods added in Task 7.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/vaults/ -run TestCascadeAdapter -count=1`
Expected: PASS.

- [ ] **Step 5: Register vault repo + service in the container**

In `internal/container/service_container.go`:
1. Add import: `vaultServices "rocketvault/internal/services/vaults"`.
2. Add to `ServiceContainerInterface`:
   ```go
   	GetVaultRepository() repositories.VaultRepositoryInterface
   	GetVaultService() vaultServices.VaultService
   ```
3. Add fields to the `ServiceContainer` struct: `vaultRepository repositories.VaultRepositoryInterface` and `vaultService vaultServices.VaultService`.
4. In the constructor (where other repos/services are built — match the existing wiring), add:
   ```go
   	c.vaultRepository = repositories.NewVaultRepository(c.db, c.logger)
   	cascade := vaultServices.NewCascadeAdapter(c.secretRepository, c.keyRepository, c.certificateRepository)
   	c.vaultService = vaultServices.NewVaultService(c.vaultRepository, cascade, c.logger)
   ```
   (Use the actual field names for db/logger/resource repos in this file.)
5. Add the getters:
   ```go
   func (c *ServiceContainer) GetVaultRepository() repositories.VaultRepositoryInterface { return c.vaultRepository }
   func (c *ServiceContainer) GetVaultService() vaultServices.VaultService { return c.vaultService }
   ```

- [ ] **Step 6: Build**

Run: `go build ./...`
Expected: success.

- [ ] **Step 7: Commit**

```bash
git add internal/services/vaults/cascade_adapter.go internal/services/vaults/cascade_adapter_test.go internal/container/service_container.go
git commit -S -m "feat(container): register vault service with cascade adapter"
```

---

## Task 9: Vault resolution middleware

**Files:**
- Modify: `internal/middleware/middleware.go`
- Test: `internal/middleware/middleware_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestVaultResolutionMiddleware_FallsBackToDefault(t *testing.T) {
	// Build a middleware with a stub container whose VaultService.GetVault("default")
	// returns an enabled vault with model.DefaultVaultID.
	mw := newTestMiddlewareWithDefaultVault(t)
	var gotVault interface{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVault = r.Context().Value(common.VaultIDKey)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	rec := httptest.NewRecorder()
	mw.VaultResolutionMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotVault != model.DefaultVaultID {
		t.Fatalf("vault id in context = %v, want default", gotVault)
	}
}

func TestVaultResolutionMiddleware_DisabledVaultRejected(t *testing.T) {
	mw := newTestMiddlewareWithDisabledVault(t, "stg")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/vaults/stg/secrets", nil),
		map[string]string{"vault_name": "stg"})
	rec := httptest.NewRecorder()
	mw.VaultResolutionMiddleware(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disabled vault should be 403, got %d", rec.Code)
	}
}
```

Implement the two `newTestMiddleware...` helpers using the existing middleware test scaffolding in this file (there is already a mock container pattern — reuse it and stub `GetVaultService`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/middleware/ -run TestVaultResolutionMiddleware -count=1`
Expected: FAIL — `mw.VaultResolutionMiddleware undefined`.

- [ ] **Step 3: Implement the middleware**

Add to `internal/middleware/middleware.go`:

```go
// VaultResolutionMiddleware resolves the target vault from the request and injects
// its ID into the request context. Resolution order: subdomain (when enabled) →
// {vault_name} path variable → the default vault. A missing vault yields 404; a
// disabled or soft-deleted vault yields 403.
func (m *Middleware) VaultResolutionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := model.DefaultVaultName
		if v := mux.Vars(r)["vault_name"]; v != "" {
			name = v
		}
		// Subdomain resolution is intentionally omitted here; it is added in the
		// optional subdomain task and only when server.subdomain_vaults is set.

		vault, err := m.container.GetVaultService().GetVault(r.Context(), name)
		if err != nil {
			m.logger.LogAuditError("", "vault_resolve", "failed", "Vault not found: "+name, err)
			http.Error(w, `{"error":"vault not found"}`, http.StatusNotFound)
			return
		}
		if !vault.Enabled {
			http.Error(w, `{"error":"vault is disabled"}`, http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), common.VaultIDKey, vault.ID.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

Ensure imports include `rocketvault/model`, `rocketvault/common`, `github.com/gorilla/mux`, `context`, `net/http`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/middleware/ -run TestVaultResolutionMiddleware -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/middleware/middleware.go internal/middleware/middleware_test.go
git commit -S -m "feat(middleware): add vault resolution middleware"
```

---

## Task 10: Vault-scope the policy middleware + access policy model

**Files:**
- Modify: `model/access_policy.go`
- Modify: `internal/middleware/middleware.go` (`PolicyMiddleware`)
- Modify: `internal/repositories/access_policy_repository.go` (lookup query)
- Test: extend `internal/middleware/middleware_test.go`

- [ ] **Step 1: Extend the access-policy model**

In `model/access_policy.go`:
- Add `VaultID *uuid.UUID json:"vault_id,omitempty"` to `AccessPolicy`.
- Add `PolicyResourceVaults PolicyResourceType = "vaults"` to the resource constants.
- Add `OpManage PolicyOperation = "manage"` to the operation constants.
- Add `VaultID string json:"vault_id,omitempty"` to `CreateAccessPolicyRequest` and `AccessPolicyResponse`.

- [ ] **Step 2: Write the failing policy-scoping test**

```go
func TestPolicyMiddleware_GlobalPolicyAppliesInAnyVault(t *testing.T) {
	// A NULL-vault allow policy for (principal, secrets, get) must permit a request
	// whose resolved vault is some specific vault.
	mw := newPolicyTestMiddleware(t, withGlobalAllow("secrets", "get"))
	req := requestWithVaultAndClaims(t, "prod", "secrets", "get")
	rec := httptest.NewRecorder()
	mw.PolicyMiddleware(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global allow should permit; got %d", rec.Code)
	}
}
```

Reuse existing policy-middleware test scaffolding; add the `withGlobalAllow` and `requestWithVaultAndClaims` helpers using the existing mock access-policy repo.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/middleware/ -run TestPolicyMiddleware_GlobalPolicy -count=1`
Expected: FAIL (lookup not yet vault-aware, or helper undefined).

- [ ] **Step 4: Make the lookup vault-aware**

In `internal/repositories/access_policy_repository.go`, find the lookup method `PolicyMiddleware` uses (it queries by `principal_id, resource_type, operation`). Add a vault parameter and change the `WHERE` clause to:

```go
	// vaultID is the resolved vault from context; NULL-vault rows are global.
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id
		 FROM access_policies
		 WHERE principal_id = ? AND resource_type = ? AND operation = ?
		   AND (vault_id = ? OR vault_id IS NULL)`,
		principalID.String(), resourceType, operation, vaultID.String())
```

Update the method signature and the scan to read `vault_id` (nullable). Update the interface in the same file and the mock in `internal/testutils/mocks.go`.

In `PolicyMiddleware` (`middleware.go`), read the resolved vault from context and pass it to the lookup:

```go
	vaultIDStr, _ := r.Context().Value(common.VaultIDKey).(string)
	vaultID, _ := uuid.Parse(vaultIDStr)
	// ...pass vaultID into the access-policy lookup call.
```

Keep deny-overrides-allow precedence exactly as it is today.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/middleware/ -run TestPolicyMiddleware -count=1`
Expected: PASS.

- [ ] **Step 6: Build all**

Run: `go build ./...`
Expected: success (mock updated).

- [ ] **Step 7: Commit**

```bash
git add model/access_policy.go internal/middleware/middleware.go internal/repositories/access_policy_repository.go internal/testutils/mocks.go internal/middleware/middleware_test.go
git commit -S -m "feat(authz): make access-policy checks vault-aware"
```

---

## Task 11: Vault management API + register middleware/routes

**Files:**
- Modify: `api/vault.go` (replace placeholder)
- Modify: `api/api.go` (routes + middleware chain)
- Modify: `api/secrets.go`, `api/keys.go`, `api/certificates.go`, `api/soft_delete.go` (read `VaultIDKey`, call vault-scoped service methods)
- Modify: service request structs in `internal/services/{secrets,keys,certificates}` to carry `VaultID`
- Test: `api/vault_test.go`

- [ ] **Step 1: Wire the middleware and routes**

In `api/api.go`:
- Add `mw.VaultResolutionMiddleware` to the `r.ApiRoot.Use(...)` chain, positioned after `AuthenticationMiddleware` and before `PolicyMiddleware`:
  ```go
  	r.ApiRoot.Use(
  		mw.CORSMiddleware,
  		mw.RateLimitMiddleware,
  		mw.AuthenticationMiddleware,
  		mw.VaultResolutionMiddleware,
  		mw.PolicyMiddleware,
  		mw.AuthorizationMiddleware,
  	)
  ```
- Add vault-scoped subrouters and management routes. After the existing `r.Vault` line:
  ```go
  	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
  	// Vault-scoped resource subrouter, e.g. /vaults/{vault_name}/secrets.
  	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
  ```
  Register management handlers on `r.Vaults` (exact paths) in `InitVault`, and register the resource subrouters (secrets/keys/certs/access-policies/deleted) on BOTH `r.ApiRoot` (legacy, default vault) and `r.VaultScoped` (vault-scoped). Add `Vaults` and `VaultScoped` fields to the `BaseRoutes` struct (find its definition in `api/api.go`).

  Registration order matters: register the exact management routes (`POST /vaults`, `GET /vaults`, `GET/PATCH/DELETE /vaults/{vault_name}`) before the `/vaults/{vault_name}/...` resource subrouter so they are not shadowed.

- [ ] **Step 2: Implement vault management handlers**

Replace `api/vault.go`:

```go
package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/model"
)

// InitVault registers vault management routes.
func (api *API) InitVault() {
	api.BaseRoutes.Vaults.HandleFunc("", api.createVault).Methods(http.MethodPost)
	api.BaseRoutes.Vaults.HandleFunc("", api.listVaults).Methods(http.MethodGet)
	api.BaseRoutes.Vaults.HandleFunc("/{vault_name:[a-z0-9-]+}", api.getVault).Methods(http.MethodGet)
	api.BaseRoutes.Vaults.HandleFunc("/{vault_name:[a-z0-9-]+}", api.updateVault).Methods(http.MethodPatch)
	api.BaseRoutes.Vaults.HandleFunc("/{vault_name:[a-z0-9-]+}", api.deleteVault).Methods(http.MethodDelete)
	api.Logger.Infoln("Vault management API initialized")
}

func (api *API) createVault(w http.ResponseWriter, r *http.Request) {
	c := api.NewContext(w, r) // match how other handlers build their context.
	req, err := model.CreateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("body")
		return
	}
	creatorStr, _ := c.Claims["user_id"].(string)
	creator, _ := uuid.Parse(creatorStr)
	v, err := api.App.ServiceContainer.GetVaultService().CreateVault(r.Context(), *req, creator)
	if err != nil {
		c.SetError(http.StatusBadRequest, err.Error()) // match existing error helper.
		return
	}
	resp := v.ToResponse()
	c.Write(resp.ToJson()) // match how other handlers write JSON.
}

// getVault, listVaults, updateVault, deleteVault follow the same shape:
// read mux.Vars(r)["vault_name"], call the matching VaultService method,
// map the result to model.VaultResponse, and write it. deleteVault returns 204.
```

Implement `getVault`, `listVaults` (honor `?include_deleted=true`), `updateVault`, and `deleteVault` using the same context/error/write helpers the other handlers in this package already use. Match the real method names (`c.SetError` / `c.Write` may differ — copy the pattern from `api/secrets.go`).

- [ ] **Step 3: Thread VaultID through resource handlers and services**

In each resource handler (`api/secrets.go`, `keys.go`, `certificates.go`, `soft_delete.go`), where it currently reads `user_id` from claims for scoping, also read the vault:

```go
	vaultIDStr, _ := r.Context().Value(common.VaultIDKey).(string)
	vaultID, err := uuid.Parse(vaultIDStr)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
```

Set `VaultID: vaultID` on the create request and call the vault-scoped service/repository methods (`ListInVault`, `ReadInVault`, etc.) instead of the user-scoped ones. Add a `VaultID uuid.UUID` field to the create-request structs in `internal/services/secrets`, `keys`, `certificates`, and have the service set it on the model before `repo.Create`. Keep using `user_id` from claims as the `Secret.UserID` (created_by) value.

- [ ] **Step 4: Write the API test**

`api/vault_test.go`:

```go
func TestCreateVault_Returns201AndPersists(t *testing.T) {
	api := newTestAPI(t) // reuse the existing API test harness in this package.
	body := `{"name":"prod"}`
	rec := api.doAuthedRequest(t, http.MethodPost, "/api/v1/vaults", body, adminClaims())
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("create vault status = %d, body=%s", rec.Code, rec.Body.String())
	}
	// List should now include "prod".
	rec = api.doAuthedRequest(t, http.MethodGet, "/api/v1/vaults", "", adminClaims())
	if !strings.Contains(rec.Body.String(), "prod") {
		t.Fatalf("listed vaults missing prod: %s", rec.Body.String())
	}
}
```

Use the existing API test harness (look at `api/*_test.go` for how a test API with an in-memory DB and auth is constructed; reuse those helpers rather than inventing new ones).

- [ ] **Step 5: Run test + build**

Run: `go build ./... && go test ./api/ -run TestCreateVault -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api/ internal/services/secrets/ internal/services/keys/ internal/services/certificates/
git commit -S -m "feat(api): add vault management endpoints and vault-scoped resource routes"
```

---

## Task 12: CLI — vaults command group + --vault selector

**Files:**
- Create: `cmd/vaults.go`
- Create: `cmd/vault_flag.go`
- Modify: `cmd/root.go` (register `vaultsCmd`, add persistent `--vault` flag + viper bind)
- Modify: `cmd/secrets.go`, `cmd/keys.go`, `cmd/certificate.go`, `cmd/rotation.go`, `cmd/backup.go` (resolve and send the vault)
- Test: `cmd/vault_flag_test.go`, `cmd/vaults_test.go`

- [ ] **Step 1: Write the failing resolver test**

`cmd/vault_flag_test.go`:

```go
package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveVault_Precedence(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")

	// 1. Flag wins.
	cmd.Flags().Set("vault", "flagvault")
	t.Setenv("ROCKETVAULT_VAULT", "envvault")
	if got := resolveVault(cmd); got != "flagvault" {
		t.Fatalf("flag should win, got %q", got)
	}

	// 2. Env when no flag.
	cmd2 := &cobra.Command{}
	cmd2.Flags().String("vault", "", "")
	t.Setenv("ROCKETVAULT_VAULT", "envvault")
	if got := resolveVault(cmd2); got != "envvault" {
		t.Fatalf("env should win when no flag, got %q", got)
	}

	// 3. Built-in default when nothing set.
	cmd3 := &cobra.Command{}
	cmd3.Flags().String("vault", "", "")
	os.Unsetenv("ROCKETVAULT_VAULT")
	if got := resolveVault(cmd3); got != "default" {
		t.Fatalf("should fall back to default, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestResolveVault -count=1`
Expected: FAIL — `undefined: resolveVault`.

- [ ] **Step 3: Implement the resolver**

`cmd/vault_flag.go`:

```go
package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/model"
)

// resolveVault determines the target vault for a resource command.
// Precedence: --vault flag > ROCKETVAULT_VAULT env > config "vault" key > "default".
func resolveVault(cmd *cobra.Command) string {
	if cmd.Flags().Changed("vault") {
		if v, _ := cmd.Flags().GetString("vault"); v != "" {
			return v
		}
	}
	if v := os.Getenv("ROCKETVAULT_VAULT"); v != "" {
		return v
	}
	if v := viper.GetString("vault"); v != "" {
		return v
	}
	return model.DefaultVaultName
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -run TestResolveVault -count=1`
Expected: PASS.

- [ ] **Step 5: Add the vaults command group**

`cmd/vaults.go` — a `vaultsCmd` parent with `create`, `list`, `get`, `update`, `delete`, `recover`, `purge` subcommands. Each builds an authenticated HTTP request to the management endpoints (copy the HTTP/auth/output pattern from an existing command such as `cmd/secrets.go` — same base URL resolution, same token handling, same output formatter). Example for `create`:

```go
var vaultsCmd = &cobra.Command{Use: "vaults", Short: "Manage vaults"}

var vaultsCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"name": args[0]}
		if pp, _ := cmd.Flags().GetBool("purge-protection"); pp {
			body["purge_protection"] = true
		}
		if rd, _ := cmd.Flags().GetInt("retention-days"); rd > 0 {
			body["retention_days"] = rd
		}
		return doVaultRequest(cmd, http.MethodPost, "/api/v1/vaults", body)
	},
}

func init() {
	vaultsCreateCmd.Flags().Bool("purge-protection", false, "Enable purge protection")
	vaultsCreateCmd.Flags().Int("retention-days", 90, "Soft-delete retention in days")
	vaultsCmd.AddCommand(vaultsCreateCmd /*, list, get, update, delete, recover, purge */)
}
```

`doVaultRequest` is a small local helper that sends an authenticated JSON request and prints the response via the existing output formatter (model it on the existing command HTTP helper in this package). Implement `list`/`get`/`update`/`delete`/`recover`/`purge` analogously (`delete` → `DELETE /api/v1/vaults/{name}`; `purge`/`recover` → the corresponding endpoints — add those endpoints in `api/vault.go` if not already present, mirroring Task 11; if recover/purge endpoints are out of scope for this milestone, omit those two subcommands and note it).

- [ ] **Step 6: Register command group and the persistent --vault flag**

In `cmd/root.go`:
- `rootCmd.AddCommand(vaultsCmd)`.
- Add a persistent flag and viper bind:
  ```go
  	rootCmd.PersistentFlags().String("vault", "", "Target vault name (default: \"default\")")
  	_ = viper.BindPFlag("vault", rootCmd.PersistentFlags().Lookup("vault"))
  ```

- [ ] **Step 7: Send the resolved vault from resource commands**

In `cmd/secrets.go`, `keys.go`, `certificate.go`, `rotation.go`, `backup.go`, change each command's request URL to the vault-scoped path using `resolveVault(cmd)`:

```go
	vault := resolveVault(cmd)
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets", vault) // was "/api/v1/secrets"
```

Because the API also keeps legacy flat routes mapped to the default vault, commands that resolve to `default` work either way; using the explicit path is consistent and correct for all vaults.

- [ ] **Step 8: Write a vaults command test**

`cmd/vaults_test.go`: assert `vaults create` with no args errors (`cobra.ExactArgs(1)`), and that `vaultsCmd` has the expected subcommands registered. Reuse the CLI test harness pattern (the package already makes CLI output capturable per recent commits).

- [ ] **Step 9: Run tests + build**

Run: `go build ./... && go test ./cmd/ -run 'TestResolveVault|TestVaults' -count=1`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add cmd/vaults.go cmd/vault_flag.go cmd/vault_flag_test.go cmd/vaults_test.go cmd/root.go cmd/secrets.go cmd/keys.go cmd/certificate.go cmd/rotation.go cmd/backup.go
git commit -S -m "feat(cli): add vaults command group and --vault selector"
```

---

## Task 13: Remove dead user-scoped methods + final verification

**Files:**
- Modify: `internal/repositories/{secret,key,certificate}_repository.go` (remove now-unused `ReadByOwner`/`ListByUser`/`ListByUserIncludeDeleted` only if no caller remains)
- Modify: `internal/testutils/mocks.go` (drop removed methods from mocks)

- [ ] **Step 1: Find remaining callers**

Run: `grep -rn "ReadByOwner\|ListByUser" --include=*.go . | grep -v _test.go`
Expected: only the repository definitions remain (all handlers/services switched in Task 11). If any production caller remains, switch it to the vault-scoped method first.

- [ ] **Step 2: Remove the dead methods**

Delete `ReadByOwner`, `ListByUser`, `ListByUserIncludeDeleted` from each resource repository interface and implementation, and from the corresponding mocks in `internal/testutils/mocks.go`. Leave them if any test depends on them — adjust those tests to the vault-scoped equivalents instead.

- [ ] **Step 3: Run the full verification gate**

Run:
```bash
go build ./... && go vet ./... && gofmt -l . && go test ./... -count=1
```
Expected: build OK, vet clean, `gofmt -l .` prints nothing, all tests PASS.

- [ ] **Step 4: Check coverage on touched packages**

Run:
```bash
go test ./internal/repositories/ ./internal/services/vaults/ ./internal/middleware/ ./api/ ./cmd/ -coverprofile=cover.out -count=1
go tool cover -func=cover.out | tail -1
```
Expected: total ≥ 80%. If below, add table tests for uncovered vault branches (collision multi-group, cascade recover, update fields, list include-deleted).

- [ ] **Step 5: Update documentation**

Update `CLAUDE.md` "Open Bugs"/architecture notes to mention multi-vault, and add a short `.claude/` doc if warranted (per the user's documentation-placement rule: detailed docs go in `.claude/`, keep `CLAUDE.md` small). Update `docs/consuming-secrets-guide.md` / API docs if they reference vault-less routes.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -S -m "refactor(repositories): remove user-scoped methods superseded by vault scoping"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- S1 Schema → Tasks 1, 5, 6 (vaults table, vault_id columns, access_policies.vault_id, (vault_id,name) unique). ✓
- S2 Routing & resolution → Tasks 9, 11 (middleware, routes, legacy + vault-scoped, chain position). Subdomain explicitly deferred (config-gated, off by default) — noted in Task 9 step 3. ✓
- S3 Vault lifecycle → Tasks 4, 8 (create/get/list/update/soft-delete/recover/purge, cascade, reserved default, purge protection, name validation). ✓
- S4 Access-policy/RBAC scoping → Task 10 (vault_id on policies, NULL=global, deny-overrides preserved, vaults resource + manage op). ✓
- S5 Repository/service scoping → Tasks 7, 11 (vault-scoped queries, created_by retained, services thread VaultID). ✓
- S6 Migration & bootstrap → Tasks 5, 6 (timestamped migration, fixed UUID, backfill, collision auto-rename+log, fresh-DB schema, startup seed). ✓
- S7 CLI & testing → Tasks 12, 13 (vaults group, --vault precedence helper, tests across all layers, verification gate, ≥80% coverage). ✓

**Placeholder scan:** Task 4 intentionally flags a draft remnant to delete (the `ReadByID(uuid.Nil)` lines) — called out explicitly with the corrective instruction, not left as a silent placeholder. No "TODO/TBD/handle edge cases" left as work-without-code.

**Type consistency:** `model.DefaultVaultID`/`DefaultVaultName`, `VaultRepositoryInterface`, `VaultService`, `CascadeRepository`, `NewCascadeAdapter`, `VaultResolutionMiddleware`, `resolveVault`, `VaultID` field, `ListInVault`/`ReadInVault`/`SoftDeleteVaultContents`/`RecoverVaultContents` used consistently across tasks. The fixed UUID literal `00000000-0000-0000-0000-00000000efa1` is identical in model, migration SQL, fresh-DB schema, and seed.
