# Provisioning Grant Storage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `vault_provisioning_grants` table, its domain type, and its repository — the storage layer for a bounded vault-creation right.

**Architecture:** A grant is one row per principal carrying a quota. Storage only in this plan: nothing reads a grant for an authorization decision yet, so the change is inert and cannot alter any existing behaviour. The vault repository also gains `CountByCreatedBy`, which the quota check in plan 04 runs inside a transaction.

**Tech Stack:** Go 1.24, `database/sql`, SQLite (dev) / PostgreSQL (prod), testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §3

**Followed by:** `…-02-purge-cleanup-and-di.md`. Release 1 is split so no plan carries more than three tasks; run the numbered plans in order.

## Global Constraints

- **Release 1 is additive only.** No existing authorization decision may change behaviour. The narrowing of the global `vaults:manage` grant is release 2 and is out of scope for every plan in this series.
- Every schema change is dual-written: the `CREATE TABLE` block *and* `migrateSchema`, both in `internal/db/db.go`. A change in only one place breaks either fresh installs or upgrades.
- `principal_id` carries **no** foreign key to `users` — OAuth2 service accounts are `oauth2_clients` rows, not users, and the MSP's automation is a service account.
- Repositories do data access only; business rules live in services (`CLAUDE.md`, Repository Pattern).
- New Tx-scoped repository methods go on the **concrete struct**, never the exported interface, so test doubles don't break. Precedent: `VaultRepository.ReadByIDTx` and the `txCapableVaultRepo` assertion in `internal/services/vaults/vault_service.go:107-118`.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Schema

**Files:**
- Modify: `internal/db/db.go` (the `CREATE TABLE` block near the `role_assignments` definition around line 709, and `migrateSchema` at line 756)
- Test: `internal/db/db_test.go`

**Interfaces:**
- Produces: table `vault_provisioning_grants(id, principal_id, quota, created_at, created_by)` and index `idx_vaults_created_by`. Task 3 and plan 04 depend on both.

`idx_vaults_created_by` is not an optimisation — plan 04 counts vaults by `created_by` on every provisioned create, and `vaults` has only `idx_vaults_name` today (`db.go:382`).

- [ ] **Step 1: Write the failing test**

Add to `internal/db/db_test.go`:

```go
func TestMigrateSchema_CreatesVaultProvisioningGrants(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	repo := newTestDBRepository(t, db)
	require.NoError(t, repo.migrateSchema(db))

	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='vault_provisioning_grants'`,
	).Scan(&name)
	require.NoError(t, err, "migrateSchema must create vault_provisioning_grants")

	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_vaults_created_by'`,
	).Scan(&name)
	require.NoError(t, err, "migrateSchema must create idx_vaults_created_by")
}
```

If `newTestDBRepository` does not already exist in that file, build the `DBRepository` the same way the neighbouring migration tests in `internal/db/db_test.go` do, and reuse that helper rather than adding a second one.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestMigrateSchema_CreatesVaultProvisioningGrants -v`
Expected: FAIL — `sql: no rows in result set`.

- [ ] **Step 3: Add the table to the CREATE TABLE block**

In `internal/db/db.go`, immediately after the `role_assignments` table and its two indexes (around line 709-721), add:

```sql
		CREATE TABLE IF NOT EXISTS vault_provisioning_grants (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL UNIQUE,
			quota        INTEGER NOT NULL,
			created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by   TEXT NOT NULL
		);
		-- No FOREIGN KEY on principal_id: a grantee may be an oauth2_clients
		-- row (a service account) rather than a users row, and the MSP
		-- automation this table exists for is exactly that.
		CREATE INDEX IF NOT EXISTS idx_vaults_created_by ON vaults(created_by);
```

- [ ] **Step 4: Add the same table to migrateSchema**

In `migrateSchema` (`internal/db/db.go:756`), alongside the existing `CREATE TABLE IF NOT EXISTS vault_webhook_configs` statement at line 860, add:

```go
		`CREATE TABLE IF NOT EXISTS vault_provisioning_grants (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL UNIQUE,
			quota        INTEGER NOT NULL,
			created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by   TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vaults_created_by ON vaults(created_by)`,
```

Match the exact slice/loop shape already used for `vault_webhook_configs` at that line — do not invent a different execution path.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/ -run TestMigrateSchema_CreatesVaultProvisioningGrants -v`
Expected: PASS

- [ ] **Step 6: Run the full db suite**

Run: `go test ./internal/db/`
Expected: PASS — no existing migration test regresses.

- [ ] **Step 7: Commit**

```bash
git add internal/db/db.go internal/db/db_test.go
git commit -S -m "feat(db): add vault_provisioning_grants table"
```

---

### Task 2: Domain type

**Files:**
- Create: `model/vault_provisioning_grant.go`
- Test: `model/vault_provisioning_grant_test.go`

**Interfaces:**
- Produces:
  - `type VaultProvisioningGrant struct { ID, PrincipalID uuid.UUID; Quota int; CreatedAt time.Time; CreatedBy uuid.UUID }`
  - `func (g *VaultProvisioningGrant) Validate() error`
  - `var ErrInvalidQuota = errors.New("quota must be greater than zero")`
  - Task 3 and plans 02, 06, 07 all consume these.

- [ ] **Step 1: Write the failing test**

Create `model/vault_provisioning_grant_test.go`:

```go
package model_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestVaultProvisioningGrant_Validate(t *testing.T) {
	tests := []struct {
		name    string
		grant   model.VaultProvisioningGrant
		wantErr bool
	}{
		{"valid", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: 5}, false},
		{"quota of one is valid", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: 1}, false},
		{"zero quota rejected", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: 0}, true},
		{"negative quota rejected", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: -1}, true},
		{"nil principal rejected", model.VaultProvisioningGrant{PrincipalID: uuid.Nil, Quota: 5}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.grant.Validate()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
```

A zero quota is rejected rather than treated as "no vaults allowed", because a zero-quota grant and no grant at all are the same permission, and having two ways to express it invites a caller to distinguish them.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/ -run TestVaultProvisioningGrant_Validate -v`
Expected: FAIL — `undefined: model.VaultProvisioningGrant`.

- [ ] **Step 3: Write the implementation**

Create `model/vault_provisioning_grant.go`:

```go
package model

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrInvalidQuota is returned when a grant's quota is not a positive count.
var ErrInvalidQuota = errors.New("quota must be greater than zero")

// ErrInvalidPrincipal is returned when a grant names no principal.
var ErrInvalidPrincipal = errors.New("principal_id is required")

// VaultProvisioningGrant is a bounded right to create vaults. It is the
// delegated alternative to a global vaults:manage grant, which additionally
// confers authority over every vault that already exists.
//
// PrincipalID is deliberately not constrained to a users row: a grantee may
// be an OAuth2 service account, which is how an MSP's automation
// authenticates.
type VaultProvisioningGrant struct {
	ID          uuid.UUID `json:"id"`
	PrincipalID uuid.UUID `json:"principal_id"`
	// Quota is the maximum number of vaults this principal may have created
	// and not yet purged. Soft-deleted vaults still count -- see the design
	// doc's §5 for why.
	Quota     int       `json:"quota"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy uuid.UUID `json:"created_by"`
}

// Validate reports whether the grant is well formed.
func (g *VaultProvisioningGrant) Validate() error {
	if g.PrincipalID == uuid.Nil {
		return ErrInvalidPrincipal
	}
	if g.Quota <= 0 {
		return ErrInvalidQuota
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./model/ -run TestVaultProvisioningGrant_Validate -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add model/vault_provisioning_grant.go model/vault_provisioning_grant_test.go
git commit -S -m "feat(model): add VaultProvisioningGrant"
```

---

### Task 3: Repository

**Files:**
- Create: `internal/repositories/vault_provisioning_grant_repository.go`
- Create: `internal/repositories/vault_provisioning_grant_repository_test.go`
- Modify: `internal/repositories/vault_repository.go` (add `CountByCreatedBy` after `ReadByIDTx`, around line 137)

**Interfaces:**
- Consumes: `model.VaultProvisioningGrant` and `model.ErrInvalidQuota` from task 2.
- Produces:
  - `type VaultProvisioningGrantRepositoryInterface interface { Upsert(ctx, *model.VaultProvisioningGrant) error; GetByPrincipal(ctx, uuid.UUID) (*model.VaultProvisioningGrant, error); Delete(ctx, uuid.UUID) error; List(ctx) ([]*model.VaultProvisioningGrant, error) }`
  - `func NewVaultProvisioningGrantRepository(database db.DB) VaultProvisioningGrantRepositoryInterface`
  - `func (r *VaultRepository) CountByCreatedBy(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error)`
  - Plans 02, 04, 06 and 07 consume these.

`GetByPrincipal` returns the package's existing `ErrNotFound` when no grant exists, matching `VaultRepository.ReadByName` (`vault_repository.go:121-129`).

`CountByCreatedBy` takes a `db.DBTX` because plan 04 calls it inside a transaction, where counting on the pooled handle would read outside the transaction's snapshot and defeat the row lock.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/vault_provisioning_grant_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func newGrantTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = database.Exec(`
		CREATE TABLE vault_provisioning_grants (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL UNIQUE,
			quota        INTEGER NOT NULL,
			created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by   TEXT NOT NULL
		);`)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	return database
}

func TestGrantRepository_UpsertAndGet(t *testing.T) {
	repo := repositories.NewVaultProvisioningGrantRepository(newGrantTestDB(t))
	ctx := context.Background()
	principal := uuid.New()

	g := &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 5, CreatedBy: uuid.New(),
	}
	require.NoError(t, repo.Upsert(ctx, g))

	got, err := repo.GetByPrincipal(ctx, principal)
	require.NoError(t, err)
	require.Equal(t, 5, got.Quota)
	require.Equal(t, principal, got.PrincipalID)
}

func TestGrantRepository_UpsertReplacesQuota(t *testing.T) {
	repo := repositories.NewVaultProvisioningGrantRepository(newGrantTestDB(t))
	ctx := context.Background()
	principal := uuid.New()

	require.NoError(t, repo.Upsert(ctx, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 5, CreatedBy: uuid.New(),
	}))
	require.NoError(t, repo.Upsert(ctx, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 9, CreatedBy: uuid.New(),
	}))

	got, err := repo.GetByPrincipal(ctx, principal)
	require.NoError(t, err)
	require.Equal(t, 9, got.Quota, "second upsert must replace the quota, not insert a duplicate")

	all, err := repo.List(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1, "principal_id is UNIQUE: one row per principal")
}

func TestGrantRepository_GetMissingReturnsNotFound(t *testing.T) {
	repo := repositories.NewVaultProvisioningGrantRepository(newGrantTestDB(t))

	_, err := repo.GetByPrincipal(context.Background(), uuid.New())
	require.True(t, errors.Is(err, repositories.ErrNotFound),
		"a principal with no grant must be distinguishable from a lookup failure")
}

func TestGrantRepository_Delete(t *testing.T) {
	repo := repositories.NewVaultProvisioningGrantRepository(newGrantTestDB(t))
	ctx := context.Background()
	principal := uuid.New()

	require.NoError(t, repo.Upsert(ctx, &model.VaultProvisioningGrant{
		ID: uuid.New(), PrincipalID: principal, Quota: 3, CreatedBy: uuid.New(),
	}))
	require.NoError(t, repo.Delete(ctx, principal))

	_, err := repo.GetByPrincipal(ctx, principal)
	require.True(t, errors.Is(err, repositories.ErrNotFound))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestGrantRepository -v`
Expected: FAIL — `undefined: repositories.NewVaultProvisioningGrantRepository`.

- [ ] **Step 3: Write the repository**

Create `internal/repositories/vault_provisioning_grant_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/model"
)

// VaultProvisioningGrantRepositoryInterface is pure data access for the
// bounded vault-creation right. Quota enforcement is a business rule and
// lives in the service layer, not here.
type VaultProvisioningGrantRepositoryInterface interface {
	Upsert(ctx context.Context, g *model.VaultProvisioningGrant) error
	GetByPrincipal(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error)
	Delete(ctx context.Context, principalID uuid.UUID) error
	List(ctx context.Context) ([]*model.VaultProvisioningGrant, error)
}

type vaultProvisioningGrantRepository struct {
	db db.DB
}

func NewVaultProvisioningGrantRepository(database db.DB) VaultProvisioningGrantRepositoryInterface {
	return &vaultProvisioningGrantRepository{db: database}
}

const grantCols = "id, principal_id, quota, created_at, created_by"

// Upsert writes the grant, replacing any existing grant for the same
// principal. principal_id is UNIQUE, so a second grant for one principal is a
// quota change rather than an additional right.
func (r *vaultProvisioningGrantRepository) Upsert(ctx context.Context, g *model.VaultProvisioningGrant) error {
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO vault_provisioning_grants (id, principal_id, quota, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (principal_id) DO UPDATE SET quota = excluded.quota`,
		g.ID.String(), g.PrincipalID.String(), g.Quota, g.CreatedAt, g.CreatedBy.String())
	if err != nil {
		return fmt.Errorf("upsert provisioning grant: %w", err)
	}
	return nil
}

func (r *vaultProvisioningGrantRepository) GetByPrincipal(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+grantCols+" FROM vault_provisioning_grants WHERE principal_id = ?",
		principalID.String())
	g, err := scanGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("provisioning grant for principal %s: %w", principalID, ErrNotFound)
	}
	return g, err
}

func (r *vaultProvisioningGrantRepository) Delete(ctx context.Context, principalID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM vault_provisioning_grants WHERE principal_id = ?", principalID.String())
	return err
}

func (r *vaultProvisioningGrantRepository) List(ctx context.Context) ([]*model.VaultProvisioningGrant, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT "+grantCols+" FROM vault_provisioning_grants ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []*model.VaultProvisioningGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanGrant(s scanner) (*model.VaultProvisioningGrant, error) {
	var (
		g           model.VaultProvisioningGrant
		idStr       string
		principal   string
		createdByID string
	)
	if err := s.Scan(&idStr, &principal, &g.Quota, &g.CreatedAt, &createdByID); err != nil {
		return nil, err
	}
	var err error
	if g.ID, err = uuid.Parse(idStr); err != nil {
		return nil, fmt.Errorf("parse grant id: %w", err)
	}
	if g.PrincipalID, err = uuid.Parse(principal); err != nil {
		return nil, fmt.Errorf("parse grant principal_id: %w", err)
	}
	if g.CreatedBy, err = uuid.Parse(createdByID); err != nil {
		return nil, fmt.Errorf("parse grant created_by: %w", err)
	}
	return &g, nil
}
```

If a `scanner` interface with this shape already exists in the `repositories` package, use that one and delete the local declaration — do not introduce a duplicate.

`ON CONFLICT (principal_id) DO UPDATE` is valid on both SQLite (3.24+) and PostgreSQL (9.5+), so no dialect branch is needed.

- [ ] **Step 4: Add CountByCreatedBy to the vault repository**

In `internal/repositories/vault_repository.go`, immediately after `ReadByIDTx` (line 135-137), add:

```go
// CountByCreatedBy counts vaults created by principalID that still exist,
// soft-deleted ones included -- a soft-deleted vault still holds its name and
// can be recovered, so it still occupies a quota slot. Only a purge removes
// the row and releases the slot.
//
// It takes a db.DBTX rather than using r.db because the quota check runs
// inside the creation transaction; counting on the pooled handle would read
// outside that transaction and defeat its row lock.
func (r *VaultRepository) CountByCreatedBy(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error) {
	var n int
	err := ex.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vaults WHERE created_by = ?", principalID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count vaults by created_by: %w", err)
	}
	return n, nil
}
```

Note the deliberate absence of `AND deleted_at IS NULL`.

- [ ] **Step 5: Write the CountByCreatedBy test**

Add to `internal/repositories/vault_repository_test.go`, reusing the existing `newVaultTestDB` helper in that file:

```go
func TestVaultRepository_CountByCreatedBy_IncludesSoftDeleted(t *testing.T) {
	database := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(database, newTestVaultLogger(t))
	ctx := context.Background()
	owner := uuid.New()
	other := uuid.New()

	for _, name := range []string{"alpha", "beta"} {
		require.NoError(t, repo.Create(ctx, &model.Vault{
			ID: uuid.New(), Name: name, CreatedBy: owner, RetentionDays: 90,
		}))
	}
	require.NoError(t, repo.Create(ctx, &model.Vault{
		ID: uuid.New(), Name: "not-mine", CreatedBy: other, RetentionDays: 90,
	}))

	n, err := repo.CountByCreatedBy(ctx, database, owner)
	require.NoError(t, err)
	require.Equal(t, 2, n, "counts only this principal's vaults")

	_, err = database.Exec(
		`UPDATE vaults SET deleted_at = CURRENT_TIMESTAMP WHERE name = 'alpha'`)
	require.NoError(t, err)

	n, err = repo.CountByCreatedBy(ctx, database, owner)
	require.NoError(t, err)
	require.Equal(t, 2, n, "a soft-deleted vault still occupies a quota slot")
}
```

Adjust the `NewVaultRepository(...)` call to match its real signature in that file if it differs.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/repositories/ -run 'TestGrantRepository|TestVaultRepository_CountByCreatedBy' -v`
Expected: PASS

- [ ] **Step 7: Run the full suite and vet**

Run: `go build ./... && go vet ./... && go test ./internal/... ./model/`
Expected: PASS — nothing else in the tree references the new symbols yet, so nothing should regress.

- [ ] **Step 8: Commit**

```bash
git add internal/repositories/vault_provisioning_grant_repository.go \
        internal/repositories/vault_provisioning_grant_repository_test.go \
        internal/repositories/vault_repository.go \
        internal/repositories/vault_repository_test.go
git commit -S -m "feat(repo): add provisioning-grant repository and vault count"
```
