# Vault-Scope Rotation Policies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Vault-scope RocketVault's two rotation-policy tables (`rotation_policies` for secrets, `key_rotation_policies` for keys) so a role grant in one vault can no longer read, assign, or act on rotation policies belonging to another vault.

**Architecture:** Add a `vault_id` column to both tables (asymmetric backfill — see Global Constraints), collapse both repositories onto `model.Scope` using a new generic scoped-CRUD helper, thread `model.Scope` through the secrets rotation service (deleting its manual ownership checks in favor of scope-filtered reads), swap `KeyService`'s rotation-policy methods onto the newly scope-real repository, and retrofit `cmd/rotation.go` with `--vault` + `vaultcli.RequireDataAction`.

**Tech Stack:** Go 1.24, SQLite (dev) / PostgreSQL (prod), `github.com/mattn/go-sqlite3` for tests, `testify` (`require`/`assert`/`mock`), Cobra CLI.

**Spec:** `docs/superpowers/specs/2026-08-17-vault-scope-rotation-policies-design.md`

## Global Constraints

- `model.DefaultVaultID = "00000000-0000-0000-0000-00000000efa1"` — every hardcoded SQL literal for the default vault must use this exact value.
- Backfill is asymmetric: `rotation_policies` gets a blind `DEFAULT`-vault backfill (safe — it predates `vault_id` existing anywhere). `key_rotation_policies` gets a JOIN-derived backfill from its parent key's `vault_id` (required — it launched after keys were already vault-scoped, so some rows may already belong to a non-default vault).
- `KeyRotationPolicy.VaultID` is always derived from its parent key's own `vault_id`; it is never an independently-settable value.
- `internal/repositories/scope_predicate.go` (the existing `scopePredicate` function) is **not modified**. Existing `secret_repository.go` / `key_repository.go` / `certificate_repository.go` are **not modified**.
- CLI authorization for `rotation_policies` reuses existing `model.ActionSecretsSet` (writes) / `model.ActionSecretsReadMetadata` (reads) — no new `DataAction` constants.
- No new HTTP API is added for `rotation_policies`; it stays CLI-only.
- Verification gate for every task: `go build ./... && go test ./...` (this codebase's standing rule — `go vet` alone misses interface/mock signature mismatches).

---

### Task 1: DB migration — `vault_id` on both rotation-policy tables

**Files:**
- Modify: `internal/db/db.go` (`createOptimizedSchema` ~line 486, ~line 561; `migrateSchema` ~line 785, ~line 836)
- Test: `internal/db/rotation_vault_scope_migration_test.go` (new)

**Interfaces:**
- Consumes: nothing new — this task only touches schema.
- Produces: `rotation_policies.vault_id` and `key_rotation_policies.vault_id` columns, both `TEXT NOT NULL`, correctly backfilled, each with a `CREATE INDEX IF NOT EXISTS idx_<table>_vault_id`. Every later task assumes these columns exist and are correctly populated.

- [ ] **Step 1: Write the failing migration test**

Create `internal/db/rotation_vault_scope_migration_test.go`:

```go
// Regression test for the rotation_policies / key_rotation_policies vault_id
// migration. Proves migrateSchema adds the column to both tables on an
// old-shape database, that key_rotation_policies is backfilled from its
// parent key's real vault (not blindly defaulted), and that a second run is
// idempotent.
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

const defaultVaultID = "00000000-0000-0000-0000-00000000efa1"
const otherVaultID = "11111111-1111-1111-1111-111111111111"

func TestMigrateSchema_RotationPoliciesVaultID(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, err = conn.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL
		);
		CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE certificates (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE audit_logs (id TEXT PRIMARY KEY);
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, scheduled_purge_at TIMESTAMP NULL
		);
		-- keys pre-dates this migration's ADD COLUMN in real installs, but already
		-- has vault_id from the 2026-07-26 migration, which runs earlier in the
		-- same migrateSchema statement list.
		CREATE TABLE keys (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '`+defaultVaultID+`'
		);
		-- Old-shape rotation_policies: no vault_id column, has existing rows.
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
			description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		-- Old-shape key_rotation_policies: no vault_id column. One row's parent
		-- key (key-in-vault-b) is in a non-default vault.
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO rotation_policies (id, user_id, name, interval_days)
			VALUES ('11111111-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000001', 'p1', 30);
		INSERT INTO keys (id, name, vault_id) VALUES
			('33333333-0000-0000-0000-000000000001', 'key-in-default', '`+defaultVaultID+`'),
			('33333333-0000-0000-0000-000000000002', 'key-in-vault-b', '`+otherVaultID+`');
		INSERT INTO key_rotation_policies (id, key_id, user_id) VALUES
			('44444444-0000-0000-0000-000000000001', '33333333-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000001'),
			('44444444-0000-0000-0000-000000000002', '33333333-0000-0000-0000-000000000002', '22222222-0000-0000-0000-000000000001');
	`)
	require.NoError(t, err)

	require.False(t, columnExists(t, conn, "rotation_policies", "vault_id"))
	require.False(t, columnExists(t, conn, "key_rotation_policies", "vault_id"))

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.migrateSchema(conn), "first migrateSchema run should succeed")
	require.NoError(t, repo.migrateSchema(conn), "second migrateSchema run should be idempotent")

	require.True(t, columnExists(t, conn, "rotation_policies", "vault_id"))
	require.True(t, columnExists(t, conn, "key_rotation_policies", "vault_id"))

	// rotation_policies: blind default-vault backfill.
	var rpVault string
	require.NoError(t, conn.QueryRow(
		`SELECT vault_id FROM rotation_policies WHERE id = '11111111-0000-0000-0000-000000000001'`,
	).Scan(&rpVault))
	require.Equal(t, defaultVaultID, rpVault)

	// key_rotation_policies: JOIN-derived backfill, not blind default.
	var krpDefault, krpOther string
	require.NoError(t, conn.QueryRow(
		`SELECT vault_id FROM key_rotation_policies WHERE id = '44444444-0000-0000-0000-000000000001'`,
	).Scan(&krpDefault))
	require.Equal(t, defaultVaultID, krpDefault, "policy on default-vault key must backfill to the default vault")

	require.NoError(t, conn.QueryRow(
		`SELECT vault_id FROM key_rotation_policies WHERE id = '44444444-0000-0000-0000-000000000002'`,
	).Scan(&krpOther))
	require.Equal(t, otherVaultID, krpOther, "policy on vault-b key must backfill to vault b, not the default vault")
}

func TestMigrateSchema_KeyRotationPoliciesVaultIDIndexes(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(conn, SQLite), "fresh install should create both indexes directly")

	for _, idx := range []string{"idx_rotation_policies_vault_id", "idx_key_rotation_policies_vault_id"} {
		var name string
		row := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx)
		require.NoError(t, row.Scan(&name), "%s missing after fresh SetupSchema", idx)
	}
}
```

**Note on `SetupSchema`:** check its exact signature (`func (d *DBRepository) SetupSchema(db *sql.DB, dialect Dialect) error`, confirmed at `internal/db/db.go:185`) before running this step — it takes `*sql.DB` directly, matching what `sql.Open` returns above.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/db/... -run TestMigrateSchema_RotationPoliciesVaultID -v` and `go test ./internal/db/... -run TestMigrateSchema_KeyRotationPoliciesVaultIDIndexes -v`
Expected: both FAIL — `rotation_policies`/`key_rotation_policies` have no `vault_id` column yet, and the new indexes don't exist yet.

- [ ] **Step 3: Add `vault_id` to both `createOptimizedSchema` CREATE TABLE bodies**

In `internal/db/db.go`, inside `createOptimizedSchema` (~line 486), change:

```sql
CREATE TABLE IF NOT EXISTS key_rotation_policies (
    id                         TEXT PRIMARY KEY,
    key_id                     TEXT NOT NULL UNIQUE,
    user_id                    TEXT NOT NULL,
    vault_id                   TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
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
CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_vault_id ON key_rotation_policies(vault_id);
```

And ~line 561:

```sql
CREATE TABLE IF NOT EXISTS rotation_policies (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
    name TEXT NOT NULL,
    description TEXT,
    interval_days INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    reminder_days INTEGER NOT NULL DEFAULT 7,
    auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_user_id ON rotation_policies(user_id);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_enabled ON rotation_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_auto_rotate ON rotation_policies(auto_rotate);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_vault_id ON rotation_policies(vault_id);
```

- [ ] **Step 4: Add `vault_id` to the `migrateSchema` duplicate `key_rotation_policies` CREATE TABLE**

At ~line 785, add the same `vault_id` column to the `migrateSchema` copy of the `CREATE TABLE IF NOT EXISTS key_rotation_policies` body (identical edit to Step 3's first block, same file, second occurrence). This handles upgrades from a DB created before 2026-08-13 that never had this table at all.

- [ ] **Step 5: Add the ALTER TABLE / index / backfill statements to `migrateSchema`'s statement list**

In `internal/db/db.go`, in the `migrations := []string{...}` list inside `migrateSchema`, insert these four lines **immediately after** the existing `"ALTER TABLE certificates ADD COLUMN vault_id ..."` line (~line 836) and **before** `"ALTER TABLE access_policies ADD COLUMN vault_id NULL"` (~line 837). Ordering matters: `key_rotation_policies`'s backfill reads `keys.vault_id`, which must already exist — the existing `"ALTER TABLE keys ADD COLUMN vault_id ..."` two lines above guarantees that.

```go
"ALTER TABLE key_rotation_policies ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
"ALTER TABLE rotation_policies ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
"CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_vault_id ON key_rotation_policies(vault_id)",
"CREATE INDEX IF NOT EXISTS idx_rotation_policies_vault_id ON rotation_policies(vault_id)",
"UPDATE key_rotation_policies SET vault_id = (SELECT vault_id FROM keys WHERE keys.id = key_rotation_policies.key_id) WHERE key_id IN (SELECT id FROM keys)",
```

The plain `ALTER TABLE`s are caught by the existing `isDuplicateColumnError` guard on re-run (idempotent). The `UPDATE` is naturally idempotent — re-running it just resets `vault_id` to the value it should already have.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/db/... -run 'TestMigrateSchema_RotationPoliciesVaultID|TestMigrateSchema_KeyRotationPoliciesVaultIDIndexes' -v`
Expected: PASS

- [ ] **Step 7: Run the full existing DB test suite to check for regressions**

Run: `go test ./internal/db/... -v`
Expected: PASS — in particular `TestMigrateSchema_AddsAssignmentIDIdempotent` and every other existing `migrateSchema` test must stay green, since this task only appends new statements.

- [ ] **Step 8: Commit**

```bash
git add internal/db/db.go internal/db/rotation_vault_scope_migration_test.go
git commit -m "feat(db): add vault_id to rotation_policies and key_rotation_policies"
```

---

### Task 2: Generic scoped-CRUD repository helpers

**Files:**
- Create: `internal/repositories/scoped_crud.go`
- Test: `internal/repositories/scoped_crud_test.go`

**Interfaces:**
- Consumes: `model.Scope`, the existing unexported `scopePredicate(scope model.Scope) (string, []any, error)` in `internal/repositories/scope_predicate.go`, `rocketvault/internal/db.DBTX` (the `ExecContext`/`QueryContext`/`QueryRowContext` subset interface, `internal/db/txhelper.go:11`).
- Produces (consumed by Tasks 4 and 5):
  ```go
  func ScopedGet[T any](ctx context.Context, conn db.DBTX, query string, args []any, scope model.Scope, scan func(*sql.Row) (T, error)) (T, error)
  func ScopedExec(ctx context.Context, conn db.DBTX, query string, args []any, scope model.Scope) (sql.Result, error)
  func ScopedList[T any](ctx context.Context, conn db.DBTX, query string, args []any, scope model.Scope, scan func(*sql.Rows) (T, error)) ([]T, error)
  ```
  `query` must be a `SELECT`/`UPDATE`/`DELETE` whose `WHERE` clause is already complete except for the trailing scope predicate — these helpers append `" AND " + predicate` and the predicate's bind args after `args`.

- [ ] **Step 1: Write the failing tests**

Create `internal/repositories/scoped_crud_test.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/model"
)

func setupScopedCRUDTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = conn.Exec(`CREATE TABLE widgets (id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, name TEXT NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec
	return conn
}

func scanWidgetName(row *sql.Row) (string, error) {
	var name string
	err := row.Scan(&name)
	return name, err
}

func TestScopedGet_VaultScopeFiltersByVault(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	vaultA, vaultB := uuid.New(), uuid.New()
	id := uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?)`, id.String(), vaultA.String(), "widget-a")
	require.NoError(t, err)

	ctx := context.Background()
	name, err := ScopedGet(ctx, conn, `SELECT name FROM widgets WHERE id = ?`, []any{id.String()},
		model.NewVaultScope(vaultA, uuid.New()), scanWidgetName)
	require.NoError(t, err)
	require.Equal(t, "widget-a", name)

	_, err = ScopedGet(ctx, conn, `SELECT name FROM widgets WHERE id = ?`, []any{id.String()},
		model.NewVaultScope(vaultB, uuid.New()), scanWidgetName)
	require.ErrorIs(t, err, sql.ErrNoRows, "a widget in vault A must not be visible under vault B's scope")
}

func TestScopedGet_AdminScopeSeesEverything(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	id := uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?)`, id.String(), uuid.New().String(), "widget-x")
	require.NoError(t, err)

	name, err := ScopedGet(context.Background(), conn, `SELECT name FROM widgets WHERE id = ?`, []any{id.String()},
		model.NewAdminScope(uuid.New()), scanWidgetName)
	require.NoError(t, err)
	require.Equal(t, "widget-x", name)
}

func TestScopedGet_InvalidScopeReturnsErrInvalidScope(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	_, err := ScopedGet(context.Background(), conn, `SELECT name FROM widgets WHERE id = ?`, []any{uuid.New().String()},
		model.Scope{}, scanWidgetName)
	require.ErrorIs(t, err, ErrInvalidScope)
}

func TestScopedExec_VaultScopeOnlyAffectsOwnVault(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	vaultA, vaultB := uuid.New(), uuid.New()
	id := uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?)`, id.String(), vaultA.String(), "widget-a")
	require.NoError(t, err)

	ctx := context.Background()
	result, err := ScopedExec(ctx, conn, `UPDATE widgets SET name = ? WHERE id = ?`, []any{"renamed", id.String()},
		model.NewVaultScope(vaultB, uuid.New()))
	require.NoError(t, err)
	n, _ := result.RowsAffected()
	require.Equal(t, int64(0), n, "update scoped to the wrong vault must affect zero rows")

	result, err = ScopedExec(ctx, conn, `UPDATE widgets SET name = ? WHERE id = ?`, []any{"renamed", id.String()},
		model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	n, _ = result.RowsAffected()
	require.Equal(t, int64(1), n)
}

func TestScopedList_VaultScopeFiltersRows(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	vaultA, vaultB := uuid.New(), uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?), (?, ?, ?)`,
		uuid.New().String(), vaultA.String(), "a1",
		uuid.New().String(), vaultB.String(), "b1")
	require.NoError(t, err)

	rows, err := ScopedList(context.Background(), conn, `SELECT name FROM widgets WHERE 1=1`, nil,
		model.NewVaultScope(vaultA, uuid.New()), func(r *sql.Rows) (string, error) {
			var name string
			return name, r.Scan(&name)
		})
	require.NoError(t, err)
	require.Equal(t, []string{"a1"}, rows)
}
```

Use `rvdb "rocketvault/internal/db"` only if the helper signature needs the package name in the test; adjust the import if `db.DBTX` is satisfied directly by `*sql.DB` (it is — `*sql.DB` implements `ExecContext`/`QueryContext`/`QueryRowContext`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/repositories/... -run TestScoped -v`
Expected: FAIL with "undefined: ScopedGet" (and siblings) — the file doesn't exist yet.

- [ ] **Step 3: Implement `scoped_crud.go`**

```go
package repositories

import (
	"context"
	"database/sql"

	rvdb "rocketvault/internal/db"
	"rocketvault/model"
)

// ScopedGet runs query (a "SELECT ... WHERE <predicate>" missing only its
// trailing scope clause) with the scope predicate appended, and scans the
// single resulting row with scan. Returns ErrInvalidScope for an
// unauthorizable scope, sql.ErrNoRows for no match — including a match that
// exists but is outside the given scope, which is indistinguishable by
// design (no existence oracle).
func ScopedGet[T any](ctx context.Context, conn rvdb.DBTX, query string, args []any, scope model.Scope, scan func(*sql.Row) (T, error)) (T, error) {
	var zero T
	predicate, predArgs, err := scopePredicate(scope)
	if err != nil {
		return zero, err
	}
	row := conn.QueryRowContext(ctx, query+" AND "+predicate, append(append([]any{}, args...), predArgs...)...)
	return scan(row)
}

// ScopedExec runs query (an "UPDATE ..." or "DELETE ..." missing only its
// trailing scope clause) with the scope predicate appended.
func ScopedExec(ctx context.Context, conn rvdb.DBTX, query string, args []any, scope model.Scope) (sql.Result, error) {
	predicate, predArgs, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}
	return conn.ExecContext(ctx, query+" AND "+predicate, append(append([]any{}, args...), predArgs...)...)
}

// ScopedList runs query (a "SELECT ... WHERE <predicate>" missing only its
// trailing scope clause) with the scope predicate appended, scanning every
// row with scan.
func ScopedList[T any](ctx context.Context, conn rvdb.DBTX, query string, args []any, scope model.Scope, scan func(*sql.Rows) (T, error)) ([]T, error) {
	predicate, predArgs, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}
	rows, err := conn.QueryContext(ctx, query+" AND "+predicate, append(append([]any{}, args...), predArgs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/repositories/... -run TestScoped -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/scoped_crud.go internal/repositories/scoped_crud_test.go
git commit -m "feat(repositories): add generic scoped-CRUD helpers"
```

---

### Task 3: Add `VaultID` to the two rotation-policy domain types

**Files:**
- Modify: `model/rotation.go`
- Modify: `model/key_rotation_policy.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `model.RotationPolicy.VaultID uuid.UUID` and `model.KeyRotationPolicy.VaultID uuid.UUID`, both consumed starting in Task 4/5.

- [ ] **Step 1: Add the field to `model.RotationPolicy`**

In `model/rotation.go`, change:

```go
// RotationPolicy represents a rotation policy for secrets.
type RotationPolicy struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	VaultID      uuid.UUID `json:"vault_id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	IntervalDays int       `json:"interval_days"`
	Enabled      bool      `json:"enabled"`
	ReminderDays int       `json:"reminder_days"`
	AutoRotate   bool      `json:"auto_rotate"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
```

- [ ] **Step 2: Add the field to `model.KeyRotationPolicy`**

In `model/key_rotation_policy.go`, change:

```go
type KeyRotationPolicy struct {
	ID                     uuid.UUID `json:"id" db:"id"`
	KeyID                  uuid.UUID `json:"key_id" db:"key_id"`
	UserID                 uuid.UUID `json:"user_id" db:"user_id"`
	VaultID                uuid.UUID `json:"vault_id" db:"vault_id"`
	RotateAfterDays        int       `json:"rotate_after_days" db:"rotate_after_days"`
	NotifyBeforeExpiryDays int       `json:"notify_before_expiry_days" db:"notify_before_expiry_days"`
	ExpiryDays             int       `json:"expiry_days" db:"expiry_days"`
	Enabled                bool      `json:"enabled" db:"enabled"`
	CreatedAt              time.Time `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time `json:"updated_at" db:"updated_at"`
}
```

- [ ] **Step 3: Build to confirm nothing depends on struct literal field order**

Run: `go build ./...`
Expected: PASS. (Both structs are always constructed with named fields throughout the codebase, confirmed in Tasks 1/2's exploration — a positional-literal build break here would indicate a call site this plan missed and must be investigated before continuing.)

- [ ] **Step 4: Commit**

```bash
git add model/rotation.go model/key_rotation_policy.go
git commit -m "feat(model): add VaultID to RotationPolicy and KeyRotationPolicy"
```

---

### Task 4: `rotation_repository.go` — collapse onto `model.Scope`

**Files:**
- Modify: `internal/repositories/rotation_repository.go`
- Test: `internal/repositories/rotation_repository_test.go` (new — no test file exists for this repository today; it has only ever been exercised indirectly through a service-layer mock)

**Interfaces:**
- Consumes: `model.Scope`, `model.RotationPolicy.VaultID` (Task 3), `ScopedGet`/`ScopedExec`/`ScopedList` (Task 2).
- Produces (consumed by Task 6):
  ```go
  type RotationPolicyRepositoryInterface interface {
      Create(ctx context.Context, policy *model.RotationPolicy) error
      Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error)
      Update(ctx context.Context, policy *model.RotationPolicy, scope model.Scope) error
      Delete(ctx context.Context, id uuid.UUID, scope model.Scope) error
      List(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error)

      AssignToSecret(ctx context.Context, secretID, policyID uuid.UUID, assignedAt, nextRotationAt time.Time) error
      RemoveFromSecret(ctx context.Context, secretID, policyID uuid.UUID) error
      GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]model.SecretPolicy, error)
      GetPoliciesForSecret(ctx context.Context, secretID uuid.UUID) ([]model.RotationPolicy, error)
      UpdateSecretPolicyRotation(ctx context.Context, secretID, policyID uuid.UUID, lastRotatedAt, nextRotationAt time.Time) error

      RecordRotation(ctx context.Context, history *model.RotationHistory) error
      GetRotationHistory(ctx context.Context, secretID uuid.UUID) ([]model.RotationHistory, error)

      GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error)
      GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error)

      CreateReminder(ctx context.Context, reminder *model.RotationReminder) error
      UpdateReminder(ctx context.Context, reminder *model.RotationReminder) error
      GetReminderBySecret(ctx context.Context, secretID, policyID uuid.UUID, reminderType string) (*model.RotationReminder, error)
  }
  ```
  `AssignToSecret`/`RemoveFromSecret`/`GetSecretPolicies`/`GetPoliciesForSecret`/`UpdateSecretPolicyRotation`/`RecordRotation`/`GetRotationHistory`/`CreateReminder`/`UpdateReminder`/`GetReminderBySecret` are unchanged from today — they operate on the `secret_policies`/`rotation_reminders`/`secret_rotation_history` join tables, which gain no `vault_id` of their own (see spec §5.2).

- [ ] **Step 1: Write the failing tests**

Create `internal/repositories/rotation_repository_test.go`:

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

func setupRotationPolicyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, vault_id TEXT NOT NULL,
			name TEXT NOT NULL, description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE secret_policies (
			secret_id TEXT NOT NULL, policy_id TEXT NOT NULL,
			assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_rotated_at TIMESTAMP, next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id)
		);
		CREATE TABLE rotation_reminders (
			id TEXT PRIMARY KEY, secret_id TEXT NOT NULL, policy_id TEXT NOT NULL,
			reminder_type TEXT NOT NULL, sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			next_reminder_at TIMESTAMP, acknowledged BOOLEAN NOT NULL DEFAULT FALSE
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

func testLog() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.ErrorLevel)
	return logging.NewLogger(l)
}

func newTestPolicy(vaultID uuid.UUID) *model.RotationPolicy {
	now := time.Now()
	return &model.RotationPolicy{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, Name: "policy",
		IntervalDays: 30, Enabled: true, ReminderDays: 5, CreatedAt: now, UpdatedAt: now,
	}
}

func TestRotationRepository_Read_CrossVaultDenied(t *testing.T) {
	sqlDB := setupRotationPolicyTestDB(t)
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	policy := newTestPolicy(vaultA)
	require.NoError(t, repo.Create(ctx, policy))

	got, err := repo.Read(ctx, policy.ID, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Equal(t, policy.Name, got.Name)

	_, err = repo.Read(ctx, policy.ID, model.NewVaultScope(vaultB, uuid.New()))
	require.Error(t, err, "a policy in vault A must not be readable under vault B's scope")
}

func TestRotationRepository_Update_CrossVaultDenied(t *testing.T) {
	sqlDB := setupRotationPolicyTestDB(t)
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	policy := newTestPolicy(vaultA)
	require.NoError(t, repo.Create(ctx, policy))

	policy.Name = "renamed"
	err := repo.Update(ctx, policy, model.NewVaultScope(vaultB, uuid.New()))
	require.Error(t, err, "update scoped to the wrong vault must fail")

	err = repo.Update(ctx, policy, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)

	got, err := repo.Read(ctx, policy.ID, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Equal(t, "renamed", got.Name)
}

func TestRotationRepository_Delete_CrossVaultDenied(t *testing.T) {
	sqlDB := setupRotationPolicyTestDB(t)
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	policy := newTestPolicy(vaultA)
	require.NoError(t, repo.Create(ctx, policy))

	require.Error(t, repo.Delete(ctx, policy.ID, model.NewVaultScope(vaultB, uuid.New())))
	require.NoError(t, repo.Delete(ctx, policy.ID, model.NewVaultScope(vaultA, uuid.New())))
	_, err := repo.Read(ctx, policy.ID, model.NewAdminScope(uuid.New()))
	require.Error(t, err)
}

func TestRotationRepository_List_FiltersByVault(t *testing.T) {
	sqlDB := setupRotationPolicyTestDB(t)
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	require.NoError(t, repo.Create(ctx, newTestPolicy(vaultA)))
	require.NoError(t, repo.Create(ctx, newTestPolicy(vaultB)))

	listA, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Len(t, listA, 1)

	listAll, err := repo.List(ctx, model.NewAdminScope(uuid.New()))
	require.NoError(t, err)
	require.Len(t, listAll, 2)
}

func TestRotationRepository_GetDueRotations_FiltersByVault(t *testing.T) {
	sqlDB := setupRotationPolicyTestDB(t)
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	policyA := newTestPolicy(vaultA)
	policyB := newTestPolicy(vaultB)
	require.NoError(t, repo.Create(ctx, policyA))
	require.NoError(t, repo.Create(ctx, policyB))

	secretA, secretB := uuid.New(), uuid.New()
	past := time.Now().Add(-time.Hour)
	require.NoError(t, repo.AssignToSecret(ctx, secretA, policyA.ID, time.Now(), past))
	require.NoError(t, repo.AssignToSecret(ctx, secretB, policyB.ID, time.Now(), past))

	dueA, err := repo.GetDueRotations(ctx, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Len(t, dueA, 1)
	require.Equal(t, secretA, dueA[0].SecretID)

	dueAll, err := repo.GetDueRotations(ctx, model.NewAdminScope(uuid.New()))
	require.NoError(t, err)
	require.Len(t, dueAll, 2)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/repositories/... -run TestRotationRepository -v`
Expected: FAIL to compile — `Read`/`Update`/`Delete`/`List`/`GetDueRotations` don't have these signatures yet.

- [ ] **Step 3: Update the interface and implementation**

In `internal/repositories/rotation_repository.go`:

1. Replace the interface (per the Produces block above).
2. Update `Create` to insert `policy.VaultID`:
   ```go
   func (r *rotationPolicyRepository) Create(ctx context.Context, policy *model.RotationPolicy) error {
       query := `
           INSERT INTO rotation_policies (id, user_id, vault_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       `
       _, err := r.db.ExecContext(ctx, query,
           policy.ID.String(), policy.UserID.String(), policy.VaultID.String(),
           policy.Name, policy.Description, policy.IntervalDays, policy.Enabled,
           policy.ReminderDays, policy.AutoRotate, policy.CreatedAt, policy.UpdatedAt,
       )
       // ... unchanged error handling/logging
   }
   ```
3. Replace `Read`, adding `vault_id` to the SELECT list and using `ScopedGet`:
   ```go
   func (r *rotationPolicyRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error) {
       query := `
           SELECT id, user_id, vault_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at
           FROM rotation_policies WHERE id = ?
       `
       policy, err := ScopedGet(ctx, r.db, query, []any{id.String()}, scope, scanRotationPolicyRow)
       if err != nil {
           if errors.Is(err, sql.ErrNoRows) {
               return nil, fmt.Errorf("rotation policy not found")
           }
           r.log.WithError(err).Error("Failed to read rotation policy")
           return nil, fmt.Errorf("failed to read rotation policy: %w", err)
       }
       return policy, nil
   }

   func scanRotationPolicyRow(row *sql.Row) (*model.RotationPolicy, error) {
       var policy model.RotationPolicy
       var id, userID, vaultID string
       if err := row.Scan(&id, &userID, &vaultID, &policy.Name, &policy.Description,
           &policy.IntervalDays, &policy.Enabled, &policy.ReminderDays, &policy.AutoRotate,
           &policy.CreatedAt, &policy.UpdatedAt); err != nil {
           return nil, err
       }
       policy.ID, _ = uuid.Parse(id)
       policy.UserID, _ = uuid.Parse(userID)
       policy.VaultID, _ = uuid.Parse(vaultID)
       return &policy, nil
   }
   ```
4. Replace `Update` and `Delete` with `ScopedExec`, checking `RowsAffected`:
   ```go
   func (r *rotationPolicyRepository) Update(ctx context.Context, policy *model.RotationPolicy, scope model.Scope) error {
       query := `
           UPDATE rotation_policies
           SET name = ?, description = ?, interval_days = ?, enabled = ?, reminder_days = ?, auto_rotate = ?, updated_at = ?
           WHERE id = ?
       `
       result, err := ScopedExec(ctx, r.db, query, []any{
           policy.Name, policy.Description, policy.IntervalDays, policy.Enabled,
           policy.ReminderDays, policy.AutoRotate, policy.UpdatedAt, policy.ID.String(),
       }, scope)
       if err != nil {
           r.log.WithError(err).Error("Failed to update rotation policy")
           return fmt.Errorf("failed to update rotation policy: %w", err)
       }
       if n, _ := result.RowsAffected(); n == 0 {
           return fmt.Errorf("rotation policy not found")
       }
       return nil
   }

   func (r *rotationPolicyRepository) Delete(ctx context.Context, id uuid.UUID, scope model.Scope) error {
       result, err := ScopedExec(ctx, r.db, `DELETE FROM rotation_policies WHERE id = ?`, []any{id.String()}, scope)
       if err != nil {
           r.log.WithError(err).Error("Failed to delete rotation policy")
           return fmt.Errorf("failed to delete rotation policy: %w", err)
       }
       if n, _ := result.RowsAffected(); n == 0 {
           return fmt.Errorf("rotation policy not found")
       }
       return nil
   }
   ```
5. Replace `ListByUser` with `List`, using `ScopedList`:
   ```go
   func (r *rotationPolicyRepository) List(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) {
       query := `
           SELECT id, user_id, vault_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at
           FROM rotation_policies WHERE 1=1
       `
       policies, err := ScopedList(ctx, r.db, query, nil, scope, func(rows *sql.Rows) (model.RotationPolicy, error) {
           var policy model.RotationPolicy
           var id, userID, vaultID string
           if err := rows.Scan(&id, &userID, &vaultID, &policy.Name, &policy.Description,
               &policy.IntervalDays, &policy.Enabled, &policy.ReminderDays, &policy.AutoRotate,
               &policy.CreatedAt, &policy.UpdatedAt); err != nil {
               return policy, err
           }
           policy.ID, _ = uuid.Parse(id)
           policy.UserID, _ = uuid.Parse(userID)
           policy.VaultID, _ = uuid.Parse(vaultID)
           return policy, nil
       })
       if err != nil {
           r.log.WithError(err).Error("Failed to list rotation policies")
           return nil, fmt.Errorf("failed to list rotation policies: %w", err)
       }
       return policies, nil
   }
   ```
6. Replace `GetDueRotations`, joining to `rotation_policies` aliased `rp` (the only table in the join with a `vault_id` column, so the unqualified predicate `ScopedList` appends is unambiguous):
   ```go
   func (r *rotationPolicyRepository) GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error) {
       query := `
           SELECT sp.secret_id, sp.policy_id, sp.assigned_at, sp.last_rotated_at, sp.next_rotation_at
           FROM secret_policies sp
           JOIN rotation_policies rp ON sp.policy_id = rp.id
           WHERE rp.enabled = TRUE AND sp.next_rotation_at <= ?
       `
       return ScopedList(ctx, r.db, query, []any{time.Now()}, scope, scanSecretPolicyRow)
   }
   ```
   (Extract the existing inline `Scan` block from the old `GetDueRotations` into a `scanSecretPolicyRow(rows *sql.Rows) (model.SecretPolicy, error)` helper — same field list as today, just moved out of the loop body so `ScopedList` can call it.)
7. Same treatment for `GetUpcomingReminders`, joining to `rotation_policies rp` and passing `scope` through `ScopedList`.
8. Leave `AssignToSecret`, `RemoveFromSecret`, `GetSecretPolicies`, `GetPoliciesForSecret`, `UpdateSecretPolicyRotation`, `RecordRotation`, `GetRotationHistory`, `CreateReminder`, `UpdateReminder`, `GetReminderBySecret` untouched — they don't operate on `rotation_policies.vault_id` directly (per spec §5.2, `secret_policies`/`rotation_reminders`/`secret_rotation_history` gain no `vault_id`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/repositories/... -run TestRotationRepository -v`
Expected: PASS

- [ ] **Step 5: Build the whole module to find broken callers**

Run: `go build ./...`
Expected: FAIL — `internal/services/secrets/rotation_service.go` and its test still call the old method signatures. This is expected; Task 6 fixes it. Confirm the failures are confined to `internal/services/secrets/...` before moving on (nothing in `internal/repositories/...` or elsewhere should fail).

- [ ] **Step 6: Commit**

```bash
git add internal/repositories/rotation_repository.go internal/repositories/rotation_repository_test.go
git commit -m "feat(repositories): collapse RotationPolicyRepository onto model.Scope"
```

---

### Task 5: `key_rotation_policy_repository.go` — real vault filtering

**Files:**
- Modify: `internal/repositories/key_rotation_policy_repository.go`
- Modify: `internal/repositories/key_rotation_policy_repository_test.go` (existing — update its inline `key_rotation_policies` schema and callers)

**Interfaces:**
- Consumes: `model.Scope`, `model.KeyRotationPolicy.VaultID` (Task 3), `ScopedGet`/`ScopedExec` (Task 2).
- Produces (consumed by Task 7):
  ```go
  type KeyRotationPolicyRepositoryInterface interface {
      Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error
      GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error)
      DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
  }
  ```
  `GetByKeyIDAny`/`DeleteByKeyIDAny` and the old owner-scoped `GetByKeyID(ctx, keyID, userID)`/`DeleteByKeyID` are removed entirely — confirmed unused outside this repository and `key_service.go` (Task 7 updates the only caller).

- [ ] **Step 1: Update the existing test file's schema and write new cross-vault tests**

In `internal/repositories/key_rotation_policy_repository_test.go`:

1. Add `vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',` to `setupKeyRotationPolicyTestDB`'s inline `key_rotation_policies` CREATE TABLE (right after `user_id`), matching the `keys` table's existing `vault_id` column in the same helper.
2. Every existing test that constructs a `model.KeyRotationPolicy{...}` literal (via named fields, confirmed in Task 3 Step 3) needs a `VaultID: ...` value — set it to match the parent key's vault in each test's fixture.
3. Every existing call to `repo.GetByKeyID(ctx, keyID, userID)` / `DeleteByKeyID(ctx, keyID, userID)` / `GetByKeyIDAny(ctx, keyID)` / `DeleteByKeyIDAny(ctx, keyID)` becomes `repo.GetByKeyID(ctx, keyID, scope)` / `repo.DeleteByKeyID(ctx, keyID, scope)`, constructing `scope := model.NewVaultScope(vaultID, uuid.New())` from each test's own seeded vault.
4. Add two new tests:

```go
func TestGetByKeyID_CrossVaultDenied(t *testing.T) {
	sqlDB := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	keyID, userID := uuid.New(), uuid.New()
	_, err := sqlDB.Exec(`INSERT INTO keys (id, user_id, vault_id, name, value, type) VALUES (?, ?, ?, 'k', 'v', 'RSA')`,
		keyID.String(), userID.String(), vaultA.String())
	require.NoError(t, err)

	now := time.Now()
	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultA,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	_, err = repo.GetByKeyID(ctx, keyID, model.NewVaultScope(vaultB, uuid.New()))
	require.Error(t, err, "a policy on a vault-A key must not be readable under vault B's scope")

	got, err := repo.GetByKeyID(ctx, keyID, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Equal(t, policy.ID, got.ID)
}

func TestDeleteByKeyID_CrossVaultDenied(t *testing.T) {
	sqlDB := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	keyID, userID := uuid.New(), uuid.New()
	_, err := sqlDB.Exec(`INSERT INTO keys (id, user_id, vault_id, name, value, type) VALUES (?, ?, ?, 'k', 'v', 'RSA')`,
		keyID.String(), userID.String(), vaultA.String())
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, repo.Upsert(ctx, &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultA,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}))

	require.Error(t, repo.DeleteByKeyID(ctx, keyID, model.NewVaultScope(vaultB, uuid.New())))
	require.NoError(t, repo.DeleteByKeyID(ctx, keyID, model.NewVaultScope(vaultA, uuid.New())))
}
```

(Check the file's existing imports — `rvdb`, `model`, `uuid`, `time`, `require`, `context` are already imported per the file excerpt read during planning; add only what's missing.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/repositories/... -run 'TestGetByKeyID_CrossVaultDenied|TestDeleteByKeyID_CrossVaultDenied' -v`
Expected: FAIL to compile — `GetByKeyID`/`DeleteByKeyID` don't take a `model.Scope` yet, and the test schema has no `vault_id` column.

- [ ] **Step 3: Update the interface and implementation**

In `internal/repositories/key_rotation_policy_repository.go`:

```go
type KeyRotationPolicyRepositoryInterface interface {
	// Upsert inserts or replaces the policy for a key. policy.VaultID must be
	// the parent key's own vault — callers derive it from the key, never
	// supply it independently.
	Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error
	// GetByKeyID retrieves the policy for a key, scoped to a vault.
	GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error)
	// DeleteByKeyID removes the policy for a key, scoped to a vault.
	DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
}
```

```go
func (r *KeyRotationPolicyRepository) Upsert(ctx context.Context, p *model.KeyRotationPolicy) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO key_rotation_policies
			(id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
			 expiry_days, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key_id) DO UPDATE SET
			rotate_after_days         = excluded.rotate_after_days,
			notify_before_expiry_days = excluded.notify_before_expiry_days,
			expiry_days               = excluded.expiry_days,
			enabled                   = excluded.enabled,
			updated_at                = excluded.updated_at`,
		p.ID.String(), p.KeyID.String(), p.UserID.String(), p.VaultID.String(),
		p.RotateAfterDays, p.NotifyBeforeExpiryDays, p.ExpiryDays, p.Enabled,
		p.CreatedAt, p.UpdatedAt,
	)
	return err
}

func (r *KeyRotationPolicyRepository) GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	query := `
		SELECT id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, created_at, updated_at
		FROM key_rotation_policies WHERE key_id = ?
	`
	return ScopedGet(ctx, r.db, query, []any{keyID.String()}, scope, scanKeyRotationPolicyRow)
}

func (r *KeyRotationPolicyRepository) DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	result, err := ScopedExec(ctx, r.db, "DELETE FROM key_rotation_policies WHERE key_id = ?", []any{keyID.String()}, scope)
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

func scanKeyRotationPolicyRow(row *sql.Row) (*model.KeyRotationPolicy, error) {
	var p model.KeyRotationPolicy
	var idStr, keyIDStr, userIDStr, vaultIDStr string
	if err := row.Scan(&idStr, &keyIDStr, &userIDStr, &vaultIDStr,
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
	if p.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return nil, err
	}
	return &p, nil
}
```

Delete `GetByKeyIDAny`, `DeleteByKeyIDAny`, and the old owner-scoped `GetByKeyID(ctx, keyID, userID)`/`DeleteByKeyID` bodies entirely — they're replaced by the two methods above.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/repositories/... -run 'TestGetByKeyID_CrossVaultDenied|TestDeleteByKeyID_CrossVaultDenied' -v`, then the full file: `go test ./internal/repositories/... -run KeyRotationPolicy -v`
Expected: PASS

- [ ] **Step 5: Build the whole module to find broken callers**

Run: `go build ./...`
Expected: FAIL — `internal/services/keys/key_service.go` still calls `GetByKeyIDAny`/`DeleteByKeyIDAny`. Expected; Task 7 fixes it. Confirm no other package fails.

- [ ] **Step 6: Commit**

```bash
git add internal/repositories/key_rotation_policy_repository.go internal/repositories/key_rotation_policy_repository_test.go
git commit -m "feat(repositories): filter KeyRotationPolicyRepository by vault_id"
```

---

### Task 6: `rotation_service.go` — thread `model.Scope`, delete manual ownership checks

**Files:**
- Modify: `internal/services/secrets/rotation_service.go`
- Modify: `internal/services/secrets/rotation_service_test.go` (existing — update `mockRotationPolicyRepo` and every call site)
- Modify: `internal/services/secrets/scheduler_service.go` (its two callers of the changed methods)

**Interfaces:**
- Consumes: `RotationPolicyRepositoryInterface` (Task 4).
- Produces (consumed by Task 8 and by `scheduler_service.go`):
  ```go
  type RotationServiceInterface interface {
      CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*model.RotationPolicy, error)
      GetPolicy(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error)
      UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (*model.RotationPolicy, error)
      DeletePolicy(ctx context.Context, id uuid.UUID, scope model.Scope) error
      ListPolicies(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error)

      AssignPolicyToSecret(ctx context.Context, req AssignPolicyRequest) error
      RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, scope model.Scope) error
      GetSecretPolicies(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationPolicy, error)

      PerformManualRotation(ctx context.Context, req ManualRotationRequest) error
      GetRotationHistory(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationHistory, error)
      GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error)

      CreateRotationReminder(ctx context.Context, req CreateReminderRequest) error
      GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error)
      AcknowledgeReminder(ctx context.Context, reminderID, secretID uuid.UUID, scope model.Scope) error
  }
  ```
  `CreatePolicyRequest`/`UpdatePolicyRequest`/`AssignPolicyRequest`/`ManualRotationRequest` gain a `Scope model.Scope` field replacing `UserID uuid.UUID`. `ListUserPolicies` is renamed `ListPolicies` to match `List` on the repository (Task 4) and avoid implying user-scoping.

  **Design decision, not literally what the spec's §6 wrote:** the spec proposed a separate `ErrPolicyVaultMismatch` check for `AssignPolicyToSecret`. Reading both the secret and the policy under the *same* `req.Scope` makes that check structurally redundant — a policy or secret outside `req.Scope`'s vault fails its own scoped read before any comparison would run. This task implements the simpler, equivalent mechanism (see Step 3) instead of adding a new error type; note this in the task's commit message so it isn't a silent deviation from the spec.

- [ ] **Step 1: Update `rotation_service_test.go`'s mock and call sites to compile against the target interface**

In `internal/services/secrets/rotation_service_test.go`, update `mockRotationPolicyRepo` (a hand-written `testify/mock` implementing `RotationPolicyRepositoryInterface`) to match Task 4's new interface: `Read`/`Update`/`Delete` gain a `scope model.Scope` parameter, `ListByUser` becomes `List(ctx, scope)`, `GetDueRotations`/`GetUpcomingReminders` take `scope` instead of `userID`. Update every `mockRotationPolicyRepo.On(...)` call in this file's test table to match the new argument lists, and every direct call to the service under test (`rotationService.GetPolicy(ctx, id)` → `rotationService.GetPolicy(ctx, id, scope)`, etc.) to pass a `model.Scope` built via `model.NewVaultScope(vaultID, userID)` from each test's fixture data.

This step doesn't need to compile yet — Step 3 changes the service, and only once both the mock and the service agree does the package build. Write the updated test file now so Step 2 shows the real, current failure.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/secrets/... -run TestRotation -v`
Expected: FAIL to compile — `rotationService` doesn't implement the new `RotationServiceInterface` shape yet.

- [ ] **Step 3: Update `rotation_service.go`**

Apply this pattern to every method (concrete example for the three representative shapes — repeat the same transformation for the rest):

**Simple scoped passthrough** (`GetPolicy`, `DeletePolicy`, `ListPolicies`, `GetRotationHistory` on the policy side, `GetDueRotations`, `GetUpcomingReminders`):
```go
func (s *rotationService) GetPolicy(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error) {
	policy, err := s.rotationRepo.Read(ctx, id, scope)
	if err != nil {
		s.log.WithError(err).WithField("policy_id", id).Error("Failed to get rotation policy")
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}
	return policy, nil
}

func (s *rotationService) DeletePolicy(ctx context.Context, id uuid.UUID, scope model.Scope) error {
	if err := s.rotationRepo.Delete(ctx, id, scope); err != nil {
		s.log.WithError(err).WithField("policy_id", id).Error("Failed to delete rotation policy")
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}
	s.log.WithFields(map[string]interface{}{"policy_id": id, "actor": scope.ActorID()}).Info("Rotation policy deleted successfully")
	return nil
}

func (s *rotationService) ListPolicies(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) {
	policies, err := s.rotationRepo.List(ctx, scope)
	if err != nil {
		s.log.WithError(err).Error("Failed to list rotation policies")
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	return policies, nil
}
```
Delete the manual `if existingPolicy.UserID != req.UserID { return ... }` / `if policy.UserID != callerID { ... }` checks that used to follow an unscoped `Read` in the old `UpdatePolicy`/`DeletePolicy` — the scoped `Read`/`Delete` call is now the check.

**Read-then-write under the same scope** (`UpdatePolicy`):
```go
func (s *rotationService) UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (*model.RotationPolicy, error) {
	existingPolicy, err := s.rotationRepo.Read(ctx, req.ID, req.Scope)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}
	if req.ReminderDays >= req.IntervalDays {
		return nil, fmt.Errorf("reminder days (%d) must be less than interval days (%d)", req.ReminderDays, req.IntervalDays)
	}
	policy := &model.RotationPolicy{
		ID: req.ID, UserID: existingPolicy.UserID, VaultID: existingPolicy.VaultID,
		Name: req.Name, Description: req.Description, IntervalDays: req.IntervalDays,
		Enabled: req.Enabled, ReminderDays: req.ReminderDays, AutoRotate: req.AutoRotate,
		CreatedAt: existingPolicy.CreatedAt, UpdatedAt: time.Now(),
	}
	if err := s.rotationRepo.Update(ctx, policy, req.Scope); err != nil {
		s.log.WithError(err).Error("Failed to update rotation policy")
		return nil, fmt.Errorf("failed to update rotation policy: %w", err)
	}
	return policy, nil
}
```

**Two-resource read under one shared scope, replacing the old ownership-comparison anti-pattern** (`AssignPolicyToSecret`, `RemovePolicyFromSecret`, `GetSecretPolicies`, `PerformManualRotation`, `AcknowledgeReminder`):
```go
func (s *rotationService) AssignPolicyToSecret(ctx context.Context, req AssignPolicyRequest) error {
	secret, err := s.secretRepo.Read(ctx, req.SecretID, req.Scope)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	policy, err := s.rotationRepo.Read(ctx, req.PolicyID, req.Scope)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}
	// secret and policy are both confirmed to be in req.Scope's vault by the
	// two reads above — a cross-vault assignment is denied here without a
	// separate comparison, because either read alone would already have failed.
	now := time.Now()
	nextRotation := now.AddDate(0, 0, policy.IntervalDays)
	if err := s.rotationRepo.AssignToSecret(ctx, req.SecretID, req.PolicyID, now, nextRotation); err != nil {
		s.log.WithError(err).Error("Failed to assign policy to secret")
		return fmt.Errorf("failed to assign policy to secret: %w", err)
	}
	if policy.ReminderDays > 0 {
		reminderTime := nextRotation.AddDate(0, 0, -policy.ReminderDays)
		_ = s.CreateRotationReminder(ctx, CreateReminderRequest{
			SecretID: req.SecretID, PolicyID: req.PolicyID,
			ReminderType: model.ReminderUpcoming, NextReminderAt: &reminderTime,
		})
	}
	_ = secret // secret is fetched only to prove scope membership; no field of it is used further
	return nil
}
```
(`GetSecretPolicies`, `RemovePolicyFromSecret`, `PerformManualRotation`, `AcknowledgeReminder` follow the identical shape: replace `s.secretRepo.Read(ctx, secretID, model.NewAdminScope(userID))` + manual `secret.UserID != userID` check with `s.secretRepo.Read(ctx, secretID, scope)` alone, and drop the `uuid.Nil`-skips-the-check convention — a system/scheduler caller now passes `model.NewAdminScope(actorID)` explicitly instead of a sentinel `uuid.Nil`.)

`CreatePolicyRequest` gains `Scope model.Scope`; `CreatePolicy`'s body changes only its `policy := &model.RotationPolicy{...}` construction to add `VaultID: req.Scope.ResolvedVaultID()` and drop `UserID: user.ID` in favor of `UserID: req.Scope.ActorID()` (the `s.userRepo.Read(ctx, req.UserID)` existence check becomes `s.userRepo.Read(ctx, req.Scope.ActorID())`).

`CreateRotationReminder` and `RecordRotation`-adjacent internals are unaffected — they take explicit secret/policy IDs already validated by their caller, not a scope.

- [ ] **Step 4: Update `scheduler_service.go`'s two call sites**

`internal/services/secrets/scheduler_service.go`'s `ProcessUserRotations`/`ProcessUserReminders` (called from `processAllUserOperations`, which iterates every user) currently call `rotationSvc.GetDueRotations(ctx, userID)` and `rotationSvc.GetUpcomingReminders(ctx, userID)`. Change both to `rotationSvc.GetDueRotations(ctx, model.NewAdminScope(userID))` / `rotationSvc.GetUpcomingReminders(ctx, model.NewAdminScope(userID))` — `ScopeAdmin` has no vault predicate, matching today's actual behavior (the scheduler already operates across every vault a user's secrets happen to be in; it never filtered by vault). This keeps the existing secrets scheduler's behavior identical, deferring any vault-aware scheduling change to Spec B.

Its `performAutomaticRotation` call into `rotationSvc.PerformManualRotation` must build `ManualRotationRequest{..., Scope: model.NewAdminScope(userID)}` in place of the old `UserID: userID` field.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/services/secrets/... -v`
Expected: PASS

- [ ] **Step 6: Build the whole module to find broken callers**

Run: `go build ./...`
Expected: FAIL — `cmd/rotation.go` and its tests still call the old signatures. Expected; Task 8 fixes it. Confirm no other package fails (in particular, `internal/container/service_container.go` must still build — its `NewRotationService(...)` constructor call is unaffected since the constructor's own parameter list didn't change, only the interface's method set).

- [ ] **Step 7: Commit**

```bash
git add internal/services/secrets/rotation_service.go internal/services/secrets/rotation_service_test.go internal/services/secrets/scheduler_service.go
git commit -m "feat(secrets): thread model.Scope through RotationService

Replaces AssignPolicyToSecret's manual ownership-comparison pattern
with two scope-filtered reads under the same scope, which denies
cross-vault assignment structurally rather than via a separate
ErrPolicyVaultMismatch check as originally specced -- equivalent
guarantee, simpler mechanism."
```

---

### Task 7: `key_service.go` — swap to scope-real repository calls

**Files:**
- Modify: `internal/services/keys/key_service.go`
- Modify: `internal/services/keys/key_service_test.go` (existing — update any mock/fake of `KeyRotationPolicyRepositoryInterface`)

**Interfaces:**
- Consumes: `KeyRotationPolicyRepositoryInterface` (Task 5).
- Produces: no change to `KeyService`'s own three public method signatures — `GetKeyRotationPolicy`/`UpsertKeyRotationPolicy`/`DeleteKeyRotationPolicy(ctx, keyID, scope, ...)` are unchanged (per spec §3, the service/API layer was already scope-aware). `api/key_rotation_policy.go` needs no change.

- [ ] **Step 1: Update `key_service_test.go`'s repository fake, if one exists**

Search `internal/services/keys/key_service_test.go` for any mock/fake implementing `KeyRotationPolicyRepositoryInterface` (e.g. a `mockKeyRotationPolicyRepo` in the style of Task 6's `mockRotationPolicyRepo`). If found, update its `GetByKeyID`/`DeleteByKeyID` methods to the Task 5 signatures (`scope model.Scope` in place of `userID uuid.UUID`), remove any `GetByKeyIDAny`/`DeleteByKeyIDAny` methods, and update its `.On(...)` expectations in the three rotation-policy test cases to pass a `model.Scope` instead of a bare `uuid.UUID`.

Write (or update) a failing test asserting the vault-derivation behavior Step 3 implements:

```go
func TestUpsertKeyRotationPolicy_DerivesVaultFromParentKey(t *testing.T) {
	// ... existing test harness setup for keyService, per this file's existing pattern ...
	vaultID := uuid.New()
	key := &model.Key{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, Type: "RSA", Enabled: true}
	// seed key via the harness's existing key-creation helper, or the fake key repo directly

	scope := model.NewVaultScope(vaultID, uuid.New())
	policy, err := keySvc.UpsertKeyRotationPolicy(context.Background(), key.ID, scope, model.UpsertKeyRotationPolicyRequest{
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
	})
	require.NoError(t, err)
	require.Equal(t, vaultID, policy.VaultID, "policy VaultID must be derived from the key's own vault, not independently settable")
}
```

Fit this into whatever test harness pattern the existing file already uses for `KeyService` (real repos over in-memory SQLite, or mocks — match Task 1's exploration finding for this specific file before writing this test).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/keys/... -run 'TestUpsertKeyRotationPolicy|TestGetKeyRotationPolicy|TestDeleteKeyRotationPolicy' -v`
Expected: FAIL — either a compile error (fake repo signature mismatch) or `policy.VaultID` being `uuid.Nil`.

- [ ] **Step 3: Update `key_service.go`'s three rotation-policy methods**

```go
func (s *keyService) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByKeyID(ctx, keyID, scope)
}

func (s *keyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 scope.ActorID(),
		VaultID:                key.VaultID, // derived from the parent key, never from the caller
		RotateAfterDays:        req.RotateAfterDays,
		NotifyBeforeExpiryDays: req.NotifyBeforeExpiryDays,
		ExpiryDays:             req.ExpiryDays,
		Enabled:                req.Enabled,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByKeyID(ctx, keyID, scope)
}

func (s *keyService) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return err
	}
	return s.policyRepo.DeleteByKeyID(ctx, keyID, scope)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/services/keys/... -v`
Expected: PASS

- [ ] **Step 5: Run the API-layer tests for this resource**

Run: `go test ./api/... -run KeyRotationPolicy -v`
Expected: PASS with no changes needed — `api/key_rotation_policy.go` calls `KeyService`'s unchanged public signatures.

- [ ] **Step 6: Build the whole module**

Run: `go build ./...`
Expected: PASS — this was the last caller of the old `key_rotation_policy_repository.go` interface. If anything outside `internal/services/keys/...` still fails, investigate before continuing; it indicates a caller this plan didn't account for.

- [ ] **Step 7: Commit**

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_service_test.go
git commit -m "feat(keys): derive KeyRotationPolicy.VaultID from parent key, use scope-real repo calls"
```

---

### Task 8: `cmd/rotation.go` — `--vault` + `vaultcli.RequireDataAction`

**Files:**
- Modify: `cmd/rotation.go`
- Modify: `cmd/rotation_test.go` (existing `MockRotationService`)
- Modify: `cmd/rotation_security_test.go` (existing `mockRotationService`)
- Modify: `cmd/rotation_service_test.go` (check for a third mock/direct dependency on the old interface)

**Interfaces:**
- Consumes: `RotationServiceInterface` (Task 6), `vaultcli.RequireDataAction` (existing, `cmd/vaultcli/vaultcli.go`), `model.ActionSecretsSet`/`model.ActionSecretsReadMetadata` (existing).
- Produces: nothing consumed by a later task — this is the last task before Task 9's regression tests.

- [ ] **Step 1: Update the three existing hand-written mocks to the Task 6 interface**

`MockRotationService` (`cmd/rotation_test.go`), `mockRotationService` (`cmd/rotation_security_test.go`), and any mock in `cmd/rotation_service_test.go` each implement `secretServices.RotationServiceInterface` in full. Update every method to Task 6's signatures: `GetPolicy`/`DeletePolicy`/`ListPolicies` (renamed from `ListUserPolicies`) take `scope model.Scope` in place of a bare `uuid.UUID`; `CreatePolicyRequest`/`UpdatePolicyRequest`/`AssignPolicyRequest`/`ManualRotationRequest` fields referenced in any `mock.MatchedBy` closure change from `req.UserID` to `req.Scope`; `RemovePolicyFromSecret`/`GetSecretPolicies`/`AcknowledgeReminder` take `scope model.Scope` as their last parameter; `GetDueRotations`/`GetUpcomingReminders` take `scope model.Scope` instead of `userID uuid.UUID`.

Write one new failing test proving the retrofit's authorization gate, following `cmd/keys/update_test.go`'s pattern:

```go
func TestRotationCreateCommand_RequiresVaultAuthorization(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.RoleAssignmentService = testutils.NewDenyingRoleAssignmentService() // or the equivalent deny-path fixture this package already uses elsewhere
	mockService := &MockRotationService{}
	tc.MockContainer.On("GetRotationService").Return(mockService)

	cmd := &cobra.Command{Use: "create", RunE: rotationCreateCmd.RunE}
	cmd.Flags().String("name", "test", "")
	cmd.Flags().Int("interval", 30, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	require.Error(t, err, "create must fail without a role grant in the resolved vault")
	mockService.AssertNotCalled(t, "CreatePolicy", mock.Anything, mock.Anything)
}
```

Check `cmd/testutils` (or a sibling test file already exercising the deny path, e.g. `cmd/keys/*_security_test.go`) for the exact deny-path fixture name before writing this — reuse it rather than inventing a new one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/... -run TestRotation -v`
Expected: FAIL to compile (mock signature mismatch) and/or the new authorization test failing because `cmd/rotation.go` doesn't call `RequireDataAction` yet.

- [ ] **Step 3: Retrofit every subcommand in `cmd/rotation.go`**

Add a `--vault` flag to `rotationCmd` (persistent, inherited by all subcommands, matching how other resource commands register it) and, in each subcommand's `RunE`, insert the authorization call before building the service request:

```go
vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpSet)
if err != nil {
	return fmt.Errorf("vault authorization failed: %w", err)
}
scope := model.NewVaultScope(vaultID, claims.UserID)
```

Per-subcommand data action (per spec §7):

| Subcommand | `model.DataAction` |
|---|---|
| `create`, `update`, `delete`, `assign`, `unassign`, `rotate` | `model.ActionSecretsSet` |
| `list`, `history`, `status` | `model.ActionSecretsReadMetadata` |

Every subcommand's request construction changes its final field from `UserID: claims.UserID` to `Scope: scope` (for `CreatePolicyRequest`/`UpdatePolicyRequest`/`AssignPolicyRequest`/`ManualRotationRequest`) or passes `scope` as the trailing argument (for `GetPolicy`/`DeletePolicy`/`ListPolicies`/`RemovePolicyFromSecret`/`GetSecretPolicies`/`GetRotationHistory`/`AcknowledgeReminder`). Each subcommand needs its own `ctx`/`claims`/`sc` extraction from `cmd.Context()` if it doesn't already have one — copy the three-line pattern from `cmd/keys/update.go` (`ctx := cmd.Context()`, `claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)`, `sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)`) into any subcommand `RunE` that doesn't already extract them.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/... -run TestRotation -v`
Expected: PASS

- [ ] **Step 5: Run the full `cmd` package test suite**

Run: `go test ./cmd/... -v`
Expected: PASS — every pre-existing `cmd/rotation_test.go`/`cmd/rotation_security_test.go` case must still pass once its mock and request-construction are updated (Step 1 already updated the mocks; this checks nothing else broke).

- [ ] **Step 6: Build the whole module**

Run: `go build ./...`
Expected: PASS. If anything still fails, it's a caller this plan didn't account for — investigate before continuing.

- [ ] **Step 7: Commit**

```bash
git add cmd/rotation.go cmd/rotation_test.go cmd/rotation_security_test.go cmd/rotation_service_test.go
git commit -m "feat(cmd): add --vault and RequireDataAction to rotation policy commands"
```

---

### Task 9: Cross-vault denial regression tests

**Files:**
- Test: `internal/repositories/rotation_scope_test.go` (new — `ErrInvalidScope` rejection coverage, mirroring `secret_scope_test.go`/`key_scope_test.go`)
- Test: extend `cmd/rotation_security_test.go` (existing, from Task 8) with an assign-across-vaults case

This task adds the defense-in-depth coverage the spec's §8 calls out that isn't already produced as a side effect of Tasks 4/5/6/8's own TDD steps (those tasks already added direct cross-vault-denial tests at the repository layer in Task 4 Step 1 and Task 5 Step 1 — this task fills the two gaps: repository-level `model.Scope{}` rejection, and an end-to-end CLI-level cross-vault assignment check).

**Interfaces:**
- Consumes: everything from Tasks 1-8. This task adds no new production code.

- [ ] **Step 1: Write `ErrInvalidScope` rejection tests**

Create `internal/repositories/rotation_scope_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestRotationRepository_RejectsUninitializedScope(t *testing.T) {
	sqlDB := setupRotationPolicyTestDB(t)
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	_, err := repo.Read(ctx, uuid.New(), model.Scope{})
	require.ErrorIs(t, err, repositories.ErrInvalidScope)

	require.ErrorIs(t, repo.Update(ctx, newTestPolicy(uuid.New()), model.Scope{}), repositories.ErrInvalidScope)
	require.ErrorIs(t, repo.Delete(ctx, uuid.New(), model.Scope{}), repositories.ErrInvalidScope)

	_, err = repo.List(ctx, model.Scope{})
	require.ErrorIs(t, err, repositories.ErrInvalidScope)
}

func TestKeyRotationPolicyRepository_RejectsUninitializedScope(t *testing.T) {
	sqlDB := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), testLog())
	ctx := context.Background()

	_, err := repo.GetByKeyID(ctx, uuid.New(), model.Scope{})
	require.ErrorIs(t, err, repositories.ErrInvalidScope)
	require.ErrorIs(t, repo.DeleteByKeyID(ctx, uuid.New(), model.Scope{}), repositories.ErrInvalidScope)
}
```

(`setupKeyRotationPolicyTestDB` is the existing helper from `key_rotation_policy_repository_test.go`, in the same `repositories_test` package — confirm its exact package clause before relying on cross-file reuse; if it's `package repositories_test` this works directly, otherwise inline an equivalent local helper.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/repositories/... -run RejectsUninitializedScope -v`
Expected: FAIL if any method's error wrapping loses `ErrInvalidScope`'s identity (e.g. a `fmt.Errorf` without `%w`) — check `Read`'s error handling from Task 4 Step 3, which wraps `ScopedGet`'s error in a generic "not found" message for the `sql.ErrNoRows` case but must still pass through `ErrInvalidScope` unwrapped.

- [ ] **Step 3: Fix wrapping if the tests fail, otherwise confirm they already pass**

If Step 2 fails, adjust the `errors.Is(err, sql.ErrNoRows)` branch added in Task 4 Step 3 to check `errors.Is(err, repositories.ErrInvalidScope)` first and return it unwrapped, falling through to the generic "not found" wrapping only for `sql.ErrNoRows`.

- [ ] **Step 4: Add the CLI-level cross-vault assignment test**

Append to `cmd/rotation_security_test.go`:

```go
func TestRotationAssignCommand_CrossVaultDenied(t *testing.T) {
	// Seed a policy in vault A (via MockRotationService returning a policy
	// with VaultID set to vault B when read under vault A's scope should
	// simply not happen -- at this layer, assert that the CLI passes the
	// vault-derived scope through unchanged to AssignPolicyToSecret, and
	// that RotationService (Task 6, tested directly in
	// internal/services/secrets/rotation_service_test.go) is what actually
	// enforces the cross-vault denial. This test only proves the CLI wires
	// the resolved vaultID into the request scope, not a second copy of the
	// service-layer behavior.
	tc := testutils.NewTestContext(t)
	mockService := &MockRotationService{}
	secretID, policyID := uuid.New(), uuid.New()

	mockService.On("AssignPolicyToSecret", mock.Anything, mock.MatchedBy(func(req secretServices.AssignPolicyRequest) bool {
		return req.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	})).Return(nil)
	tc.MockContainer.On("GetRotationService").Return(mockService)

	cmd := &cobra.Command{Use: "assign", RunE: rotationAssignCmd.RunE}
	cmd.Flags().String("secret-id", secretID.String(), "")
	cmd.Flags().String("policy-id", policyID.String(), "")
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	mockService.AssertExpectations(t)
}
```

This documents, at the test-suite level, the boundary between what the CLI task (8) is responsible for (resolving and threading the vault scope) and what the service task (6) is responsible for (actually denying a cross-vault assignment) — so a future reader doesn't go looking for the enforcement logic in the wrong file.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/repositories/... ./cmd/... -v`
Expected: PASS

- [ ] **Step 6: Full-suite verification gate**

Run: `go build ./... && go test ./...`
Expected: PASS, zero failures anywhere in the module.

- [ ] **Step 7: Commit**

```bash
git add internal/repositories/rotation_scope_test.go cmd/rotation_security_test.go internal/repositories/rotation_repository.go internal/repositories/key_rotation_policy_repository.go
git commit -m "test: add ErrInvalidScope and cross-vault regression coverage for rotation policies"
```

---

## Self-Review Notes

**Spec coverage:** §4 (DB migration) → Task 1. §5.1 (generic helper) → Task 2. §5.2/§5.3 (repositories) → Tasks 4/5. §6 (service/CLI-visible layer) → Task 6/7. §7 (CLI) → Task 8. §8 (testing) → Tasks 1/4/5/9 collectively cover cross-vault denial, backfill correctness, and `ErrInvalidScope` rejection; the CLI `--vault` flag coverage and per-subcommand authorization-denial case are in Task 8 Step 1. §9 (error handling) is realized inline across Tasks 4-7 (not a separate task — it's not a separable unit of work). §10 (out of scope) — no task in this plan touches `internal/schedulerkit`, adds an HTTP API for `rotation_policies`, retrofits `secret_repository.go`/`key_repository.go`/`certificate_repository.go` onto `scoped_crud.go`, or adds a CLI `rotationpolicy` subcommand for keys, matching the spec.

**Deviation flagged:** Task 6 implements the spec's "cross-vault assignment refusal" via two scope-filtered reads under one shared scope rather than the spec's literal `ErrPolicyVaultMismatch` proposal — same guarantee, simpler mechanism, called out explicitly in that task's commit message so it's traceable.

**Type consistency check:** `model.Scope` flows as the last parameter on every repository/service method touched (Tasks 4-7); `RotationServiceInterface.ListPolicies` (Task 6) is the renamed `ListUserPolicies`, and Task 8 references the new name consistently. `KeyRotationPolicy.VaultID` (Task 3) is produced only by `KeyService.UpsertKeyRotationPolicy` (Task 7) from the parent key's own `VaultID`, never accepted as caller input — verified consistent across Tasks 3, 5, and 7.
