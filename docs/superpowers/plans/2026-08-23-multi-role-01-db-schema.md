# Multi-Role: DB Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `user_roles` join table and a startup backfill migration that
absorbs every existing user's role(s) — including legacy comma-joined strings
— into it.

**Architecture:** Mirror the existing `role_assignments` table exactly:
`CREATE TABLE IF NOT EXISTS user_roles` in both `createOptimizedSchema()`
(fresh installs) and `migrateSchema()` (upgrades), same dual-write pattern
already used for every table in this codebase. Backfill runs as part of
`migrateSchema()`, using `INSERT OR IGNORE` so it's idempotent on every
startup.

**Tech Stack:** Go, SQLite (via `database/sql`), existing `internal/db`
package conventions.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- New table only — do not touch the `users.role` column (kept, unused,
  deprecated-in-place per the spec's locked decision).
- `user_roles` schema exactly: `(id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
  role TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (user_id, role), FOREIGN KEY (user_id) REFERENCES users(id) ON
  DELETE CASCADE)`.
- Every migration statement must be idempotent — this repo's `migrateSchema()`
  runs on every startup, not just once.

---

### Task 1: Add `user_roles` table to both schema paths

**Files:**
- Modify: `internal/db/db.go` (two locations: inside `createOptimizedSchema()`
  near line 335-351's `users` table block; inside `migrateSchema()` near the
  `role_assignments` standalone-`db.Exec` block at lines 954-974)
- Test: `internal/db/db_test.go` (or add a new `internal/db/user_roles_test.go`
  if `db_test.go` doesn't exist — check first with `ls internal/db/*_test.go`)

**Interfaces:**
- Produces: a `user_roles` table reachable via the existing `*sql.DB`/`db.DB`
  connection every other task in this plan set depends on. No Go-level
  interface yet — that's Task 2 of the repository plan.

- [ ] **Step 1: Write the failing test**

Create `internal/db/user_roles_schema_test.go`:

```go
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

func TestUserRolesTable_CreatedOnFreshInstall(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	repo := &DBRepository{db: conn, dialect: SQLite}
	require.NoError(t, repo.createOptimizedSchema())

	var name string
	err = conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='user_roles'`,
	).Scan(&name)
	require.NoError(t, err, "user_roles table must exist after createOptimizedSchema")
	require.Equal(t, "user_roles", name)

	// UNIQUE(user_id, role) must reject an exact duplicate but allow a
	// second, different role for the same user.
	_, err = conn.Exec(`INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'alice', 'h', 'admin')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO user_roles (id, user_id, role) VALUES ('r1', 'u1', 'admin')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO user_roles (id, user_id, role) VALUES ('r2', 'u1', 'admin')`)
	require.Error(t, err, "duplicate (user_id, role) must be rejected")
	_, err = conn.Exec(`INSERT INTO user_roles (id, user_id, role) VALUES ('r3', 'u1', 'secrets_manager')`)
	require.NoError(t, err, "a second, different role for the same user must be allowed")
}
```

Check the exact `DBRepository` struct field names (`db`, `dialect`) and
`createOptimizedSchema()`'s receiver/signature in `internal/db/db.go` before
writing this test — match them exactly; the struct is defined around line 68
of that file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/... -run TestUserRolesTable_CreatedOnFreshInstall -v`
Expected: FAIL — `no such table: user_roles`

- [ ] **Step 3: Add the table to `createOptimizedSchema()`**

In `internal/db/db.go`, find this exact block (around line 335-351):

```go
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			auth_provider TEXT NOT NULL DEFAULT 'local',
			external_idp_subject TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
		CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
		CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
```

Immediately after the three `CREATE INDEX ... users` lines (and before the
trailing comment about `idx_users_external_idp`), insert:

```go
		CREATE TABLE IF NOT EXISTS user_roles (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			role       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (user_id, role),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
```

- [ ] **Step 4: Add the table to `migrateSchema()`**

Find the `role_assignments` standalone block in `migrateSchema()` (around
line 954-974):

```go
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS role_assignments (
		...
	)`); err != nil {
		return fmt.Errorf("create role_assignments: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id)`); err != nil {
		return fmt.Errorf("index role_assignments vault: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_assignments_principal_vault ON role_assignments(principal_id, vault_id)`); err != nil {
		return fmt.Errorf("index role_assignments principal/vault: %w", err)
	}
```

Immediately after that block, add:

```go
	// Feature: multi-role users (idempotent). users.role is left in place,
	// unused by new code — see docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		id         TEXT PRIMARY KEY,
		user_id    TEXT NOT NULL,
		role       TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (user_id, role),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create user_roles: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id)`); err != nil {
		return fmt.Errorf("index user_roles user: %w", err)
	}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/... -run TestUserRolesTable_CreatedOnFreshInstall -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/db/db.go internal/db/user_roles_schema_test.go
git commit -m "feat(db): add user_roles table"
```

---

### Task 2: Backfill migration for existing users

**Files:**
- Modify: `internal/db/db.go` — `migrateSchema()`, immediately after Task 1's
  new `user_roles` block
- Test: `internal/db/user_roles_schema_test.go` (same file as Task 1)

**Interfaces:**
- Consumes: the `user_roles` table from Task 1.
- Produces: every existing `users` row has at least one corresponding
  `user_roles` row after `migrateSchema()` runs, even if `users.role` was a
  legacy comma-joined string like `"secrets_manager, crypto_manager"`.

- [ ] **Step 1: Write the failing test**

Add to `internal/db/user_roles_schema_test.go`:

```go
func TestUserRolesBackfill_SplitsLegacyCommaJoinedRoles(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	repo := &DBRepository{db: conn, dialect: SQLite}
	require.NoError(t, repo.createOptimizedSchema())

	// Seed users the way pre-migration data actually looks: a plain single
	// role, a legacy comma-joined pair (the exact historical shape from the
	// Oct 2025 commit), and a messy-whitespace duplicate-laden variant.
	seed := []struct{ id, username, role string }{
		{"u1", "alice", "admin"},
		{"u2", "bob", "secrets_manager, crypto_manager"},
		{"u3", "carol", "user,  user , admin"},
	}
	for _, u := range seed {
		_, err := conn.Exec(
			`INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, 'h', ?)`,
			u.id, u.username, u.role,
		)
		require.NoError(t, err)
	}

	require.NoError(t, repo.migrateSchema())

	assertRoles := func(userID string, want []string) {
		rows, err := conn.Query(`SELECT role FROM user_roles WHERE user_id = ? ORDER BY role`, userID)
		require.NoError(t, err)
		defer rows.Close()
		var got []string
		for rows.Next() {
			var r string
			require.NoError(t, rows.Scan(&r))
			got = append(got, r)
		}
		require.ElementsMatch(t, want, got, "user_id=%s", userID)
	}

	assertRoles("u1", []string{"admin"})
	assertRoles("u2", []string{"crypto_manager", "secrets_manager"})
	assertRoles("u3", []string{"admin", "user"}) // deduped

	// Idempotency: running migrateSchema() again must not error or duplicate rows.
	require.NoError(t, repo.migrateSchema())
	assertRoles("u3", []string{"admin", "user"})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/... -run TestUserRolesBackfill -v`
Expected: FAIL — `user_roles` is empty (no backfill logic yet)

- [ ] **Step 3: Implement the backfill**

In `internal/db/db.go`, immediately after Task 1's new `user_roles`
`CREATE TABLE`/`CREATE INDEX` block inside `migrateSchema()`, add:

```go
	// Backfill: split every existing users.role value (including legacy
	// comma-joined strings from the pre-normalization multi-role feature)
	// into user_roles. INSERT OR IGNORE makes this idempotent -- safe to
	// run on every startup, not just once.
	rows, err := db.Query(`SELECT id, role FROM users`)
	if err != nil {
		return fmt.Errorf("read users for role backfill: %w", err)
	}
	type userRoleRow struct{ userID, role string }
	var toBackfill []userRoleRow
	for rows.Next() {
		var id, role string
		if err := rows.Scan(&id, &role); err != nil {
			rows.Close()
			return fmt.Errorf("scan user for role backfill: %w", err)
		}
		toBackfill = append(toBackfill, userRoleRow{id, role})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate users for role backfill: %w", err)
	}
	rows.Close()

	for _, u := range toBackfill {
		seen := map[string]bool{}
		for _, part := range strings.Split(u.role, ",") {
			r := strings.TrimSpace(part)
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			if _, err := db.Exec(
				`INSERT OR IGNORE INTO user_roles (id, user_id, role) VALUES (?, ?, ?)`,
				uuid.New().String(), u.userID, r,
			); err != nil {
				return fmt.Errorf("backfill user_roles for user %s: %w", u.userID, err)
			}
		}
	}
```

Check the top of `internal/db/db.go` for existing `"strings"` and
`"github.com/google/uuid"` imports — add them if missing (run `go build
./internal/db/...` to confirm).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/... -run TestUserRolesBackfill -v`
Expected: PASS

- [ ] **Step 5: Run the full package test suite**

Run: `go test ./internal/db/... -v`
Expected: all PASS, including the pre-existing `role_backfill_test.go`,
`vault_partial_unique_index_test.go`, etc. — this backfill must not disturb
any other migration.

- [ ] **Step 6: Commit**

```bash
git add internal/db/db.go internal/db/user_roles_schema_test.go
git commit -m "feat(db): backfill user_roles from legacy users.role on migration"
```
