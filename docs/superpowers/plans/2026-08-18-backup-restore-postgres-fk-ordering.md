# Backup/Restore Postgres FK-Ordering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make whole-database restore (`internal/backup/backup.go`) safe on Postgres — RocketVault's own documented production database — by ordering the delete and insert phases by real foreign-key dependency instead of plain alphabetical table order (Critical Finding #9), before this is discovered during an actual disaster-recovery incident rather than in CI.

**Architecture:** A hardcoded `tableDependencies` map (child table → parent tables it references) drives a topological sort. `RestoreBackup` is restructured from its current single per-table delete-then-insert loop into two explicit phases: delete every table in reverse-topological order (children before parents, so no FK is ever violated by deleting a still-referenced row), then insert every table in topological order (parents before children, so no FK is ever violated by inserting a row before what it references exists). A schema-drift-guard test cross-checks the hardcoded map against the live database's real FK constraints (via SQLite's `PRAGMA foreign_key_list` and Postgres's `information_schema`) so a future migration that adds a table/FK without updating the map fails CI immediately, instead of silently reintroducing this exact bug class. A Postgres-testcontainer integration test proves a real backup-then-restore round-trip succeeds under genuine FK enforcement — the thing no test in this repo currently exercises, per the audit finding.

**Tech Stack:** Go 1.24, `database/sql`, SQLite (`github.com/mattn/go-sqlite3`) and Postgres (`github.com/lib/pq`) dual-dialect support already used elsewhere in this codebase, `github.com/testcontainers/testcontainers-go` + its `postgres` module (already a direct dependency, already used in `internal/repositories/pg_integration_test.go`).

**Spec:** `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Critical Finding #9 — see the "Critical findings" table and the "Backup and restore" section for full detail)

## Global Constraints

- The full table dependency graph, derived from every `FOREIGN KEY` constraint in `internal/db/db.go`'s `createOptimizedSchema` (the canonical fresh-install schema), is:
  ```
  users:                   (no dependencies)
  vaults:                  (no dependencies)
  bootstrap_tokens:        (no dependencies)
  audit_logs:              (no dependencies)
  access_policies:         (no dependencies -- has a vault_id column but no FK on it)
  oauth2_clients:          (no dependencies)
  audit_config:            (no dependencies)
  secrets:                 users
  keys:                    users
  certificates:            users
  crl:                     users
  rotation_policies:       users
  user_sessions:           users
  role_assignments:        vaults
  key_tags:                keys
  key_versions:            keys
  certificate_tags:        certificates
  certificate_policies:    certificates, users
  key_rotation_policies:   keys, users
  secret_tags:             secrets
  secret_versions:         secrets, users
  secret_rotation_history: secrets, rotation_policies
  rotation_reminders:      secrets, rotation_policies
  secret_policies:         secrets, rotation_policies
  ```
  Use these exact table names and parent lists in Task 1's `tableDependencies` map — do not re-derive them from scratch, and do not add or omit an edge without re-checking `internal/db/db.go`'s actual `FOREIGN KEY` clauses first.
- `RestoreBackup`'s existing single-transaction, single-commit-at-the-end structure (`tx.Begin()` → all work → `tx.Commit()`, with `defer tx.Rollback()` for the error path) must be preserved — this plan changes the *order* of operations within that transaction, not its atomicity.
- Verification gate for every task: `go build ./... && go test ./...` (this codebase's standing rule). The Postgres integration test in Task 4 is `//go:build integration` tagged (matching `internal/repositories/pg_integration_test.go`'s existing convention) and is NOT part of the default `go test ./...` run — run it explicitly with `go test -tags=integration ./internal/backup/...` and note in your task report whether Docker was available to actually run it.

---

### Task 1: Table-dependency map and topological sort

**Files:**
- Create: `internal/backup/table_order.go`
- Create: `internal/backup/table_order_test.go`

**Interfaces:**
- Consumes: nothing — pure, standalone logic with no dependency on `Manager` or any DB connection.
- Produces: `tableDependencies map[string][]string` and `topologicalOrder(tables []string) ([]string, error)`. Task 2 calls `topologicalOrder` directly; Task 3's drift-guard test reads `tableDependencies` directly.

- [ ] **Step 1: Write the failing tests**

Create `internal/backup/table_order_test.go`:

```go
package backup

import (
	"reflect"
	"testing"
)

func TestTopologicalOrder_ParentsBeforeChildren(t *testing.T) {
	tables := []string{"secret_versions", "users", "secrets", "secret_tags"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	pos := make(map[string]int, len(order))
	for i, name := range order {
		pos[name] = i
	}
	if pos["users"] > pos["secrets"] {
		t.Fatalf("users must come before secrets, got order %v", order)
	}
	if pos["secrets"] > pos["secret_versions"] {
		t.Fatalf("secrets must come before secret_versions, got order %v", order)
	}
	if pos["secrets"] > pos["secret_tags"] {
		t.Fatalf("secrets must come before secret_tags, got order %v", order)
	}
	if pos["users"] > pos["secret_versions"] {
		t.Fatalf("users must come before secret_versions (transitive), got order %v", order)
	}
}

func TestTopologicalOrder_TableWithTwoParents(t *testing.T) {
	tables := []string{"secret_policies", "secrets", "rotation_policies", "users"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	pos := make(map[string]int, len(order))
	for i, name := range order {
		pos[name] = i
	}
	if pos["secrets"] > pos["secret_policies"] {
		t.Fatalf("secrets must come before secret_policies, got order %v", order)
	}
	if pos["rotation_policies"] > pos["secret_policies"] {
		t.Fatalf("rotation_policies must come before secret_policies, got order %v", order)
	}
}

func TestTopologicalOrder_UnknownTableTreatedAsRoot(t *testing.T) {
	// A table present in the input but absent from tableDependencies (e.g. a
	// brand-new table nobody has updated the map for yet) must not error --
	// it's treated as having no dependencies, sorting first. The Task 3
	// drift-guard test is what catches this staleness; topologicalOrder
	// itself must stay defensive, not panic or fail the whole restore.
	tables := []string{"users", "some_future_table"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 {
		t.Fatalf("expected both tables in output, got %v", order)
	}
}

func TestTopologicalOrder_OnlyIncludesInputTables(t *testing.T) {
	// tableDependencies knows about many more tables than this small input
	// list -- the output must never include a table the caller didn't ask
	// for (e.g. a live SQLite DB mid-migration might not have every table
	// tableDependencies eventually needs to know about).
	tables := []string{"users", "secrets"}
	order, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sortedCopy(order), sortedCopy([]string{"users", "secrets"})) {
		t.Fatalf("expected exactly {users, secrets}, got %v", order)
	}
}

func TestTopologicalOrder_Deterministic(t *testing.T) {
	tables := []string{"key_rotation_policies", "keys", "users", "key_versions", "key_tags"}
	first, err := topologicalOrder(tables)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := topologicalOrder(tables)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("topologicalOrder must be deterministic across calls; got %v then %v", first, again)
		}
	}
}

func sortedCopy(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/backup/... -run TestTopologicalOrder -v`
Expected: FAIL — `tableDependencies`/`topologicalOrder` don't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/backup/table_order.go`:

```go
package backup

import (
	"fmt"
	"sort"
)

// tableDependencies maps each table to the tables it holds a foreign key to
// (its parents). Restoring data must create parents before children;
// clearing data must remove children before parents, or Postgres's enforced
// FK constraints reject the operation mid-transaction (SQLite's foreign_keys
// pragma is off by default, which is what let this bug ship unnoticed --
// see Critical Finding #9, docs/plans/2026-08-18-azure-keyvault-parity-audit.md).
//
// Derived directly from every FOREIGN KEY clause in
// internal/db/db.go's createOptimizedSchema. Task 3's drift-guard test
// cross-checks this map against the live database's real FK constraints on
// every test run -- if this map goes stale after a schema change, that test
// fails, not a production restore.
var tableDependencies = map[string][]string{
	"users":                   {},
	"vaults":                  {},
	"bootstrap_tokens":        {},
	"audit_logs":              {},
	"access_policies":         {},
	"oauth2_clients":          {},
	"audit_config":            {},
	"secrets":                 {"users"},
	"keys":                    {"users"},
	"certificates":            {"users"},
	"crl":                     {"users"},
	"rotation_policies":       {"users"},
	"user_sessions":           {"users"},
	"role_assignments":        {"vaults"},
	"key_tags":                {"keys"},
	"key_versions":            {"keys"},
	"certificate_tags":        {"certificates"},
	"certificate_policies":    {"certificates", "users"},
	"key_rotation_policies":   {"keys", "users"},
	"secret_tags":             {"secrets"},
	"secret_versions":         {"secrets", "users"},
	"secret_rotation_history": {"secrets", "rotation_policies"},
	"rotation_reminders":      {"secrets", "rotation_policies"},
	"secret_policies":         {"secrets", "rotation_policies"},
}

// topologicalOrder returns tables ordered so every table appears after all
// tables it depends on (parents before children) -- the correct order for
// INSERT during a restore. Reverse the result for DELETE. Only tables
// present in the tables argument are included in the output. A table
// present in tables but absent from tableDependencies is treated as having
// no dependencies (sorts first) rather than erroring -- a defensive
// fallback; Task 3's drift-guard test is the real check for this staleness.
func topologicalOrder(tables []string) ([]string, error) {
	present := make(map[string]bool, len(tables))
	for _, t := range tables {
		present[t] = true
	}

	var order []string
	const (
		unvisited = 0
		inFlight  = 1
		done      = 2
	)
	visited := make(map[string]int)
	var visit func(t string) error
	visit = func(t string) error {
		switch visited[t] {
		case done:
			return nil
		case inFlight:
			return fmt.Errorf("circular table dependency detected at %q", t)
		}
		visited[t] = inFlight
		for _, parent := range tableDependencies[t] {
			if !present[parent] {
				continue
			}
			if err := visit(parent); err != nil {
				return err
			}
		}
		visited[t] = done
		order = append(order, t)
		return nil
	}

	// Sort input first for deterministic traversal order -- map iteration
	// order is not stable, and DFS visit order affects the output.
	sorted := make([]string, len(tables))
	copy(sorted, tables)
	sort.Strings(sorted)

	for _, t := range sorted {
		if err := visit(t); err != nil {
			return nil, err
		}
	}
	return order, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/backup/... -run TestTopologicalOrder -v`
Expected: PASS (all 5 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/backup/table_order.go internal/backup/table_order_test.go
git commit -m "$(cat <<'EOF'
feat(backup): add FK-dependency topological sort for tables

tableDependencies encodes every FOREIGN KEY relationship in the
schema; topologicalOrder sorts a table list so parents precede
children (insert order), reversible for delete order. Pure, standalone
logic with no DB dependency yet -- wired into RestoreBackup next.

Critical Finding #9, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```

---

### Task 2: Wire topological ordering into `RestoreBackup`

**Files:**
- Modify: `internal/backup/backup.go`
- Test: `internal/backup/backup_test.go` (extend)

**Interfaces:**
- Consumes: `topologicalOrder(tables []string) ([]string, error)` (Task 1).
- Produces: `RestoreBackup` now orders its delete and insert phases by FK dependency instead of alphabetically. No exported signature changes — `RestoreBackup(backupPath string, encrypted bool) error` keeps its existing signature; this is an internal-behavior fix.

- [ ] **Step 1: Write the failing test**

Read `internal/backup/backup_test.go` in full first — it already has a `setupTestDB(t) (*sql.DB, func())` helper (a temp-file SQLite DB with a minimal, real, FK-declared `users`/`secrets` schema: `secrets.user_id REFERENCES users(id)`, no `foreign_keys` pragma enabled) and an existing `TestBackupManager` with a `"BackupAndRestore"` subtest showing the exact `CreateBackup` → mutate → `RestoreBackup` → assert idiom. Reuse `setupTestDB` directly; do not invent a different fixture. Add this test to `internal/backup/backup_test.go`, following that same idiom:

```go
// TestRestoreBackup_PreservesReferentialIntegrity proves RestoreBackup's
// two-phase (delete-then-insert, each FK-ordered) restructure still
// round-trips correctly on this package's existing minimal SQLite fixture:
// every secret's user_id must still resolve to a real users row after
// restore, not just match row counts. SQLite's foreign_keys pragma is off
// by default (setupTestDB doesn't enable it), so this test cannot by itself
// prove the OLD alphabetical order would have failed -- it proves the NEW
// FK-ordered code path preserves existing correct behavior. The Postgres
// integration test (Task 4) is what proves the ordering itself matters,
// against an engine that actually enforces FK constraints.
func TestRestoreBackup_PreservesReferentialIntegrity(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	logger := logging.InitLogger()
	manager := NewManager(db, rvdb.SQLite, logger)

	tmpDir, err := os.MkdirTemp("", "backup_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck
	backupPath := filepath.Join(tmpDir, "integrity.backup")

	if err := manager.CreateBackup(backupPath, false); err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Mutate before restoring, so the restore's effect is observable.
	if _, err := db.Exec("DELETE FROM secrets; DELETE FROM users;"); err != nil {
		t.Fatalf("Failed to clear data: %v", err)
	}

	if err := manager.RestoreBackup(backupPath, false); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	// setupTestDB seeds secret1/secret2, both owned by user1. Prove the
	// restored secrets still resolve to a real user row via an actual JOIN,
	// not just independently-matching counts on each table.
	var joinedCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM secrets s
		JOIN users u ON u.id = s.user_id
	`).Scan(&joinedCount)
	if err != nil {
		t.Fatalf("Failed to count joined rows: %v", err)
	}
	if joinedCount != 2 {
		t.Errorf("expected 2 secrets with a resolvable user_id after restore, got %d", joinedCount)
	}
}
```

- [ ] **Step 2: Run test to verify it currently passes**

Run: `go test ./internal/backup/... -run TestRestoreBackup_PreservesReferentialIntegrity -v`

This should PASS even before Step 3's fix — `setupTestDB` doesn't enable SQLite's `foreign_keys` pragma, so the old alphabetical-order code doesn't fail here either; that's expected and matches the audit finding's own root-cause description (this exact gap is why the bug shipped unnoticed). This step confirms the test compiles and runs cleanly against the current code, establishing a baseline before Step 3's refactor. The real proof of a *behavior change* comes from Task 4's Postgres integration test, which genuinely can fail on the wrong order; this test's job is only to confirm Step 3's refactor doesn't regress the correct behavior that already existed.

- [ ] **Step 3: Restructure `RestoreBackup` into two ordered phases**

Replace `RestoreBackup` in `internal/backup/backup.go`:

```go
// RestoreBackup restores the database from a backup file
func (m *Manager) RestoreBackup(backupPath string, encrypted bool) error {
	m.logger.Info("Starting database restore")

	// Read and parse backup file
	backupData, err := m.readBackupFile(backupPath, encrypted)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Validate backup data
	if err := m.validateBackupData(backupData); err != nil {
		return fmt.Errorf("invalid backup data: %w", err)
	}

	// Determine restore order by FK dependency, not the backup file's own
	// (alphabetical) table order -- see table_order.go. Index the backup's
	// tables by name so both phases below can look them up regardless of
	// what order they appear in the file.
	byName := make(map[string]*TableData, len(backupData.Tables))
	names := make([]string, 0, len(backupData.Tables))
	for i := range backupData.Tables {
		byName[backupData.Tables[i].Name] = &backupData.Tables[i]
		names = append(names, backupData.Tables[i].Name)
	}
	order, err := topologicalOrder(names)
	if err != nil {
		return fmt.Errorf("determine table restore order: %w", err)
	}

	// Begin transaction for restore
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Delete phase: children before parents (reverse topological order), so
	// clearing a table never violates an FK still pointing at a row in a
	// table cleared later.
	for i := len(order) - 1; i >= 0; i-- {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s", order[i])); err != nil {
			return fmt.Errorf("failed to clear table %s: %w", order[i], err)
		}
	}

	// Insert phase: parents before children (topological order), so
	// inserting a row never violates an FK pointing at a not-yet-restored
	// parent row.
	totalRecords := 0
	for _, name := range order {
		tableData := byName[name]
		if err := m.insertTableData(tx, tableData); err != nil {
			return fmt.Errorf("failed to restore table %s: %w", name, err)
		}
		totalRecords += tableData.RowCount
		m.logger.WithField("table", tableData.Name).WithField("records", tableData.RowCount).Info("Restored table")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	m.logger.WithFields(map[string]interface{}{
		"file":    backupPath,
		"tables":  len(backupData.Tables),
		"records": totalRecords,
	}).Info("Restore completed successfully")

	return nil
}
```

Then split the old `restoreTableData` (which did DELETE then INSERT together per table) into just its insert half, renamed `insertTableData`, and delete the old combined function:

```go
// insertTableData inserts all rows for a specific table. The caller (RestoreBackup)
// is responsible for clearing the table first, in the correct FK-safe order --
// this function only inserts.
func (m *Manager) insertTableData(tx *sql.Tx, tableData *TableData) error {
	if len(tableData.Rows) == 0 {
		return nil
	}

	columnsStr := ""
	for i, col := range tableData.Columns {
		if i > 0 {
			columnsStr += ", "
		}
		columnsStr += col
	}

	placeholdersStr := ""
	for i := range tableData.Columns {
		if i > 0 {
			placeholdersStr += ", "
		}
		placeholdersStr += "?"
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		tableData.Name, columnsStr, placeholdersStr)

	// Rebind "?" placeholders for the active engine before preparing.
	query = m.dialect.Rebind(query)

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck

	args := make([]interface{}, len(tableData.Columns))
	for _, row := range tableData.Rows {
		for i, col := range tableData.Columns {
			args[i] = row[col]
		}
		if _, err := stmt.Exec(args...); err != nil {
			return err
		}
	}

	return nil
}
```

Remove the old `restoreTableData` function entirely (its delete-then-insert body is now split across `RestoreBackup`'s two phases and `insertTableData`). Confirm no other file in the repo calls `restoreTableData` directly before deleting it (`grep -rn "restoreTableData" --include="*.go" .`) — it's unexported, so this should only be `backup.go` itself and possibly `backup_test.go`; update any test call site to call `insertTableData` instead, or to go through the public `RestoreBackup` path if that's what the existing test actually needs.

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/backup/... -v
```
Expected: PASS, including the new test from Step 1 and every pre-existing test in `backup_test.go`, `backup_edge_test.go`, `backup_internal_edge_test.go`, `item_backup_test.go`.

- [ ] **Step 5: Full repo verification**

```bash
go build ./... && go test ./...
```
Expected: clean across the entire repository.

- [ ] **Step 6: Commit**

```bash
git add internal/backup/backup.go internal/backup/backup_test.go
git commit -m "$(cat <<'EOF'
fix(backup): order restore delete/insert by FK dependency

RestoreBackup deleted and re-inserted tables in plain alphabetical
order with no FK-dependency awareness -- SQLite's foreign_keys pragma
being off by default masked this, but Postgres (this repo's own
documented production database) enforces FK constraints
unconditionally, so a real restore was very likely to abort mid-
transaction (e.g. certificates sorts alphabetically before keys).

Split into two explicit phases using table_order.go's topologicalOrder:
delete children before parents, then insert parents before children.

Critical Finding #9, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```

---

### Task 3: Schema-drift guard — cross-check `tableDependencies` against the real schema

**Files:**
- Create: `internal/backup/table_order_schema_test.go`

**Interfaces:**
- Consumes: `tableDependencies` (Task 1), a live SQLite connection (this repo's default test engine — reuse whatever in-memory SQLite setup `internal/backup`'s existing tests already use).
- Produces: `TestTableDependencies_MatchesLiveSchema`, a normal (always-runs) test — the actual, permanent guard against this bug class recurring after a future schema change.

- [ ] **Step 1: Write the failing test**

Create `internal/backup/table_order_schema_test.go`:

```go
package backup

import (
	"database/sql"
	"sort"
	"testing"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// TestTableDependencies_MatchesLiveSchema proves table_order.go's hardcoded
// tableDependencies map agrees with the real schema's FK constraints,
// queried live via SQLite's PRAGMA foreign_key_list. If a future migration
// adds a table or a foreign key without updating tableDependencies, this
// test fails -- instead of silently reintroducing the ordering bug this
// plan fixes (Critical Finding #9).
//
// It also proves every table the live schema creates has SOME entry in
// tableDependencies (even an empty one), so a brand-new table can't be
// silently treated as dependency-free by topologicalOrder's own defensive
// fallback without a human having actually looked at it.
func TestTableDependencies_MatchesLiveSchema(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	repo := rvdb.NewRepository(logging.InitLogger())
	if err := repo.SetupSchema(sqlDB, rvdb.SQLite); err != nil {
		t.Fatalf("setup schema: %v", err)
	}

	liveTables, err := queryLiveTableNames(sqlDB)
	if err != nil {
		t.Fatal(err)
	}

	for _, table := range liveTables {
		wantParents, known := tableDependencies[table]
		if !known {
			t.Errorf("table %q exists in the live schema but has no entry in tableDependencies -- add one (table_order.go)", table)
			continue
		}

		gotParents, err := queryLiveForeignKeyParents(sqlDB, table)
		if err != nil {
			t.Fatalf("query FK parents for %q: %v", table, err)
		}

		sort.Strings(wantParents)
		sort.Strings(gotParents)
		if !equalStringSlices(wantParents, gotParents) {
			t.Errorf("table %q: tableDependencies says parents=%v, live schema FK constraints say parents=%v -- update table_order.go", table, wantParents, gotParents)
		}
	}

	// Reverse direction: every table tableDependencies knows about should
	// still exist in the live schema (catches a removed/renamed table left
	// stale in the map).
	liveSet := make(map[string]bool, len(liveTables))
	for _, t := range liveTables {
		liveSet[t] = true
	}
	for table := range tableDependencies {
		if !liveSet[table] {
			t.Errorf("tableDependencies has an entry for %q, but no such table exists in the live schema -- remove it from table_order.go", table)
		}
	}
}

func queryLiveTableNames(sqlDB *sql.DB) ([]string, error) {
	rows, err := sqlDB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

func queryLiveForeignKeyParents(sqlDB *sql.DB, table string) ([]string, error) {
	// PRAGMA calls don't support parameter binding; table names here come
	// only from queryLiveTableNames's own sqlite_master read, never from
	// external input.
	rows, err := sqlDB.Query(`PRAGMA foreign_key_list(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	parentSet := make(map[string]bool)
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, col := range cols {
			if col == "table" {
				if s, ok := vals[i].(string); ok {
					parentSet[s] = true
				}
			}
		}
	}

	parents := make([]string, 0, len(parentSet))
	for p := range parentSet {
		parents = append(parents, p)
	}
	return parents, rows.Err()
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

Note: `wantParents` for a table with zero dependencies is an empty (non-nil in the map, but zero-length) slice `{}` in `tableDependencies`; `sort.Strings` on a nil or empty slice is a no-op either way, so the comparison in `equalStringSlices` works correctly whether `gotParents`/`wantParents` end up nil or empty-non-nil — do not add special-case handling for that distinction.

- [ ] **Step 2: Run test to verify it fails or passes as expected**

```bash
go test ./internal/backup/... -run TestTableDependencies_MatchesLiveSchema -v
```
Expected: PASS immediately — Task 1's `tableDependencies` map was built directly from `internal/db/db.go`'s real schema, so it should already agree with the live schema. If it FAILS, that means Task 1's map has an error (a missed or extra FK edge) — fix `table_order.go`'s `tableDependencies` map to match what this test's failure output says the live schema actually has, then re-run.

- [ ] **Step 3: Prove the test actually catches drift**

Temporarily add a bogus extra parent to one entry in `tableDependencies` (e.g. add `"vaults"` to `"secrets"`'s parent list, which is not a real FK), re-run the test, confirm it FAILS naming that exact mismatch, then revert:
```bash
# after the temporary edit:
go test ./internal/backup/... -run TestTableDependencies_MatchesLiveSchema -v
# Expected: FAIL, naming "secrets" and the mismatched parent lists
git checkout -- internal/backup/table_order.go
go test ./internal/backup/... -run TestTableDependencies_MatchesLiveSchema -v
# Expected: PASS again
```
This step is verification, not a permanent change — do not commit the temporary breakage.

- [ ] **Step 4: Full repo verification**

```bash
go build ./... && go test ./...
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add internal/backup/table_order_schema_test.go
git commit -m "$(cat <<'EOF'
test(backup): guard tableDependencies against schema drift

TestTableDependencies_MatchesLiveSchema cross-checks table_order.go's
hardcoded FK-dependency map against the real schema's constraints,
queried live via PRAGMA foreign_key_list. A future migration that adds
a table or FK without updating the map now fails this test, instead
of silently reintroducing the restore-ordering bug (Critical Finding #9).

Critical Finding #9, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```

---

### Task 4: Postgres integration test — a real backup+restore round-trip under FK enforcement

**Files:**
- Create: `internal/backup/pg_integration_test.go`

**Interfaces:**
- Consumes: `Manager` (`internal/backup`, unchanged public API), a live Postgres testcontainer (mirroring `internal/repositories/pg_integration_test.go`'s existing `newPostgresConn` pattern — read that file in full first).
- Produces: `TestPostgres_BackupRestore_RoundTrip`, a `//go:build integration`-tagged test — the actual proof this plan set out to establish: a whole-database restore succeeds against a database that genuinely enforces FK constraints, not just SQLite's no-op default.

- [ ] **Step 1: Read the existing Postgres integration test pattern**

Read `internal/repositories/pg_integration_test.go` in full. Note its `//go:build integration` tag, its `newPostgresConn(t)` helper (boots a `postgres:16-alpine` testcontainer, runs `rvdb.NewRepository(...).SetupSchema(sqlDB, rvdb.Postgres)` to get the real, FK-enforcing schema, returns a `(*rvdb.Conn, func())` cleanup pair), and its `seedUser` helper pattern for satisfying FK prerequisites. This task mirrors that pattern in a new file inside `internal/backup` (a different package, so you cannot import `newPostgresConn` directly — write an equivalent helper in the new file, following the same construction).

- [ ] **Step 2: Write the test**

Create `internal/backup/pg_integration_test.go`:

```go
//go:build integration

// Package backup integration suite proves a full backup-then-restore
// round-trip succeeds against a live PostgreSQL database, which -- unlike
// this package's default SQLite-backed tests -- genuinely enforces foreign
// key constraints. Run with:
//
//	go test -tags=integration ./internal/backup/...
//
// It requires Docker. The default `go test ./...` run skips this file.
package backup

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

func newBackupPostgresDB(t *testing.T) (*sql.DB, rvdb.Dialect, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("rocketvault"),
		tcpostgres.WithUsername("rv"),
		tcpostgres.WithPassword("rv-secret"),
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithSQLDriver("postgres"),
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "start postgres container")

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return sqlDB.PingContext(ctx) == nil
	}, 60*time.Second, 500*time.Millisecond, "postgres did not become ready")

	repo := rvdb.NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres), "setup schema on postgres")

	cleanup := func() {
		sqlDB.Close()
		_ = container.Terminate(ctx)
	}
	return sqlDB, rvdb.Postgres, cleanup
}

// TestPostgres_BackupRestore_RoundTrip proves CreateBackup + RestoreBackup
// succeed end-to-end against real Postgres FK enforcement. Before Task 2's
// fix, this would fail with a foreign key violation partway through the
// restore transaction (whichever child table's alphabetical position came
// before its parent's) -- this test is what Critical Finding #9 asked for:
// a Postgres-backed backup/restore test that didn't exist anywhere before
// this plan.
func TestPostgres_BackupRestore_RoundTrip(t *testing.T) {
	sqlDB, dialect, cleanup := newBackupPostgresDB(t)
	defer cleanup()

	userID := uuid.New()
	vaultID := uuid.MustParse("00000000-0000-0000-0000-00000000efa1") // model.DefaultVaultID
	secretID := uuid.New()
	keyID := uuid.New()

	// Seed data spanning multiple dependency levels: users (root),
	// secrets/keys (depend on users), secret_tags/key_tags (depend on
	// secrets/keys) -- exercising a real multi-level FK chain, not just a
	// single parent-child pair.
	_, err := sqlDB.Exec(`INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)`,
		userID.String(), "backup-test-user", "hash", "user")
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO secrets (id, user_id, vault_id, name, value, version) VALUES ($1, $2, $3, $4, $5, $6)`,
		secretID.String(), userID.String(), vaultID.String(), "test-secret", "encrypted-value", 1)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO secret_tags (secret_id, tag_key, tag_value) VALUES ($1, $2, $3)`,
		secretID.String(), "env", "test")
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO keys (id, user_id, vault_id, name, value, type, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
		keyID.String(), userID.String(), vaultID.String(), "test-key", "encrypted-key-material", "RSA")
	require.NoError(t, err)

	mgr := NewManager(sqlDB, dialect, logging.InitLogger())

	backupPath := t.TempDir() + "/pg-roundtrip.backup"
	require.NoError(t, mgr.CreateBackup(backupPath, false))

	// Mutate the live DB before restoring, so the restore's effect is
	// actually observable (otherwise a no-op restore would also "pass").
	_, err = sqlDB.Exec(`DELETE FROM secret_tags WHERE secret_id = $1`, secretID.String())
	require.NoError(t, err)
	_, err = sqlDB.Exec(`UPDATE secrets SET name = $1 WHERE id = $2`, "mutated-name", secretID.String())
	require.NoError(t, err)

	// The real assertion: this must not return an FK-violation error.
	require.NoError(t, mgr.RestoreBackup(backupPath, false))

	var restoredName string
	require.NoError(t, sqlDB.QueryRow(`SELECT name FROM secrets WHERE id = $1`, secretID.String()).Scan(&restoredName))
	require.Equal(t, "test-secret", restoredName, "restore must have reverted the pre-restore mutation")

	var tagCount int
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM secret_tags WHERE secret_id = $1`, secretID.String()).Scan(&tagCount))
	require.Equal(t, 1, tagCount, "restore must have brought the deleted tag back")

	require.NoError(t, os.Remove(backupPath))
}
```

- [ ] **Step 3: Run the integration test**

```bash
go test -tags=integration ./internal/backup/... -run TestPostgres_BackupRestore_RoundTrip -v
```
Expected: PASS, if Docker is available in your environment. If Docker is not available, report that explicitly in your task report rather than silently skipping this step — this test is the primary deliverable this plan exists to produce; its existence (even if you personally couldn't run it in a Docker-less environment) still satisfies the audit finding's "add a Postgres-container-backed integration test" recommendation, but you must say so plainly, not claim a pass you didn't observe.

- [ ] **Step 4: Confirm the untagged default test run is unaffected**

```bash
go test ./internal/backup/...
```
Expected: PASS, and confirm via `go test -v ./internal/backup/... 2>&1 | grep -i postgres` that `TestPostgres_BackupRestore_RoundTrip` does NOT appear in this untagged run's output — the build tag must actually exclude it from the default suite, matching `internal/repositories/pg_integration_test.go`'s existing convention.

- [ ] **Step 5: Full repo verification**

```bash
go build ./... && go test ./...
```
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/backup/pg_integration_test.go
git commit -m "$(cat <<'EOF'
test(backup): add Postgres-backed backup/restore round-trip test

TestPostgres_BackupRestore_RoundTrip proves CreateBackup + RestoreBackup
succeed against real FK enforcement, seeding a multi-level dependency
chain (users -> secrets -> secret_tags, users -> keys) and asserting
restore correctly reverts a pre-restore mutation and deletion. Mirrors
the existing internal/repositories/pg_integration_test.go pattern
(testcontainers postgres:16-alpine, //go:build integration tag). This
is the test Critical Finding #9 asked for and that did not exist
anywhere in the repo before this plan.

Critical Finding #9, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```
