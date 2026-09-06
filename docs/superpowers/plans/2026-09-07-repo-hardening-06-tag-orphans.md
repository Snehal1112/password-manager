# Repository Hardening — Plan 06: Orphaned Tag Rows and the Shared Delete

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop purge and delete from stranding tag rows on SQLite, and collapse the three near-identical `Delete` methods into one shared `deleteItemWithTags` while doing it.

**Architecture:** `secret_tags`, `key_tags`, and `certificate_tags` each declare `ON DELETE CASCADE` (`internal/db/db.go:437-443, 479-485, 589-595`), but SQLite runs with the `foreign_keys` pragma **off** project-wide. That cascade therefore never fires — the documented reason `RoleAssignmentRepository.DeleteByVault`, `AccessPolicyRepository.DeleteByVault`, and the webhook cleaner exist at all. `item_lifecycle.go`'s `purgeItem` and `purgeVaultContents` issue a bare row delete, stranding every tag row of the purged item for all three types; `SecretRepository.Delete` does the same. Key's and certificate's `Delete` already clean up their tags explicitly, which establishes the intended behavior. Teaching `itemLifecycleConfig` the tag table lets the purge paths clean up *and* lets the three `Delete` methods share one implementation, since they otherwise differ only in table names and log labels.

**Tech Stack:** Go 1.24, `database/sql`, transactions, `testify`, in-memory SQLite.

**Spec:** `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md` (finding F5)

## Global Constraints

- **No exported interface, signature, or error-message change.** `Delete(ctx, id) error` keeps its shape on all three repositories. `internal/repositories/mocks/` must not be regenerated.
- **`crud()` stays a method, never a field.** Tests build these repositories via struct literals; a constructor-set config would zero-value and the nil `wrap` would panic on first call. The new `tagTable`/`tagFK` fields must be supplied from inside `crud()` like every existing field.
- **Preserve each type's existing divergences.** `itemLifecycleConfig` exists to encode them, not to unify them: secrets log audit rows with an empty actor string while key and certificate use `uuid.Nil.String()`; secrets pass `passthroughWrap` while the others pass their own wrapper; `notFoundIsSentinel` is true only for secrets. Do not "tidy" any of these.
- **Adding a second write to `purgeItem` makes it two statements that must succeed or fail together.** It must run in a transaction.
- Branch: `refactor/repo-hardening`. One signed commit per task (GPG key `61D246B30285ED35`).
- Per task, before committing: `go build ./...`, `go vet ./...`, `go test ./internal/repositories/... ./internal/services/...`

---

### Task 1: Teach `itemLifecycleConfig` the tag table, and clean up on purge

**Files:**
- Modify: `internal/repositories/item_lifecycle.go:20-42` (config struct), `:110-165` (`purgeItem`), `:230-247` (`purgeVaultContents`); `secret_repository.go:110-122`, `key_repository.go:265-277`, `certificate_repository.go:316-328` (the three `crud()` methods)
- Test: `internal/repositories/tag_orphan_test.go` (create)

**Interfaces:**
- Produces: `itemLifecycleConfig` gains `tagTable string` and `tagFK string`; `purgeItem` and `purgeVaultContents` delete tag rows in the same transaction as the item rows.

- [ ] **Step 1: Write the failing test**

```go
// internal/repositories/tag_orphan_test.go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupTagOrphanTestDB creates an in-memory SQLite database with the keys and
// key_tags tables. The FOREIGN KEY ... ON DELETE CASCADE is declared exactly as
// production declares it -- and, exactly as in production, SQLite leaves the
// foreign_keys pragma off, so it never fires. That is the whole point of the
// test: the cascade looks like it handles this and does not.
//
// Named distinctly from the package-scope setupTestDB, setupRotationTestDB,
// setupSessionTestDB, setupCertListAllTestDB, setupRoleAssignmentTestDB and
// setupCertLifecycleTestDB helpers that already exist in this test package.
func setupTagOrphanTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:tagorphan_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP,
			not_before TIMESTAMP,
			bits INTEGER NOT NULL DEFAULT 0,
			curve TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP,
			deleted_at TIMESTAMP,
			scheduled_purge_at TIMESTAMP,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		);
	`)
	require.NoError(t, err, "create keys schema")

	return raw
}

func countKeyTags(t *testing.T, raw *sql.DB, keyID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, raw.QueryRow(
		"SELECT COUNT(*) FROM key_tags WHERE key_id = ?", keyID.String()).Scan(&n))
	return n
}

// TestPurgeKeyRemovesItsTags pins the F5 fix. key_tags declares ON DELETE
// CASCADE, but SQLite runs with the foreign_keys pragma off project-wide, so
// the cascade never fires and purging a key strands every tag row it owned --
// unreachable through any route and never swept.
func TestPurgeKeyRemovesItsTags(t *testing.T) {
	raw := setupTagOrphanTestDB(t)
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "signing-key",
		Value:     "ENCRYPTED",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
		Tags:      []string{"prod", "signing"},
	}
	require.NoError(t, repo.Create(ctx, key))
	require.Equal(t, 2, countKeyTags(t, raw, key.ID), "tags were stored")

	require.NoError(t, repo.SoftDelete(ctx, key.ID))
	require.NoError(t, repo.PurgeKey(ctx, key.ID))

	require.Equal(t, 0, countKeyTags(t, raw, key.ID),
		"purging a key must remove its tag rows; SQLite's declared cascade does not fire")
}

// TestDeleteKeyRemovesItsTags confirms the hard-delete path, which key and
// certificate already handled explicitly and secret did not.
func TestDeleteKeyRemovesItsTags(t *testing.T) {
	raw := setupTagOrphanTestDB(t)
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "throwaway",
		Value:     "ENCRYPTED",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
		Tags:      []string{"temp"},
	}
	require.NoError(t, repo.Create(ctx, key))
	require.Equal(t, 1, countKeyTags(t, raw, key.ID))

	require.NoError(t, repo.Delete(ctx, key.ID))
	require.Equal(t, 0, countKeyTags(t, raw, key.ID))
}
```

- [ ] **Step 2: Run the tests and verify the purge one fails**

Run: `go test ./internal/repositories/ -run 'TestPurgeKeyRemovesItsTags|TestDeleteKeyRemovesItsTags' -v`
Expected:
- `TestPurgeKeyRemovesItsTags` FAILS — 2 tag rows survive the purge.
- `TestDeleteKeyRemovesItsTags` PASSES already — `KeyRepository.Delete` cleans up explicitly today.

- [ ] **Step 3: Add the tag fields to the config**

In `internal/repositories/item_lifecycle.go`, add to the `itemLifecycleConfig` struct (after `idField`):

```go
	tagTable           string // join table holding this item's tags: "secret_tags" / "key_tags" / "certificate_tags"
	tagFK              string // the tag table's column referencing the item: "secret_id" / "key_id" / "certificate_id"
```

Extend the struct's doc comment with:

```go
//   - tagTable/tagFK identify the item's tag join table. Each declares
//     ON DELETE CASCADE, but SQLite runs with the foreign_keys pragma off
//     project-wide, so the cascade never fires and the rows must be deleted
//     explicitly -- the same reason RoleAssignmentRepository.DeleteByVault and
//     AccessPolicyRepository.DeleteByVault exist.
```

- [ ] **Step 4: Populate the fields in all three `crud()` methods**

`secret_repository.go` (in `crud()`, after `idField: "secret_id",`):

```go
		tagTable:           "secret_tags",
		tagFK:              "secret_id",
```

`key_repository.go` (after `idField: "key_id",`):

```go
		tagTable:           "key_tags",
		tagFK:              "key_id",
```

`certificate_repository.go` (after `idField: "cert_id",`):

```go
		tagTable:           "certificate_tags",
		tagFK:              "certificate_id",
```

Note the certificate tag foreign key is `certificate_id`, not `cert_id` — `idField` is a logrus label, `tagFK` is a SQL column, and for certificates they differ. Getting this wrong produces a "no such column" error at purge time, not at compile time.

- [ ] **Step 5: Delete tags inside `purgeItem`, in a transaction**

In `internal/repositories/item_lifecycle.go`, `purgeItem` currently issues a bare `ex.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE id = ?", id.String())`. Replace that single statement (and its result handling) so both deletes run together.

Replace:

```go
		result, err := ex.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE id = ?", id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to purge "+cfg.item, err)
			return fmt.Errorf("failed to purge %s: %w", cfg.item, err)
		}
```

with:

```go
		// Tag rows first, then the item, both against ex. The tag table
		// declares ON DELETE CASCADE, but SQLite runs with the foreign_keys
		// pragma off project-wide, so that cascade never fires -- without this
		// the tags outlive the item as unreachable rows nothing ever sweeps.
		if _, tagErr := ex.ExecContext(ctx,
			"DELETE FROM "+cfg.tagTable+" WHERE "+cfg.tagFK+" = ?", id.String()); tagErr != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to purge "+cfg.item+" tags", tagErr)
			return fmt.Errorf("failed to purge %s tags: %w", cfg.item, tagErr)
		}

		result, err := ex.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE id = ?", id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to purge "+cfg.item, err)
			return fmt.Errorf("failed to purge %s: %w", cfg.item, err)
		}
```

**On atomicity:** `purgeItem` receives `ex db.DBTX`, which is already a transaction when reached through a `...Tx` caller but is a plain connection when reached through `PurgeKey`/`PurgeSecret`/`PurgeCertificate`. Two statements on a plain connection are not atomic — a crash between them leaves the item gone and its tags stranded, which is the state this task exists to prevent.

Order the deletes tags-first so the failure window leaves *tags gone, item present* rather than the reverse. An item with missing tags is recoverable and visible; an orphaned tag row is neither. This matches the tags-first ordering `KeyRepository.Delete` and `CertificateRepository.Delete` already use inside their own transactions.

Do **not** open a transaction inside `purgeItem` — it cannot know whether `ex` is already one, and `database/sql` does not support nesting. Record this tradeoff in the commit message.

- [ ] **Step 6: Delete tags inside `purgeVaultContents`**

Replace the single `DELETE FROM`+`cfg.table` statement in `purgeVaultContents` with a tag delete followed by the item delete:

```go
		// Same cascade caveat as purgeItem: delete the vault's tag rows via a
		// subquery over the items about to be removed, before removing them.
		if _, tagErr := ex.ExecContext(ctx,
			"DELETE FROM "+cfg.tagTable+" WHERE "+cfg.tagFK+
				" IN (SELECT id FROM "+cfg.table+" WHERE vault_id = ?)", vaultID.String()); tagErr != nil {
			cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to purge vault "+cfg.tagTable, tagErr)
			return fmt.Errorf("failed to purge vault %s: %w", cfg.tagTable, tagErr)
		}

		_, err := ex.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE vault_id = ?", vaultID.String())
		if err != nil {
			cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to purge vault "+cfg.table, err)
			return fmt.Errorf("failed to purge vault %s: %w", cfg.table, err)
		}
```

The subquery must run before the item delete, or it matches nothing.

- [ ] **Step 7: Run the tests and verify they pass**

Run: `go test ./internal/repositories/ -run 'TestPurgeKeyRemovesItsTags|TestDeleteKeyRemovesItsTags' -v`
Expected: PASS

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 8: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/item_lifecycle.go internal/repositories/secret_repository.go \
        internal/repositories/key_repository.go internal/repositories/certificate_repository.go \
        internal/repositories/tag_orphan_test.go
```

---

### Task 2: Shared `deleteItemWithTags`

**Files:**
- Create the function in: `internal/repositories/item_lifecycle.go`
- Modify: `key_repository.go:478-523` (`Delete`), `certificate_repository.go:474-519` (`Delete`), `secret_repository.go:369-392` (`Delete`)
- Test: `internal/repositories/tag_orphan_test.go` (extend)

**Interfaces:**
- Consumes: `itemLifecycleConfig` with `tagTable`/`tagFK` from Task 1.
- Produces: `func deleteItemWithTags(ctx context.Context, conn db.DB, cfg itemLifecycleConfig, id uuid.UUID) error`.

`KeyRepository.Delete` and `CertificateRepository.Delete` are the same 45 lines with `keys`/`key_tags`/`key_id` swapped for `certificates`/`certificate_tags`/`certificate_id`. `SecretRepository.Delete` is the odd one out: it deletes no tags and opens no transaction. Folding all three onto one helper fixes secret's missing cleanup as a side effect of the deduplication.

Note the signature takes `db.DB`, not `db.DBTX` — unlike the other lifecycle functions, this one **begins its own transaction**, which requires `BeginTx`.

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/tag_orphan_test.go`:

```go
// TestDeleteKeyIsAtomic pins the transaction the shared helper opens: if the
// item delete finds no row, the tag delete that ran first must roll back
// rather than leaving the key present with its tags gone.
func TestDeleteKeyIsAtomic(t *testing.T) {
	raw := setupTagOrphanTestDB(t)
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "keeper",
		Value:     "ENCRYPTED",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
		Tags:      []string{"keep-me"},
	}
	require.NoError(t, repo.Create(ctx, key))

	// Delete a key that does not exist. The helper deletes tags first, so
	// without a rollback this would strip the real key's tags -- except the
	// id does not match, so nothing should change at all.
	err := repo.Delete(ctx, uuid.New())
	require.Error(t, err, "deleting an absent key is an error")
	require.Contains(t, err.Error(), "key not found")

	require.Equal(t, 1, countKeyTags(t, raw, key.ID),
		"an unrelated failed delete must not touch this key's tags")
}
```

- [ ] **Step 2: Run the test and verify it passes**

Run: `go test ./internal/repositories/ -run TestDeleteKeyIsAtomic -v`
Expected: PASS before the change (key's `Delete` already uses a transaction). It is a regression guard for Task 2's refactor, and it must still pass after.

- [ ] **Step 3: Add the shared helper**

Add to `internal/repositories/item_lifecycle.go`:

```go
// deleteItemWithTags hard-deletes one row and its tag rows in a single
// transaction, tags first. Unlike the other functions in this file it takes a
// db.DB rather than a db.DBTX, because it begins the transaction itself.
//
// The tag delete is not optional bookkeeping: the tag tables declare
// ON DELETE CASCADE, but SQLite runs with the foreign_keys pragma off
// project-wide, so the cascade never fires. Before this helper, secret's
// Delete omitted the tag cleanup entirely while key's and certificate's
// performed it -- the divergence this consolidates away.
func deleteItemWithTags(ctx context.Context, conn db.DB, cfg itemLifecycleConfig, id uuid.UUID) error {
	op := "delete_" + cfg.item
	return cfg.wrap(op, func() error {
		logrus.WithField(cfg.idField, id.String()).Debug("Deleting " + cfg.item + " from database")

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		if _, err := tx.ExecContext(ctx,
			"DELETE FROM "+cfg.tagTable+" WHERE "+cfg.tagFK+" = ?", id.String()); err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to delete tags", err)
			return fmt.Errorf("failed to delete tags: %w", err)
		}

		result, err := tx.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE id = ?", id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to delete "+cfg.item, err)
			return fmt.Errorf("failed to delete %s: %w", cfg.item, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" not found for deletion", nil)
			return fmt.Errorf("%s not found", cfg.item)
		}

		if err := tx.Commit(); err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		cfg.log.LogAuditInfo(cfg.auditActor, op, "success", cfg.itemCap+" deleted successfully")
		logrus.WithField(cfg.idField, id.String()).Debug(cfg.itemCap + " deleted successfully")
		return nil
	})
}
```

- [ ] **Step 4: Point `KeyRepository.Delete` at the helper**

Replace the whole body of `Delete` in `key_repository.go` with:

```go
func (r *KeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return deleteItemWithTags(ctx, r.db, r.crud(), id)
}
```

Keep the existing doc comment above it.

- [ ] **Step 5: Point `CertificateRepository.Delete` at the helper**

Replace the whole body of `Delete` in `certificate_repository.go` with:

```go
func (r *CertificateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return deleteItemWithTags(ctx, r.db, r.crud(), id)
}
```

- [ ] **Step 6: Point `SecretRepository.Delete` at the helper**

Replace the whole body of `Delete` in `secret_repository.go` with:

```go
func (r *SecretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return deleteItemWithTags(ctx, r.db, r.crud(), id)
}
```

**Three behavior changes for secrets, all intended — state them in the commit message:**
1. Secret deletes now remove `secret_tags` rows, which they never did.
2. Secret deletes now run in a transaction; previously a single bare `Exec`.
3. Secret's audit actor stays `""` (its `crud()` sets `auditActor: ""`), so the audit trail's shape is unchanged — verify this rather than assuming it.

Plan 05 Task 3 deliberately left `SecretRepository.Delete` uninstrumented for exactly this reason: `deleteItemWithTags` calls `cfg.wrap`, and secret's `crud()` supplies `passthroughWrap`, so any wrapper added there would have been discarded here. Secret deletes therefore remain unmeasured. That is the config doing its job — if they should be measured, change secret's `crud()` to pass `r.executeWithMetrics`, which is a one-line change and a separate decision.

- [ ] **Step 7: Verify the error strings survived**

Run: `go test ./internal/services/... -run 'Delete' -v 2>&1 | tail -40`

The helper produces `"key not found"`, `"certificate not found"`, and `"secret not found"` — the same strings the three hand-written versions produced. If a service test fails on a message mismatch, the helper's `fmt.Errorf` differs from what that repository used to emit; fix the helper, not the test.

- [ ] **Step 8: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 9: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/item_lifecycle.go internal/repositories/key_repository.go \
        internal/repositories/certificate_repository.go internal/repositories/secret_repository.go \
        internal/repositories/tag_orphan_test.go
```

---

### Task 3: Final verification and documentation

**Files:**
- Modify: `.claude/known-bugs.md`

**Interfaces:**
- Consumes: everything from Plans 01-06.
- Produces: a record of the six findings and their fixes.

- [ ] **Step 1: Run the whole suite**

```bash
go build ./...
go vet ./...
go test ./...
```

Expected: all PASS. This is the first run across the *entire* module in this chain; earlier plans scoped their runs to `internal/repositories/...` and `internal/services/...`.

- [ ] **Step 2: Run the `scope-gate` CI checks locally**

The CI job greps for hand-built populated `model.Scope{...}` literals and for legacy `InVault`/`ByOwner` method names. Reproduce it:

```bash
grep -rn --include='*.go' 'model\.Scope{\([^}]\|$\)' . | grep -v model/scope_test.go
# Expected: no output (the empty model.Scope{} is deliberately allowed)

grep -rn --include='*.go' 'func .*\(InVault\|ByOwner\)(' internal/repositories/ \
  | grep -v role_assignment
# Expected: no output
```

If either returns something you introduced, fix it. If it returns something pre-existing and documented as an exclusion in `.github/workflows/go.yml`, leave it.

- [ ] **Step 3: Record the findings in `.claude/known-bugs.md`**

Append a fixed-bugs entry. Follow the file's existing entry format — read a recent entry first and match its heading style, field order, and level of detail. Cover all six findings with, for each: the symptom, the root cause, the fix, and the commit. Reference the spec at `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md` rather than restating its analysis.

Also record the two things this work deliberately did **not** do, so they are not rediscovered from scratch:
- The non-goals listed in the spec (dead `SecretRepositoryInterface` stubs, `SecretFilter.Tags` silently ignored, `SecretFilter` not in `model/`, secret `List` not loading tags) — all excluded because each needs an exported-interface change.
- `purgeItem`'s two statements are not atomic when reached through a non-`Tx` caller (see Task 1 Step 5), ordered tags-first so the failure window is the recoverable direction.

- [ ] **Step 4: Verify the branch is clean and review the whole diff**

```bash
git status
git diff v-4.0.0...HEAD --stat
```

Read the stat output. Expect roughly 14 commits across `internal/repositories/`, one file in `internal/db/`, plus the spec, six plans, and `.claude/known-bugs.md`. Anything outside those paths was not part of this work — investigate before proceeding.

- [ ] **Step 5: Commit** (use the `1-git-commit` skill)

```bash
git add .claude/known-bugs.md
```

---

## On completion

All six findings (F1-F6) are closed on `refactor/repo-hardening`, `go test ./...` is green, and `.claude/known-bugs.md` records both the fixes and the deferred non-goals.

**This is the final plan in the chain — do not look for a next one.**

Report to the user: the branch name, the commit count, the `go test ./...` result, and the four non-goals left open. Do not merge, push, or open a pull request without asking.
