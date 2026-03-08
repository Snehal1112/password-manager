# Migration Sequence Fix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restore the accidentally deleted `20241026000002` migration so that `migrate:to <any version>` works without errors.

**Architecture:** One new SQL file added to `internal/db/migrations/`. The migration runner uses `//go:embed *.sql` so no Go code changes are needed. The file adds the `tags` column to `secrets`, which the already-existing migration `20241026000003` then drops.

**Tech Stack:** SQLite, Go embed FS, migration runner at `internal/db/migrations/migration_runner.go`

---

### Task 1: Create the missing migration file

**Files:**
- Create: `internal/db/migrations/20241026000002_add_tags_column.sql`

**Step 1: Create the file**

```sql
-- Migration: Add tags column to secrets table
-- Description: Adds inline tags column for secret categorization.
--              Dropped by 20241026000003 which moves tags to the
--              secret_tags join table.
-- Version: 20241026000002

ALTER TABLE secrets ADD COLUMN tags TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_secrets_tags ON secrets(tags);
```

**Step 2: Rebuild the binary so the embed picks up the new file**

```bash
go build -o rocketvault .
```

Expected: no errors.

**Step 3: Verify migration status shows 002 as pending**

```bash
./rocketvault migrate:status
```

Expected output includes:
```
[ ] 20241026000002 - add_tags_column (Pending)
[ ] 20241026000003 - drop_tags_column (Pending)
[ ] 20241026000004 - add_tags (Pending)
[ ] 20241026000005 - remove_tags_functionality (Pending)
```

**Step 4: Test migrate:to 20241026000002 succeeds**

```bash
./rocketvault migrate:to 20241026000002
```

Expected: exits 0, no errors.

**Step 5: Confirm tags column exists in DB**

```bash
sqlite3 dev-rocketvault.db "PRAGMA table_info(secrets);" | grep tags
```

Expected: a row containing `tags`.

**Step 6: Test migrate:to 20241026000003 succeeds**

```bash
./rocketvault migrate:to 20241026000003
```

Expected: exits 0, no errors. Migration drops the `tags` column.

**Step 7: Confirm tags column is gone**

```bash
sqlite3 dev-rocketvault.db "PRAGMA table_info(secrets);" | grep tags
```

Expected: no output (column was dropped).

**Step 8: Run all migrations to confirm the full sequence works**

```bash
./rocketvault migrate
```

Expected:
```
All migrations completed successfully
```
or "No pending migrations found" if already at latest.

**Step 9: Run existing tests to confirm nothing is broken**

```bash
go test ./internal/db/... ./internal/repositories/... -count=1
```

Expected: all pass.

**Step 10: Commit**

```bash
git add internal/db/migrations/20241026000002_add_tags_column.sql
git commit -m "fix: restore missing 20241026000002 migration to fix migrate:to sequence"
```

---

### Task 2: Reset dev database for clean verification (optional)

If you want to verify the full sequence from scratch on a clean database:

**Step 1: Remove the existing dev database**

```bash
rm dev-rocketvault.db
```

**Step 2: Run the server briefly to recreate the base schema**

```bash
./rocketvault migrate
```

Expected: all 6 migrations applied in order with no errors.

**Step 3: Confirm final schema has no tags column**

```bash
sqlite3 dev-rocketvault.db "PRAGMA table_info(secrets);"
```

Expected: columns are `id, user_id, name, value, version, created_at, deleted_at, purge_protection, expires_at, not_before, enabled` — no `tags`.

**Step 4: Re-create admin user since database was wiped**

```bash
./rocketvault users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token ***SECRET-REMOVED-2026-08-17***
```
