# Migration Sequence Fix Design

**Date:** 2026-03-08
**Status:** Approved
**Scope:** One new SQL file — no Go code changes

## Problem

`./password-manager migrate:to 20241026000003` fails with:

```
no such column: "tags"
```

Migration `20241026000003_drop_tags_column.sql` runs:

```sql
ALTER TABLE secrets DROP COLUMN tags;
```

But the `tags` column does not exist on the `secrets` table because migration
`20241026000002` — which added it — was accidentally deleted from the repository.

### Intended sequence (with 002 present)

| Version | Action |
|---------|--------|
| 001 | no-op placeholder |
| 20241025000001 | add `deleted_at`, `purge_protection` |
| 20241026000001 | add `expires_at`, `not_before`, `enabled` |
| **20241026000002** | **add `tags` column** ← deleted |
| 20241026000003 | drop `tags` (move to `secret_tags` join table) |
| 20241026000004 | add `tags` back |
| 20241026000005 | drop `tags` permanently |

### Current database state (dev)

Applied through `20241026000001`. No `tags` column on `secrets`.
`secret_tags` join table exists and is the canonical store for tags.

## Decision

**Option A — Restore the missing `20241026000002` migration (chosen)**

Rejected alternatives:
- Option B (collapse 003–005 into one safe migration): requires complex
  SQLite table-recreation and destroys intermediate history.
- Option C (restore 002 + squash 004+005): deleting applied migrations
  would break databases that already have 004/005 in `schema_migrations`.

## Change

### Add `internal/db/migrations/20241026000002_add_tags_column.sql`

```sql
-- Migration: Add tags column to secrets table
-- Description: Adds inline tags column for secret categorization.
--              Dropped by 20241026000003 which moves tags to the
--              secret_tags join table.
-- Version: 20241026000002

ALTER TABLE secrets ADD COLUMN tags TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_secrets_tags ON secrets(tags);
```

No Go code changes are required. The migration runner uses
`//go:embed *.sql` so the new file is picked up automatically on the
next build.

## Result

Full sequence after the fix:

| Version | Action | Net effect on schema |
|---------|--------|----------------------|
| 001 | no-op | — |
| 20241025000001 | add `deleted_at`, `purge_protection` | +2 cols |
| 20241026000001 | add `expires_at`, `not_before`, `enabled` | +3 cols |
| 20241026000002 | add `tags` | +1 col |
| 20241026000003 | drop `tags` | −1 col |
| 20241026000004 | add `tags` | +1 col |
| 20241026000005 | drop `tags` | −1 col |

End state: no `tags` column on `secrets`. Matches current production schema.
`migrate:to <any version>` works correctly for all six targets.
