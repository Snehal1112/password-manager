# migrate:create Command Design

**Date:** 2026-03-08
**Status:** Approved
**Scope:** `cmd/migrate.go` only — no new files, no new dependencies

## Problem

Migration files must be created manually. There is no tooling to generate the
correct filename, version prefix, or header template, making it easy to get the
naming convention wrong and break the migration sequence.

## Decision

**Option A — Add `migrate:create` inline to `cmd/migrate.go` (chosen)**

Rejected alternatives:
- Option B (new file + `MigrationRunner.CreateMigration()`): overengineered for a
  file-creation utility; runner is focused on DB operations.
- Option C (new `cmd/migrate_create.go` + standalone helper): splits ~40 lines
  across two files with no real benefit.

## Command interface

```bash
./password-manager migrate:create <description>
```

- `<description>` is one or more words; spaces are joined with underscores for the filename.
- Version format: `YYYYMMDD` + 6-digit zero-padded sequence (e.g. `20260308000001`).
- Sequence is determined by scanning `internal/db/migrations/` for files whose
  names start with today's date prefix, finding the highest sequence number, and
  incrementing by 1. Starts at `000001` if no files exist for today.
- Prints the created file path on success.

```
$ ./password-manager migrate:create add priority to secrets
Created: internal/db/migrations/20260308000001_add_priority_to_secrets.sql
```

## Generated file template

```sql
-- Migration: Add priority to secrets
-- Description: TODO
-- Version: 20260308000001

-- TODO: Add your SQL here
-- Example: ALTER TABLE secrets ADD COLUMN my_col TEXT DEFAULT '';
```

- `-- Migration:` title is the description with underscores replaced by spaces.
- `-- Version:` matches the filename version prefix exactly.
- Placeholder SQL matches the style of existing migration files.

## Implementation

### Changes to `cmd/migrate.go`

**1. New command var:**
```go
var migrateCreateCmd = &cobra.Command{
    Use:   "migrate:create [description]",
    Short: "Create a new migration file",
    Long:  `Create a new timestamped migration file in internal/db/migrations/.`,
    Args:  cobra.MinimumNArgs(1),
    RunE:  createMigration,
}
```

**2. New handler `createMigration()`:**
- Join `args` with `_` for the slug.
- `time.Now().Format("20060102")` for the date prefix.
- `os.ReadDir("internal/db/migrations/")` to find highest sequence for today.
- Increment and zero-pad: `fmt.Sprintf("%06d", seq)`.
- Write file with `os.WriteFile`.
- Print created path.

**3. Register in `init()`:**
```go
rootCmd.AddCommand(migrateCreateCmd)
```

### No changes to
- `internal/db/migrations/migration_runner.go`
- Any other file

### New imports needed in `cmd/migrate.go`
- `"os"`
- `"strings"`
- `"strconv"`

(All standard library — no new module dependencies.)
