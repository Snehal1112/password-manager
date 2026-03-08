# migrate:create Command Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `migrate:create <description>` CLI command that generates a correctly-named, pre-populated migration file in `internal/db/migrations/`.

**Architecture:** Two unexported helper functions are extracted from the command handler to keep the logic testable without invoking the CLI. `nextMigrationVersion` scans the migrations directory and computes the next `YYYYMMDD000001`-style version; `migrationFileContent` renders the file template. The command handler in `cmd/migrate.go` wires them together, writes the file, and prints the path.

**Tech Stack:** Go standard library (`os`, `strings`, `strconv`, `fmt`, `time`), Cobra, existing project conventions in `cmd/migrate.go`.

---

### Task 1: Test + implement `nextMigrationVersion`

**Files:**
- Create: `cmd/migrate_create_test.go`
- Modify: `cmd/migrate.go`

#### Step 1: Write the failing tests

Create `cmd/migrate_create_test.go`:

```go
package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextMigrationVersion_EmptyDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000001", version)
}

func TestNextMigrationVersion_ExistingFilesForToday(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Create two existing migration files for today
	touch(t, dir, "20260308000001_first.sql")
	touch(t, dir, "20260308000003_third.sql") // gap in sequence — should still give 000004
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000004", version)
}

func TestNextMigrationVersion_FilesFromOtherDays(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	touch(t, dir, "20260307000005_yesterday.sql") // different day — must be ignored
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000001", version)
}

func TestNextMigrationVersion_NonSQLFilesIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	touch(t, dir, "20260308000001_migration.go") // .go file — must be ignored
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000001", version)
}

// touch creates an empty file in dir with the given name.
func touch(t *testing.T, dir, name string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	require.NoError(t, err)
	f.Close()
}
```

#### Step 2: Run tests to verify they fail

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/... -run TestNextMigrationVersion -v
```

Expected: `FAIL` — `nextMigrationVersion` undefined.

#### Step 3: Implement `nextMigrationVersion` in `cmd/migrate.go`

Add these imports to the existing import block in `cmd/migrate.go`:

```go
"os"
"strconv"
"strings"
```

Add the function after the existing `init()` block:

```go
// nextMigrationVersion returns the next version string for a new migration.
// It scans dir for .sql files whose names start with today, finds the highest
// 6-digit sequence suffix, and returns today + (max+1) zero-padded to 6 digits.
func nextMigrationVersion(dir string, today string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("failed to read migrations directory: %w", err)
	}

	max := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		if !strings.HasPrefix(name, today) {
			continue
		}
		// Filename format: YYYYMMDDNNNNNN_description.sql
		// Sequence occupies characters [8:14].
		if len(name) < 14 {
			continue
		}
		seq, err := strconv.Atoi(name[8:14])
		if err != nil {
			continue
		}
		if seq > max {
			max = seq
		}
	}

	return fmt.Sprintf("%s%06d", today, max+1), nil
}
```

#### Step 4: Run tests to verify they pass

```bash
go test ./cmd/... -run TestNextMigrationVersion -v
```

Expected: all 4 tests `PASS`.

---

### Task 2: Test + implement `migrationFileContent`

**Files:**
- Modify: `cmd/migrate_create_test.go`
- Modify: `cmd/migrate.go`

#### Step 1: Add failing tests

Append to `cmd/migrate_create_test.go`:

```go
func TestMigrationFileContent(t *testing.T) {
	t.Parallel()
	content := migrationFileContent("20260308000001", "add_priority_to_secrets")
	assert.Contains(t, content, "-- Version: 20260308000001")
	assert.Contains(t, content, "-- Migration: Add priority to secrets")
	assert.Contains(t, content, "-- Description: TODO")
	assert.Contains(t, content, "-- TODO: Add your SQL here")
	assert.Contains(t, content, "-- Example: ALTER TABLE")
}

func TestMigrationFileContent_SingleWord(t *testing.T) {
	t.Parallel()
	content := migrationFileContent("20260308000002", "users")
	assert.Contains(t, content, "-- Migration: Users")
	assert.Contains(t, content, "-- Version: 20260308000002")
}
```

#### Step 2: Run to verify they fail

```bash
go test ./cmd/... -run TestMigrationFileContent -v
```

Expected: `FAIL` — `migrationFileContent` undefined.

#### Step 3: Implement `migrationFileContent` in `cmd/migrate.go`

Add after `nextMigrationVersion`:

```go
// migrationFileContent renders the template for a new migration file.
// slug is the underscore-separated description (e.g. "add_priority_to_secrets").
func migrationFileContent(version, slug string) string {
	title := strings.ReplaceAll(slug, "_", " ")
	// Title-case: capitalise first letter only (keep rest as-is).
	if len(title) > 0 {
		title = strings.ToUpper(title[:1]) + title[1:]
	}
	return fmt.Sprintf(`-- Migration: %s
-- Description: TODO
-- Version: %s

-- TODO: Add your SQL here
-- Example: ALTER TABLE secrets ADD COLUMN my_col TEXT DEFAULT '';
`, title, version)
}
```

#### Step 4: Run to verify they pass

```bash
go test ./cmd/... -run TestMigrationFileContent -v
```

Expected: all 2 tests `PASS`.

---

### Task 3: Wire up the CLI command

**Files:**
- Modify: `cmd/migrate.go`

#### Step 1: Add the command var

Add after `migrateToCmd`:

```go
// migrateCreateCmd represents the migrate:create command.
var migrateCreateCmd = &cobra.Command{
	Use:   "migrate:create [description]",
	Short: "Create a new migration file",
	Long: `Create a new timestamped migration file in internal/db/migrations/.

The description words are joined with underscores to form the filename.

Example:
  rocketvault migrate:create add priority to secrets
  # Creates: internal/db/migrations/20260308000001_add_priority_to_secrets.sql`,
	Args: cobra.MinimumNArgs(1),
	RunE: createMigration,
}
```

#### Step 2: Add the handler function

Add after `migrateToVersion`:

```go
// createMigration creates a new migration file in internal/db/migrations/.
func createMigration(cmd *cobra.Command, args []string) error {
	const migrationsDir = "internal/db/migrations"

	today := time.Now().Format("20060102")
	slug := strings.Join(args, "_")

	version, err := nextMigrationVersion(migrationsDir, today)
	if err != nil {
		return fmt.Errorf("failed to determine next version: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.sql", version, slug)
	path := fmt.Sprintf("%s/%s", migrationsDir, filename)

	content := migrationFileContent(version, slug)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write migration file: %w", err)
	}

	fmt.Printf("Created: %s\n", path)
	return nil
}
```

#### Step 3: Register the command in `init()`

Append inside the existing `func init()` in `cmd/migrate.go`:

```go
rootCmd.AddCommand(migrateCreateCmd)
```

#### Step 4: Build

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 5: Smoke-test the command

```bash
./rocketvault migrate:create add priority to secrets
```

Expected output:
```
Created: internal/db/migrations/20260308000001_add_priority_to_secrets.sql
```

Verify the file:
```bash
cat internal/db/migrations/20260308000001_add_priority_to_secrets.sql
```

Expected:
```sql
-- Migration: Add priority to secrets
-- Description: TODO
-- Version: 20260308000001

-- TODO: Add your SQL here
-- Example: ALTER TABLE secrets ADD COLUMN my_col TEXT DEFAULT '';
```

Verify it appears in migration status:
```bash
./rocketvault migrate:status
```

Expected: new file listed as `[ ] 20260308000001 - add_priority_to_secrets (Pending)`.

#### Step 6: Clean up the test migration file

The smoke-test file is not a real migration — delete it before committing:

```bash
rm internal/db/migrations/20260308000001_add_priority_to_secrets.sql
```

#### Step 7: Run the full test suite

```bash
go test ./... -count=1
```

Expected: all packages pass.

#### Step 8: Commit

```bash
git add cmd/migrate.go cmd/migrate_create_test.go
git commit -m "feat: add migrate:create command to generate migration files"
```
