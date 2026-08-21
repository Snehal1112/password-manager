# B39 — `migrate:to` Downward Refusal Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rocketvault migrate:to <version>` refuses, with a clear error and a non-zero exit, when `<version>` is lower than the database's current schema version, instead of silently doing nothing.

**Architecture:** `MigrationRunner.MigrateToVersion` (`internal/db/migrations/migration_runner.go`) gains a version-magnitude check, evaluated before any migration is loaded or applied: fetch the current version via the existing `GetCurrentVersion`, parse both it and the target to `int64` with a new unexported `parseVersionNumber` helper, and return a descriptive error if the target is lower. The pre-existing forward-apply loop's own version comparison is switched to the same numeric comparator, since it shares the defect this plan fixes. `cmd/migrate.go` needs no behavioral change — its `RunE` already propagates whatever error `MigrateToVersion` returns, and cobra's existing `run()` wrapper (`cmd/root.go:98-103`) already turns any non-nil `RunE` error into exit code 1 — but its help text is updated to describe the new behavior.

**Tech Stack:** Go 1.25.0, `database/sql` + `mattn/go-sqlite3` (in-memory, existing test pattern), `stretchr/testify`.

**Spec:** docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md

## Global Constraints

> The spec has no section literally titled "Global Constraints" — this list is assembled from its B39 section, its "Non-goals" section, its "Testing" table, and this repo's `CLAUDE.md`/`MY.md`. See "Deviations from the task framing" below for the one place the task's own premise did not survive contact with the code.

- No down-migration support: no `Down()` method, no interface change (spec "Non-goals": "Implementing down-migrations" was rejected — some migrations drop columns and cannot be reversed without data loss).
- Refuse a downward target with exactly this error shape (spec B39 section): `cannot migrate down: current schema is at version 7, target 3 is lower. Down-migrations are not supported.`
- Exit non-zero.
- Every fix starts with a failing test (spec "Testing" section preamble).
- Headline test (spec "Testing" table, B39 row): `migrate:to` below current → non-zero exit and no schema change (assert the applied-migrations set is identical before and after).
- Comments: short, easy, full sentences ending in a punctuation mark. No emojis (`MY.md`).
- Code must build and be lint-clean before this is considered done (`MY.md`: "ensure that the code actually builds and has no linter errors").
- Commits signed with GPG key `61D246B30285ED35` (repo convention, confirmed via `git log --show-signature`).
- `go.mod` is at Go 1.25.0 — no new dependencies needed for this fix.

---

## What reading the code actually found

**GetCurrentVersion's signature and behavior** (`internal/db/migrations/migration_runner.go:248-264`): `func (r *MigrationRunner) GetCurrentVersion(ctx context.Context) (string, error)`. It calls `r.Initialize(ctx)` itself, then `SELECT MAX(version) FROM schema_migrations`, returning `"0"` when no rows exist. The returned value is a plain string — SQLite's `MAX()` over a `VARCHAR` column is a **byte-wise (lexicographic) comparison**, not numeric.

**The task's framing was wrong about the loop.** The instructions state "Migration versions in the loop are compared numerically" — they are not. `MigrateToVersion`'s loop (`migration_runner.go:224-227`, and `LoadMigrations`'s sort at `:126-128`) compares `Migration.Version`, a plain `string` field, with Go's default `>`/`<` operators, which is byte-wise lexicographic, exactly like the SQL `MAX()` above. This is precisely the "10 sorts before 9" trap the task warned about, and it is real: `strconv.ParseInt` treats `"10" < "9"` as false but `"10" < "9"` as a Go string expression is **true** (`'1' < '9'`). Confirmed empirically:

```
$ go run -
package main
import "fmt"
func main() { fmt.Println("10" < "9") } // true
```

**Why it hasn't bitten yet.** Every real file under `internal/db/migrations/*.sql` (13 files, confirmed by listing the directory) uses one of exactly two version shapes: the single legacy `001` (3 digits) and twelve `YYYYMMDDNNNNNN` timestamps (14 digits) that `migrate:create` always generates (`cmd/migrate.go:349`, `nextMigrationVersion`). Comparisons across `001` and any 14-digit version happen to resolve correctly by luck (`'0' < '2'` for the leading digit), and comparisons within the 14-digit set are correct because they are all the same width. No file on disk currently proves the bug wrong. It is latent, not active — but the task explicitly asked for the comparison to be made "correct and consistent," not just patched for the shapes that exist today, so this plan fixes both the new refusal check and the pre-existing loop, not just the former.

**Resolution: `parseVersionNumber`.** Every version string in this package is confirmed to be decimal digits only (`grep -vE '^[0-9]+$'` over the real filenames returns nothing). A `strconv.ParseInt(version, 10, 64)` is therefore safe and gives true magnitude comparison. This plan adds it as a small, unexported, independently-tested helper (Task 1), then uses it both for the new refusal check and to fix the existing loop's `break` condition (Task 2).

**"Target version does not exist at all" — decided and tested two ways:**
- **Below current, no matching file** (e.g. current is a real 14-digit version, target is `"5"`): refused, identically to a target that does match a real file. The refusal is a pure magnitude comparison against the current version — it must not depend on whether the target happens to name a real migration, or an operator could dodge the refusal by guessing an arbitrary small number. Tested by `TestMigrateToVersion_RefusesDownwardTargetEvenWithNoExactFileMatch`.
- **At or above current, no matching file** (e.g. target is `"99999999999999"`): this is **not** a down-migration and is left alone — pre-existing permissive behavior (apply everything with version ≤ target, which may be nothing) is preserved unchanged. B39 is scoped to the downward case; inventing a "target must name a real migration" requirement is a different, unrequested feature and is explicitly not added. Tested by `TestMigrateToVersion_TargetAboveCurrentWithNoExactMatchSucceeds`.
- A target that is not numeric at all (e.g. `"not-a-version"`) cannot be compared to the current version, so it is rejected with a parse error before anything else runs. This was not an explicit spec requirement, but it falls straight out of implementing the numeric comparison honestly: something has to happen when `strconv.ParseInt` fails, and silently falling back to the old string comparison would reintroduce the exact bug this plan removes. Tested by `TestMigrateToVersion_RejectsNonNumericTarget`.

**"Target equals current" — confirmed to succeed as a no-op**, both by reading the code and by test. The existing loop's `break` condition is `migration.Version > targetVersion` (strictly greater), so a migration exactly at the target is never skipped by the break, only by the `applied[...]` check if it's already applied — which it is, since it *is* the current version. The new refusal check uses `<` (strictly less), so equality never trips it either. Tested by `TestMigrateToVersion_TargetEqualToCurrentSucceedsAsNoOp`.

**A lint constraint the spec's literal error text collides with.** `.golangci.yml` enables `staticcheck`, which includes `ST1005` ("error strings should not end with punctuation"). The spec's required message ends in a period after two sentences. Verified empirically in a scratch module (`golangci-lint run` against a standalone file) that this literal text trips `ST1005`, and that no error string anywhere in this repo currently ends in punctuation (`grep -rE 'fmt\.Errorf\(".*\.["\)]'` over the whole tree, zero hits). The plan below carries this construction with a targeted `//nolint:staticcheck` and an explanatory comment (Task 2, Step 3) rather than silently rewording the spec's exact required text or leaving a lint failure behind. This is a new category of `nolint` for this repo (previously only `errcheck`/`gosec` were suppressed inline) — flagged here rather than done quietly.

**Test design constraint discovered while planning the tests:** `LoadMigrations` reads from a `//go:embed *.sql` tied to the real `internal/db/migrations/` directory — a test cannot inject synthetic migration files without refactoring the loader to accept an injectable filesystem, which is out of scope here. Every test below therefore drives `MigrateToVersion` against the **real embedded migration set**, seeding `schema_migrations` directly (`INSERT INTO schema_migrations (version) VALUES (?)`) rather than running real migration SQL, so tests are fast and never depend on the current shape of unrelated tables. Every test that is not specifically checking the refusal path pre-seeds *all* real versions as applied, so the pre-existing forward-apply loop never has anything pending to execute for real — this was verified by hand-tracing the old (pre-fix) string-comparison behavior for each test's chosen target to confirm it is deterministic and side-effect-free both before and after this fix.

---

## File structure

| File | Change |
|---|---|
| `internal/db/migrations/migration_runner.go` | Add `parseVersionNumber`; add the refusal check to `MigrateToVersion`; switch its loop's `break` condition to the same numeric comparator |
| `internal/db/migrations/migration_runner_test.go` (new) | Unit tests for `parseVersionNumber` and `MigrateToVersion`'s refusal/no-op/permissive/invalid-input behavior |
| `cmd/migrate.go` | Update `migrateToCmd.Long` to describe the refusal (no logic change — the error already propagates and already exits non-zero) |

---

### Task 1: Numeric version comparator, proven against the lexicographic trap

**Files:**
- Create: `internal/db/migrations/migration_runner_test.go`
- Modify: `internal/db/migrations/migration_runner.go` (import block at lines 4-14; new function inserted after `GetCurrentVersion`, i.e. after line 264, before the `// Example usage:` comment at line 266)

**Interfaces:**
- Consumes: `strconv.ParseInt` (stdlib).
- Produces: `func parseVersionNumber(version string) (int64, error)` — unexported. Task 2 is the only other caller in this plan.

- [ ] **Step 1: Write the failing test**

Create `internal/db/migrations/migration_runner_test.go`:

```go
package migrations

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersionNumber_NumericNotLexicographic(t *testing.T) {
	t.Parallel()
	nine, err := parseVersionNumber("9")
	require.NoError(t, err)
	ten, err := parseVersionNumber("10")
	require.NoError(t, err)

	assert.Equal(t, int64(9), nine)
	assert.Equal(t, int64(10), ten)
	assert.Greater(t, ten, nine, "10 must sort after 9 numerically")
	assert.Less(t, "10", "9", "sanity check: lexicographic string comparison gets this backwards, which is exactly why MigrateToVersion must not compare version strings directly")
}

func TestParseVersionNumber_LeadingZeros(t *testing.T) {
	t.Parallel()
	n, err := parseVersionNumber("001")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestParseVersionNumber_Timestamp(t *testing.T) {
	t.Parallel()
	n, err := parseVersionNumber("20260606000001")
	require.NoError(t, err)
	assert.Equal(t, int64(20260606000001), n)
}

func TestParseVersionNumber_NonNumeric(t *testing.T) {
	t.Parallel()
	_, err := parseVersionNumber("not-a-version")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-version")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/migrations/... -run TestParseVersionNumber -v`
Expected: FAIL to compile — `undefined: parseVersionNumber` (four times, once per test function).

- [ ] **Step 3: Write minimal implementation**

In `internal/db/migrations/migration_runner.go`, add `"strconv"` to the import block (alphabetical, between `"sort"` and `"strings"`):

```go
import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)
```

Then insert this function immediately after `GetCurrentVersion` (i.e. right after its closing `}` at line 264, before the `// Example usage:` comment):

```go
// parseVersionNumber converts a migration version string to its numeric
// value for magnitude comparison. Every version in this package is decimal
// digits only -- either the legacy zero-padded sequential form (e.g. "001")
// or the YYYYMMDDNNNNNN timestamp form migrate:create generates -- so a
// base-10 parse is safe. Comparing the strings directly is not: it is only
// correct when every version being compared has the same width, and nothing
// enforces that across this package's own version files (e.g. "9" < "10"
// numerically but "9" > "10" lexicographically).
func parseVersionNumber(version string) (int64, error) {
	n, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid migration version %q: must be a decimal number: %w", version, err)
	}
	return n, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/migrations/... -run TestParseVersionNumber -v`
Expected: PASS — all four tests.

- [ ] **Step 5: Commit**

```bash
git add internal/db/migrations/migration_runner.go internal/db/migrations/migration_runner_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "$(cat <<'EOF'
feat(migrations): add a numeric version comparator

GetCurrentVersion and every migration file version are strings, and this
package compared them with Go's default string ordering, which is
lexicographic, not numeric -- "10" sorts before "9". Every real version file
happens to share a digit width within its own generation era (the legacy
"001" and the 14-digit YYYYMMDDNNNNNN form), so the bug has never fired, but
it is real, and B39's downward-target refusal (next commit) depends on
comparing versions correctly. parseVersionNumber parses the decimal-digit
string every version actually is and gives magnitude comparison a place to
live.
EOF
)"
```

---

### Task 2: Refuse a `migrate:to` target below the current version

**Files:**
- Modify: `internal/db/migrations/migration_runner.go` (`MigrateToVersion`, lines 208-245)
- Modify: `internal/db/migrations/migration_runner_test.go` (append)

**Interfaces:**
- Consumes: `parseVersionNumber` (Task 1), `MigrationRunner.GetCurrentVersion(ctx) (string, error)` (existing, unchanged), `MigrationRunner.GetAppliedMigrations(ctx) (map[string]bool, error)` (existing, unchanged), `MigrationRunner.LoadMigrations() ([]Migration, error)` (existing, unchanged).
- Produces: `func (r *MigrationRunner) MigrateToVersion(ctx context.Context, targetVersion string) error` — same signature as today, new refusal behavior. No exported type changes, no new interface.

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/migrations/migration_runner_test.go`. Add these imports to the existing import block:

```go
import (
	"context"
	"database/sql"
	"io"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```

Then add these helpers and tests:

```go
// silentLogger returns a logrus.Logger that discards output, keeping test
// runs quiet.
func silentLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// newTestRunner opens an in-memory SQLite database, initializes the
// schema_migrations table, and returns a MigrationRunner against it along
// with the raw connection for seeding.
func newTestRunner(t *testing.T) (*MigrationRunner, *sql.DB) {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	runner := NewMigrationRunner(conn, silentLogger())
	require.NoError(t, runner.Initialize(context.Background()))
	return runner, conn
}

// seedApplied marks the given versions as already applied, without running
// their migration SQL. MigrateToVersion's downward refusal is decided from
// the recorded version alone, before any migration SQL runs, so this is
// enough to establish a "current version" for these tests without depending
// on the real migration files' SQL succeeding against a bare in-memory
// database.
func seedApplied(t *testing.T, conn *sql.DB, versions ...string) {
	t.Helper()
	for _, v := range versions {
		_, err := conn.Exec("INSERT INTO schema_migrations (version) VALUES (?)", v)
		require.NoError(t, err)
	}
}

// allRealVersions returns every version string in the real, embedded
// migration set (internal/db/migrations/*.sql), in file order.
func allRealVersions(t *testing.T, runner *MigrationRunner) []string {
	t.Helper()
	all, err := runner.LoadMigrations()
	require.NoError(t, err)
	require.NotEmpty(t, all, "the embedded migration set must not be empty for these tests to be meaningful")
	versions := make([]string, len(all))
	for i, m := range all {
		versions[i] = m.Version
	}
	return versions
}

// TestMigrateToVersion_RefusesDownwardTarget is the headline B39 test: with
// the schema at a known version, targeting a lower one must fail and leave
// the applied set unchanged.
func TestMigrateToVersion_RefusesDownwardTarget(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	// Seed the first 8 real versions as applied; the loop's break condition
	// (same digit width throughout this prefix) stops before reaching any
	// unapplied migration, so no real migration SQL runs even before the fix.
	seedApplied(t, conn,
		"001",
		"20241025000001",
		"20241026000001",
		"20241026000002",
		"20241026000003",
		"20241026000004",
		"20241026000005",
		"20260308000001",
	)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "20241026000002")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot migrate down")
	assert.Contains(t, err.Error(), "current schema is at version 20260308000001")
	assert.Contains(t, err.Error(), "target 20241026000002 is lower")
	assert.Contains(t, err.Error(), "Down-migrations are not supported.")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a refused downward migration must leave the applied set unchanged")
}

// TestMigrateToVersion_RefusesDownwardTargetEvenWithNoExactFileMatch proves
// the refusal is a pure magnitude comparison against the current version,
// not conditioned on the target naming a real migration file -- otherwise an
// operator could dodge it by guessing an arbitrary small number.
func TestMigrateToVersion_RefusesDownwardTargetEvenWithNoExactFileMatch(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "5")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot migrate down")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// TestMigrateToVersion_TargetEqualToCurrentSucceedsAsNoOp confirms equality
// is not treated as "downward" -- it must succeed and change nothing.
func TestMigrateToVersion_TargetEqualToCurrentSucceedsAsNoOp(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn,
		"001",
		"20241025000001",
		"20241026000001",
		"20241026000002",
		"20241026000003",
		"20241026000004",
		"20241026000005",
		"20260308000001",
	)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "20260308000001")
	require.NoError(t, err, "targeting the current version must succeed, not error")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "targeting the current version must not change the applied set")
}

// TestMigrateToVersion_TargetAboveCurrentWithNoExactMatchSucceeds confirms
// B39 does not add a "target must name a real migration" requirement --
// that is pre-existing, unrelated permissive behavior and stays as-is.
func TestMigrateToVersion_TargetAboveCurrentWithNoExactMatchSucceeds(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "99999999999999")
	require.NoError(t, err, "a target above current that matches no file is permitted, as before this fix")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "every migration was already applied, so nothing should change")
}

// TestMigrateToVersion_RejectsNonNumericTarget confirms a target that
// cannot be compared to the current version is rejected rather than falling
// back to a string comparison.
func TestMigrateToVersion_RejectsNonNumericTarget(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "not-a-version")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-version")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// TestMigrateToVersion_RejectsCorruptCurrentVersion is a defensive test: a
// non-numeric row in schema_migrations (only reachable through direct DB
// tampering) must fail closed, not panic or silently misorder.
func TestMigrateToVersion_RejectsCorruptCurrentVersion(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)
	seedApplied(t, conn, "corrupted-version")

	err := runner.MigrateToVersion(ctx, "20260308000001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot determine current schema version")
}
```

- [ ] **Step 2: Run tests to verify the refusal tests fail**

Run: `go test ./internal/db/migrations/... -run TestMigrateToVersion -v`

Expected: two tests fail against today's code, four already pass (they document pre-existing or coincidentally-correct behavior and exist as regression guards, not as red tests):

- FAIL `TestMigrateToVersion_RefusesDownwardTarget` — `require.Error` fails: today's `MigrateToVersion` applies nothing pending below the target and returns `nil`, the exact silent no-op B39 describes.
- FAIL `TestMigrateToVersion_RefusesDownwardTargetEvenWithNoExactFileMatch` — same reason.
- PASS `TestMigrateToVersion_TargetEqualToCurrentSucceedsAsNoOp` — already true today; hand-traced in the "What reading the code actually found" section above.
- PASS `TestMigrateToVersion_TargetAboveCurrentWithNoExactMatchSucceeds` — already true today.
- FAIL `TestMigrateToVersion_RejectsNonNumericTarget` — today's code never validates the target's shape and returns `nil`.
- FAIL `TestMigrateToVersion_RejectsCorruptCurrentVersion` — today's code never reads the current version inside `MigrateToVersion` at all, so a corrupt row in `schema_migrations` has no effect and it returns `nil`.

- [ ] **Step 3: Write minimal implementation**

Replace the entire `MigrateToVersion` function (`internal/db/migrations/migration_runner.go:208-245`) with:

```go
// MigrateToVersion applies migrations up to a specific version.
//
// It refuses when targetVersion is lower than the database's current schema
// version rather than silently doing nothing: this package has no
// down-migration support, so treating a lower target as a no-op would let an
// operator believe they rolled back when nothing happened (B39).
func (r *MigrationRunner) MigrateToVersion(ctx context.Context, targetVersion string) error {
	if err := r.Initialize(ctx); err != nil {
		return err
	}

	currentVersion, err := r.GetCurrentVersion(ctx)
	if err != nil {
		return err
	}

	currentNum, err := parseVersionNumber(currentVersion)
	if err != nil {
		return fmt.Errorf("cannot determine current schema version: %w", err)
	}

	targetNum, err := parseVersionNumber(targetVersion)
	if err != nil {
		return fmt.Errorf("cannot parse target version %q: %w", targetVersion, err)
	}

	if targetNum < currentNum {
		//nolint:staticcheck // ST1005: this two-sentence error is the exact, deliberate
		// user-facing text the B39 fix specifies -- not a wrapped/chained error --
		// see docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md.
		return fmt.Errorf("cannot migrate down: current schema is at version %s, target %s is lower. Down-migrations are not supported.",
			currentVersion, targetVersion)
	}

	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	migrations, err := r.LoadMigrations()
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		migrationNum, err := parseVersionNumber(migration.Version)
		if err != nil {
			return fmt.Errorf("migration file version %q is not numeric: %w", migration.Version, err)
		}
		if migrationNum > targetNum {
			break // Stop at target version
		}

		if applied[migration.Version] {
			continue // Skip already applied migrations
		}

		r.logger.WithFields(logrus.Fields{
			"version": migration.Version,
			"name":    migration.Name,
		}).Info("Applying migration")

		if err := r.ApplyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}
	}

	r.logger.WithField("target_version", targetVersion).Info("Migrated to target version")
	return nil
}
```

Note what changed from the original and why:
- The version-magnitude check (current vs. target) is new — this is the B39 fix itself.
- The loop's `if migration.Version > targetVersion` (string comparison) became `if migrationNum > targetNum` (numeric comparison), fixing the same latent defect inside the one function this plan touches. `LoadMigrations`'s own sort (line 126-128) and `MigrateUp` are untouched — they serve `migrate` and `migrate:status`, not `migrate:to`, and are out of scope for B39.

- [ ] **Step 4: Run tests to verify they all pass**

Run: `go test ./internal/db/migrations/... -v`
Expected: PASS — every test in the package, including all four from Task 1 and all six from this task.

- [ ] **Step 5: Confirm no lint regressions**

Run: `golangci-lint run ./internal/db/migrations/...`
Expected: `0 issues`. This specifically confirms the `//nolint:staticcheck` on the refusal error correctly suppresses `ST1005` for that one line without masking anything else in the file.

- [ ] **Step 6: Commit**

```bash
git add internal/db/migrations/migration_runner.go internal/db/migrations/migration_runner_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "$(cat <<'EOF'
fix(migrations): refuse a migrate:to target below the current version

MigrateToVersion only ever applied forward: its break/continue loop skipped
already-applied migrations and stopped once a migration's version exceeded
the target, so pointing it at a version below the current schema silently
did nothing. An operator running `migrate:to <old-version>` could believe
they had rolled back when the schema never changed (B39).

There is no down-migration support in this codebase and none is added here
-- refusing is cheaper and removes the false impression, per the design
decision in docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md.
The refusal is a pure magnitude comparison against the current version, so it
applies whether or not the target names a real migration file. The forward
loop's own version comparison is switched to the same numeric comparator for
consistency, since it shared the same string-comparison defect (dormant only
because every real migration file so far shares a digit width within its own
generation era).
EOF
)"
```

---

### Task 3: Document the refusal in `migrate:to`'s help text

**Files:**
- Modify: `cmd/migrate.go` (`migrateToCmd.Long`, lines 69-71)

**Interfaces:** None. Prose only — `migrateToCmd`'s `Use`, `Short`, `Example`, `Args`, and `RunE` are all unchanged, so `TestExampleFlagsAreRegistered` (`cmd/help_examples_test.go`) is unaffected.

No test-first cycle applies here: there is no behavior to assert against, only text. `cmd/migrate.go` needs no logic change at all — `migrateToVersion`'s existing `if err := runner.MigrateToVersion(ctx, targetVersion); err != nil { return fmt.Errorf("migration failed: %w", err) }` (`cmd/migrate.go:267-270`) already propagates Task 2's error, and `cmd/root.go`'s `run()` already turns any non-nil `RunE` error into exit code 1. This step exists solely so the command's own `--help` output matches what it now actually does, matching the spirit of the broader B35-B41 help-text sweep this bug was found during.

- [ ] **Step 1: Update the help text**

In `cmd/migrate.go`, replace:

```go
	Long: `Apply every pending migration whose version is less than or equal to the
given version, in order; already-applied migrations are skipped. It does not
roll back migrations already applied past the target version.`,
```

with:

```go
	Long: `Apply every pending migration whose version is less than or equal to the
given version, in order; already-applied migrations are skipped. If the
given version is lower than the database's current schema version, the
command refuses and exits non-zero instead of silently doing nothing --
there is no down-migration support.`,
```

- [ ] **Step 2: Confirm the build and the help-text validator still pass**

Run: `go build ./... && go test ./cmd/... -run TestExampleFlagsAreRegistered -v`
Expected: PASS — the `Example` block is untouched, so the flag-registration validator has nothing new to check.

- [ ] **Step 3: Commit**

```bash
git add cmd/migrate.go
git commit -S --gpg-sign=61D246B30285ED35 -m "$(cat <<'EOF'
docs(cli): document migrate:to's downward refusal in its help text

The Long description still described the pre-fix silent-no-op behavior.
Updated to match what the command actually does now (B39).
EOF
)"
```

---

## Verification

```bash
go build ./...
go vet ./internal/db/migrations/... ./cmd/...
golangci-lint run ./internal/db/migrations/... ./cmd/...
go test ./internal/db/migrations/... ./cmd/... -v
go test ./internal/db/migrations/... -race -count=2
```

Expected: clean build, zero vet/lint findings, all tests pass including the two-and-only-two genuinely red-then-green tests (`TestMigrateToVersion_RefusesDownwardTarget`, `TestMigrateToVersion_RefusesDownwardTargetEvenWithNoExactFileMatch`, plus `TestMigrateToVersion_RejectsNonNumericTarget` and `TestMigrateToVersion_RejectsCorruptCurrentVersion`), race-clean, stable across repeated runs (no shared state between `:memory:` databases across tests).

## Non-goals (carried from the spec, restated for this plan)

- No down-migration support: no `Down()` method, no reverse SQL, no interface change.
- No change to `MigrateUp`, `migrate:status`, or `LoadMigrations`'s sort — they are unaffected by `migrate:to` and out of scope for B39, even though `LoadMigrations`'s sort has the same latent string-comparison shape. Flagged above as a candidate follow-up, not fixed here.
- No refactor of `LoadMigrations` to accept an injectable filesystem for testing synthetic version shapes — tests instead prove the numeric comparator correct in isolation (Task 1) and prove the integration behavior correct against the real, embedded migration set (Task 2).
