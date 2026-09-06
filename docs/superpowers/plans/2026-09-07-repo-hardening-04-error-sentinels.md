# Repository Hardening — Plan 04: Error Sentinels and `errors.Is`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace error identification by string comparison with the `ErrNotFound` sentinel, and replace `err == sql.ErrNoRows` with `errors.Is`, without changing a single error message a caller can observe.

**Architecture:** `errors.go` declares `ErrNotFound` precisely so repositories stop being identified by their message text, but several lookups never adopted it. The sharpest case is `role_assignment_repository.go:119`, where `FindByTuple`'s entire "no such assignment" contract rests on the literal string `"role assignment not found"` — rewording that message anywhere silently flips the method from returning `(nil, nil)` to returning an error, on an authorization-adjacent path. Three other sites compare with `==` rather than `errors.Is`, which works today only because nothing between the driver and those lines wraps the error.

**Tech Stack:** Go 1.24, `errors`, `database/sql`, `testify`.

**Spec:** `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md` (finding F3)

## Global Constraints

- **Error messages are extended, never replaced.** This is the constraint the whole plan turns on. Service-layer tests assert on substrings — `assert.Contains(t, err.Error(), "user not found")` appears in `internal/services/auth/auth_edge_cases_test.go:331`, and more than a dozen equivalents exist across the certificate, key, and secret service suites. Every change here takes the form:

  ```go
  // Before
  return fmt.Errorf("user not found")
  // After
  return fmt.Errorf("user not found: %w", ErrNotFound)
  ```

  The original text survives as a prefix, so every `Contains` assertion keeps passing while `errors.Is` starts working. **Never reword, reorder, or capitalize differently.**
- **No exported interface or signature change.** `internal/repositories/mocks/` must not be regenerated.
- **Compare errors with `errors.Is`, never `==` or `err.Error() == "..."`.**
- Branch: `refactor/repo-hardening`. One signed commit per task (GPG key `61D246B30285ED35`).
- Per task, before committing: `go build ./...`, `go vet ./...`, `go test ./internal/repositories/... ./internal/services/...`

## Out of scope for this plan

The scoped `Read` methods on the secret, key, and certificate repositories return `"<item> not found or access denied"` deliberately, so a caller cannot distinguish a missing row from an inaccessible one (no existence oracle). Leave those messages and their error identity exactly as they are.

---

### Task 1: `FindByTuple` must not identify errors by string

**Files:**
- Modify: `internal/repositories/role_assignment_repository.go:145-156` (`scanRoleAssignment`), `:112-126` (`FindByTuple`)
- Test: `internal/repositories/role_assignment_sentinel_test.go` (create)

**Interfaces:**
- Consumes: `ErrNotFound` (`errors.go:10`).
- Produces: `scanRoleAssignment` now returns an error wrapping `ErrNotFound` on no rows; `FindByTuple`'s `(nil, nil)` contract is unchanged.

- [ ] **Step 1: Write the failing test**

`NewRoleAssignmentRepository` takes a bare `db.DB` and no logger (verified at `role_assignment_repository.go:39`).

```go
// internal/repositories/role_assignment_sentinel_test.go
package repositories_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

// setupRoleAssignmentTestDB creates an in-memory SQLite database with the
// role_assignments table. Named distinctly from the package-scope setupTestDB,
// setupRotationTestDB, setupSessionTestDB, setupCertListAllTestDB and
// setupCertLifecycleTestDB helpers that already exist in this test package.
func setupRoleAssignmentTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:roleassign_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE role_assignments (
			id TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			role TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);
	`)
	require.NoError(t, err, "create role_assignments schema")

	return raw
}

// TestFindByTupleDoesNotCompareErrorStrings pins the F3 fix. FindByTuple's
// "no such assignment" contract used to rest on the literal string
// "role assignment not found": rewording that message in scanRoleAssignment --
// an edit nothing would flag as risky -- silently flipped FindByTuple from
// returning (nil, nil) to returning an error, on an authorization-adjacent
// path. The sentinel makes the coupling explicit and compiler-visible.
func TestFindByTupleDoesNotCompareErrorStrings(t *testing.T) {
	src, err := os.ReadFile("role_assignment_repository.go")
	require.NoError(t, err, "read role_assignment_repository.go")

	require.NotContains(t, string(src), `err.Error() ==`,
		"identify errors with errors.Is against a sentinel, never by message text")
	require.NotContains(t, string(src), `== sql.ErrNoRows`,
		"use errors.Is(err, sql.ErrNoRows) so a wrapped driver error still matches")
}

// TestFindByTupleReportsAbsenceAsNilNil pins the behavior the string
// comparison was protecting, so the switch to a sentinel cannot change it.
func TestFindByTupleReportsAbsenceAsNilNil(t *testing.T) {
	raw := setupRoleAssignmentTestDB(t)
	repo := repositories.NewRoleAssignmentRepository(rvdb.NewConn(raw, rvdb.SQLite))

	ra, err := repo.FindByTuple(context.Background(), uuid.New(), "Key Vault Reader", uuid.New())
	require.NoError(t, err, "an absent assignment is not an error")
	require.Nil(t, ra, "an absent assignment yields a nil assignment")
}

// TestFindByTupleFindsAnExistingAssignment is the positive half: the sentinel
// switch must not turn a real hit into a miss.
func TestFindByTupleFindsAnExistingAssignment(t *testing.T) {
	raw := setupRoleAssignmentTestDB(t)
	repo := repositories.NewRoleAssignmentRepository(rvdb.NewConn(raw, rvdb.SQLite))

	ctx := context.Background()
	principalID, vaultID := uuid.New(), uuid.New()
	_, err := raw.ExecContext(ctx,
		`INSERT INTO role_assignments
		 (id, principal_id, principal_type, role, vault_id, created_by, created_at)
		 VALUES (?, ?, 'user', 'Key Vault Reader', ?, ?, CURRENT_TIMESTAMP)`,
		uuid.New().String(), principalID.String(), vaultID.String(), uuid.New().String())
	require.NoError(t, err, "insert role assignment")

	ra, err := repo.FindByTuple(ctx, principalID, "Key Vault Reader", vaultID)
	require.NoError(t, err)
	require.NotNil(t, ra, "an existing assignment must still be found")
	require.Equal(t, vaultID, ra.VaultID)
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `go test ./internal/repositories/ -run TestFindByTupleDoesNotCompareErrorStrings -v`
Expected: FAIL — the source still contains `err.Error() ==` at line 119 and `== sql.ErrNoRows` at line 149.

- [ ] **Step 3: Wrap the sentinel in `scanRoleAssignment`**

In `internal/repositories/role_assignment_repository.go`, replace lines 149-151:

```go
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role assignment not found")
	}
```

with:

```go
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("role assignment not found: %w", ErrNotFound)
	}
```

Ensure `"errors"` is in the file's import block.

- [ ] **Step 4: Identify the miss by sentinel in `FindByTuple`**

Replace lines 118-123:

```go
	if err != nil {
		if err.Error() == "role assignment not found" {
			return nil, nil
		}
		return nil, err
	}
```

with:

```go
	if err != nil {
		// (nil, nil) means "no such assignment", which callers treat as a
		// normal absence rather than a failure. Identified by sentinel, not by
		// message text: the previous string comparison meant rewording
		// scanRoleAssignment's message silently turned every miss into an
		// error on an authorization-adjacent path.
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `go test ./internal/repositories/ -run TestFindByTuple -v`
Expected: all three PASS.

`TestFindByTupleReportsAbsenceAsNilNil` and `TestFindByTupleFindsAnExistingAssignment` passed before the change too — they exist to prove the sentinel switch preserved both halves of the contract, not to drive it. Only `TestFindByTupleDoesNotCompareErrorStrings` goes red-to-green.

- [ ] **Step 6: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS. Pay attention to `internal/services/authorization/` — `FindByTuple`'s callers live there.

- [ ] **Step 7: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/role_assignment_repository.go internal/repositories/role_assignment_sentinel_test.go
```

---

### Task 2: `errors.Is` and `ErrNotFound` in the user, access-policy, and OAuth2 repositories

**Files:**
- Modify: `internal/repositories/access_policy_repository.go:198`, `internal/repositories/oauth2_client_repository.go:110`, `internal/repositories/user_repository.go:190,259,333,452,489`

**Interfaces:**
- Consumes: `ErrNotFound` (`errors.go:10`).
- Produces: five user lookups and two scanners now wrap `ErrNotFound`; no signature changes.

- [ ] **Step 1: Fix `access_policy_repository.go`**

Replace lines 198-200:

```go
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("access policy not found")
	}
```

with:

```go
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("access policy not found: %w", ErrNotFound)
	}
```

Ensure `"errors"` is imported.

- [ ] **Step 2: Fix `oauth2_client_repository.go`**

Replace lines 110-112:

```go
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("oauth2 client not found")
	}
```

with:

```go
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("oauth2 client not found: %w", ErrNotFound)
	}
```

Ensure `"errors"` is imported.

- [ ] **Step 3: Wrap the five `user not found` sites**

In `internal/repositories/user_repository.go`, make the same edit at each of these five lines — replacing `fmt.Errorf("user not found")` with `fmt.Errorf("user not found: %w", ErrNotFound)`:

| Line | Method | Return shape |
|------|--------|--------------|
| 190 | `Read` | `return nil, fmt.Errorf("user not found: %w", ErrNotFound)` |
| 259 | `Update` | `return fmt.Errorf("user not found: %w", ErrNotFound)` |
| 333 | `Delete` | `return fmt.Errorf("user not found: %w", ErrNotFound)` |
| 452 | `ReadByUsername` | `return user, fmt.Errorf("user not found: %w", ErrNotFound)` |
| 489 | `ReadByExternalSubject` | `return nil, fmt.Errorf("user not found: %w", ErrNotFound)` |

Note lines 259 and 333 return only an error, and 452 returns `(user, error)` — keep each return's existing shape and preceding statements (including the `_ = tx.Rollback()` and `LogAuditError` calls at 257-258 and 331-332) exactly as they are. Only the `fmt.Errorf` call changes.

Line 489 is the one with a concrete consequence: `ReadByExternalSubject` feeds OIDC's `FindOrCreateExternalUser`, which needs to tell "no such external user, create one" apart from "the database is broken". It could not do that by `errors.Is` before this change.

- [ ] **Step 4: Verify every message text is unchanged**

Run: `git diff internal/repositories/user_repository.go | grep '^[-+].*Errorf'`
Expected: every `+` line is its `-` line with `: %w", ErrNotFound` appended before the closing paren. No other difference. If any message text differs, revert and redo — service tests assert on these substrings.

- [ ] **Step 5: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 6: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/access_policy_repository.go internal/repositories/oauth2_client_repository.go internal/repositories/user_repository.go
```

---

### Task 3: `ErrNotFound` in the session and rotation repositories

**Files:**
- Modify: `internal/repositories/session_repository.go:125,177,296,327`, `internal/repositories/rotation_repository.go:108,149,170,371,619`

**Interfaces:**
- Consumes: `ErrNotFound` (`errors.go:10`).
- Produces: nine lookups now wrap `ErrNotFound`; no signature changes.

- [ ] **Step 1: Wrap the four session sites**

In `internal/repositories/session_repository.go`, append `: %w", ErrNotFound` to each:

| Line | Current | Becomes |
|------|---------|---------|
| 125 | `fmt.Errorf("session not found")` | `fmt.Errorf("session not found: %w", ErrNotFound)` |
| 177 | `fmt.Errorf("session not found or expired")` | `fmt.Errorf("session not found or expired: %w", ErrNotFound)` |
| 296 | `fmt.Errorf("session not found or already revoked")` | `fmt.Errorf("session not found or already revoked: %w", ErrNotFound)` |
| 327 | `fmt.Errorf("session not found or already revoked")` | `fmt.Errorf("session not found or already revoked: %w", ErrNotFound)` |

- [ ] **Step 2: Wrap the five rotation sites**

In `internal/repositories/rotation_repository.go`:

| Line | Method | Current | Becomes |
|------|--------|---------|---------|
| 108 | `Read` | `fmt.Errorf("rotation policy not found")` | `fmt.Errorf("rotation policy not found: %w", ErrNotFound)` |
| 149 | `Update` | `fmt.Errorf("rotation policy not found")` | `fmt.Errorf("rotation policy not found: %w", ErrNotFound)` |
| 170 | `Delete` | `fmt.Errorf("rotation policy not found")` | `fmt.Errorf("rotation policy not found: %w", ErrNotFound)` |
| 371 | `UpdateSecretPolicyRotation` | `fmt.Errorf("secret policy not found")` | `fmt.Errorf("secret policy not found: %w", ErrNotFound)` |
| 619 | `UpdateReminder` | `fmt.Errorf("reminder not found")` | `fmt.Errorf("reminder not found: %w", ErrNotFound)` |

Line numbers shift if Plans 01 and 02 changed line counts above them. Locate each by its enclosing method name, not by line number alone.

- [ ] **Step 3: Verify every message text is unchanged**

Run: `git diff internal/repositories/session_repository.go internal/repositories/rotation_repository.go | grep '^[-+].*not found'`
Expected: every `+` line is its `-` line with `: %w", ErrNotFound` appended. No other difference.

- [ ] **Step 4: Confirm no `==` error comparisons remain in the package**

Run: `grep -rn "== sql.ErrNoRows\|err.Error() ==" internal/repositories/*.go | grep -v _test`
Expected: no output.

- [ ] **Step 5: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 6: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/session_repository.go internal/repositories/rotation_repository.go
```

---

## On completion

Finding F3 is closed. No repository identifies an error by its message text or by `==`, and every "not found" return in the package wraps `ErrNotFound` while keeping its original message as a prefix.

**Next plan — execute this immediately, without asking:**
`docs/superpowers/plans/2026-09-07-repo-hardening-05-shared-metrics.md`
