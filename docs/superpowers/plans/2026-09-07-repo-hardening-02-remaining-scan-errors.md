# Repository Hardening — Plan 02: Remaining Discarded-Error Sites

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish findings F1 and F6 by removing the remaining discarded `uuid.Parse` errors from `versioning_repository.go` and `certificate_policy_repository.go`, and stopping `session_repository.go` from silently dropping session rows.

**Architecture:** Plan 01 handled `rotation_repository.go` (21 of the 35 discarded-parse sites, 3 of the 4 row-dropping loops). This plan takes the other 14 parse sites and the last loop. `certificate_policy_repository.go` has the same scan-and-parse block duplicated in two methods, so it gets a shared helper in the shape of `parseRoleAssignmentIDs` (`role_assignment_repository.go:167`); `versioning_repository.go`'s three sites are in distinct methods with different return types, so they are fixed in place.

**Tech Stack:** Go 1.24, `database/sql`, `github.com/google/uuid`, `testify`, in-memory SQLite (`github.com/mattn/go-sqlite3`).

**Spec:** `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md` (findings F1 and F6)

## Global Constraints

- **No exported interface, signature, or error-message change.** Every edit is internal to a function body or adds an unexported helper. `internal/repositories/mocks/` must not be regenerated.
- **Error messages are extended, never replaced.** If you touch an existing message, the original text stays as a prefix.
- **Never use `uuid.MustParse` in repository code.** It panics; every scanner returns a wrapped error instead.
- **Compare errors with `errors.Is`, never `==` or `err.Error() == "..."`.**
- Tests live in `package repositories_test`. Package-scope helpers `setupTestDB` (`key_soft_delete_test.go`) and `setupRotationTestDB` (added by Plan 01) already exist — name new helpers distinctly.
- Test helpers return `*sql.DB`; callers wrap with `rvdb.NewConn(db, rvdb.SQLite)`. The logger is `logging.InitLogger()`.
- Branch: `refactor/repo-hardening`. One signed commit per task (GPG key `61D246B30285ED35`).
- Per task, before committing: `go build ./...`, `go vet ./...`, `go test ./internal/repositories/... ./internal/services/...`

---

### Task 1: `versioning_repository.go` parse errors

**Files:**
- Modify: `internal/repositories/versioning_repository.go:109-111` (`GetVersions` loop), `:146-148` (`GetVersion`), `:178-180` (`GetLatestVersion`)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing new; three method bodies change.

All three methods scan `id, secret_id, user_id` and then discard the parse errors. `GetVersions`'s scan-error handling is already correct (commit `6cd6d52` fixed it); only its parses need work.

- [ ] **Step 1: Fix `GetVersions`**

In `internal/repositories/versioning_repository.go`, replace lines 109-111:

```go
		v.ID, _ = uuid.Parse(id)
		v.SecretID, _ = uuid.Parse(secretIDStr)
		v.UserID, _ = uuid.Parse(userIDStr)
```

with:

```go
		if v.ID, err = uuid.Parse(id); err != nil {
			return nil, fmt.Errorf("invalid secret version id: %w", err)
		}
		if v.SecretID, err = uuid.Parse(secretIDStr); err != nil {
			return nil, fmt.Errorf("invalid secret id: %w", err)
		}
		if v.UserID, err = uuid.Parse(userIDStr); err != nil {
			return nil, fmt.Errorf("invalid user id: %w", err)
		}
```

`err` is already declared in this loop body by the `rows.Scan` call above it, so these use `=`, not `:=`.

- [ ] **Step 2: Fix `GetVersion`**

Replace lines 146-148:

```go
	v.ID, _ = uuid.Parse(id)
	v.SecretID, _ = uuid.Parse(secretIDStr)
	v.UserID, _ = uuid.Parse(userIDStr)
```

with:

```go
	if v.ID, err = uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid secret version id: %w", err)
	}
	if v.SecretID, err = uuid.Parse(secretIDStr); err != nil {
		return nil, fmt.Errorf("invalid secret id: %w", err)
	}
	if v.UserID, err = uuid.Parse(userIDStr); err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
```

`err` is in scope from the `QueryRowContext(...).Scan(...)` call above.

- [ ] **Step 3: Fix `GetLatestVersion`**

Replace lines 178-180 with the identical block from Step 2 (same three fields, same `err` already in scope):

```go
	if v.ID, err = uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid secret version id: %w", err)
	}
	if v.SecretID, err = uuid.Parse(secretIDStr); err != nil {
		return nil, fmt.Errorf("invalid secret id: %w", err)
	}
	if v.UserID, err = uuid.Parse(userIDStr); err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
```

- [ ] **Step 4: Verify no discarded parses remain in the file**

Run: `grep -n ", _ = uuid.Parse\|, _ := uuid.Parse" internal/repositories/versioning_repository.go`
Expected: no output.

- [ ] **Step 5: Run the verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 6: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/versioning_repository.go
```

---

### Task 2: `certificate_policy_repository.go` shared parse helper

**Files:**
- Modify: `internal/repositories/certificate_policy_repository.go:93-95` (`GetByCertificateID`), `:191-193` (`GetByCertificateIDAny`)

**Interfaces:**
- Consumes: nothing.
- Produces: `func parseCertificatePolicyIDs(p *model.CertificatePolicy, idStr, cidStr, uidStr string) error` — unexported, used by both methods in this task.

The two methods contain byte-identical scan-then-parse blocks differing only in their SQL predicate. Extract the parse half.

- [ ] **Step 1: Add the shared parse helper**

Insert immediately before `GetByCertificateID` in `internal/repositories/certificate_policy_repository.go`:

```go
// parseCertificatePolicyIDs fills p's three UUID fields from their string
// column values. Errors are returned rather than discarded: a malformed
// column would otherwise yield uuid.Nil, and p.UserID feeds ownership checks
// where a nil value is not an obviously-invalid sentinel. Mirrors
// parseRoleAssignmentIDs in role_assignment_repository.go.
func parseCertificatePolicyIDs(p *model.CertificatePolicy, idStr, cidStr, uidStr string) error {
	var err error
	if p.ID, err = uuid.Parse(idStr); err != nil {
		return fmt.Errorf("invalid certificate policy id: %w", err)
	}
	if p.CertificateID, err = uuid.Parse(cidStr); err != nil {
		return fmt.Errorf("invalid certificate id: %w", err)
	}
	if p.UserID, err = uuid.Parse(uidStr); err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}
	return nil
}
```

- [ ] **Step 2: Point `GetByCertificateID` at the helper**

Replace lines 93-96:

```go
	p.ID, _ = uuid.Parse(idStr)
	p.CertificateID, _ = uuid.Parse(cidStr)
	p.UserID, _ = uuid.Parse(uidStr)
	return &p, nil
```

with:

```go
	if err := parseCertificatePolicyIDs(&p, idStr, cidStr, uidStr); err != nil {
		return nil, err
	}
	return &p, nil
```

- [ ] **Step 3: Point `GetByCertificateIDAny` at the helper**

Replace lines 191-194 with the identical replacement from Step 2:

```go
	if err := parseCertificatePolicyIDs(&p, idStr, cidStr, uidStr); err != nil {
		return nil, err
	}
	return &p, nil
```

- [ ] **Step 4: Verify no discarded parses remain in the file**

Run: `grep -n ", _ = uuid.Parse\|, _ := uuid.Parse" internal/repositories/certificate_policy_repository.go`
Expected: no output.

- [ ] **Step 5: Run the verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 6: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/certificate_policy_repository.go
```

---

### Task 3: `GetActiveSessionsByUserID` must not drop rows

**Files:**
- Modify: `internal/repositories/session_repository.go:225-265` (`GetActiveSessionsByUserID`)
- Test: `internal/repositories/session_scan_errors_test.go` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing new; one method body changes.

The method skips any row whose scan or `uuid.Parse` fails. A user asking "where am I signed in?" is then shown fewer sessions than exist, with no indication anything was omitted — the worst shape for a security-facing listing.

- [ ] **Step 1: Write the failing test**

```go
// internal/repositories/session_scan_errors_test.go
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
)

// setupSessionTestDB creates an in-memory SQLite database with the
// user_sessions table. Named distinctly from the package-scope setupTestDB
// and setupRotationTestDB helpers that already exist in this test package.
func setupSessionTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:sessiontest_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE user_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			refresh_token_hash TEXT NOT NULL,
			device_info TEXT NOT NULL DEFAULT '',
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMP NOT NULL,
			last_used_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at TIMESTAMP,
			revoked_reason TEXT
		);
	`)
	require.NoError(t, err, "create user_sessions schema")

	return raw
}

// TestGetActiveSessionsReturnsEveryMatchingRow is regression coverage for the
// F1 fix. It cannot go red before the fix -- see the note in the plan -- so it
// pins the well-formed path instead: every stored active session for the user
// is returned, and revoked/expired ones are not.
func TestGetActiveSessionsReturnsEveryMatchingRow(t *testing.T) {
	raw := setupSessionTestDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{
		DB:     rvdb.NewConn(raw, rvdb.SQLite),
		Logger: logging.InitLogger(),
	})

	userID := uuid.New()
	ctx := context.Background()
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	insert := func(hash string, expiresAt time.Time, revoked bool) {
		t.Helper()
		_, err := raw.ExecContext(ctx,
			`INSERT INTO user_sessions
			 (id, user_id, refresh_token_hash, expires_at, last_used_at, created_at, revoked)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			uuid.New().String(), userID.String(), hash, expiresAt, time.Now(), time.Now(), revoked)
		require.NoError(t, err, "insert session %s", hash)
	}

	insert("hash-active-a", future, false)
	insert("hash-active-b", future, false)
	insert("hash-revoked", future, true)
	insert("hash-expired", past, false)

	sessions, err := repo.GetActiveSessionsByUserID(ctx, userID)
	require.NoError(t, err)
	require.Len(t, sessions, 2, "both active sessions, neither the revoked nor the expired one")
	for _, s := range sessions {
		require.Equal(t, userID, s.UserID, "user id parsed, not left as uuid.Nil")
	}
}
```

- [ ] **Step 2: Run the test and confirm it passes**

Run: `go test ./internal/repositories/ -run TestGetActiveSessionsReturnsEveryMatchingRow -v`
Expected: PASS — before *and* after the fix.

**This task has no red-to-green cycle, and you must not manufacture one.** `GetActiveSessionsByUserID` filters on `user_id = ?` bound from a `uuid.UUID`, so a row whose `user_id` is unparseable can never match the predicate: the `uuid.Parse` branch inside the loop is unreachable through this method's own query. The other branch, `rows.Scan` failing, needs a driver-level column-type mismatch that a test controlling its own schema cannot provoke.

So the fix rests on code review, not on a failing test, and the test above exists to prove the well-formed path did not regress. Say this plainly in the commit message rather than implying the change was test-driven.

- [ ] **Step 3: Replace both `continue` branches**

In `internal/repositories/session_repository.go`, replace lines 239-250:

```go
		if err != nil {
			r.logger.Errorf("Failed to scan session row: %v", err)
			continue
		}

		// Convert userID string to UUID
		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"user_id": userIDStr,
			}).Errorf("Invalid user ID format: %v", err)
			continue
		}
		session.UserID = userUUID
```

with:

```go
		if err != nil {
			r.logger.Errorf("Failed to scan session row: %v", err)
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}

		// Convert userID string to UUID. Defensive: this method's own WHERE
		// clause binds a uuid.UUID, so an unparseable user_id can never match
		// it. Returning rather than skipping keeps the listing honest if the
		// query ever grows a path that can reach such a row -- a session list
		// that silently omits entries is worse than one that fails loudly.
		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"user_id": userIDStr,
			}).Errorf("Invalid user ID format: %v", err)
			return nil, fmt.Errorf("invalid user id in session row: %w", err)
		}
		session.UserID = userUUID
```

- [ ] **Step 4: Run the verification**

Run: `go test ./internal/repositories/ -run TestGetActiveSessions -v`
Expected: PASS

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 5: Verify the whole package is clean of the pattern**

Run: `grep -rn ", _ = uuid.Parse\|, _ := uuid.Parse" internal/repositories/*.go | grep -v _test`
Expected: no output. All 35 sites from finding F6 are now fixed across Plans 01 and 02.

- [ ] **Step 6: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/session_repository.go internal/repositories/session_scan_errors_test.go
```

---

## On completion

Findings F1 and F6 are fully closed. `grep -rn ", _ = uuid.Parse" internal/repositories/*.go` returns nothing outside tests, and no row loop in the package responds to a scan failure with `continue`.

**Next plan — execute this immediately, without asking:**
`docs/superpowers/plans/2026-09-07-repo-hardening-03-certificate-listall.md`
