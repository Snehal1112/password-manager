# Repository Hardening — Plan 01: Rotation Repository Error Handling

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `internal/repositories/rotation_repository.go` from silently truncating result sets on scan failures and from silently substituting `uuid.Nil` for malformed UUID columns.

**Architecture:** Three `for rows.Next()` loops respond to a failed `rows.Scan` with `log.Error(...); continue` and never call `rows.Err()`, so a driver failure returns a short list with a nil error. Separately, 21 sites assign parsed UUIDs with `x, _ = uuid.Parse(y)`, turning corrupt data into `uuid.Nil` — a value this codebase treats as meaningful (`model.NewAdminScope(uuid.Nil)`, the `auditActor` constant). Both defects live in the same function bodies, so they are fixed together. The fix follows prior art already in the package: `parseRoleAssignmentIDs` (`role_assignment_repository.go:167`) shows the shared-parse-helper shape, and commit `6cd6d52` applied the identical scan-error fix to `versioning_repository.go`.

**Tech Stack:** Go 1.24, `database/sql`, `github.com/google/uuid`, `testify`, in-memory SQLite (`github.com/mattn/go-sqlite3`).

**Spec:** `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md` (findings F1 and F6)

## Global Constraints

- **No exported interface, signature, or error-message change.** Every edit is internal to a function body or adds an unexported helper. `internal/repositories/mocks/` must not be regenerated.
- **Error messages are extended, never replaced.** Service tests assert on substrings (e.g. `assert.Contains(t, err.Error(), "key not found")`). If you touch an existing message, the original text stays as a prefix.
- **Never use `uuid.MustParse` in repository code.** It panics; every scanner returns a wrapped error instead.
- **Compare errors with `errors.Is`, never `==` or `err.Error() == "..."`.**
- Tests live in `package repositories_test`. A package-scope `setupTestDB` helper **already exists** in `key_soft_delete_test.go` — new test files must name their helpers differently or the package will not compile.
- Branch: `refactor/repo-hardening` off `v-4.0.0`. One signed commit per task (GPG key `61D246B30285ED35`).
- Per task, before committing: `go build ./...`, `go vet ./...`, `go test ./internal/repositories/... ./internal/services/...`

## Pre-flight

- [ ] **Create the branch** (first plan in the chain only — skip if it already exists)

```bash
cd /home/numericlabs/data/rocket/rocketvault
git checkout v-4.0.0
git checkout -b refactor/repo-hardening
```

---

### Task 1: Shared UUID-parse helper for rotation policies

**Files:**
- Modify: `internal/repositories/rotation_repository.go:117-129` (`scanRotationPolicyRow`), `:183-195` (the `List` scan closure)
- Test: `internal/repositories/rotation_parse_errors_test.go` (create)

**Interfaces:**
- Produces: `func parseRotationPolicyIDs(policy *model.RotationPolicy, id, userID, vaultID string) error` — unexported, used by Task 1 and referenced again in Task 2's `GetPoliciesForSecret` fix.

`scanRotationPolicyRow` and the `List` closure scan the same eleven columns and then run the same three discarded-error parses. This task extracts the parse half into one helper that returns an error, and points both call sites at it.

- [ ] **Step 1: Write the failing test**

```go
// internal/repositories/rotation_parse_errors_test.go
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

// setupRotationTestDB creates an in-memory SQLite database with the rotation
// tables. Named distinctly from key_soft_delete_test.go's package-scope
// setupTestDB, which already occupies that name in this test package. Returns
// *sql.DB and lets callers wrap it, matching setupCertLifecycleTestDB.
func setupRotationTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:rotationtest_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			interval_days INTEGER NOT NULL DEFAULT 90,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);
		CREATE TABLE secret_policies (
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			assigned_at TIMESTAMP NOT NULL,
			last_rotated_at TIMESTAMP,
			next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id)
		);
		CREATE TABLE secret_rotation_history (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT,
			rotated_at TIMESTAMP NOT NULL,
			previous_version INTEGER NOT NULL DEFAULT 0,
			new_version INTEGER NOT NULL DEFAULT 0,
			triggered_by TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT ''
		);
	`)
	require.NoError(t, err, "create rotation schema")

	return raw
}

// TestReadRejectsMalformedVaultID pins the F6 fix: a corrupt vault_id column
// must surface as an error, not silently become uuid.Nil. uuid.Nil is a
// meaningful value here -- model.NewAdminScope(uuid.Nil) is a real privileged
// scope -- so substituting it for corrupt data is strictly worse than failing.
func TestReadRejectsMalformedVaultID(t *testing.T) {
	raw := setupRotationTestDB(t)
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	repo := repositories.NewRotationPolicyRepository(conn, logging.InitLogger())

	policyID := uuid.New()
	userID := uuid.New()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO rotation_policies
		 (id, user_id, vault_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		policyID.String(), userID.String(), "not-a-uuid", "nightly", "", 90, true, 7, false,
		time.Now(), time.Now())
	require.NoError(t, err, "insert policy with corrupt vault_id")

	_, err = repo.Read(context.Background(), policyID, model.NewAdminScope(userID))
	require.Error(t, err, "a malformed vault_id must be an error, not uuid.Nil")
	require.Contains(t, err.Error(), "vault id")
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `go test ./internal/repositories/ -run TestReadRejectsMalformedVaultID -v`
Expected: FAIL — the read succeeds and returns a policy whose `VaultID` is `uuid.Nil`, so `require.Error` fails with "An error is expected but got nil."

- [ ] **Step 3: Add the shared parse helper**

Insert immediately after `scanRotationPolicyRow` in `internal/repositories/rotation_repository.go`:

```go
// parseRotationPolicyIDs fills policy's three UUID fields from their string
// column values. Errors are returned rather than discarded: a malformed
// column would otherwise yield uuid.Nil, which is a meaningful value in this
// codebase (model.NewAdminScope(uuid.Nil)) rather than an obvious sentinel.
// Mirrors parseRoleAssignmentIDs in role_assignment_repository.go.
func parseRotationPolicyIDs(policy *model.RotationPolicy, id, userID, vaultID string) error {
	var err error
	if policy.ID, err = uuid.Parse(id); err != nil {
		return fmt.Errorf("invalid rotation policy id: %w", err)
	}
	if policy.UserID, err = uuid.Parse(userID); err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}
	if policy.VaultID, err = uuid.Parse(vaultID); err != nil {
		return fmt.Errorf("invalid vault id: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Point `scanRotationPolicyRow` at the helper**

Replace lines 125-128 of `internal/repositories/rotation_repository.go`:

```go
	policy.ID, _ = uuid.Parse(id)
	policy.UserID, _ = uuid.Parse(userID)
	policy.VaultID, _ = uuid.Parse(vaultID)
	return &policy, nil
```

with:

```go
	if err := parseRotationPolicyIDs(&policy, id, userID, vaultID); err != nil {
		return nil, err
	}
	return &policy, nil
```

- [ ] **Step 5: Point the `List` closure at the helper**

Replace lines 191-194 of the same file:

```go
		policy.ID, _ = uuid.Parse(id)
		policy.UserID, _ = uuid.Parse(userID)
		policy.VaultID, _ = uuid.Parse(vaultID)
		return policy, nil
```

with:

```go
		if err := parseRotationPolicyIDs(&policy, id, userID, vaultID); err != nil {
			return policy, err
		}
		return policy, nil
```

- [ ] **Step 6: Run the tests and verify they pass**

Run: `go test ./internal/repositories/ -run TestReadRejectsMalformedVaultID -v`
Expected: PASS

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 7: Commit** (use the `1-git-commit` skill to author the message)

```bash
git add internal/repositories/rotation_repository.go internal/repositories/rotation_parse_errors_test.go
# then invoke the 1-git-commit skill
```

---

### Task 2: Return scan errors from the three row loops

**Files:**
- Modify: `internal/repositories/rotation_repository.go:268-344` (`GetSecretPolicies`, `GetPoliciesForSecret`), `:429-459` (`GetRotationHistory`)
- Test: `internal/repositories/rotation_parse_errors_test.go` (extend)

**Interfaces:**
- Consumes: `parseRotationPolicyIDs` from Task 1.
- Produces: nothing new; three method bodies change.

Each loop currently does `log.Error(...); continue` on a scan failure and skips `rows.Err()`. All three must return a wrapped error instead, and check `rows.Err()` after the loop.

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/rotation_parse_errors_test.go`:

```go
// TestGetRotationHistoryReportsCorruptRow pins the F1 fix: a row that cannot be
// parsed must surface as an error rather than being dropped from the returned
// slice. Before the fix this returned (1 row, nil error) for two stored rows --
// a silently short list the caller could not distinguish from a complete one.
func TestGetRotationHistoryReportsCorruptRow(t *testing.T) {
	raw := setupRotationTestDB(t)
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	repo := repositories.NewRotationPolicyRepository(conn, logging.InitLogger())

	secretID := uuid.New()
	ctx := context.Background()

	_, err := conn.ExecContext(ctx,
		`INSERT INTO secret_rotation_history
		 (id, secret_id, policy_id, rotated_at, previous_version, new_version, triggered_by, notes)
		 VALUES (?, ?, NULL, ?, 1, 2, 'scheduler', '')`,
		uuid.New().String(), secretID.String(), time.Now())
	require.NoError(t, err, "insert well-formed history row")

	_, err = conn.ExecContext(ctx,
		`INSERT INTO secret_rotation_history
		 (id, secret_id, policy_id, rotated_at, previous_version, new_version, triggered_by, notes)
		 VALUES (?, ?, NULL, ?, 2, 3, 'scheduler', '')`,
		"not-a-uuid", secretID.String(), time.Now())
	require.NoError(t, err, "insert history row with corrupt id")

	_, err = repo.GetRotationHistory(ctx, secretID)
	require.Error(t, err, "a corrupt history row must be reported, not silently dropped")
	require.Contains(t, err.Error(), "invalid rotation history id")
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `go test ./internal/repositories/ -run TestGetRotationHistoryReportsCorruptRow -v`
Expected: FAIL — `GetRotationHistory` returns two rows (one with `ID == uuid.Nil`) and a nil error.

- [ ] **Step 3: Fix `GetSecretPolicies`**

In `internal/repositories/rotation_repository.go`, replace lines 281-288:

```go
		if err != nil {
			r.log.WithError(err).Error("Failed to scan secret policy")
			continue
		}

		sp.SecretID, _ = uuid.Parse(secretIDStr)
		sp.PolicyID, _ = uuid.Parse(policyIDStr)
```

with:

```go
		if err != nil {
			return nil, fmt.Errorf("failed to scan secret policy: %w", err)
		}

		if sp.SecretID, err = uuid.Parse(secretIDStr); err != nil {
			return nil, fmt.Errorf("invalid secret id: %w", err)
		}
		if sp.PolicyID, err = uuid.Parse(policyIDStr); err != nil {
			return nil, fmt.Errorf("invalid policy id: %w", err)
		}
```

Then replace the loop's closing `return policies, nil` (line 300) with:

```go
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate secret policies: %w", err)
	}

	return policies, nil
```

- [ ] **Step 4: Fix `GetPoliciesForSecret`**

Replace lines 334-340:

```go
		if err != nil {
			r.log.WithError(err).Error("Failed to scan policy")
			continue
		}

		policy.ID, _ = uuid.Parse(policyID)
		policy.UserID, _ = uuid.Parse(userIDStr)
```

with:

```go
		if err != nil {
			return nil, fmt.Errorf("failed to scan rotation policy: %w", err)
		}

		if policy.ID, err = uuid.Parse(policyID); err != nil {
			return nil, fmt.Errorf("invalid rotation policy id: %w", err)
		}
		if policy.UserID, err = uuid.Parse(userIDStr); err != nil {
			return nil, fmt.Errorf("invalid user id: %w", err)
		}
```

Note: this query selects no `vault_id` column (see the SELECT at line 303), so `parseRotationPolicyIDs` does not fit here — `policy.VaultID` stays zero, as it already does. That is pre-existing behavior and out of scope for this plan.

Then replace this loop's closing `return policies, nil` (line 344) with:

```go
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate rotation policies: %w", err)
	}

	return policies, nil
```

- [ ] **Step 5: Fix `GetRotationHistory`**

Replace lines 445-455:

```go
		if err != nil {
			r.log.WithError(err).Error("Failed to scan rotation history")
			continue
		}

		h.ID, _ = uuid.Parse(historyID)
		h.SecretID, _ = uuid.Parse(secretIDStr)
		if policyID.Valid {
			pid, _ := uuid.Parse(policyID.String)
			h.PolicyID = &pid
		}
```

with:

```go
		if err != nil {
			return nil, fmt.Errorf("failed to scan rotation history: %w", err)
		}

		if h.ID, err = uuid.Parse(historyID); err != nil {
			return nil, fmt.Errorf("invalid rotation history id: %w", err)
		}
		if h.SecretID, err = uuid.Parse(secretIDStr); err != nil {
			return nil, fmt.Errorf("invalid secret id: %w", err)
		}
		if policyID.Valid {
			pid, parseErr := uuid.Parse(policyID.String)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid policy id: %w", parseErr)
			}
			h.PolicyID = &pid
		}
```

Then replace this loop's closing `return history, nil` (line 459) with:

```go
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate rotation history: %w", err)
	}

	return history, nil
```

- [ ] **Step 6: Run the tests and verify they pass**

Run: `go test ./internal/repositories/ -run 'TestGetRotationHistoryReportsCorruptRow|TestReadRejectsMalformedVaultID' -v`
Expected: PASS

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

If a rotation-service test now fails because it fed a fake repository a malformed UUID, that is the fix working. Update the test's fixture to a valid UUID; do not weaken the repository.

- [ ] **Step 7: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/rotation_repository.go internal/repositories/rotation_parse_errors_test.go
```

---

### Task 3: Fix the remaining single-row parse sites

**Files:**
- Modify: `internal/repositories/rotation_repository.go:464-488` (`scanSecretPolicyRow`), `:512-536` (`scanRotationReminderRow`), `:654-656` (`GetReminderBySecret`)

**Interfaces:**
- Consumes: nothing from Tasks 1-2.
- Produces: nothing new; three function bodies change.

These three are outside any `rows.Next()` loop, so Task 2 did not reach them. Same discarded-parse pattern, same fix.

- [ ] **Step 1: Fix `scanSecretPolicyRow`**

Replace lines 479-480:

```go
	sp.SecretID, _ = uuid.Parse(secretIDStr)
	sp.PolicyID, _ = uuid.Parse(policyIDStr)
```

with:

```go
	var err error
	if sp.SecretID, err = uuid.Parse(secretIDStr); err != nil {
		return sp, fmt.Errorf("invalid secret id: %w", err)
	}
	if sp.PolicyID, err = uuid.Parse(policyIDStr); err != nil {
		return sp, fmt.Errorf("invalid policy id: %w", err)
	}
```

- [ ] **Step 2: Fix `scanRotationReminderRow`**

Replace lines 529-531:

```go
	reminder.ID, _ = uuid.Parse(reminderID)
	reminder.SecretID, _ = uuid.Parse(secretIDStr)
	reminder.PolicyID, _ = uuid.Parse(policyIDStr)
```

with:

```go
	var err error
	if reminder.ID, err = uuid.Parse(reminderID); err != nil {
		return reminder, fmt.Errorf("invalid reminder id: %w", err)
	}
	if reminder.SecretID, err = uuid.Parse(secretIDStr); err != nil {
		return reminder, fmt.Errorf("invalid secret id: %w", err)
	}
	if reminder.PolicyID, err = uuid.Parse(policyIDStr); err != nil {
		return reminder, fmt.Errorf("invalid policy id: %w", err)
	}
```

- [ ] **Step 3: Fix `GetReminderBySecret`**

Replace lines 654-656:

```go
	reminder.ID, _ = uuid.Parse(idStr)
	reminder.SecretID, _ = uuid.Parse(secretIDStr)
	reminder.PolicyID, _ = uuid.Parse(policyIDStr)
```

with:

```go
	if reminder.ID, err = uuid.Parse(idStr); err != nil {
		return nil, fmt.Errorf("invalid reminder id: %w", err)
	}
	if reminder.SecretID, err = uuid.Parse(secretIDStr); err != nil {
		return nil, fmt.Errorf("invalid secret id: %w", err)
	}
	if reminder.PolicyID, err = uuid.Parse(policyIDStr); err != nil {
		return nil, fmt.Errorf("invalid policy id: %w", err)
	}
```

Note the reused `err` here: `GetReminderBySecret` already declares `err` at its `QueryRowContext` call, so these use `=` rather than `:=`. The other two functions declare `var err error` because they have none in scope.

- [ ] **Step 4: Verify no discarded parses remain in the file**

Run: `grep -n ", _ = uuid.Parse\|, _ := uuid.Parse" internal/repositories/rotation_repository.go`
Expected: no output.

- [ ] **Step 5: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 6: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/rotation_repository.go
```

---

## On completion

All three tasks are committed and `go test ./internal/repositories/... ./internal/services/...` is green.

**Next plan — execute this immediately, without asking:**
`docs/superpowers/plans/2026-09-07-repo-hardening-02-remaining-scan-errors.md`
