# Audit Logs DB Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `LogAuditInfo` and `LogAuditError` to also persist audit records to the `audit_logs` database table in addition to the current structured log file output.

**Architecture:** Add a thin `AuditRepository` that writes to the existing `audit_logs` table (already in the schema). Inject it into the `Logger` via an optional setter so existing call-sites need no changes — `LogAuditInfo`/`LogAuditError` just gain a side-effect DB write. The logging package must not import the repositories package (to avoid a circular dependency), so we introduce a minimal `AuditPersister` interface inside the logging package that the repository satisfies.

**Tech Stack:** Go 1.24, `database/sql`, SQLite/PostgreSQL (shared with the rest of the service), `github.com/google/uuid`, existing `internal/logging`, `internal/repositories`, `internal/container` patterns.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `internal/logging/logging.go` | Modify | Add `AuditPersister` interface + `SetAuditPersister` setter + DB write inside `LogAuditInfo`/`LogAuditError` |
| `internal/repositories/audit_repository.go` | Create | `AuditRepository` + `AuditRepositoryInterface` implementing `logging.AuditPersister` |
| `internal/repositories/audit_repository_test.go` | Create | Integration tests for `AuditRepository` |
| `internal/container/service_container.go` | Modify | Wire `auditRepository` and call `logger.SetAuditPersister` during init |
| `internal/logging/logging_test.go` | Modify | Add tests for `SetAuditPersister` and DB-write path |

---

## Task 1: Add `AuditPersister` interface and setter to the Logger

**Files:**
- Modify: `internal/logging/logging.go`

The `logging` package must not import `repositories` (circular dependency). We define a minimal interface here that the repository will satisfy from the outside.

- [ ] **Step 1: Add the interface and field to `logging.go`**

Open `internal/logging/logging.go`. After the `Logger` struct definition (line 21–28), add:

```go
// AuditPersister is implemented by anything that can durably store an audit record.
// Keeping the interface here avoids a circular import with the repositories package.
type AuditPersister interface {
	PersistAudit(userID, action, details string) error
}
```

Add a new field to the `Logger` struct:

```go
type Logger struct {
	*logrus.Logger
	logFile        string
	maxSizeBytes   int64
	maxBackups     int
	maxAgeDays     int
	rotationMethod string
	auditPersister AuditPersister // optional; nil means DB writes are skipped
}
```

- [ ] **Step 2: Add the setter**

After the struct, add:

```go
// SetAuditPersister wires a durable storage backend for audit records.
// Called once during container initialisation; safe to leave nil (log-only mode).
func (l *Logger) SetAuditPersister(p AuditPersister) {
	l.auditPersister = p
}
```

- [ ] **Step 3: Write to DB inside `LogAuditInfo`**

Replace the existing `LogAuditInfo` body (current lines 153–155):

```go
func (l *Logger) LogAuditInfo(userID, operation, status, message string) {
	l.WithAuditFields(userID, operation, status).Info(message)
	if l.auditPersister != nil {
		details := fmt.Sprintf("operation=%s status=%s message=%s", operation, status, message)
		if err := l.auditPersister.PersistAudit(userID, operation, details); err != nil {
			l.WithError(err).Warn("Failed to persist audit record to database")
		}
	}
}
```

- [ ] **Step 4: Write to DB inside `LogAuditError`**

Replace the existing `LogAuditError` body (current lines 158–160):

```go
func (l *Logger) LogAuditError(userID string, operation, status, message string, err error) {
	l.WithAuditFields(userID, operation, status).WithError(err).Error(message)
	if l.auditPersister != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		details := fmt.Sprintf("operation=%s status=%s message=%s error=%s", operation, status, message, errStr)
		if persistErr := l.auditPersister.PersistAudit(userID, operation, details); persistErr != nil {
			l.WithError(persistErr).Warn("Failed to persist audit error record to database")
		}
	}
}
```

Make sure `"fmt"` is already in the import block (it is not currently — add it).

- [ ] **Step 5: Verify the build compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./internal/logging/...
```

Expected: no output (clean build).

- [ ] **Step 6: Commit**

```bash
git add internal/logging/logging.go
git commit -m "feat(logging): add AuditPersister interface and DB write to LogAuditInfo/Error"
```

---

## Task 2: Create `AuditRepository`

**Files:**
- Create: `internal/repositories/audit_repository.go`
- Create: `internal/repositories/audit_repository_test.go`

- [ ] **Step 1: Write the failing test first**

Create `internal/repositories/audit_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/numericlabs/rocketvault/internal/repositories"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_logs (
		id      TEXT PRIMARY KEY,
		user_id TEXT,
		action  TEXT NOT NULL,
		details TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	return db
}

func TestAuditRepository_PersistAudit(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(db)

	err := repo.PersistAudit("user-1", "create_secret", "status=success message=done")
	require.NoError(t, err)

	var count int
	err = db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id = ? AND action = ?",
		"user-1", "create_secret",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestAuditRepository_PersistAudit_EmptyUserID(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(db)

	// Empty user_id is valid (unauthenticated events like auth failures).
	err := repo.PersistAudit("", "auth", "status=failed message=missing token")
	require.NoError(t, err)

	var count int
	err = db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id IS NULL OR user_id = ''",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestAuditRepository_PersistAudit_MultipleRecords(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(db)

	for i := 0; i < 5; i++ {
		err := repo.PersistAudit("user-2", "get_key", "status=success")
		require.NoError(t, err)
	}

	var count int
	err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id = ?", "user-2",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/repositories/... -run TestAuditRepository -v
```

Expected: compile error — `repositories.NewAuditRepository` does not exist yet.

- [ ] **Step 3: Implement `audit_repository.go`**

Create `internal/repositories/audit_repository.go`:

```go
package repositories

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// AuditRepositoryInterface is the contract for persisting audit log records.
// It satisfies logging.AuditPersister so the logger can write to the DB.
type AuditRepositoryInterface interface {
	PersistAudit(userID, action, details string) error
}

// AuditRepository writes audit records to the audit_logs table.
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates an AuditRepository backed by db.
func NewAuditRepository(db *sql.DB) AuditRepositoryInterface {
	return &AuditRepository{db: db}
}

// PersistAudit inserts one row into audit_logs.
// An empty userID is stored as an empty string (not NULL) for simplicity.
func (r *AuditRepository) PersistAudit(userID, action, details string) error {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := r.db.Exec(
		`INSERT INTO audit_logs (id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)`,
		id, userID, action, details, now,
	)
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/repositories/... -run TestAuditRepository -v
```

Expected:
```
--- PASS: TestAuditRepository_PersistAudit (0.00s)
--- PASS: TestAuditRepository_EmptyUserID (0.00s)
--- PASS: TestAuditRepository_MultipleRecords (0.00s)
PASS
```

- [ ] **Step 5: Run the full repository test suite to check for regressions**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/repositories/... -v 2>&1 | tail -20
```

Expected: all existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/repositories/audit_repository.go internal/repositories/audit_repository_test.go
git commit -m "feat(repositories): add AuditRepository for writing to audit_logs table"
```

---

## Task 3: Wire `AuditRepository` into the service container

**Files:**
- Modify: `internal/container/service_container.go`

- [ ] **Step 1: Add field to `ServiceContainer` struct**

In `internal/container/service_container.go`, find the `ServiceContainer` struct (around line 108). In the `// Repositories` block (around line 121–129), add:

```go
auditRepository repositories.AuditRepositoryInterface
```

The block will look like:

```go
// Repositories
userRepository               repositories.UserRepositoryInterface
secretRepository             repositories.SecretRepositoryInterface
rotationRepository           repositories.RotationPolicyRepositoryInterface
versionRepository            repositories.SecretVersionRepositoryInterface
keyRepository                repositories.KeyRepositoryInterface
certificateRepository        repositories.CertificateRepositoryInterface
certPolicyRepository         repositories.CertificatePolicyRepositoryInterface
sessionRepository            repositories.SessionRepositoryInterface
auditRepository              repositories.AuditRepositoryInterface
```

- [ ] **Step 2: Initialise and wire in `initRepositories`**

Find `initRepositories` in `service_container.go` (the function that calls `repositories.NewUserRepository`, etc. — around line 225–234). Add one line at the end of that function:

```go
c.auditRepository = repositories.NewAuditRepository(c.db)
```

Then, immediately after that, wire the persister into the logger. Still inside `initRepositories` (or in the calling `Initialize` function — wherever the repositories are initialised before services):

```go
c.logger.SetAuditPersister(c.auditRepository)
```

> **Why here?** The logger is used by every service. Setting the persister right after the repository is initialised ensures all subsequent audit calls (from services and middleware) already have the DB back-end available.

- [ ] **Step 3: Build the whole project**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./...
```

Expected: no errors. If you see "cannot use AuditRepository as AuditPersister", the interface is not satisfied — check that `PersistAudit` signature matches exactly in both files.

- [ ] **Step 4: Run the full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./... 2>&1 | tail -30
```

Expected: all tests pass (or the same set that passed before this change).

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): wire AuditRepository into logger for DB audit persistence"
```

---

## Task 4: Add Logger-level tests for the DB write path

**Files:**
- Modify: `internal/logging/logging_test.go`

- [ ] **Step 1: Write the failing tests**

Find `internal/logging/logging_test.go`. Add a new test group at the end of the file:

```go
// mockAuditPersister captures calls to PersistAudit for testing.
type mockAuditPersister struct {
	calls []struct{ userID, action, details string }
	err   error
}

func (m *mockAuditPersister) PersistAudit(userID, action, details string) error {
	m.calls = append(m.calls, struct{ userID, action, details string }{userID, action, details})
	return m.err
}

func TestLogAuditInfo_PersistsToDBWhenPersisterSet(t *testing.T) {
	logger := logging.WrapLogrus(logrus.New())
	mock := &mockAuditPersister{}
	logger.SetAuditPersister(mock)

	logger.LogAuditInfo("user-abc", "create_secret", "success", "secret created")

	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 PersistAudit call, got %d", len(mock.calls))
	}
	if mock.calls[0].userID != "user-abc" {
		t.Errorf("expected userID user-abc, got %s", mock.calls[0].userID)
	}
	if mock.calls[0].action != "create_secret" {
		t.Errorf("expected action create_secret, got %s", mock.calls[0].action)
	}
}

func TestLogAuditError_PersistsToDBWhenPersisterSet(t *testing.T) {
	logger := logging.WrapLogrus(logrus.New())
	mock := &mockAuditPersister{}
	logger.SetAuditPersister(mock)

	logger.LogAuditError("user-xyz", "get_key", "failed", "key not found", errors.New("sql: no rows"))

	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 PersistAudit call, got %d", len(mock.calls))
	}
	if mock.calls[0].userID != "user-xyz" {
		t.Errorf("expected userID user-xyz, got %s", mock.calls[0].userID)
	}
}

func TestLogAuditInfo_SkipsDBWhenNoPersister(t *testing.T) {
	// No persister set — must not panic.
	logger := logging.WrapLogrus(logrus.New())
	assert.NotPanics(t, func() {
		logger.LogAuditInfo("u1", "op", "status", "msg")
	})
}

func TestLogAuditError_PersisterFailureDoesNotPanic(t *testing.T) {
	logger := logging.WrapLogrus(logrus.New())
	mock := &mockAuditPersister{err: errors.New("db connection lost")}
	logger.SetAuditPersister(mock)

	// Must not panic or return an error — it should just warn.
	assert.NotPanics(t, func() {
		logger.LogAuditError("u1", "op", "failed", "msg", nil)
	})
}
```

Add any missing imports (`"errors"`, `"github.com/stretchr/testify/assert"`) to the import block.

The `mockAuditPersister` struct uses an unexported type in the test file — this is fine because the test file is in the same package or uses the `_test` convention. Check the existing test file's `package` declaration and use the same convention (either `package logging` or `package logging_test`). If `logging_test`, the `mockAuditPersister` goes in the same test file.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/logging/... -run TestLogAudit -v
```

Expected: compile error or test failure because `SetAuditPersister` doesn't exist yet (Task 1 must be complete first).

If Task 1 is already done, these tests should pass immediately — that's fine too. Move to Step 3.

- [ ] **Step 3: Run all logging tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/logging/... -v
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add internal/logging/logging_test.go
git commit -m "test(logging): verify LogAuditInfo/Error writes to AuditPersister"
```

---

## Task 5: Smoke-test end-to-end (manual verification)

This task has no code changes — it verifies the wiring actually works at runtime.

- [ ] **Step 1: Run the server**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go run main.go serve &
SERVER_PID=$!
sleep 2
```

- [ ] **Step 2: Make an authenticated request**

Obtain a token (adapt credentials to your local config):

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123","totp_code":"<6-digit code>"}' \
  | jq -r '.token')
echo "TOKEN=$TOKEN"
```

Make a data-plane request:

```bash
curl -s -X GET http://localhost:8080/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" | jq .
```

- [ ] **Step 3: Check the audit_logs table**

```bash
sqlite3 /path/to/rocketvault.db "SELECT id, user_id, action, details, timestamp FROM audit_logs LIMIT 10;"
```

Expected: rows are present with `action` values like `auth`, `list_secrets`, etc.

- [ ] **Step 4: Stop the server**

```bash
kill $SERVER_PID
```

---

## Self-Review

### Spec coverage

The audit says: "Wire `LogAuditInfo`/`LogAuditError` to also write `audit_logs` table, or drop the table."

- Task 1 wires the DB write into `LogAuditInfo`/`LogAuditError`. ✓
- Task 2 creates the repository that satisfies the interface. ✓
- Task 3 connects repository to logger in the DI container. ✓
- Task 4 adds tests. ✓
- Task 5 smoke-tests the end-to-end. ✓

Dropping the table is not implemented — that would be a regression (the table is useful). The plan wires it instead, matching the recommended option ("wire ... or drop").

### Placeholder scan

No TBD, TODO, or "similar to Task N" patterns present.

### Type consistency

- `AuditPersister.PersistAudit(userID, action, details string) error` — defined in Task 1, implemented in Task 2, used in Task 4 mock. Names match throughout.
- `AuditRepositoryInterface` satisfies `AuditPersister` because `AuditRepository.PersistAudit` has the exact same signature.
- `logging.WrapLogrus` is the existing constructor used in logging tests (line 148 of `logging.go`).

All types consistent.
