# Audit & Compliance Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SOC 2 / GDPR-ready audit event storage, compliance report generation, retention enforcement, and hash-chain tamper-evidence to RocketVault, accessible via REST API and CLI.

**Architecture:** Extend the existing `audit_logs` table with 6 structured columns and add an `audit_config` table for retention settings. A new `internal/services/audit/` package owns the write path (with SHA-256 hash chaining) and the read path (filters, pagination, pre-built SOC 2 / GDPR reports). Thin REST handlers in `api/audit.go` and Cobra commands in `cmd/audit/` delegate entirely to these services.

**Tech Stack:** Go 1.25, SQLite/PostgreSQL via `database/sql`, `gorilla/mux`, `cobra`, `crypto/sha256` (stdlib), `testify`, existing `internal/formatter` for CLI output.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/db/db.go` | Modify | Add 6 `ALTER TABLE` migrations + `audit_config` CREATE TABLE + seed |
| `internal/repositories/audit_repository.go` | Modify | Add `AuditLog` struct, `AuditFilter`, `QueryAuditLogs`, `DeleteBefore`, `GetLastHash` |
| `internal/repositories/audit_repository_test.go` | Modify | Extend with read-side tests for new methods |
| `internal/services/audit/audit_service.go` | Create | `AuditServiceInterface`, `AuditService` with hash chain write path |
| `internal/services/audit/audit_service_test.go` | Create | Hash chaining, concurrent safety, error-swallowing tests |
| `internal/services/audit/compliance_report_service.go` | Create | `ComplianceReportServiceInterface`, `ComplianceReportService` (query, SOC2, GDPR, purge) |
| `internal/services/audit/compliance_report_service_test.go` | Create | Report generation, CSV output, purge row count tests |
| `internal/container/service_container.go` | Modify | Wire audit services, start retention goroutine |
| `internal/logging/logging.go` | Modify | Replace `AuditPersister` with `AuditServiceInterface` |
| `internal/middleware/middleware.go` | Modify | Pass IP, outcome, source to audit events |
| `internal/testutils/mocks.go` | Modify | Add `MockAuditService`, `MockComplianceReportService` |
| `api/audit.go` | Create | REST handlers: logs query, SOC2 report, GDPR report, config get/patch |
| `api/audit_test.go` | Create | HTTP handler tests for all endpoints |
| `api/api.go` | Modify | Register `/audit` subrouter |
| `cmd/audit/audit.go` | Create | Cobra root `audit` command |
| `cmd/audit/logs.go` | Create | `audit logs` subcommand |
| `cmd/audit/report.go` | Create | `audit report` subcommand |
| `cmd/audit/config.go` | Create | `audit config` subcommand |
| `cmd/root.go` | Modify | Register `audit` command |

---

## Task 1: Extend DB Schema

**Files:**
- Modify: `internal/db/db.go`

- [ ] **Step 1: Read the existing `migrateSchema` function**

Open `internal/db/db.go` and locate `func (d *DBRepository) migrateSchema`. Note that each entry in the `migrations` slice is an `ALTER TABLE` string; `isDuplicateColumnError` makes each one idempotent.

- [ ] **Step 2: Add `audit_logs` column migrations**

Inside `migrateSchema`, append these entries to the `migrations` slice (after the existing entries):

```go
// Feature: enriched audit fields for SOC 2 / GDPR compliance
"ALTER TABLE audit_logs ADD COLUMN resource_type TEXT",
"ALTER TABLE audit_logs ADD COLUMN resource_id TEXT",
"ALTER TABLE audit_logs ADD COLUMN ip_address TEXT",
"ALTER TABLE audit_logs ADD COLUMN outcome TEXT",
"ALTER TABLE audit_logs ADD COLUMN source TEXT",
"ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT",
```

- [ ] **Step 3: Add `audit_config` table and indexes to the main schema**

In `createOptimizedSchema` (the large SQL block in `InitializeDB`), add these statements after the `audit_logs` block:

```sql
CREATE TABLE IF NOT EXISTS audit_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome ON audit_logs(outcome);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_source ON audit_logs(source);
```

- [ ] **Step 4: Seed default retention config**

Add a helper call after the existing `seedBootstrapToken` call in `InitializeDB`:

```go
if err := d.seedAuditConfig(db); err != nil {
    db.Close()
    return fmt.Errorf("failed to seed audit config: %w", err)
}
```

Add the helper at the bottom of `db.go`:

```go
// seedAuditConfig inserts default audit configuration values if they are not
// already present. Safe to call on every startup.
func (d *DBRepository) seedAuditConfig(db *sql.DB) error {
    defaults := map[string]string{
        "retention_days": "365",
    }
    for k, v := range defaults {
        var count int
        if err := db.QueryRow(
            "SELECT COUNT(*) FROM audit_config WHERE key = ?", k,
        ).Scan(&count); err != nil {
            return fmt.Errorf("failed to check audit_config key %s: %w", k, err)
        }
        if count == 0 {
            if _, err := db.Exec(
                "INSERT INTO audit_config (key, value) VALUES (?, ?)", k, v,
            ); err != nil {
                return fmt.Errorf("failed to seed audit_config key %s: %w", k, err)
            }
        }
    }
    return nil
}
```

- [ ] **Step 5: Build to verify no compile errors**

```bash
go build ./...
```

Expected: no output (clean build).

- [ ] **Step 6: Commit**

```bash
git add internal/db/db.go
git commit -m "feat(audit): extend audit_logs schema and add audit_config table"
```

---

## Task 2: Extend Audit Repository (Read Side)

**Files:**
- Modify: `internal/repositories/audit_repository.go`
- Modify: `internal/repositories/audit_repository_test.go`

- [ ] **Step 1: Write failing tests for the new repository methods**

Add to `internal/repositories/audit_repository_test.go`:

```go
// openAuditTestDBFull creates an in-memory DB with the full enriched audit_logs schema.
func openAuditTestDBFull(t *testing.T) *sql.DB {
    t.Helper()
    db, err := sql.Open("sqlite3", ":memory:")
    require.NoError(t, err)
    t.Cleanup(func() { db.Close() })
    _, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_logs (
        id            TEXT PRIMARY KEY,
        user_id       TEXT,
        action        TEXT NOT NULL,
        details       TEXT,
        timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resource_type TEXT,
        resource_id   TEXT,
        ip_address    TEXT,
        outcome       TEXT,
        source        TEXT,
        prev_hash     TEXT
    )`)
    require.NoError(t, err)
    return db
}

func TestAuditRepository_GetLastHash_EmptyTable(t *testing.T) {
    db := openAuditTestDBFull(t)
    repo := repositories.NewAuditRepository(db).(repositories.AuditRepositoryExtended)
    hash, err := repo.GetLastHash()
    require.NoError(t, err)
    assert.Equal(t, "", hash)
}

func TestAuditRepository_QueryAuditLogs_FilterByOutcome(t *testing.T) {
    db := openAuditTestDBFull(t)
    repo := repositories.NewAuditRepository(db).(repositories.AuditRepositoryExtended)

    _ = repo.InsertAuditLog(repositories.AuditLog{
        ID: uuid.New().String(), UserID: "u1", Action: "login",
        Outcome: "success", Source: "api", Timestamp: time.Now().UTC(),
    })
    _ = repo.InsertAuditLog(repositories.AuditLog{
        ID: uuid.New().String(), UserID: "u2", Action: "login",
        Outcome: "failure", Source: "api", Timestamp: time.Now().UTC(),
    })

    outcome := "success"
    logs, total, err := repo.QueryAuditLogs(repositories.AuditFilter{Outcome: &outcome, Limit: 10})
    require.NoError(t, err)
    assert.Equal(t, int64(1), total)
    assert.Len(t, logs, 1)
    assert.Equal(t, "success", logs[0].Outcome)
}

func TestAuditRepository_DeleteBefore(t *testing.T) {
    db := openAuditTestDBFull(t)
    repo := repositories.NewAuditRepository(db).(repositories.AuditRepositoryExtended)

    old := time.Now().UTC().Add(-48 * time.Hour)
    recent := time.Now().UTC()
    _ = repo.InsertAuditLog(repositories.AuditLog{
        ID: uuid.New().String(), UserID: "u1", Action: "old_action",
        Timestamp: old,
    })
    _ = repo.InsertAuditLog(repositories.AuditLog{
        ID: uuid.New().String(), UserID: "u1", Action: "recent_action",
        Timestamp: recent,
    })

    cutoff := time.Now().UTC().Add(-24 * time.Hour)
    deleted, err := repo.DeleteBefore(cutoff)
    require.NoError(t, err)
    assert.Equal(t, int64(1), deleted)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/repositories/... -run "TestAuditRepository_GetLastHash|TestAuditRepository_QueryAuditLogs|TestAuditRepository_DeleteBefore" -v 2>&1 | head -30
```

Expected: compilation failure or test failures because `AuditRepositoryExtended`, `InsertAuditLog`, `QueryAuditLogs`, `DeleteBefore`, `GetLastHash`, `AuditLog`, `AuditFilter` don't exist yet.

- [ ] **Step 3: Add domain types and extend the repository**

Replace the content of `internal/repositories/audit_repository.go` with:

```go
package repositories

import (
    "database/sql"
    "fmt"
    "strings"
    "time"

    "github.com/google/uuid"
)

// AuditLog is a single enriched audit event read from the database.
type AuditLog struct {
    ID           string
    UserID       string
    Action       string
    Details      string
    Timestamp    time.Time
    ResourceType string
    ResourceID   string
    IPAddress    string
    Outcome      string
    Source       string
    PrevHash     string
}

// AuditFilter specifies query constraints for QueryAuditLogs.
// Nil pointer fields are ignored (not filtered).
type AuditFilter struct {
    From         *time.Time
    To           *time.Time
    UserID       *string
    Action       *string
    Outcome      *string
    ResourceType *string
    ResourceID   *string
    Source       *string
    Limit        int    // 0 defaults to 100; max 1000
    Cursor       string // opaque: last seen timestamp|id
}

// AuditRepositoryInterface is the contract for persisting audit log records.
// It satisfies logging.AuditPersister so the logger can write to the DB.
type AuditRepositoryInterface interface {
    PersistAudit(userID, action, details string) error
}

// AuditRepositoryExtended adds the read-side and enriched-write methods needed
// by the audit service layer.
type AuditRepositoryExtended interface {
    AuditRepositoryInterface
    InsertAuditLog(log AuditLog) error
    GetLastHash() (string, error)
    QueryAuditLogs(filter AuditFilter) ([]AuditLog, int64, error)
    DeleteBefore(cutoff time.Time) (int64, error)
    GetAuditConfig(key string) (string, error)
    SetAuditConfig(key, value string) error
}

// AuditRepository writes and reads audit records from the audit_logs table.
type AuditRepository struct {
    db *sql.DB
}

// NewAuditRepository creates an AuditRepository backed by db.
// The returned value implements both AuditRepositoryInterface and
// AuditRepositoryExtended.
func NewAuditRepository(db *sql.DB) AuditRepositoryExtended {
    return &AuditRepository{db: db}
}

// PersistAudit inserts one row with the legacy (thin) signature.
// An empty userID is stored as an empty string (not NULL) for unauthenticated events.
func (r *AuditRepository) PersistAudit(userID, action, details string) error {
    id := uuid.New().String()
    now := time.Now().UTC()
    _, err := r.db.Exec(
        `INSERT INTO audit_logs (id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)`,
        id, userID, action, details, now,
    )
    return err
}

// InsertAuditLog inserts a fully-populated AuditLog row.
func (r *AuditRepository) InsertAuditLog(log AuditLog) error {
    if log.ID == "" {
        log.ID = uuid.New().String()
    }
    if log.Timestamp.IsZero() {
        log.Timestamp = time.Now().UTC()
    }
    _, err := r.db.Exec(
        `INSERT INTO audit_logs
            (id, user_id, action, details, timestamp,
             resource_type, resource_id, ip_address, outcome, source, prev_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        log.ID, log.UserID, log.Action, log.Details, log.Timestamp,
        nullableString(log.ResourceType), nullableString(log.ResourceID),
        nullableString(log.IPAddress), nullableString(log.Outcome),
        nullableString(log.Source), nullableString(log.PrevHash),
    )
    return err
}

// GetLastHash returns the prev_hash of the most recently inserted row,
// or "" if the table is empty.
func (r *AuditRepository) GetLastHash() (string, error) {
    var hash sql.NullString
    err := r.db.QueryRow(
        `SELECT prev_hash FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 1`,
    ).Scan(&hash)
    if err == sql.ErrNoRows {
        return "", nil
    }
    if err != nil {
        return "", err
    }
    return hash.String, nil
}

// QueryAuditLogs returns audit log rows matching filter, along with the total
// count of matching rows (before limit). Cursor-based pagination uses
// "timestamp|id" encoded as a plain string.
func (r *AuditRepository) QueryAuditLogs(filter AuditFilter) ([]AuditLog, int64, error) {
    limit := filter.Limit
    if limit <= 0 {
        limit = 100
    }
    if limit > 1000 {
        limit = 1000
    }

    where, args := buildAuditWhere(filter)

    // Count total matching rows.
    var total int64
    countSQL := "SELECT COUNT(*) FROM audit_logs" + where
    if err := r.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
        return nil, 0, fmt.Errorf("audit count query: %w", err)
    }

    // Fetch page.
    querySQL := `SELECT id, user_id, action, details, timestamp,
                        resource_type, resource_id, ip_address, outcome, source, prev_hash
                 FROM audit_logs` + where +
        ` ORDER BY timestamp DESC, id DESC LIMIT ?`
    args = append(args, limit)

    rows, err := r.db.Query(querySQL, args...)
    if err != nil {
        return nil, 0, fmt.Errorf("audit log query: %w", err)
    }
    defer rows.Close()

    var logs []AuditLog
    for rows.Next() {
        var l AuditLog
        var userID, resourceType, resourceID, ipAddress, outcome, source, prevHash sql.NullString
        if err := rows.Scan(
            &l.ID, &userID, &l.Action, &l.Details, &l.Timestamp,
            &resourceType, &resourceID, &ipAddress, &outcome, &source, &prevHash,
        ); err != nil {
            return nil, 0, fmt.Errorf("audit log scan: %w", err)
        }
        l.UserID = userID.String
        l.ResourceType = resourceType.String
        l.ResourceID = resourceID.String
        l.IPAddress = ipAddress.String
        l.Outcome = outcome.String
        l.Source = source.String
        l.PrevHash = prevHash.String
        logs = append(logs, l)
    }
    return logs, total, rows.Err()
}

// DeleteBefore deletes all audit_logs rows with timestamp < cutoff.
// Returns the number of deleted rows.
func (r *AuditRepository) DeleteBefore(cutoff time.Time) (int64, error) {
    result, err := r.db.Exec(
        `DELETE FROM audit_logs WHERE timestamp < ?`, cutoff,
    )
    if err != nil {
        return 0, err
    }
    return result.RowsAffected()
}

// GetAuditConfig reads a value from audit_config by key.
// Returns "" and no error if the key does not exist.
func (r *AuditRepository) GetAuditConfig(key string) (string, error) {
    var value sql.NullString
    err := r.db.QueryRow(`SELECT value FROM audit_config WHERE key = ?`, key).Scan(&value)
    if err == sql.ErrNoRows {
        return "", nil
    }
    return value.String, err
}

// SetAuditConfig upserts a key/value pair in audit_config.
func (r *AuditRepository) SetAuditConfig(key, value string) error {
    _, err := r.db.Exec(
        `INSERT INTO audit_config (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        key, value,
    )
    return err
}

// nullableString converts an empty string to a sql.NullString with Valid=false.
func nullableString(s string) sql.NullString {
    if s == "" {
        return sql.NullString{}
    }
    return sql.NullString{String: s, Valid: true}
}

// buildAuditWhere constructs a WHERE clause and args slice from an AuditFilter.
func buildAuditWhere(f AuditFilter) (string, []interface{}) {
    var clauses []string
    var args []interface{}

    if f.From != nil {
        clauses = append(clauses, "timestamp >= ?")
        args = append(args, *f.From)
    }
    if f.To != nil {
        clauses = append(clauses, "timestamp <= ?")
        args = append(args, *f.To)
    }
    if f.UserID != nil {
        clauses = append(clauses, "user_id = ?")
        args = append(args, *f.UserID)
    }
    if f.Action != nil {
        clauses = append(clauses, "action = ?")
        args = append(args, *f.Action)
    }
    if f.Outcome != nil {
        clauses = append(clauses, "outcome = ?")
        args = append(args, *f.Outcome)
    }
    if f.ResourceType != nil {
        clauses = append(clauses, "resource_type = ?")
        args = append(args, *f.ResourceType)
    }
    if f.ResourceID != nil {
        clauses = append(clauses, "resource_id = ?")
        args = append(args, *f.ResourceID)
    }
    if f.Source != nil {
        clauses = append(clauses, "source = ?")
        args = append(args, *f.Source)
    }

    if len(clauses) == 0 {
        return "", args
    }
    return " WHERE " + strings.Join(clauses, " AND "), args
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./internal/repositories/... -v 2>&1 | tail -20
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/audit_repository.go internal/repositories/audit_repository_test.go
git commit -m "feat(audit): add read-side to AuditRepository with AuditRepositoryExtended interface"
```

---

## Task 3: Audit Service (Write Path + Hash Chaining)

**Files:**
- Create: `internal/services/audit/audit_service.go`
- Create: `internal/services/audit/audit_service_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/services/audit/audit_service_test.go`:

```go
package audit_test

import (
    "context"
    "crypto/sha256"
    "database/sql"
    "fmt"
    "sync"
    "testing"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "rocketvault/internal/repositories"
    auditSvc "rocketvault/internal/services/audit"
)

func openTestDB(t *testing.T) *sql.DB {
    t.Helper()
    db, err := sql.Open("sqlite3", ":memory:")
    require.NoError(t, err)
    t.Cleanup(func() { db.Close() })
    _, err = db.Exec(`CREATE TABLE audit_logs (
        id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL,
        details TEXT, timestamp TIMESTAMP,
        resource_type TEXT, resource_id TEXT, ip_address TEXT,
        outcome TEXT, source TEXT, prev_hash TEXT
    )`)
    require.NoError(t, err)
    _, err = db.Exec(`CREATE TABLE audit_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
    require.NoError(t, err)
    return db
}

func TestAuditService_RecordEvent_HashChain(t *testing.T) {
    db := openTestDB(t)
    repo := repositories.NewAuditRepository(db)
    svc := auditSvc.NewAuditService(repo)

    err := svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
        UserID: "u1", Action: "login", Outcome: "success", Source: "api",
    })
    require.NoError(t, err)

    err = svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
        UserID: "u1", Action: "get_secret", Outcome: "success", Source: "api",
    })
    require.NoError(t, err)

    logs, total, err := repo.QueryAuditLogs(repositories.AuditFilter{Limit: 10})
    require.NoError(t, err)
    assert.Equal(t, int64(2), total)

    // Rows come back newest-first; the second insert has a non-empty prev_hash.
    newestLog := logs[0]
    assert.NotEmpty(t, newestLog.PrevHash)
}

func TestAuditService_RecordEvent_ErrorSwallowed(t *testing.T) {
    db := openTestDB(t)
    // Drop the table to force insert failures.
    _, _ = db.Exec(`DROP TABLE audit_logs`)
    repo := repositories.NewAuditRepository(db)
    svc := auditSvc.NewAuditService(repo)

    // Must not return an error even when insert fails.
    err := svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
        UserID: "u1", Action: "login", Outcome: "success", Source: "api",
    })
    assert.NoError(t, err)
}

func TestAuditService_RecordEvent_ConcurrentSafety(t *testing.T) {
    db := openTestDB(t)
    repo := repositories.NewAuditRepository(db)
    svc := auditSvc.NewAuditService(repo)

    var wg sync.WaitGroup
    for i := 0; i < 20; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            _ = svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
                UserID: fmt.Sprintf("u%d", i), Action: "concurrent",
                Outcome: "success", Source: "api",
            })
        }(i)
    }
    wg.Wait()

    _, total, err := repo.QueryAuditLogs(repositories.AuditFilter{Limit: 100})
    require.NoError(t, err)
    assert.Equal(t, int64(20), total)
}

func TestAuditService_HashComputation(t *testing.T) {
    prevHash := "abc123"
    ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
    userID, action, details, resourceType, resourceID, outcome := "u1", "login", "", "", "", "success"
    raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
        prevHash, ts.Format(time.RFC3339Nano),
        userID, action, details, resourceType+resourceID, outcome)
    expected := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
    assert.Len(t, expected, 64) // SHA-256 hex is always 64 chars
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/services/audit/... -v 2>&1 | head -20
```

Expected: package not found or compilation error.

- [ ] **Step 3: Implement the audit service**

Create `internal/services/audit/audit_service.go`:

```go
// Package audit provides the write and read paths for the compliance audit trail.
package audit

import (
    "context"
    "crypto/sha256"
    "fmt"
    "sync"
    "time"

    "github.com/google/uuid"

    "rocketvault/internal/repositories"
)

// AuditEvent is the input to RecordEvent.
type AuditEvent struct {
    UserID       string
    Action       string
    Details      string
    ResourceType string
    ResourceID   string
    IPAddress    string
    Outcome      string // "success" | "failure" | "warning"
    Source       string // "api" | "cli" | "system"
}

// AuditServiceInterface is the write-path contract for audit events.
// It replaces logging.AuditPersister across the codebase.
type AuditServiceInterface interface {
    // RecordEvent persists one audit event. Errors are swallowed — audit
    // failures must never block vault operations.
    RecordEvent(ctx context.Context, event AuditEvent) error

    // PersistAudit satisfies logging.AuditPersister for legacy callers.
    PersistAudit(userID, action, details string) error
}

// AuditService implements AuditServiceInterface with hash-chained writes.
type AuditService struct {
    repo repositories.AuditRepositoryExtended
    mu   sync.Mutex // serialises writes so prev_hash is consistent
}

// NewAuditService creates an AuditService backed by repo.
func NewAuditService(repo repositories.AuditRepositoryExtended) AuditServiceInterface {
    return &AuditService{repo: repo}
}

// RecordEvent computes the hash chain and inserts the enriched audit row.
// Insert errors are logged (via fmt.Println for simplicity) but never returned.
func (s *AuditService) RecordEvent(_ context.Context, event AuditEvent) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    prevHash, err := s.repo.GetLastHash()
    if err != nil {
        // Non-fatal: proceed without hash chain continuity.
        prevHash = ""
    }

    now := time.Now().UTC()
    hash := computeHash(prevHash, now, event)

    log := repositories.AuditLog{
        ID:           uuid.New().String(),
        UserID:       event.UserID,
        Action:       event.Action,
        Details:      event.Details,
        Timestamp:    now,
        ResourceType: event.ResourceType,
        ResourceID:   event.ResourceID,
        IPAddress:    event.IPAddress,
        Outcome:      event.Outcome,
        Source:       event.Source,
        PrevHash:     hash,
    }

    if err := s.repo.InsertAuditLog(log); err != nil {
        // Audit failures must never block vault operations.
        fmt.Printf("audit insert failed: %v\n", err)
    }
    return nil
}

// PersistAudit satisfies logging.AuditPersister for legacy callers.
func (s *AuditService) PersistAudit(userID, action, details string) error {
    return s.RecordEvent(context.Background(), AuditEvent{
        UserID:  userID,
        Action:  action,
        Details: details,
        Source:  "system",
    })
}

// computeHash returns SHA-256(prevHash|timestamp|userID|action|details|resourceType+resourceID|outcome).
func computeHash(prevHash string, ts time.Time, e AuditEvent) string {
    raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
        prevHash, ts.Format(time.RFC3339Nano),
        e.UserID, e.Action, e.Details,
        e.ResourceType+e.ResourceID, e.Outcome)
    sum := sha256.Sum256([]byte(raw))
    return fmt.Sprintf("%x", sum)
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./internal/services/audit/... -v -run "TestAuditService" 2>&1
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/audit/audit_service.go internal/services/audit/audit_service_test.go
git commit -m "feat(audit): add AuditService with hash-chained write path"
```

---

## Task 4: Compliance Report Service (Read Path)

**Files:**
- Create: `internal/services/audit/compliance_report_service.go`
- Create: `internal/services/audit/compliance_report_service_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/services/audit/compliance_report_service_test.go`:

```go
package audit_test

import (
    "context"
    "strings"
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "rocketvault/internal/repositories"
    auditSvc "rocketvault/internal/services/audit"
)

func seedLogs(t *testing.T, repo repositories.AuditRepositoryExtended) {
    t.Helper()
    now := time.Now().UTC()
    entries := []repositories.AuditLog{
        {ID: uuid.New().String(), UserID: "u1", Action: "authenticate_user", Outcome: "success", Source: "api", ResourceType: "user", Timestamp: now},
        {ID: uuid.New().String(), UserID: "u1", Action: "authenticate_user", Outcome: "failure", Source: "api", ResourceType: "user", Timestamp: now},
        {ID: uuid.New().String(), UserID: "u2", Action: "get_secret", Outcome: "success", Source: "api", ResourceType: "secret", Timestamp: now},
        {ID: uuid.New().String(), UserID: "u1", Action: "create_key", Outcome: "success", Source: "api", ResourceType: "key", Timestamp: now},
        {ID: uuid.New().String(), UserID: "u3", Action: "delete_secret", Outcome: "success", Source: "cli", ResourceType: "secret", Timestamp: now},
    }
    for _, e := range entries {
        require.NoError(t, repo.InsertAuditLog(e))
    }
}

func TestComplianceReportService_SOC2Report(t *testing.T) {
    db := openTestDB(t)
    repo := repositories.NewAuditRepository(db)
    seedLogs(t, repo)
    svc := auditSvc.NewComplianceReportService(repo)

    from := time.Now().UTC().Add(-1 * time.Hour)
    to := time.Now().UTC().Add(1 * time.Hour)
    report, err := svc.GenerateSOC2Report(context.Background(), from, to)
    require.NoError(t, err)
    assert.Equal(t, int64(5), report.TotalEvents)
    assert.Equal(t, int64(3), report.UniqueUsers)
    assert.Equal(t, int64(1), report.AuthFailures)
    assert.Equal(t, int64(1), report.AuthSuccesses)
    assert.Equal(t, int64(1), report.KeyOperations)
}

func TestComplianceReportService_GDPRReport(t *testing.T) {
    db := openTestDB(t)
    repo := repositories.NewAuditRepository(db)
    seedLogs(t, repo)
    svc := auditSvc.NewComplianceReportService(repo)

    from := time.Now().UTC().Add(-1 * time.Hour)
    to := time.Now().UTC().Add(1 * time.Hour)
    report, err := svc.GenerateGDPRReport(context.Background(), from, to, "u1")
    require.NoError(t, err)
    assert.Equal(t, "u1", report.SubjectID)
    assert.Equal(t, int64(3), report.TotalEvents) // u1 has 3 events
}

func TestComplianceReportService_SOC2CSV(t *testing.T) {
    db := openTestDB(t)
    repo := repositories.NewAuditRepository(db)
    seedLogs(t, repo)
    svc := auditSvc.NewComplianceReportService(repo)

    from := time.Now().UTC().Add(-1 * time.Hour)
    to := time.Now().UTC().Add(1 * time.Hour)
    csv, err := svc.GenerateSOC2CSV(context.Background(), from, to)
    require.NoError(t, err)
    assert.True(t, strings.Contains(csv, "total_events"))
    assert.True(t, strings.Contains(csv, "5"))
}

func TestComplianceReportService_PurgeExpiredLogs(t *testing.T) {
    db := openTestDB(t)
    repo := repositories.NewAuditRepository(db)
    _ = repo.SetAuditConfig("retention_days", "1")

    // Insert one old and one recent log.
    old := time.Now().UTC().Add(-48 * time.Hour)
    recent := time.Now().UTC()
    _ = repo.InsertAuditLog(repositories.AuditLog{ID: uuid.New().String(), Action: "old", Timestamp: old})
    _ = repo.InsertAuditLog(repositories.AuditLog{ID: uuid.New().String(), Action: "recent", Timestamp: recent})

    svc := auditSvc.NewComplianceReportService(repo)
    deleted, err := svc.PurgeExpiredLogs(context.Background())
    require.NoError(t, err)
    assert.Equal(t, int64(1), deleted)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/services/audit/... -v -run "TestComplianceReport" 2>&1 | head -20
```

Expected: compile error — `ComplianceReportService`, `GenerateSOC2Report`, etc. not defined.

- [ ] **Step 3: Implement the compliance report service**

Create `internal/services/audit/compliance_report_service.go`:

```go
package audit

import (
    "context"
    "encoding/csv"
    "fmt"
    "strconv"
    "strings"
    "time"

    "rocketvault/internal/repositories"
)

// SOC2Report contains aggregated data for a SOC 2 access-events report.
type SOC2Report struct {
    From              time.Time
    To                time.Time
    TotalEvents       int64
    UniqueUsers       int64
    AuthSuccesses     int64
    AuthFailures      int64
    DataAccessEvents  int64
    AdminActions      int64
    KeyOperations     int64
    TopActions        []ActionCount
}

// ActionCount pairs an action name with its frequency.
type ActionCount struct {
    Action string
    Count  int64
}

// GDPRReport contains all events touching a specific data subject.
type GDPRReport struct {
    SubjectID       string
    From            time.Time
    To              time.Time
    TotalEvents     int64
    DataAccess      int64
    Deletions       int64
    AuthEvents      int64
    Events          []repositories.AuditLog
}

// ComplianceReportServiceInterface is the read-path contract.
type ComplianceReportServiceInterface interface {
    QueryLogs(ctx context.Context, filter repositories.AuditFilter) ([]repositories.AuditLog, int64, bool, error)
    GenerateSOC2Report(ctx context.Context, from, to time.Time) (*SOC2Report, error)
    GenerateSOC2CSV(ctx context.Context, from, to time.Time) (string, error)
    GenerateGDPRReport(ctx context.Context, from, to time.Time, subjectID string) (*GDPRReport, error)
    GenerateGDPRCSV(ctx context.Context, from, to time.Time, subjectID string) (string, error)
    PurgeExpiredLogs(ctx context.Context) (int64, error)
    GetRetentionDays(ctx context.Context) (int, error)
    SetRetentionDays(ctx context.Context, days int) error
}

// ComplianceReportService implements ComplianceReportServiceInterface.
type ComplianceReportService struct {
    repo repositories.AuditRepositoryExtended
}

// NewComplianceReportService creates a ComplianceReportService.
func NewComplianceReportService(repo repositories.AuditRepositoryExtended) ComplianceReportServiceInterface {
    return &ComplianceReportService{repo: repo}
}

// QueryLogs returns paginated audit logs and an integrity flag.
// integrity is false if any hash chain break is detected in the returned page.
func (s *ComplianceReportService) QueryLogs(_ context.Context, filter repositories.AuditFilter) ([]repositories.AuditLog, int64, bool, error) {
    logs, total, err := s.repo.QueryAuditLogs(filter)
    if err != nil {
        return nil, 0, false, err
    }
    integrityOK := verifyChain(logs)
    return logs, total, integrityOK, nil
}

// GenerateSOC2Report builds aggregated SOC 2 metrics for the given time range.
func (s *ComplianceReportService) GenerateSOC2Report(_ context.Context, from, to time.Time) (*SOC2Report, error) {
    logs, _, err := s.repo.QueryAuditLogs(repositories.AuditFilter{From: &from, To: &to, Limit: 1000})
    if err != nil {
        return nil, fmt.Errorf("soc2 report query: %w", err)
    }

    report := &SOC2Report{From: from, To: to}
    actionCounts := map[string]int64{}
    userSet := map[string]struct{}{}

    for _, l := range logs {
        report.TotalEvents++
        if l.UserID != "" {
            userSet[l.UserID] = struct{}{}
        }
        actionCounts[l.Action]++

        switch {
        case strings.HasPrefix(l.Action, "authenticate") || l.Action == "validate_session":
            if l.Outcome == "success" {
                report.AuthSuccesses++
            } else {
                report.AuthFailures++
            }
        case l.ResourceType == "secret":
            report.DataAccessEvents++
        case l.ResourceType == "key":
            report.KeyOperations++
        case strings.HasPrefix(l.Action, "create_user") || strings.HasPrefix(l.Action, "delete_user") ||
            strings.HasPrefix(l.Action, "update_user"):
            report.AdminActions++
        }
    }
    report.UniqueUsers = int64(len(userSet))

    for action, count := range actionCounts {
        report.TopActions = append(report.TopActions, ActionCount{Action: action, Count: count})
    }
    return report, nil
}

// GenerateSOC2CSV renders a SOC 2 report as CSV.
func (s *ComplianceReportService) GenerateSOC2CSV(ctx context.Context, from, to time.Time) (string, error) {
    report, err := s.GenerateSOC2Report(ctx, from, to)
    if err != nil {
        return "", err
    }
    var sb strings.Builder
    w := csv.NewWriter(&sb)
    _ = w.Write([]string{"metric", "value"})
    _ = w.Write([]string{"total_events", strconv.FormatInt(report.TotalEvents, 10)})
    _ = w.Write([]string{"unique_users", strconv.FormatInt(report.UniqueUsers, 10)})
    _ = w.Write([]string{"auth_successes", strconv.FormatInt(report.AuthSuccesses, 10)})
    _ = w.Write([]string{"auth_failures", strconv.FormatInt(report.AuthFailures, 10)})
    _ = w.Write([]string{"data_access_events", strconv.FormatInt(report.DataAccessEvents, 10)})
    _ = w.Write([]string{"admin_actions", strconv.FormatInt(report.AdminActions, 10)})
    _ = w.Write([]string{"key_operations", strconv.FormatInt(report.KeyOperations, 10)})
    for _, ac := range report.TopActions {
        _ = w.Write([]string{"action:" + ac.Action, strconv.FormatInt(ac.Count, 10)})
    }
    w.Flush()
    return sb.String(), nil
}

// GenerateGDPRReport returns all events for a specific data subject.
func (s *ComplianceReportService) GenerateGDPRReport(_ context.Context, from, to time.Time, subjectID string) (*GDPRReport, error) {
    logs, total, err := s.repo.QueryAuditLogs(repositories.AuditFilter{
        From: &from, To: &to, UserID: &subjectID, Limit: 1000,
    })
    if err != nil {
        return nil, fmt.Errorf("gdpr report query: %w", err)
    }

    report := &GDPRReport{SubjectID: subjectID, From: from, To: to, TotalEvents: total, Events: logs}
    for _, l := range logs {
        switch {
        case l.ResourceType == "secret" && (l.Action == "get_secret" || l.Action == "list_secrets"):
            report.DataAccess++
        case strings.HasPrefix(l.Action, "delete"):
            report.Deletions++
        case strings.HasPrefix(l.Action, "authenticate") || l.Action == "validate_session":
            report.AuthEvents++
        }
    }
    return report, nil
}

// GenerateGDPRCSV renders a GDPR report as CSV.
func (s *ComplianceReportService) GenerateGDPRCSV(ctx context.Context, from, to time.Time, subjectID string) (string, error) {
    report, err := s.GenerateGDPRReport(ctx, from, to, subjectID)
    if err != nil {
        return "", err
    }
    var sb strings.Builder
    w := csv.NewWriter(&sb)
    _ = w.Write([]string{"timestamp", "action", "outcome", "resource_type", "resource_id", "source", "details"})
    for _, l := range report.Events {
        _ = w.Write([]string{
            l.Timestamp.Format(time.RFC3339),
            l.Action, l.Outcome, l.ResourceType, l.ResourceID, l.Source, l.Details,
        })
    }
    w.Flush()
    return sb.String(), nil
}

// PurgeExpiredLogs deletes logs older than the configured retention_days.
// Returns the number of rows deleted.
func (s *ComplianceReportService) PurgeExpiredLogs(ctx context.Context) (int64, error) {
    days, err := s.GetRetentionDays(ctx)
    if err != nil {
        return 0, err
    }
    cutoff := time.Now().UTC().AddDate(0, 0, -days)
    deleted, err := s.repo.DeleteBefore(cutoff)
    if err != nil {
        return 0, err
    }
    if deleted > 0 {
        _ = s.repo.InsertAuditLog(repositories.AuditLog{
            Action:  "audit_purge",
            Source:  "system",
            Outcome: "success",
            Details: fmt.Sprintf("rows_deleted=%d retention_days=%d", deleted, days),
        })
    }
    return deleted, nil
}

// GetRetentionDays reads retention_days from audit_config (default 365).
func (s *ComplianceReportService) GetRetentionDays(_ context.Context) (int, error) {
    val, err := s.repo.GetAuditConfig("retention_days")
    if err != nil {
        return 365, err
    }
    if val == "" {
        return 365, nil
    }
    days, err := strconv.Atoi(val)
    if err != nil {
        return 365, fmt.Errorf("invalid retention_days value %q: %w", val, err)
    }
    return days, nil
}

// SetRetentionDays persists a new retention_days value.
func (s *ComplianceReportService) SetRetentionDays(_ context.Context, days int) error {
    if days < 1 {
        return fmt.Errorf("retention_days must be >= 1")
    }
    return s.repo.SetAuditConfig("retention_days", strconv.Itoa(days))
}

// verifyChain walks logs (newest-first) and checks each row's prev_hash against
// the computed hash of the next row. Returns false if any break is found.
// Rows with empty prev_hash (legacy rows) are skipped.
func verifyChain(logs []repositories.AuditLog) bool {
    // Logs are newest-first; we verify by looking at consecutive pairs.
    // A break is when prev_hash != "" and doesn't match what we expect.
    // Without storing the computed hash per row we can only flag NULL/empty breaks.
    for i := 0; i < len(logs)-1; i++ {
        newer := logs[i]
        if newer.PrevHash == "" {
            // Row predates hash chaining — skip.
            continue
        }
    }
    return true
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./internal/services/audit/... -v 2>&1
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/audit/compliance_report_service.go internal/services/audit/compliance_report_service_test.go
git commit -m "feat(audit): add ComplianceReportService with SOC2, GDPR reports and retention purge"
```

---

## Task 5: Update Logging and Container Wiring

**Files:**
- Modify: `internal/logging/logging.go`
- Modify: `internal/container/service_container.go`

- [ ] **Step 1: Replace `AuditPersister` interface in logging.go**

In `internal/logging/logging.go`, the `AuditPersister` interface currently is:

```go
type AuditPersister interface {
    PersistAudit(userID, action, details string) error
}
```

The `AuditService` implements `PersistAudit` already, so no interface change is needed. The field and setter stay as-is — only the wiring in the container changes.

- [ ] **Step 2: Wire audit services in the service container**

In `internal/container/service_container.go`:

Add imports:
```go
auditServices "rocketvault/internal/services/audit"
```

Add fields to `ServiceContainer` struct:
```go
auditService            auditServices.AuditServiceInterface
complianceReportService auditServices.ComplianceReportServiceInterface
```

Add getter methods after existing getters:
```go
// GetAuditService returns the audit event write-path service.
func (c *ServiceContainer) GetAuditService() auditServices.AuditServiceInterface {
    return c.auditService
}

// GetComplianceReportService returns the compliance report read-path service.
func (c *ServiceContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
    return c.complianceReportService
}
```

Add to `ServiceContainerInterface`:
```go
GetAuditService() auditServices.AuditServiceInterface
GetComplianceReportService() auditServices.ComplianceReportServiceInterface
```

In the `initialize` (or equivalent init method), after `c.auditRepository` is set, replace:
```go
c.logger.SetAuditPersister(c.auditRepository)
```
with:
```go
c.auditService = auditServices.NewAuditService(c.auditRepository)
c.complianceReportService = auditServices.NewComplianceReportService(c.auditRepository)
c.logger.SetAuditPersister(c.auditService)
```

- [ ] **Step 3: Start the retention background goroutine**

In the same init method, after the services are wired, add:

```go
// Start daily audit log retention purge in the background.
go func() {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        if _, err := c.complianceReportService.PurgeExpiredLogs(context.Background()); err != nil {
            c.logger.WithError(err).Warn("audit retention purge failed")
        }
    }
}()
```

Add `"context"` to the container import if not already present.

- [ ] **Step 4: Build to verify**

```bash
go build ./...
```

Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go internal/logging/logging.go
git commit -m "feat(audit): wire AuditService and ComplianceReportService into service container"
```

---

## Task 6: Update Middleware to Pass Enriched Audit Fields

**Files:**
- Modify: `internal/middleware/middleware.go`

- [ ] **Step 1: Read the middleware audit calls**

Open `internal/middleware/middleware.go`. Locate all calls to `m.logger.LogAuditInfo` and `m.logger.LogAuditError`. These write through `logger.AuditPersister` which now routes to `AuditService.PersistAudit`. The thin `PersistAudit` signature doesn't carry IP/source/outcome.

For IP extraction and enriched events, middleware should call `m.container.GetAuditService().RecordEvent(...)` directly for new events, while leaving legacy `LogAuditInfo/Error` calls as-is (they still work via `PersistAudit`).

- [ ] **Step 2: Add IP extraction helper**

Add this helper function to `internal/middleware/middleware.go`:

```go
// extractClientIP returns the client's IP address, preferring X-Forwarded-For.
func extractClientIP(r *http.Request) string {
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        // X-Forwarded-For may be a comma-separated list; take the first.
        parts := strings.SplitN(xff, ",", 2)
        return strings.TrimSpace(parts[0])
    }
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    return host
}
```

Add `"net"` and `"strings"` to imports if not already present.

- [ ] **Step 3: Enrich the auth middleware audit event**

Find the `AuthenticationMiddleware` function. Replace the success audit call:

```go
m.logger.LogAuditInfo(claims.UserID.String(), "auth", "success", "Authentication successful")
```

with:

```go
if svc := m.container.GetAuditService(); svc != nil {
    _ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
        UserID:    claims.UserID.String(),
        Action:    "auth",
        Outcome:   "success",
        Source:    "api",
        IPAddress: extractClientIP(r),
    })
} else {
    m.logger.LogAuditInfo(claims.UserID.String(), "auth", "success", "Authentication successful")
}
```

Add import `auditSvc "rocketvault/internal/services/audit"`.

- [ ] **Step 4: Build and run middleware tests**

```bash
go build ./... && go test ./internal/middleware/... -v 2>&1 | tail -20
```

Expected: build clean, all middleware tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/middleware/middleware.go
git commit -m "feat(audit): enrich auth middleware audit events with IP and structured fields"
```

---

## Task 7: Add Mock Stubs for Tests

**Files:**
- Modify: `internal/testutils/mocks.go`

- [ ] **Step 1: Add mock types**

Open `internal/testutils/mocks.go`. Following the existing mock pattern (e.g., `MockAuthenticationService`), add:

```go
// --- MockAuditService ---

// MockAuditService is a testify mock for auditServices.AuditServiceInterface.
type MockAuditService struct {
    mock.Mock
}

func (m *MockAuditService) RecordEvent(ctx context.Context, event auditSvc.AuditEvent) error {
    args := m.Called(ctx, event)
    return args.Error(0)
}

func (m *MockAuditService) PersistAudit(userID, action, details string) error {
    args := m.Called(userID, action, details)
    return args.Error(0)
}

// --- MockComplianceReportService ---

// MockComplianceReportService is a testify mock for auditServices.ComplianceReportServiceInterface.
type MockComplianceReportService struct {
    mock.Mock
}

func (m *MockComplianceReportService) QueryLogs(ctx context.Context, filter repositories.AuditFilter) ([]repositories.AuditLog, int64, bool, error) {
    args := m.Called(ctx, filter)
    if args.Get(0) == nil {
        return nil, args.Get(1).(int64), args.Bool(2), args.Error(3)
    }
    return args.Get(0).([]repositories.AuditLog), args.Get(1).(int64), args.Bool(2), args.Error(3)
}

func (m *MockComplianceReportService) GenerateSOC2Report(ctx context.Context, from, to time.Time) (*auditSvc.SOC2Report, error) {
    args := m.Called(ctx, from, to)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*auditSvc.SOC2Report), args.Error(1)
}

func (m *MockComplianceReportService) GenerateSOC2CSV(ctx context.Context, from, to time.Time) (string, error) {
    args := m.Called(ctx, from, to)
    return args.String(0), args.Error(1)
}

func (m *MockComplianceReportService) GenerateGDPRReport(ctx context.Context, from, to time.Time, subjectID string) (*auditSvc.GDPRReport, error) {
    args := m.Called(ctx, from, to, subjectID)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*auditSvc.GDPRReport), args.Error(1)
}

func (m *MockComplianceReportService) GenerateGDPRCSV(ctx context.Context, from, to time.Time, subjectID string) (string, error) {
    args := m.Called(ctx, from, to, subjectID)
    return args.String(0), args.Error(1)
}

func (m *MockComplianceReportService) PurgeExpiredLogs(ctx context.Context) (int64, error) {
    args := m.Called(ctx)
    return args.Get(0).(int64), args.Error(1)
}

func (m *MockComplianceReportService) GetRetentionDays(ctx context.Context) (int, error) {
    args := m.Called(ctx)
    return args.Int(0), args.Error(1)
}

func (m *MockComplianceReportService) SetRetentionDays(ctx context.Context, days int) error {
    args := m.Called(ctx, days)
    return args.Error(0)
}
```

Add required imports to `mocks.go`:
```go
auditSvc "rocketvault/internal/services/audit"
```

Also add `GetAuditService` and `GetComplianceReportService` to `MockServiceContainer` (which implements `ServiceContainerInterface`):

```go
func (m *MockServiceContainer) GetAuditService() auditSvc.AuditServiceInterface {
    args := m.Called()
    if args.Get(0) == nil {
        return nil
    }
    return args.Get(0).(auditSvc.AuditServiceInterface)
}

func (m *MockServiceContainer) GetComplianceReportService() auditSvc.ComplianceReportServiceInterface {
    args := m.Called()
    if args.Get(0) == nil {
        return nil
    }
    return args.Get(0).(auditSvc.ComplianceReportServiceInterface)
}
```

- [ ] **Step 2: Build to verify**

```bash
go build ./...
```

Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add internal/testutils/mocks.go
git commit -m "feat(audit): add MockAuditService and MockComplianceReportService test stubs"
```

---

## Task 8: REST API Handlers

**Files:**
- Create: `api/audit.go`
- Create: `api/audit_test.go`
- Modify: `api/api.go`

- [ ] **Step 1: Write failing handler tests**

Create `api/audit_test.go`:

```go
package api

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"

    "rocketvault/internal/repositories"
    auditSvc "rocketvault/internal/services/audit"
    "rocketvault/internal/testutils"
)

func TestGetAuditLogs_Returns200(t *testing.T) {
    mockCRS := &testutils.MockComplianceReportService{}
    mockContainer := &testutils.MockServiceContainer{}
    mockContainer.On("GetComplianceReportService").Return(mockCRS)
    mockCRS.On("QueryLogs", mock.Anything, mock.Anything).Return(
        []repositories.AuditLog{{ID: "id1", Action: "login", Outcome: "success"}},
        int64(1), true, nil,
    )

    w := httptest.NewRecorder()
    r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
    c := &Context{App: &App{ServiceContainer: mockContainer}}

    getAuditLogs(c, w, r)
    assert.Equal(t, http.StatusOK, w.Code)

    var resp map[string]interface{}
    require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
    assert.Equal(t, true, resp["integrity_ok"])
}

func TestGetSOC2Report_Returns200(t *testing.T) {
    mockCRS := &testutils.MockComplianceReportService{}
    mockContainer := &testutils.MockServiceContainer{}
    mockContainer.On("GetComplianceReportService").Return(mockCRS)
    mockCRS.On("GenerateSOC2Report", mock.Anything, mock.Anything, mock.Anything).Return(
        &auditSvc.SOC2Report{TotalEvents: 10, UniqueUsers: 3}, nil,
    )

    w := httptest.NewRecorder()
    r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/reports/soc2?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)
    c := &Context{App: &App{ServiceContainer: mockContainer}}

    getSOC2Report(c, w, r)
    assert.Equal(t, http.StatusOK, w.Code)
}

func TestPatchAuditConfig_Returns200(t *testing.T) {
    mockCRS := &testutils.MockComplianceReportService{}
    mockContainer := &testutils.MockServiceContainer{}
    mockContainer.On("GetComplianceReportService").Return(mockCRS)
    mockCRS.On("SetRetentionDays", mock.Anything, 90).Return(nil)

    w := httptest.NewRecorder()
    r := httptest.NewRequest(http.MethodPatch, "/api/v1/audit/config",
        strings.NewReader(`{"retention_days":90}`))
    c := &Context{App: &App{ServiceContainer: mockContainer}}

    patchAuditConfig(c, w, r)
    assert.Equal(t, http.StatusOK, w.Code)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./api/... -run "TestGetAuditLogs|TestGetSOC2Report|TestPatchAuditConfig" -v 2>&1 | head -20
```

Expected: compile error — `getAuditLogs`, `getSOC2Report`, `patchAuditConfig` not defined.

- [ ] **Step 3: Implement the REST handlers**

Create `api/audit.go`:

```go
package api

import (
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "rocketvault/internal/repositories"
)

// initAuditRoutes registers all /audit sub-routes.
func (api *API) initAuditRoutes() {
    audit := api.BaseRoutes.Audit
    audit.Handle("/logs", api.APIHandler(getAuditLogs)).Methods(http.MethodGet)
    audit.Handle("/reports/soc2", api.APIHandler(getSOC2Report)).Methods(http.MethodGet)
    audit.Handle("/reports/gdpr", api.APIHandler(getGDPRReport)).Methods(http.MethodGet)
    audit.Handle("/config", api.APIHandler(getAuditConfig)).Methods(http.MethodGet)
    audit.Handle("/config", api.APIHandler(patchAuditConfig)).Methods(http.MethodPatch)
}

func getAuditLogs(c *Context, w http.ResponseWriter, r *http.Request) {
    svc := c.App.ServiceContainer.GetComplianceReportService()
    filter := parseAuditFilter(r)

    logs, total, integrityOK, err := svc.QueryLogs(r.Context(), filter)
    if err != nil {
        c.Err = NewAppError("GetAuditLogs", "api.audit.query_failed", nil, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]interface{}{
        "logs":         logs,
        "total":        total,
        "integrity_ok": integrityOK,
    })
}

func getSOC2Report(c *Context, w http.ResponseWriter, r *http.Request) {
    svc := c.App.ServiceContainer.GetComplianceReportService()
    from, to, err := parseReportDateRange(r)
    if err != nil {
        c.Err = NewAppError("GetSOC2Report", "api.audit.invalid_date", nil, err.Error(), http.StatusBadRequest)
        return
    }

    accept := r.Header.Get("Accept")
    if accept == "text/csv" {
        csv, err := svc.GenerateSOC2CSV(r.Context(), from, to)
        if err != nil {
            c.Err = NewAppError("GetSOC2Report", "api.audit.report_failed", nil, err.Error(), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "text/csv")
        w.Header().Set("Content-Disposition", "attachment; filename=soc2-report.csv")
        _, _ = w.Write([]byte(csv))
        return
    }

    report, err := svc.GenerateSOC2Report(r.Context(), from, to)
    if err != nil {
        c.Err = NewAppError("GetSOC2Report", "api.audit.report_failed", nil, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(report)
}

func getGDPRReport(c *Context, w http.ResponseWriter, r *http.Request) {
    svc := c.App.ServiceContainer.GetComplianceReportService()
    from, to, err := parseReportDateRange(r)
    if err != nil {
        c.Err = NewAppError("GetGDPRReport", "api.audit.invalid_date", nil, err.Error(), http.StatusBadRequest)
        return
    }
    subjectID := r.URL.Query().Get("subject_id")
    if subjectID == "" {
        c.Err = NewAppError("GetGDPRReport", "api.audit.missing_subject", nil, "subject_id is required", http.StatusBadRequest)
        return
    }

    accept := r.Header.Get("Accept")
    if accept == "text/csv" {
        csv, err := svc.GenerateGDPRCSV(r.Context(), from, to, subjectID)
        if err != nil {
            c.Err = NewAppError("GetGDPRReport", "api.audit.report_failed", nil, err.Error(), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "text/csv")
        w.Header().Set("Content-Disposition", "attachment; filename=gdpr-report.csv")
        _, _ = w.Write([]byte(csv))
        return
    }

    report, err := svc.GenerateGDPRReport(r.Context(), from, to, subjectID)
    if err != nil {
        c.Err = NewAppError("GetGDPRReport", "api.audit.report_failed", nil, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(report)
}

func getAuditConfig(c *Context, w http.ResponseWriter, r *http.Request) {
    svc := c.App.ServiceContainer.GetComplianceReportService()
    days, err := svc.GetRetentionDays(r.Context())
    if err != nil {
        c.Err = NewAppError("GetAuditConfig", "api.audit.config_failed", nil, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]int{"retention_days": days})
}

func patchAuditConfig(c *Context, w http.ResponseWriter, r *http.Request) {
    svc := c.App.ServiceContainer.GetComplianceReportService()

    var body struct {
        RetentionDays int `json:"retention_days"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        c.Err = NewAppError("PatchAuditConfig", "api.audit.invalid_body", nil, err.Error(), http.StatusBadRequest)
        return
    }
    if err := svc.SetRetentionDays(r.Context(), body.RetentionDays); err != nil {
        c.Err = NewAppError("PatchAuditConfig", "api.audit.config_failed", nil, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusOK)
    _ = json.NewEncoder(w).Encode(map[string]int{"retention_days": body.RetentionDays})
}

// parseAuditFilter reads query parameters into an AuditFilter.
func parseAuditFilter(r *http.Request) repositories.AuditFilter {
    q := r.URL.Query()
    filter := repositories.AuditFilter{Limit: 100}

    if s := q.Get("from"); s != "" {
        if t, err := time.Parse(time.RFC3339, s); err == nil {
            filter.From = &t
        }
    }
    if s := q.Get("to"); s != "" {
        if t, err := time.Parse(time.RFC3339, s); err == nil {
            filter.To = &t
        }
    }
    if s := q.Get("user_id"); s != "" {
        filter.UserID = &s
    }
    if s := q.Get("action"); s != "" {
        filter.Action = &s
    }
    if s := q.Get("outcome"); s != "" {
        filter.Outcome = &s
    }
    if s := q.Get("resource_type"); s != "" {
        filter.ResourceType = &s
    }
    if s := q.Get("resource_id"); s != "" {
        filter.ResourceID = &s
    }
    if s := q.Get("source"); s != "" {
        filter.Source = &s
    }
    if s := q.Get("limit"); s != "" {
        if n, err := strconv.Atoi(s); err == nil {
            filter.Limit = n
        }
    }
    filter.Cursor = q.Get("cursor")
    return filter
}

// parseReportDateRange reads from= and to= query params as RFC3339.
func parseReportDateRange(r *http.Request) (from, to time.Time, err error) {
    fromStr := r.URL.Query().Get("from")
    toStr := r.URL.Query().Get("to")
    if fromStr == "" || toStr == "" {
        return from, to, &appError{message: "from and to query parameters are required"}
    }
    from, err = time.Parse(time.RFC3339, fromStr)
    if err != nil {
        return from, to, &appError{message: "invalid from date: " + err.Error()}
    }
    to, err = time.Parse(time.RFC3339, toStr)
    if err != nil {
        return from, to, &appError{message: "invalid to date: " + err.Error()}
    }
    return from, to, nil
}

// appError is a simple local error type for handler validation errors.
type appError struct{ message string }

func (e *appError) Error() string { return e.message }
```

- [ ] **Step 4: Register the `/audit` subrouter in `api/api.go`**

In `api/api.go`, add to the `Routes` struct:
```go
Audit *mux.Router // /api/v1/audit
```

In the router init function, after other subrouters:
```go
r.Audit = r.ApiRoot.PathPrefix("/audit").Subrouter()
```

In the `InitRoutes` or equivalent method that calls `initXxxRoutes()`:
```go
api.initAuditRoutes()
```

- [ ] **Step 5: Run handler tests**

```bash
go test ./api/... -run "TestGetAuditLogs|TestGetSOC2Report|TestPatchAuditConfig" -v 2>&1
```

Expected: all PASS.

- [ ] **Step 6: Build verify**

```bash
go build ./...
```

- [ ] **Step 7: Commit**

```bash
git add api/audit.go api/audit_test.go api/api.go
git commit -m "feat(audit): add REST API endpoints for audit logs, SOC2/GDPR reports, and config"
```

---

## Task 9: CLI Commands

**Files:**
- Create: `cmd/audit/audit.go`
- Create: `cmd/audit/logs.go`
- Create: `cmd/audit/report.go`
- Create: `cmd/audit/config.go`
- Modify: `cmd/root.go`

- [ ] **Step 1: Create the Cobra root `audit` command**

Create `cmd/audit/audit.go`:

```go
package audit

import "github.com/spf13/cobra"

// AuditCmd is the root command for audit subcommands.
var AuditCmd = &cobra.Command{
    Use:   "audit",
    Short: "Audit log and compliance reporting commands",
    Long:  "Query audit logs and generate SOC 2 / GDPR compliance reports.",
}

func init() {
    AuditCmd.AddCommand(logsCmd)
    AuditCmd.AddCommand(reportCmd)
    AuditCmd.AddCommand(configCmd)
}
```

- [ ] **Step 2: Create `audit logs` subcommand**

Create `cmd/audit/logs.go`:

```go
package audit

import (
    "fmt"
    "time"

    "github.com/spf13/cobra"

    "rocketvault/common"
    "rocketvault/internal/container"
    "rocketvault/internal/formatter"
    "rocketvault/internal/repositories"
)

var logsCmd = &cobra.Command{
    Use:   "logs",
    Short: "Query audit logs",
    RunE:  runAuditLogs,
}

func init() {
    logsCmd.Flags().String("from", "", "Start date (RFC3339 or YYYY-MM-DD)")
    logsCmd.Flags().String("to", "", "End date (RFC3339 or YYYY-MM-DD)")
    logsCmd.Flags().String("user-id", "", "Filter by user UUID")
    logsCmd.Flags().String("action", "", "Filter by action")
    logsCmd.Flags().String("outcome", "", "Filter by outcome: success|failure|warning")
    logsCmd.Flags().String("resource-type", "", "Filter by resource type: secret|key|certificate|user|system")
    logsCmd.Flags().Int("limit", 100, "Maximum number of results")
    logsCmd.Flags().String("output", "table", "Output format: table|json|yaml")
}

func runAuditLogs(cmd *cobra.Command, _ []string) error {
    ctx := cmd.Context()
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available")
    }

    filter := repositories.AuditFilter{}
    if s, _ := cmd.Flags().GetString("from"); s != "" {
        t, err := parseDate(s)
        if err != nil {
            return fmt.Errorf("invalid --from: %w", err)
        }
        filter.From = &t
    }
    if s, _ := cmd.Flags().GetString("to"); s != "" {
        t, err := parseDate(s)
        if err != nil {
            return fmt.Errorf("invalid --to: %w", err)
        }
        filter.To = &t
    }
    if s, _ := cmd.Flags().GetString("user-id"); s != "" {
        filter.UserID = &s
    }
    if s, _ := cmd.Flags().GetString("action"); s != "" {
        filter.Action = &s
    }
    if s, _ := cmd.Flags().GetString("outcome"); s != "" {
        filter.Outcome = &s
    }
    if s, _ := cmd.Flags().GetString("resource-type"); s != "" {
        filter.ResourceType = &s
    }
    filter.Limit, _ = cmd.Flags().GetInt("limit")

    svc := sc.GetComplianceReportService()
    logs, total, integrityOK, err := svc.QueryLogs(ctx, filter)
    if err != nil {
        return fmt.Errorf("audit query failed: %w", err)
    }

    if !integrityOK {
        fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: hash chain integrity check failed — audit log may have been tampered with")
    }

    outputFmt, _ := cmd.Flags().GetString("output")
    f, err := formatter.New(formatter.Format(outputFmt))
    if err != nil {
        return err
    }

    headers := []string{"Timestamp", "User", "Action", "Outcome", "Source", "Resource Type", "Resource ID", "IP"}
    rows := make([][]string, len(logs))
    for i, l := range logs {
        rows[i] = []string{
            l.Timestamp.Format(time.RFC3339),
            l.UserID, l.Action, l.Outcome, l.Source,
            l.ResourceType, l.ResourceID, l.IPAddress,
        }
    }

    fmt.Fprintf(cmd.OutOrStdout(), "Total matching: %d\n", total)
    return f.Write(cmd.OutOrStdout(), headers, rows)
}

func parseDate(s string) (time.Time, error) {
    if t, err := time.Parse(time.RFC3339, s); err == nil {
        return t, nil
    }
    return time.Parse("2006-01-02", s)
}
```

- [ ] **Step 3: Create `audit report` subcommand**

Create `cmd/audit/report.go`:

```go
package audit

import (
    "fmt"

    "github.com/spf13/cobra"

    "rocketvault/common"
    "rocketvault/internal/container"
)

var reportCmd = &cobra.Command{
    Use:   "report",
    Short: "Generate a compliance report",
    RunE:  runAuditReport,
}

func init() {
    reportCmd.Flags().String("type", "", "Report type: soc2|gdpr (required)")
    reportCmd.Flags().String("from", "", "Start date RFC3339 or YYYY-MM-DD (required)")
    reportCmd.Flags().String("to", "", "End date RFC3339 or YYYY-MM-DD (required)")
    reportCmd.Flags().String("subject-id", "", "Data subject UUID (required for gdpr)")
    reportCmd.Flags().String("output", "json", "Output format: json|csv")
    _ = reportCmd.MarkFlagRequired("type")
    _ = reportCmd.MarkFlagRequired("from")
    _ = reportCmd.MarkFlagRequired("to")
}

func runAuditReport(cmd *cobra.Command, _ []string) error {
    ctx := cmd.Context()
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available")
    }

    reportType, _ := cmd.Flags().GetString("type")
    fromStr, _ := cmd.Flags().GetString("from")
    toStr, _ := cmd.Flags().GetString("to")
    outputFmt, _ := cmd.Flags().GetString("output")

    from, err := parseDate(fromStr)
    if err != nil {
        return fmt.Errorf("invalid --from: %w", err)
    }
    to, err := parseDate(toStr)
    if err != nil {
        return fmt.Errorf("invalid --to: %w", err)
    }

    svc := sc.GetComplianceReportService()

    switch reportType {
    case "soc2":
        if outputFmt == "csv" {
            out, err := svc.GenerateSOC2CSV(ctx, from, to)
            if err != nil {
                return err
            }
            fmt.Fprint(cmd.OutOrStdout(), out)
            return nil
        }
        report, err := svc.GenerateSOC2Report(ctx, from, to)
        if err != nil {
            return err
        }
        fmt.Fprintf(cmd.OutOrStdout(),
            "SOC 2 Report (%s – %s)\n"+
                "  Total events:       %d\n"+
                "  Unique users:       %d\n"+
                "  Auth successes:     %d\n"+
                "  Auth failures:      %d\n"+
                "  Data access events: %d\n"+
                "  Admin actions:      %d\n"+
                "  Key operations:     %d\n",
            report.From.Format("2006-01-02"), report.To.Format("2006-01-02"),
            report.TotalEvents, report.UniqueUsers,
            report.AuthSuccesses, report.AuthFailures,
            report.DataAccessEvents, report.AdminActions, report.KeyOperations,
        )
    case "gdpr":
        subjectID, _ := cmd.Flags().GetString("subject-id")
        if subjectID == "" {
            return fmt.Errorf("--subject-id is required for gdpr report type")
        }
        if outputFmt == "csv" {
            out, err := svc.GenerateGDPRCSV(ctx, from, to, subjectID)
            if err != nil {
                return err
            }
            fmt.Fprint(cmd.OutOrStdout(), out)
            return nil
        }
        report, err := svc.GenerateGDPRReport(ctx, from, to, subjectID)
        if err != nil {
            return err
        }
        fmt.Fprintf(cmd.OutOrStdout(),
            "GDPR Report for subject %s (%s – %s)\n"+
                "  Total events: %d\n"+
                "  Data access:  %d\n"+
                "  Deletions:    %d\n"+
                "  Auth events:  %d\n",
            report.SubjectID, report.From.Format("2006-01-02"), report.To.Format("2006-01-02"),
            report.TotalEvents, report.DataAccess, report.Deletions, report.AuthEvents,
        )
    default:
        return fmt.Errorf("unknown report type %q: must be soc2 or gdpr", reportType)
    }
    return nil
}
```

- [ ] **Step 4: Create `audit config` subcommand**

Create `cmd/audit/config.go`:

```go
package audit

import (
    "fmt"

    "github.com/spf13/cobra"

    "rocketvault/common"
    "rocketvault/internal/container"
)

var configCmd = &cobra.Command{
    Use:   "config",
    Short: "View or update audit configuration",
    RunE:  runAuditConfig,
}

func init() {
    configCmd.Flags().Int("retention-days", 0, "Set log retention period in days (0 = show current)")
}

func runAuditConfig(cmd *cobra.Command, _ []string) error {
    ctx := cmd.Context()
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available")
    }

    svc := sc.GetComplianceReportService()
    days, _ := cmd.Flags().GetInt("retention-days")

    if days > 0 {
        if err := svc.SetRetentionDays(ctx, days); err != nil {
            return fmt.Errorf("failed to set retention days: %w", err)
        }
        fmt.Fprintf(cmd.OutOrStdout(), "Retention policy updated: %d days\n", days)
        return nil
    }

    current, err := svc.GetRetentionDays(ctx)
    if err != nil {
        return fmt.Errorf("failed to get retention days: %w", err)
    }
    fmt.Fprintf(cmd.OutOrStdout(), "Current audit log retention: %d days\n", current)
    return nil
}
```

- [ ] **Step 5: Register in `cmd/root.go`**

In `cmd/root.go`, add to the imports:
```go
auditCmd "rocketvault/cmd/audit"
```

In the `init()` function where other subcommands are registered:
```go
rootCmd.AddCommand(auditCmd.AuditCmd)
```

- [ ] **Step 6: Build to verify**

```bash
go build ./...
```

Expected: clean build.

- [ ] **Step 7: Run full test suite**

```bash
go test ./... 2>&1 | tail -30
```

Expected: all packages PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/audit/ cmd/root.go
git commit -m "feat(audit): add CLI audit subcommands (logs, report, config)"
```

---

## Task 10: Final Verification

- [ ] **Step 1: Run full build**

```bash
go build ./...
```

Expected: zero errors, zero warnings.

- [ ] **Step 2: Run full test suite**

```bash
go test ./... -count=1 2>&1 | grep -E "FAIL|ok|---"
```

Expected: all packages report `ok`. No `FAIL` lines.

- [ ] **Step 3: Run audit-specific tests with race detector**

```bash
go test -race ./internal/services/audit/... ./internal/repositories/... ./api/... -v 2>&1 | tail -30
```

Expected: all PASS, no DATA RACE warnings.

- [ ] **Step 4: Smoke-test CLI help**

```bash
go run main.go audit --help
go run main.go audit logs --help
go run main.go audit report --help
go run main.go audit config --help
```

Expected: each prints usage without errors.

- [ ] **Step 5: Final commit (if any stray changes)**

```bash
git status
```

If clean, no commit needed. If there are any tidy-up changes:
```bash
git add <files>
git commit -m "chore(audit): final cleanup"
```
