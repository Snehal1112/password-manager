# Audit & Compliance Reporting — Design Spec

**Date:** 2026-05-27
**Status:** Approved
**Scope:** SOC 2 and GDPR audit trail, compliance reports, retention enforcement, tamper-evidence

---

## 1. Goal

Extend RocketVault with production-grade audit and compliance reporting capabilities:

- Structured, queryable audit event store with enriched fields
- Pre-built SOC 2 and GDPR report templates
- Configurable log retention with automated purge
- Hash-chained tamper-evidence for audit trail integrity
- REST API and CLI interfaces for operators

---

## 2. Schema Changes

### 2.1 Extend `audit_logs`

New columns added via `migrateSchema()` in `internal/db/db.go`:

| Column | Type | Default | Purpose |
|---|---|---|---|
| `resource_type` | TEXT | NULL | `secret` / `key` / `certificate` / `user` / `system` |
| `resource_id` | TEXT | NULL | UUID of the affected resource |
| `ip_address` | TEXT | NULL | Client IP extracted from HTTP request |
| `outcome` | TEXT | NULL | `success` / `failure` / `warning` |
| `source` | TEXT | NULL | `api` / `cli` / `system` |
| `prev_hash` | TEXT | NULL | SHA-256 of previous row — forms the hash chain |

Existing rows retain NULL for all new columns. No backfill required.

New indexes:
- `idx_audit_logs_outcome ON audit_logs(outcome)`
- `idx_audit_logs_resource ON audit_logs(resource_type, resource_id)`
- `idx_audit_logs_source ON audit_logs(source)`

### 2.2 New `audit_config` table

```sql
CREATE TABLE IF NOT EXISTS audit_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

Seeded at init with `retention_days = 365`. Operators can update via `PATCH /api/v1/audit/config`.

---

## 3. Architecture

### 3.1 New packages

**`internal/services/audit/`**

- `AuditServiceInterface` — replaces the thin `logging.AuditPersister` interface across the codebase.
- `AuditService` — write path: enriches events, computes hash chain (mutex-serialized), delegates to repository.
- `ComplianceReportService` — read path: query with filters, pre-built report generators, retention purge.

**`internal/repositories/audit_repository.go`** (extended)

Gains:
- `QueryAuditLogs(filter AuditFilter) ([]AuditLog, int64, error)` — paginated, cursor-based
- `DeleteBefore(cutoff time.Time) (int64, error)` — retention purge
- `GetLastHash() (string, error)` — used by write path for hash chaining

**`api/audit.go`** — REST handlers (thin, delegates to services)

**`cmd/audit/`** — Cobra subcommands (thin, delegates to services via service container)

### 3.2 Service container

`internal/container/service_container.go` gains:
- `auditService AuditServiceInterface`
- `complianceReportService ComplianceReportServiceInterface`
- `GetAuditService() AuditServiceInterface`
- `GetComplianceReportService() ComplianceReportServiceInterface`

### 3.3 Existing callers

`LogAuditInfo` / `LogAuditError` in middleware and services are updated to pass enriched fields where context is available:
- IP address: extracted from `r.RemoteAddr` / `X-Forwarded-For` in middleware
- Resource type / ID: available in route handlers via path params
- Outcome: derived from the existing `status` string (`success` → `success`, anything else → `failure`)
- Source: `api` in HTTP handlers, `cli` in Cobra commands, `system` for background jobs

---

## 4. REST API

All endpoints require authentication (existing `AuthenticationMiddleware`). Report endpoints require `admin` role.

### Audit log query

```
GET /api/v1/audit/logs
  ?from=<RFC3339>
  &to=<RFC3339>
  &user_id=<uuid>
  &action=<string>
  &outcome=success|failure|warning
  &resource_type=secret|key|certificate|user|system
  &resource_id=<uuid>
  &source=api|cli|system
  &limit=<int, default 100, max 1000>
  &cursor=<opaque pagination token>
```

Response:
```json
{
  "logs": [...],
  "total": 1234,
  "next_cursor": "...",
  "integrity_ok": true
}
```

`integrity_ok` is `false` if any hash chain break is detected in the returned page.

### Compliance reports

```
GET /api/v1/audit/reports/soc2?from=<RFC3339>&to=<RFC3339>
GET /api/v1/audit/reports/gdpr?from=<RFC3339>&to=<RFC3339>&subject_id=<uuid>
```

Accept: `application/json` (default) or `text/csv`.

SOC 2 report fields: total events, unique users, auth events (success/failure), data access events, admin actions, key operations, top actions by frequency.

GDPR report fields: all events touching a specific data subject (user), event categories, data access breakdown, deletions, exports.

### Config

```
GET  /api/v1/audit/config
PATCH /api/v1/audit/config
  Body: {"retention_days": 90}
```

---

## 5. CLI

```
rocketvault audit logs [flags]
  --from, --to       date range (RFC3339 or YYYY-MM-DD)
  --user-id          filter by user UUID
  --action           filter by action string
  --outcome          success|failure|warning
  --resource-type    secret|key|certificate|user|system
  --limit            default 100
  --output           table|json|yaml (uses existing formatter)

rocketvault audit report [flags]
  --type             soc2|gdpr (required)
  --from, --to       date range (required)
  --subject-id       for gdpr: data subject UUID
  --output           json|csv (default json)

rocketvault audit config [flags]
  --retention-days   set retention policy
```

---

## 6. Data Flow

### Write path

1. Caller invokes `AuditService.RecordEvent(ctx, AuditEvent{...})`.
2. Service acquires append mutex.
3. Calls `AuditRepository.GetLastHash()` to read the previous row's hash.
4. Computes `SHA-256(prev_hash + timestamp + user_id + action + details + resource_type + resource_id + outcome)`.
5. Calls `AuditRepository.Insert(...)` with all fields including `prev_hash`.
6. Releases mutex.
7. On any error: logs the failure, returns without error to caller — audit failures never block vault operations.

### Read path

1. Handler validates query params, constructs `AuditFilter`.
2. Calls `ComplianceReportService.QueryLogs(filter)` or `GenerateReport(reportType, filter)`.
3. For integrity check: service walks the returned page verifying each row's `prev_hash` chain.
4. Returns paginated result with `integrity_ok` flag.

### Retention

- At application startup, a background goroutine starts a daily ticker.
- On each tick: `ComplianceReportService.PurgeExpiredLogs()` reads `retention_days` from `audit_config`, calls `AuditRepository.DeleteBefore(time.Now().UTC().AddDate(0,0,-retentionDays))`.
- Purge itself is recorded as an audit event: `action=audit_purge`, `source=system`, `details="{rows_deleted: N}"`.

---

## 7. Error Handling

| Scenario | Behaviour |
|---|---|
| Audit insert fails | Log warning, return nil to caller — never block vault ops |
| Hash chain break detected on read | Return results with `integrity_ok: false`, log warning |
| Retention purge fails | Log error, retry on next daily tick |
| Invalid filter params | HTTP 400 / CLI error with clear message |
| Report generation DB error | HTTP 500 / CLI non-zero exit |
| Config update with invalid value | HTTP 400 |

---

## 8. Testing

- **`internal/services/audit/audit_service_test.go`**: hash chaining correctness, concurrent write safety, write-error swallowing, in-memory SQLite (pattern from `audit_repository_test.go`).
- **`internal/services/audit/compliance_report_service_test.go`**: SOC 2 and GDPR report generation with fixture data, CSV and JSON output, retention purge row count.
- **`internal/repositories/audit_repository_test.go`** (extended): `QueryAuditLogs` filter combinations, `DeleteBefore` correctness, `GetLastHash` on empty table.
- **`api/audit_test.go`**: HTTP handler tests for all endpoints, following `api/secrets_test.go` pattern.
- **`cmd/audit/audit_test.go`**: CLI command tests with mock service container.

---

## 9. File Map

| File | Change |
|---|---|
| `internal/db/db.go` | Add 6 columns to `audit_logs` via `migrateSchema()`, add `audit_config` table |
| `internal/repositories/audit_repository.go` | Add `AuditLog` domain struct, `AuditFilter`, `QueryAuditLogs`, `DeleteBefore`, `GetLastHash` |
| `internal/repositories/audit_repository_test.go` | Extend with read-side tests |
| `internal/services/audit/audit_service.go` | New: `AuditServiceInterface`, `AuditService` with hash chaining |
| `internal/services/audit/compliance_report_service.go` | New: `ComplianceReportServiceInterface`, `ComplianceReportService` |
| `internal/services/audit/audit_service_test.go` | New: unit tests |
| `internal/services/audit/compliance_report_service_test.go` | New: unit tests |
| `internal/container/service_container.go` | Wire `AuditService`, `ComplianceReportService`, start retention goroutine |
| `internal/logging/logging.go` | `AuditPersister` replaced by `AuditServiceInterface` |
| `internal/middleware/middleware.go` | Pass IP, outcome, source to audit events |
| `api/audit.go` | New: REST handlers |
| `api/audit_test.go` | New: handler tests |
| `api/api.go` | Register `/audit` subrouter |
| `cmd/audit/audit.go` | New: Cobra root command |
| `cmd/audit/logs.go` | New: `audit logs` subcommand |
| `cmd/audit/report.go` | New: `audit report` subcommand |
| `cmd/audit/config.go` | New: `audit config` subcommand |
| `cmd/root.go` | Register `audit` command |
| `internal/testutils/mocks.go` | Add `MockAuditService`, `MockComplianceReportService` |
