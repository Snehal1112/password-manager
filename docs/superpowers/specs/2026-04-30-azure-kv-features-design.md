# RocketVault — Azure Key Vault Feature Parity: Design Spec

**Date:** 2026-04-30
**Status:** Approved
**Approach:** Layered delivery — Content Types → Key Wrapping → Certificate Auto-Renewal

---

## Overview

Three new features that close the gap between RocketVault and Azure Key Vault:

1. **Secret Content Types** — media-type metadata on secrets (`contentType` in AKV)
2. **Key Wrapping / Unwrapping** — envelope encryption via vault keys (`wrapKey`/`unwrapKey` in AKV)
3. **Certificate Auto-Renewal** — scheduler-driven renewal with per-cert opt-in/opt-out flag (AKV `lifetime_action`)

All three follow the existing DDD architecture: domain types in `internal/domain/`, business logic in `internal/services/`, data access in `internal/repositories/`, HTTP in `api/`, CLI in `cmd/`.

---

## Feature 1 — Secret Content Types

### Purpose

Let callers declare the media type of a secret value so consumers know how to parse it. Mirrors Azure KV's `contentType` attribute exactly.

### Domain

Add `ContentType string` to `domain.Secret`. Empty string means unset (backwards compatible). No enum in the domain — validation is at the service boundary.

```go
// internal/domain/secret.go
ContentType string `json:"content_type,omitempty"`
```

### Allowlist (service boundary)

Validated in `SecretService` before persist. Unknown values are rejected with a 400.

```
text/plain
application/json
application/xml
application/x-pem-file
application/x-pkcs12
application/octet-stream
```

Empty string is always accepted (unset).

### Schema

Two changes required:

**`createOptimizedSchema`** — add `content_type TEXT NOT NULL DEFAULT ''` to the `CREATE TABLE secrets` statement.

**`migrateSchema`** — add:
```sql
ALTER TABLE secrets ADD COLUMN content_type TEXT NOT NULL DEFAULT '';
```
Also fix known bug B1 in the same migration pass:
```sql
ALTER TABLE secrets ADD COLUMN deleted_at DATETIME;
ALTER TABLE secrets ADD COLUMN purge_protection BOOLEAN NOT NULL DEFAULT FALSE;
```

### Service

`CreateSecretRequest` and `UpdateSecretRequest` gain:
```go
ContentType string `json:"content_type,omitempty"`
```

`SecretService.CreateSecret` and `UpdateSecret` validate `ContentType` against the allowlist before delegating to the repository.

### API

- `POST /secrets` — accepts `content_type` in request body
- `PUT /secrets/{id}` — accepts `content_type` in request body
- `GET /secrets/{id}` — includes `content_type` in response

### CLI

`cmd/secrets/create.go` and `cmd/secrets/update.go` gain:
```
--content-type string   Media type of the secret value (e.g. application/json)
```

### Error cases

| Condition | Response |
|---|---|
| Unknown content type value | 400 Bad Request |
| Missing (empty) | Accepted, stored as `""` |

---

## Feature 2 — Key Wrapping / Unwrapping

### Purpose

Use a vault RSA key (the KEK — key encryption key) to wrap (encrypt) arbitrary key material (the DEK — data encryption key), and later unwrap it. This is the standard envelope encryption pattern. Mirrors Azure KV's `wrapKey` / `unwrapKey` operations.

### Algorithm

RSA-OAEP with SHA-256. This is the industry standard for key wrapping and is already partially supported in the existing `CryptoService` RSA path. ECDH-ES wrap is deferred.

### Domain

No domain changes. The operation is stateless — the vault key is loaded by ID, the key material arrives in the request, the result leaves in the response. Nothing new is persisted.

### Service

Extend `CryptoServiceInterface` in `internal/services/keys/crypto_service.go`:

```go
WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error)
UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error)
```

**Request / result types:**

```go
type WrapKeyRequest struct {
    KeyID        uuid.UUID // vault KEK
    UserID       uuid.UUID // for access control + audit
    PlaintextKey []byte    // raw key material to wrap
    Algorithm    string    // defaults to "RSA-OAEP"
}

type WrapKeyResult struct {
    WrappedKey []byte
    Algorithm  string
}

type UnwrapKeyRequest struct {
    KeyID      uuid.UUID
    UserID     uuid.UUID
    WrappedKey []byte
    Algorithm  string
}

type UnwrapKeyResult struct {
    PlaintextKey []byte
    Algorithm    string
}
```

**Implementation:** Load and decrypt the vault private key (same pattern as `Sign` and `Decrypt`), then apply RSA-OAEP wrap/unwrap. Emit audit log entries on success and failure via `logger.LogAuditInfo` / `logger.LogAuditError`.

### Access control

Reuse the existing `ValidateKeyAccess` check. Only the key owner or an admin may wrap/unwrap with a given vault key.

### API

Two new routes registered in `api/keys.go`:

```
POST /keys/{id}/wrap    — wraps caller-supplied key material with vault key {id}
POST /keys/{id}/unwrap  — unwraps previously wrapped key material with vault key {id}
```

Both require an authenticated session. Request/response bodies are JSON. Key bytes are base64-encoded strings in JSON to avoid binary transport issues.

**Wrap request body:**
```json
{ "plaintext_key": "<base64>", "algorithm": "RSA-OAEP" }
```

**Wrap response body:**
```json
{ "wrapped_key": "<base64>", "algorithm": "RSA-OAEP" }
```

**Unwrap request/response:** same shape, field names swapped (`wrapped_key` in, `plaintext_key` out).

### CLI

Two new subcommands under `cmd/keys/`:

```
rocketvault keys wrap   --key-id <uuid> --key-material <base64>
rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64>
```

Output is base64-encoded to stdout.

### Error cases

| Condition | Response |
|---|---|
| Unsupported algorithm | 400 Bad Request |
| Key not found | 404 Not Found |
| Access denied | 403 Forbidden |
| RSA operation fails | 500 Internal Server Error |
| Malformed base64 input | 400 Bad Request |

---

## Feature 3 — Certificate Auto-Renewal

### Purpose

Certificates gain an `auto_renew` flag. A daily background scheduler inspects all certificates, finds those nearing expiry within their configured `renewal_days` window, and either renews them automatically (if `auto_renew = true`) or emits a structured audit-log warning (if `auto_renew = false`). Mirrors Azure KV's `lifetime_action` model.

### Domain

Add three fields to `domain.Certificate`:

```go
ExpiresAt   *time.Time `json:"expires_at,omitempty"` // read-only, from X.509 NotAfter
AutoRenew   bool       `json:"auto_renew"`            // default false
RenewalDays int        `json:"renewal_days"`          // default 30
```

`ExpiresAt` is populated automatically on create and renew by parsing the X.509 `NotAfter` field from the PEM certificate. It is never accepted from API callers — only written by the service layer.

### Schema

**`createOptimizedSchema`** — add to `CREATE TABLE certificates`:
```sql
expires_at   DATETIME,
auto_renew   BOOLEAN NOT NULL DEFAULT FALSE,
renewal_days INTEGER NOT NULL DEFAULT 30
```

**`migrateSchema`** — add:
```sql
ALTER TABLE certificates ADD COLUMN expires_at DATETIME;
ALTER TABLE certificates ADD COLUMN auto_renew BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE certificates ADD COLUMN renewal_days INTEGER NOT NULL DEFAULT 30;
```

### Service — CertificateRenewalService

New file: `internal/services/certificates/renewal_service.go`

```go
type CertificateRenewalService interface {
    CheckAndRenewCertificates(ctx context.Context) (renewed int, warned int, err error)
}
```

**Logic:**
1. List all users via `UserRepository.List`.
2. For each user, call `CertificateRepository.ListByUser`.
3. For each certificate where `ExpiresAt` is within `RenewalDays` days from now:
   - If `AutoRenew = true`: call `CertificateService.RenewCertificate` with the same `ValidityDays` as the original cert's lifetime (derived from `ExpiresAt - CreatedAt`). Increment `renewed`.
   - If `AutoRenew = false`: emit `logger.LogAuditInfo` with `action = "cert_expiry_warning"`. Increment `warned`.
4. Return counts.

### Scheduler — CertificateRenewalScheduler

New file: `internal/services/certificates/renewal_scheduler.go`

Mirrors `internal/services/softdelete/purge_scheduler.go` exactly:
- `Start(ctx)` launches a `time.Ticker` (interval configurable, default 24h)
- `Stop()` closes the stop channel and waits for the goroutine
- The tick handler calls `CheckAndRenewCertificates`

Started in `bootstrap` alongside the purge scheduler, wired via the service container.

### API

- `POST /certificates` — accepts `auto_renew` (bool), `renewal_days` (int) in request body
- `PUT /certificates/{id}` — accepts `auto_renew`, `renewal_days`
- `GET /certificates/{id}` — includes `expires_at`, `auto_renew`, `renewal_days` in response

`expires_at` is always read-only in API responses; any value sent by callers is ignored.

### CLI

`cmd/certificates/create.go` and `cmd/certificates/update.go` gain:
```
--auto-renew          Enable automatic renewal before expiry (default: false)
--renewal-days int    Days before expiry to trigger renewal (default: 30)
```

### Error cases

| Condition | Behaviour |
|---|---|
| Renewal fails for one cert | Log error, continue processing remaining certs |
| X.509 parse fails on create | Return 500, do not persist |
| `renewal_days <= 0` | Reject with 400 at service boundary |
| Certificate already expired | Log warning, skip renewal attempt |

---

## Implementation Order

1. **Content Types** — schema migration (fixes B1 too), domain, service validation, API, CLI. No new files.
2. **Key Wrapping** — two new methods on `CryptoService`, two new API routes, two new CLI subcommands. No schema change.
3. **Certificate Auto-Renewal** — domain + schema, `CertificateRenewalService`, `CertificateRenewalScheduler`, API, CLI, bootstrap wiring.

---

## Files Touched (summary)

| File | Change |
|---|---|
| `internal/domain/secret.go` | Add `ContentType` |
| `internal/domain/certificate.go` | Add `ExpiresAt`, `AutoRenew`, `RenewalDays` |
| `internal/db/db.go` | Schema + migration for secrets (B1 fix + content_type) and certificates |
| `internal/services/secrets/secret_service.go` | Validate + persist `ContentType` |
| `internal/services/keys/crypto_service.go` | Add `WrapKey`, `UnwrapKey` methods + types |
| `internal/services/certificates/certificate_service.go` | Populate `ExpiresAt` from X.509 on create/renew |
| `internal/services/certificates/renewal_service.go` | New — `CertificateRenewalService` |
| `internal/services/certificates/renewal_scheduler.go` | New — `CertificateRenewalScheduler` |
| `internal/container/service_container.go` | Wire `CertificateRenewalService` + start scheduler |
| `api/secrets.go` | Accept + return `content_type` |
| `api/keys.go` | Add `/wrap` and `/unwrap` routes |
| `api/certificates.go` | New — HTTP handlers for certificates (currently CLI-only); accept `auto_renew`, `renewal_days`; return `expires_at` |
| `cmd/secrets/create.go`, `update.go` | Add `--content-type` flag |
| `cmd/keys/wrap.go` | New — wrap subcommand |
| `cmd/keys/unwrap.go` | New — unwrap subcommand |
| `cmd/certificates/create.go`, `update.go` | Add `--auto-renew`, `--renewal-days` flags |
| `bootstrap/` | Start `CertificateRenewalScheduler` |

---

## Out of Scope

- ECDH-ES key wrapping
- Email/webhook notifications for cert expiry warnings (log-only for now)
- Secret content type enforcement (vault does not validate that the value matches the declared type)
- Managed identities / workload identity
- Key import (BYOK)
