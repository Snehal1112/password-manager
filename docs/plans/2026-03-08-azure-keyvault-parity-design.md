# RocketVault — Azure Key Vault Feature Parity Design

**Date:** 2026-03-08
**Status:** Approved
**Goal:** Bring RocketVault to full Azure Key Vault feature parity, natively in Go, with zero Azure dependencies.

---

## Background

RocketVault currently sits at ~65% feature parity with Azure Key Vault. Core secrets, keys, certificate management, RBAC, versioning, rotation, backup, and a REST API are all implemented. This document covers the remaining gaps and the design decisions made to close them.

---

## Decisions Summary

| Feature | Decision |
|---|---|
| HSM support | Software HSM emulation using Go's `crypto` stdlib (Argon2id + AES-256 wrapping) |
| Access control | Per-operation policies: `secrets:get`, `keys:rotate`, etc. |
| App authentication | OAuth2 client credentials (RFC 6749 §4.4) — no TOTP for service accounts |
| Soft-delete | Full AKV parity — configurable retention (7–90 days) + purge protection |
| Network security | Global IP allowlist + CIDR ranges in `.rocketvault.yaml` |
| Events | Signed webhook notifications (HMAC-SHA256, GitHub-compatible scheme) |
| Certificates | Built-in private CA — root CA, intermediate CA, CSR signing |
| Observability | Prometheus `/metrics` endpoint + pre-built Grafana dashboard JSON |

---

## Architecture Overview

Incremental layering on the existing A-grade DDD architecture. No big-bang refactor. New features ship as new services added to the existing service layer.

```
internal/services/
├── auth/              ← existing (JWT, TOTP, Password)
├── oauth2/            ← NEW: client credentials flow
├── secrets/           ← existing + soft-delete hooks
├── keys/              ← existing + soft-delete hooks + software HSM
├── certificates/      ← existing + private CA integration
├── authorization/     ← existing RBAC + NEW per-operation policies
├── softdelete/        ← NEW: recovery, purge protection, retention
├── webhook/           ← NEW: event dispatch, signing, retry
├── pki/               ← NEW: root CA, intermediate CA, cert issuance
├── metrics/           ← NEW: Prometheus collectors
└── network/           ← NEW: IP allowlist middleware
```

Cross-cutting concerns (soft-delete state check, policy enforcement, webhook trigger, audit log) are handled inside each service method — no new abstraction layer required.

---

## Feature Milestones

### Milestone 1 — Soft-Delete & Purge Protection (2–3 weeks)

**What:** When a resource is deleted it moves to a soft-deleted state. It remains recoverable for a configurable retention period (7–90 days, default 30). Purge protection prevents permanent deletion until retention expires.

**New API routes:**
```
GET    /api/v1/deleted/secrets
GET    /api/v1/deleted/keys
GET    /api/v1/deleted/certificates
POST   /api/v1/deleted/secrets/{id}/recover
POST   /api/v1/deleted/keys/{id}/recover
POST   /api/v1/deleted/certificates/{id}/recover
DELETE /api/v1/deleted/secrets/{id}         ← purge (permanent)
DELETE /api/v1/deleted/keys/{id}
DELETE /api/v1/deleted/certificates/{id}
```

**Schema changes:**
```sql
-- secrets already has deleted_at and purge_protection — extend to keys and certs
ALTER TABLE keys         ADD COLUMN deleted_at         TIMESTAMP NULL;
ALTER TABLE keys         ADD COLUMN purge_protection    BOOLEAN DEFAULT FALSE;
ALTER TABLE keys         ADD COLUMN scheduled_purge_at  TIMESTAMP NULL;
ALTER TABLE certificates ADD COLUMN deleted_at         TIMESTAMP NULL;
ALTER TABLE certificates ADD COLUMN purge_protection    BOOLEAN DEFAULT FALSE;
ALTER TABLE certificates ADD COLUMN scheduled_purge_at  TIMESTAMP NULL;
```

**Background job:** A scheduler runs daily, scanning for `scheduled_purge_at < NOW()` and permanently deleting expired soft-deleted items (unless `purge_protection = TRUE`).

**Config:**
```yaml
soft_delete:
  enabled: true
  retention_days: 30       # 7–90
  purge_protection: false  # set true to prevent admin force-purge
```

---

### Milestone 2 — Per-Operation Access Policies (2–3 weeks)

**What:** Each principal (user or service account) has an explicit allow/deny list of operations per resource type. Replaces coarse RBAC for fine-grained control.

**Operations:**
```
secrets:get    secrets:list   secrets:set    secrets:delete
secrets:backup secrets:restore secrets:purge  secrets:recover
keys:get       keys:list      keys:create    keys:delete
keys:rotate    keys:sign      keys:verify    keys:encrypt   keys:decrypt
certificates:get certificates:list certificates:create
certificates:delete certificates:import certificates:renew
```

**New API routes:**
```
POST   /api/v1/access-policies
GET    /api/v1/access-policies
GET    /api/v1/access-policies/{id}
PUT    /api/v1/access-policies/{id}
DELETE /api/v1/access-policies/{id}
GET    /api/v1/access-policies/principal/{id}
```

**Schema:**
```sql
CREATE TABLE access_policies (
    id             TEXT PRIMARY KEY,
    principal_id   TEXT NOT NULL,
    principal_type TEXT NOT NULL,   -- 'user' | 'service_account'
    resource_type  TEXT NOT NULL,   -- 'secrets' | 'keys' | 'certificates'
    operation      TEXT NOT NULL,   -- e.g. 'get' | 'delete' | 'rotate'
    effect         TEXT NOT NULL,   -- 'allow' | 'deny'
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Enforcement:** A `PolicyMiddleware` maps each incoming request to `(principal, resource_type, operation)` and queries `access_policies`. Explicit `deny` always wins over `allow`. If no policy exists, falls back to RBAC role defaults — existing users are unaffected.

---

### Milestone 3 — OAuth2 / Service Accounts (2–3 weeks)

**What:** Machine-to-machine authentication without TOTP. Applications authenticate with `client_id` + `client_secret` and receive a short-lived JWT. Service accounts are subject to access policies from Milestone 2.

**Flow (RFC 6749 §4.4 client credentials):**
```
POST /api/v1/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<id>&client_secret=<secret>

→ { "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 1800 }
```

**New API routes:**
```
POST   /api/v1/oauth2/token
POST   /api/v1/service-accounts
GET    /api/v1/service-accounts
GET    /api/v1/service-accounts/{id}
DELETE /api/v1/service-accounts/{id}
POST   /api/v1/service-accounts/{id}/rotate
```

**Schema:**
```sql
CREATE TABLE oauth2_clients (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    client_secret TEXT NOT NULL,       -- bcrypt hashed
    description   TEXT,
    enabled       BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP NULL
);
```

**Token config:**
```yaml
oauth2:
  token_expiry: 30m      # 5m–24h
  issuer: "rocketvault"
```

---

### Milestone 4 — Software HSM (1–2 weeks)

**What:** Private keys never leave an HSM boundary. A master wrapping key (AES-256-GCM) is derived from a configurable HSM passphrase using Argon2id. All private keys are wrapped before storage. Crypto operations (sign, verify, encrypt, decrypt) happen in-memory only.

**Implementation:**
- `internal/services/keys/hsm.go` — wrapping key derivation + wrap/unwrap operations
- `internal/services/keys/key_service.go` — sign/verify/encrypt/decrypt methods added
- `key_material` column stores encrypted (wrapped) private key blob only — raw key never persisted

**New operations exposed via API:**
```
POST /api/v1/keys/{id}/sign     → Sign data with private key
POST /api/v1/keys/{id}/verify   → Verify signature with public key
POST /api/v1/keys/{id}/encrypt  → Encrypt data with public key
POST /api/v1/keys/{id}/decrypt  → Decrypt data with private key
```

**Config:**
```yaml
hsm:
  enabled: true
  passphrase: "your-hsm-passphrase"   # stored in env var in production
  argon2_time: 3
  argon2_memory: 65536
```

---

### Milestone 5 — Private CA & Certificate Authority (2–3 weeks)

**What:** RocketVault acts as a full internal CA. Generates root CAs and intermediate CAs, signs CSRs to issue certificates. CA private keys are HSM-protected (Milestone 4).

**Implementation:** Uses Go stdlib `crypto/x509`, `crypto/x509/pkix`, `crypto/rand` — no external CA library.

**New API routes:**
```
POST   /api/v1/ca/roots                  Create root CA
GET    /api/v1/ca/roots                  List root CAs
GET    /api/v1/ca/roots/{id}/cert        Download root CA PEM (public)
POST   /api/v1/ca/intermediates          Create intermediate CA (signed by root)
GET    /api/v1/ca/intermediates          List intermediate CAs
POST   /api/v1/ca/issue                  Issue certificate from CSR
```

**Schema:**
```sql
CREATE TABLE ca_certificates (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,          -- 'root' | 'intermediate'
    parent_id   TEXT REFERENCES ca_certificates(id),
    certificate TEXT NOT NULL,          -- PEM public cert
    private_key TEXT NOT NULL,          -- HSM-wrapped private key
    not_before  TIMESTAMP NOT NULL,
    not_after   TIMESTAMP NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### Milestone 6 — Webhook Event System (1–2 weeks)

**What:** HTTP POST notifications when significant events occur. Payloads signed with HMAC-SHA256 (GitHub-compatible). Failed deliveries retried with exponential backoff.

**Event types:**
```
secret.expiring          secret.rotated         secret.purged
key.rotated              key.expiring           key.purged
certificate.expiring     certificate.renewed    certificate.purged
auth.failed              policy.violated        backup.completed
```

**New API routes:**
```
POST   /api/v1/webhooks
GET    /api/v1/webhooks
GET    /api/v1/webhooks/{id}
PUT    /api/v1/webhooks/{id}
DELETE /api/v1/webhooks/{id}
GET    /api/v1/webhooks/{id}/deliveries
POST   /api/v1/webhooks/{id}/test
```

**Payload format:**
```json
{
  "id": "evt_01J...",
  "type": "secret.expiring",
  "timestamp": "2026-03-08T12:00:00Z",
  "data": { "secret_id": "...", "name": "db-password", "expires_at": "..." }
}
```

**Signature header:** `X-RocketVault-Signature: sha256=<hmac-hex>`

**Schema:**
```sql
CREATE TABLE webhook_endpoints (
    id          TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL,
    event_types TEXT NOT NULL,          -- JSON array
    enabled     BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE webhook_deliveries (
    id           TEXT PRIMARY KEY,
    webhook_id   TEXT REFERENCES webhook_endpoints(id),
    event_type   TEXT NOT NULL,
    payload      TEXT NOT NULL,
    status       TEXT NOT NULL,         -- 'pending'|'delivered'|'failed'
    attempts     INTEGER DEFAULT 0,
    delivered_at TIMESTAMP NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### Milestone 7 — Network Security / IP Allowlist (1 week)

**What:** Server-wide IP allowlist enforced before authentication. Requests from unlisted IPs receive `403 Forbidden` immediately.

**Middleware:** `internal/services/network/allowlist_middleware.go` — runs first in the middleware chain, checks `r.RemoteAddr` against configured CIDR ranges.

**Config:**
```yaml
network:
  ip_allowlist:
    enabled: true
    allow:
      - "127.0.0.1/32"
      - "10.0.0.0/8"
      - "192.168.1.0/24"
```

**Hot reload:** Allowlist is re-read from config on `SIGHUP` — no restart needed.

---

### Milestone 8 — Prometheus Metrics & Grafana Dashboard (1 week)

**What:** Standard Prometheus scrape endpoint. Pre-built Grafana dashboard shipped in repo.

**Endpoint:** `GET /metrics` (no `/api/v1` prefix — standard Prometheus convention)

**Metrics:**
```
rocketvault_requests_total{resource_type, operation, status_code}
rocketvault_request_duration_seconds{resource_type, operation}
rocketvault_secrets_total{status}           -- active | soft_deleted
rocketvault_keys_total{status}
rocketvault_certificates_total{status}
rocketvault_auth_failures_total{reason}
rocketvault_webhook_deliveries_total{status}
rocketvault_policy_violations_total
rocketvault_hsm_operations_total{operation}
```

**Files:**
- `internal/services/metrics/prometheus.go` — collector registration
- `internal/middleware/metrics_middleware.go` — request instrumentation
- `grafana/rocketvault-dashboard.json` — importable dashboard

---

## No Changes To

- `internal/db/migrations/migration_runner.go`
- `bootstrap/` package
- `config/` package (only extended, not changed)
- Any existing test files

---

## Final API Surface (post all milestones)

- Existing: **29 routes**
- New: **~35 routes**
- **Total: ~64 routes** — comparable to Azure Key Vault REST API

---

## Technology Stack (all Go stdlib or existing dependencies)

| Feature | Library |
|---|---|
| Software HSM | `crypto/aes`, `crypto/rand`, `golang.org/x/crypto/argon2` |
| Private CA | `crypto/x509`, `crypto/x509/pkix` |
| OAuth2 tokens | `github.com/golang-jwt/jwt` (already used) |
| Webhook signing | `crypto/hmac`, `crypto/sha256` |
| Prometheus | `github.com/prometheus/client_golang` |
| IP allowlist | `net` stdlib |

**Zero new Azure dependencies. Zero new cloud dependencies.**
