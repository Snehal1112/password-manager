# Milestone 3 — OAuth2 / Service Accounts

**Date:** 2026-03-09
**Branch:** v-4.0.0
**Design ref:** docs/plans/2026-03-08-azure-keyvault-parity-design.md §Milestone 3
**Status:** In progress

---

## Goal

Enable machine-to-machine authentication without TOTP.
Applications authenticate with `client_id` + `client_secret` (bcrypt-hashed) and receive a short-lived JWT using the RFC 6749 §4.4 client credentials flow.
Service accounts are first-class principals that slot into the existing `access_policies` table (`principal_type = 'service_account'`).

---

## Architecture Decisions

- **Token issuing:** re-uses `JWTService.GenerateToken(id, name, "service_account")` — same JWT structure, existing `AuthenticationMiddleware` validates it unchanged.
- **Secret storage:** bcrypt-hashed via `PasswordService.HashPassword` — same pattern as user passwords.
- **No TOTP:** service accounts are not 2FA-capable by design.
- **Token endpoint NOT behind auth middleware:** `/api/v1/oauth2/token` is a public route (mirrors the existing `/api/v1/users/login` public exemption in `AuthenticationMiddleware`).
- **Rotation:** generates a new `client_secret`, bcrypt-hashes it, stores it, returns plain text once.
- **RBAC:** role `"service_account"` must be added to `RBACService` permission map.

---

## Files To Create

| File | Purpose |
|---|---|
| `internal/db/migrations/20260309000001_add_oauth2_clients.sql` | DDL for `oauth2_clients` table |
| `internal/domain/oauth2_client.go` | `OAuth2Client` domain type |
| `internal/repositories/oauth2_client_repository.go` | CRUD + `FindByClientID` |
| `internal/repositories/oauth2_client_repository_test.go` | 5 tests |
| `internal/services/oauth2/oauth2_service.go` | `OAuth2Service` interface + impl |
| `internal/services/oauth2/oauth2_service_test.go` | 6 tests |
| `api/oauth2.go` | HTTP handlers |

## Files To Modify

| File | Change |
|---|---|
| `internal/db/db.go` | Add `oauth2_clients` CREATE TABLE + index to `createOptimizedSchema` |
| `internal/container/service_container.go` | Add repo + service fields, getters, interface entries |
| `cmd/testutils/test_utils.go` | Add nil-stub getters for new interface methods |
| `internal/middleware/middleware.go` | Add `/oauth2/token` to public-path whitelist |
| `internal/middleware/middleware.go` | Add `"service_account"` role exemption to `Container` interface (no change needed — ValidateEndpointAccess handles it) |
| `internal/services/authorization/rbac_service.go` | Add `"service_account"` role with full policy permissions |
| `api/api.go` | Register `OAuth2` subrouter + `InitOAuth2` |
| `.rocketvault.yaml` | Add `oauth2:` config block |

---

## Tasks

### Task 1 — DB Migration: oauth2_clients table

**File:** `internal/db/migrations/20260309000001_add_oauth2_clients.sql`

```sql
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,          -- bcrypt hashed
    description   TEXT,
    enabled       BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_name ON oauth2_clients(name);
```

Also update `createOptimizedSchema` in `internal/db/db.go` (append before closing backtick).

**Commit:** `feat(db): add oauth2_clients table — Milestone 3`

---

### Task 2 — Domain Type

**File:** `internal/domain/oauth2_client.go`

```go
type OAuth2Client struct {
    ID           uuid.UUID
    Name         string
    ClientSecret string    // bcrypt hash when stored; plain text on creation/rotation response
    Description  string
    Enabled      bool
    CreatedAt    time.Time
    ExpiresAt    *time.Time
}
```

**Commit:** `feat(domain): add OAuth2Client domain type`

---

### Task 3 — Repository TDD (RED → GREEN)

**Interface:**
```go
type OAuth2ClientRepositoryInterface interface {
    Create(ctx, client) error
    GetByID(ctx, id) (*OAuth2Client, error)
    FindByClientID(ctx, clientID string) (*OAuth2Client, error)  // lookup by name (client_id in RFC terms)
    List(ctx) ([]*OAuth2Client, error)
    Update(ctx, client) error
    Delete(ctx, id) error
}
```

**5 tests:** Create+Get, FindByClientID, List, Update, Delete — in-memory SQLite.

**Commit:** `feat(repositories): add OAuth2ClientRepository with TDD`

---

### Task 4 — Service TDD (RED → GREEN)

**Interface:**
```go
type OAuth2Service interface {
    // IssueToken validates credentials and returns a signed JWT.
    IssueToken(ctx, clientID, clientSecret string) (*TokenResponse, error)
    // CreateClient registers a new service account, returns plain-text secret once.
    CreateClient(ctx, name, description string) (*OAuth2Client, string, error)
    GetClient(ctx, id uuid.UUID) (*OAuth2Client, error)
    ListClients(ctx) ([]*OAuth2Client, error)
    // RotateSecret generates a new secret, returns plain-text once.
    RotateSecret(ctx, id uuid.UUID) (string, error)
    DeleteClient(ctx, id uuid.UUID) error
}

type TokenResponse struct {
    AccessToken string `json:"access_token"`
    TokenType   string `json:"token_type"`   // "Bearer"
    ExpiresIn   int    `json:"expires_in"`   // seconds
}
```

**Business logic for `IssueToken`:**
1. `FindByClientID(name)` — name serves as `client_id`
2. Check `Enabled` and `ExpiresAt`
3. `PasswordService.ValidatePassword(secret, hash)` — bcrypt compare
4. `JWTService.GenerateToken(client.ID, client.Name, "service_account")`
5. Return `TokenResponse`

**6 tests (mockRepo + mockJWT + mockPassword):**
- IssueToken_Success
- IssueToken_InvalidSecret
- IssueToken_ClientNotFound
- IssueToken_DisabledClient
- CreateClient_HashesSecret
- RotateSecret_ReturnsPlainText

**Commit:** `feat(oauth2): add OAuth2Service with IssueToken TDD`

---

### Task 5 — Wire into ServiceContainer

Add to `ServiceContainerInterface`:
```go
GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface
GetOAuth2Service() oauth2Services.OAuth2Service
```

Initialization (after `accessPolicyService`):
```go
c.oauth2ClientRepository = repositories.NewOAuth2ClientRepository(c.db)
c.oauth2Service = oauth2Services.NewOAuth2Service(oauth2Services.OAuth2Config{
    ClientRepo:      c.oauth2ClientRepository,
    PasswordService: c.passwordService,
    JWTService:      c.jwtService,
    TokenExpiry:     viper.GetDuration("oauth2.token_expiry"),
    Issuer:          viper.GetString("oauth2.issuer"),
})
```

Also add nil-stub getters to `cmd/testutils/test_utils.go::MockServiceContainer`.

**Commit:** `feat(container): wire OAuth2ClientRepository and OAuth2Service`

---

### Task 6 — Middleware: public route + RBAC role

**File:** `internal/middleware/middleware.go` — `AuthenticationMiddleware`

The existing middleware has a public-path check. Add `/oauth2/token` to that whitelist.

**File:** `internal/services/authorization/rbac_service.go`

Add `"service_account"` role entry with appropriate permissions (all policy-managed operations pass through to `access_policies`; for safety default to read-only RBAC until access policies are set).

**Commit:** `feat(middleware): allow service_account role + public /oauth2/token route`

---

### Task 7 — API handlers + routes

**File:** `api/oauth2.go` — 6 handlers:
- `tokenHandler` — POST /oauth2/token (public, form-encoded)
- `createServiceAccount` — POST /service-accounts
- `listServiceAccounts` — GET /service-accounts
- `getServiceAccount` — GET /service-accounts/{id}
- `deleteServiceAccount` — DELETE /service-accounts/{id}
- `rotateServiceAccountSecret` — POST /service-accounts/{id}/rotate

**File:** `api/api.go` — register two subrouters:
- `api.BaseRoutes["OAuth2"]` prefix `/oauth2` (NOT authenticated — public)
- `api.BaseRoutes["ServiceAccounts"]` prefix `/service-accounts` (authenticated)

**Commit:** `feat(api): add OAuth2 token endpoint and service account CRUD`

---

### Task 8 — Config + full verification + push

Add to `.rocketvault.yaml`:
```yaml
oauth2:
  token_expiry: "30m"
  issuer: "rocketvault"
```

Verification:
```bash
go test ./... -count=1 -race
go build ./...
git push origin v-4.0.0
```

**Commit:** `chore(config): add oauth2 config block`

---

## Dependency Map

```
Task 1 (DB) → Task 3 (Repo)
Task 2 (Domain) → Task 3 (Repo) → Task 4 (Service) → Task 5 (Container)
Task 5 → Task 6 → Task 7 → Task 8
```

Tasks 1 + 2 can be done in parallel.
Tasks 3 + 4 must complete before Task 5.
Tasks 6 + 7 can be done in parallel after Task 5.

