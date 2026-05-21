# Secret Consumption Design

**Date**: 2026-05-21
**Status**: Approved
**Scope**: How backend services and web frontends consume secrets stored in RocketVault

---

## 1. Problem

Secrets are stored in RocketVault but there is no first-class Go SDK or structured integration
pattern for consuming them in application code. Developers currently have no clear path for:

- Injecting secrets into backend service config at startup
- Safely exposing non-sensitive config values to a web frontend
- Bootstrapping credentials across different deployment environments

---

## 2. Goals

- Backend services fetch secrets at startup via OAuth2 client-credentials, with no plaintext
  values on disk or in logs
- Web frontends receive only safe, non-sensitive config through a backend proxy endpoint
- Credential bootstrap works identically for env vars, config files, and platform secrets stores
  (GitHub Actions, Kubernetes, AWS)
- All new code follows the existing DDD architecture: domain types in `domain/`, services in
  `services/`, bootstrap in `bootstrap/`, API handlers in `api/`

## 3. Non-Goals

- Per-request dynamic secret injection (out of scope — can be added later for high-rotation secrets)
- A browser-side RocketVault SDK
- Secret rotation triggering app restarts (operational concern, not in this design)

---

## 4. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Credential Bootstrap                                   │
│  (env vars / config file / platform secrets store)      │
│  → VAULT_URL, VAULT_CLIENT_ID, VAULT_CLIENT_SECRET      │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  internal/vaultclient  (new Go package)                 │
│  - Priority-chain credential resolution                 │
│  - OAuth2 client-credentials token fetch + cache        │
│  - Secret fetch by name or UUID                         │
│  - Token auto-refresh (60s buffer before expiry)        │
│  - Retry via existing internal/retry package            │
└────────────────────┬────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
┌──────────────────┐   ┌─────────────────────────────────┐
│  SecretsInit-    │   │  GET /api/v1/config              │
│  ializer         │   │  (backend proxy endpoint)        │
│  (bootstrap/)    │   │  returns FrontendConfig only     │
│  maps secrets    │   │  — never raw secret values       │
│  into AppConfig  │   └─────────────────────────────────┘
└──────────────────┘
```

---

## 5. `internal/vaultclient` Package

### 5.1 Credential Resolution (priority chain)

1. Explicit `Config` struct passed at construction (for platform secrets stores — caller reads
   from AWS/GH/K8s and passes values in)
2. Environment variables: `VAULT_URL`, `VAULT_CLIENT_ID`, `VAULT_CLIENT_SECRET`
3. Viper config file: `vault_client.url`, `vault_client.client_id`, `vault_client.client_secret`

`client_secret` should never be written to the config file in plaintext. It must come from an
env var or platform secrets store in all non-local environments.

### 5.2 Public API

```go
// Construction
client, err := vaultclient.New(vaultclient.Config{...})  // explicit config
client, err := vaultclient.NewFromEnv()                   // env vars
client, err := vaultclient.NewFromViper()                 // Viper config file

// Secret access
value, err := client.Get(ctx, "secret-uuid")
// GetByName resolves name→UUID from the vault_client.secrets config mapping (no live API call)
value, err := client.GetByName(ctx, "DB_PASSWORD")
secrets, err := client.GetMany(ctx, []string{"DB_PASSWORD", "API_KEY", "JWT_SECRET"})
```

### 5.3 Token Lifecycle

- Token is fetched lazily on the first `Get` call, not at construction
- Cached in memory; refreshed 60 seconds before expiry
- Thread-safe via `sync.Mutex`
- Never persisted to disk
- Re-fetched fresh on each process start

### 5.4 Error Types

| Error | Behaviour |
|---|---|
| Network error | Retried via `internal/retry` with exponential backoff |
| 401 Unauthorized | Surfaces immediately — no retry |
| 404 Not Found | Returns typed `ErrSecretNotFound` |

### 5.5 Config File Section (`.rocketvault.yaml`)

```yaml
vault_client:
  url: "https://vault.example.com"
  client_id: "my-service-account"
  # client_secret: never here — use VAULT_CLIENT_SECRET env var
  secrets:
    - name: DB_PASSWORD
      uuid: "550e8400-e29b-41d4-a716-446655440001"
    - name: JWT_SECRET
      uuid: "550e8400-e29b-41d4-a716-446655440002"
    - name: SMTP_PASSWORD
      uuid: "550e8400-e29b-41d4-a716-446655440003"
```

---

## 6. Backend Service Integration

### 6.1 SecretsInitializer

A new `SecretsInitializer` is added to `bootstrap/` following the existing modular initializer
pattern (alongside `DatabaseInitializer`, `ServerStarter`, etc.).

The `SecretsInitializer` receives a `*vaultclient.Client` via constructor injection from the DI
container — consistent with how other initializers receive their dependencies.

```go
// bootstrap/secrets_initializer.go
type SecretsInitializer struct {
    client *vaultclient.Client
}

func (s *SecretsInitializer) Initialize(ctx context.Context, cfg *config.AppConfig) error {
    secrets, err := s.client.GetMany(ctx, []string{
        "DB_PASSWORD", "JWT_SECRET", "SMTP_PASSWORD",
    })
    if err != nil {
        return fmt.Errorf("secrets initializer: %w", err)
    }
    cfg.Database.Password = secrets["DB_PASSWORD"]
    cfg.JWT.Secret        = secrets["JWT_SECRET"]
    cfg.SMTP.Password     = secrets["SMTP_PASSWORD"]
    return nil
}
```

### 6.2 Logging Rules

- Log secret **names** and **UUIDs** freely (for traceability)
- Never log secret **values** — not even at debug level
- The structured logger must receive field names only:
  `logger.Info("fetched secret", zap.String("name", name))` — no value field

---

## 7. Frontend Proxy Endpoint

### 7.1 Route

```
GET /api/v1/config
```

Registered in `api/api.go` alongside existing routes. Protected by the existing authentication
middleware — only authenticated sessions receive config values.

### 7.2 Handler

New file `api/config.go`. Handler reads `App.FrontendConfig` (populated at startup by
`SecretsInitializer`) and serializes it. No RocketVault call at request time.

```go
type FrontendConfig struct {
    FeatureFlags map[string]bool `json:"feature_flags"`
    PublicAPIURL string          `json:"public_api_url"`
    SentryDSN    string          `json:"sentry_dsn"`
}
```

### 7.3 What Is Never Returned

Passwords, JWT secrets, private keys, TOTP secrets, database credentials, or any value that
grants access to infrastructure. Sensitive values are mapped only into internal `AppConfig`
fields and never reach `FrontendConfig`.

### 7.4 Frontend Consumption Pattern

```typescript
// Call once after login, store in app state
const config = await fetch('/api/v1/config', {
  headers: { Authorization: `Bearer ${token}` }
}).then(r => r.json());

// Read from app state for the rest of the session
```

No RocketVault SDK, credentials, or UUIDs are ever present in frontend code.

---

## 8. Credential Bootstrap per Environment

All environments resolve to the same `vaultclient.Config` struct. The source differs:

| Environment | Bootstrap method | App call |
|---|---|---|
| Local dev | `.env` file → env vars | `NewFromEnv()` |
| Docker / systemd | `EnvironmentFile=` or `env:` block | `NewFromEnv()` |
| GitHub Actions | `secrets.VAULT_CLIENT_SECRET` → step env | `NewFromEnv()` |
| Kubernetes | `envFrom: secretRef` → pod env | `NewFromEnv()` |
| AWS ECS | Secrets Manager → task def env injection | `NewFromEnv()` |
| Config file deployments | `.rocketvault.yaml` (no secret value) + env var | `NewFromViper()` |

`client_secret` is always injected at runtime. It is never written to a config file or committed
to version control.

### 8.1 CI/CD (non-Go runtimes)

The existing `scripts/rocketvault-fetch-secrets.sh` covers this path unchanged. It uses the same
OAuth2 `/oauth2/token` endpoint and the same env var convention (`VAULT_CLIENT_ID`,
`VAULT_CLIENT_SECRET`, `VAULT_SECRETS`).

---

## 9. Files to Create / Modify

| Path | Action | Notes |
|---|---|---|
| `internal/vaultclient/client.go` | Create | Core package: config resolution, token cache, Get/GetMany |
| `internal/vaultclient/errors.go` | Create | Typed errors: ErrSecretNotFound, ErrAuthFailed |
| `internal/vaultclient/client_test.go` | Create | Unit tests with mock HTTP server |
| `bootstrap/secrets_initializer.go` | Create | Follows existing initializer pattern |
| `api/config.go` | Create | GET /api/v1/config handler |
| `api/api.go` | Modify | Register config route |
| `app/options.go` | Modify | Add FrontendConfig field to App |
| `.rocketvault.yaml` | Modify | Add vault_client section (no secret value) |

---

## 10. Testing Strategy

- `vaultclient` package: unit tests with `httptest.NewServer` mocking the OAuth2 and secrets
  endpoints — no real RocketVault needed
- `SecretsInitializer`: tested with a mock `vaultclient.Client` interface
- `GET /api/v1/config`: existing API test patterns in `api/` — assert sensitive fields are absent
  from response
