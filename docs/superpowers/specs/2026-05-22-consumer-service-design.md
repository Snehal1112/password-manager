# Consumer Service Design

**Date**: 2026-05-22
**Status**: Approved
**Scope**: A simple Go HTTP service inside the `rocketvault` repo that demonstrates
consuming secrets from a running RocketVault instance via `internal/vaultclient`.

---

## 1. Purpose

Provide a runnable end-to-end test that proves the `vaultclient` integration works:
authenticate as a service account, fetch secrets, display their load status (values
masked), and fetch `GET /api/v1/config` from RocketVault.

---

## 2. Location

`examples/consumer-service/` — part of the `rocketvault` module (no separate `go.mod`).
Run with: `go run ./examples/consumer-service/` from the repo root.

---

## 3. File Structure

```
examples/consumer-service/
├── main.go       — entry point: load config, fetch secrets, start server
├── server.go     — HTTP handlers for /healthz and /status
├── config.go     — Viper config loading with env var overrides
└── config.yaml   — example config (committed, safe placeholder values)
```

---

## 4. Configuration

### 4.1 Config File (`config.yaml`)

```yaml
vault:
  url: "http://localhost:8774"
  client_id: ""      # set here or via VAULT_CLIENT_ID env var
  secrets:
    - name: DB_PASSWORD
      uuid: ""       # fill in UUID from RocketVault
    - name: API_KEY
      uuid: ""

server:
  listen: ":9000"
```

### 4.2 Environment Variable Overrides

| Env var | Overrides |
|---|---|
| `VAULT_URL` | `vault.url` |
| `VAULT_CLIENT_ID` | `vault.client_id` |
| `VAULT_CLIENT_SECRET` | always from env — never in config file |

Priority: env var > config file. `VAULT_CLIENT_SECRET` is env-only.

---

## 5. Startup Flow

```
1. Load config.yaml via Viper; apply env var overrides
2. Build vaultclient.Client via vaultclient.New(Config{...})
   → Fatal exit if URL/ClientID/ClientSecret missing
   → Fatal exit if ErrAuthFailed (bad credentials)
3. Fetch each secret by UUID individually
   → Record {loaded: true, masked: "xxxx***"} on success
   → Record {loaded: false, error: "..."} on ErrSecretNotFound or network error
   → Non-fatal — server still starts with partial results
4. Fetch GET /api/v1/config from RocketVault via plain net/http
   → Record result on success
   → Record frontend_config_error on failure — non-fatal
5. Start HTTP server on server.listen address
6. Serve /healthz and /status from in-memory state (no vault calls at request time)
```

---

## 6. HTTP Endpoints

### `GET /healthz`

Always 200. Proves the process is alive.

```json
{"status": "ok"}
```

### `GET /status`

Returns the full in-memory startup state.

```json
{
  "vault_url": "http://localhost:8774",
  "client_id": "my-service-account",
  "secrets": {
    "DB_PASSWORD": {"loaded": true,  "masked": "my-d***"},
    "API_KEY":     {"loaded": false, "error": "vaultclient: secret not found"}
  },
  "frontend_config": {
    "feature_flags": {},
    "public_api_url": "http://localhost:8774",
    "sentry_dsn": ""
  },
  "frontend_config_error": null,
  "startup_error": null
}
```

---

## 7. Masking Rule

- Value length > 4: show first 4 chars + `***` (e.g. `"my-database-pass"` → `"my-d***"`)
- Value length ≤ 4: show `"***"` entirely
- Empty value: show `"(empty)"`
- Never log or write full secret values anywhere

---

## 8. Error Handling

| Condition | Behaviour |
|---|---|
| Missing URL / ClientID / ClientSecret | Fatal — print error, exit 1 |
| `ErrAuthFailed` on token fetch | Fatal — print error, exit 1 |
| `ErrSecretNotFound` for a secret | Non-fatal — record in status, continue |
| Network error fetching a secret | Non-fatal — record in status, continue |
| `GET /api/v1/config` unreachable | Non-fatal — `frontend_config: null`, `frontend_config_error` set |

---

## 9. Files to Create

| Path | Responsibility |
|---|---|
| `examples/consumer-service/main.go` | Entry point, startup orchestration |
| `examples/consumer-service/server.go` | `/healthz` and `/status` handlers |
| `examples/consumer-service/config.go` | Viper loading + env override |
| `examples/consumer-service/config.yaml` | Committed example config with placeholders |

---

## 10. Usage

```bash
# 1. Start RocketVault
go run main.go serve

# 2. Create a service account in RocketVault (via API or admin CLI)
# 3. Create a secret and note its UUID
# 4. Fill in config.yaml (or set env vars)

export VAULT_CLIENT_SECRET="<service-account-secret>"

# 5. Run the consumer service
go run ./examples/consumer-service/

# 6. Test
curl http://localhost:9000/healthz
curl http://localhost:9000/status | jq .
```
