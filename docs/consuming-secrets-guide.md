# Consuming RocketVault Secrets in Your Application

This guide walks through the complete process of integrating your application with a
running RocketVault instance — from creating a service account to fetching secrets at
startup and verifying the integration works.

---

## Mental Model

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│   RocketVault Server        │        │   Your Application           │
│   :8774                     │        │   (Go service, CI script,    │
│                             │◄───────│    any HTTP client)          │
│   Stores secrets            │        │                              │
│   Issues OAuth2 tokens      │        │   1. Authenticate (OAuth2)   │
│   Enforces access policies  │        │   2. Fetch secrets by UUID   │
│                             │        │   3. Use values at runtime   │
└─────────────────────────────┘        └──────────────────────────────┘
```

**Key rules:**
- Service accounts are **read-only consumers** — admins create secrets and grant access via access policies (Azure Key Vault model).
- `client_id` in OAuth2 is the service account **name**, not its UUID.
- `VAULT_CLIENT_SECRET` must always come from an environment variable — never a config file.
- RocketVault's own `.rocketvault.yaml` must have `vault_client.client_id = ""` — the server never calls itself.

---

## Prerequisites

- RocketVault server running: `./rocketvault serve`
- Admin credentials configured (username `admin`, password `admin123`, TOTP set up)
- `curl` and `jq` installed

---

## Step 1: Create a Service Account

A service account is an OAuth2 client identity for your application. You create it once
and store the credentials securely.

### 1a. Get an admin JWT

```bash
# Replace <totp> with the current 6-digit code from your authenticator app
ADMIN_JWT=$(curl -s -X POST http://localhost:8774/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"<totp>"}' \
  | jq -r '.token')

echo "JWT set: ${ADMIN_JWT:+yes}"
```

### 1b. Create the service account

```bash
SA=$(curl -s -X POST http://localhost:8774/api/v1/service-accounts \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-app","description":"My application service account"}')

SA_NAME=$(echo $SA | jq -r '.name')
SA_SECRET=$(echo $SA | jq -r '.client_secret')

echo "Service account name:   $SA_NAME"
echo "Service account secret: ${SA_SECRET:0:8}..."
```

> **Important:** The `client_secret` is shown **only once** at creation. Save it
> immediately. If you lose it, rotate it via `POST /api/v1/service-accounts/{id}/rotate`.

### 1c. Export the secret as an environment variable

```bash
export VAULT_CLIENT_SECRET="$SA_SECRET"
```

In production, inject this via your deployment platform (Docker env, Kubernetes Secret,
GitHub Actions secret, AWS Secrets Manager) — never write it to a file.

---

## Step 2: Create Secrets and Grant Access to the Service Account

Service accounts are **read-only consumers** (Azure Key Vault model). An admin creates
the secrets and then grants the service account access via an access policy.

### 2a. Create secrets as admin

```bash
# Create DB_PASSWORD secret (using the admin JWT from Step 1a)
DB_UUID=$(curl -s -X POST http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"DB_PASSWORD","value":"your-database-password"}' \
  | jq -r '.id')

echo "DB_PASSWORD UUID: $DB_UUID"

# Create API_KEY secret
API_UUID=$(curl -s -X POST http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"API_KEY","value":"your-api-key"}' \
  | jq -r '.id')

echo "API_KEY UUID: $API_UUID"
```

### 2b. Grant the service account read access via access policies

```bash
# Get the service account ID
SA_ID=$(echo $SA | jq -r '.id')

# Grant "get" permission on secrets
curl -s -X POST http://localhost:8774/api/v1/access-policies \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"principal_id\":\"$SA_ID\",\"principal_type\":\"service_account\",\"resource_type\":\"secrets\",\"operation\":\"get\",\"effect\":\"allow\"}"

# Grant "list" permission on secrets
curl -s -X POST http://localhost:8774/api/v1/access-policies \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"principal_id\":\"$SA_ID\",\"principal_type\":\"service_account\",\"resource_type\":\"secrets\",\"operation\":\"list\",\"effect\":\"allow\"}"
```

### 2c. Get a service account token

```bash
SA_TOKEN=$(curl -s -X POST http://localhost:8774/api/v1/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=my-app" \
  --data-urlencode "client_secret=$VAULT_CLIENT_SECRET" \
  | jq -r '.access_token')

echo "Token set: ${SA_TOKEN:+yes}"
```

> **Note the UUIDs** — you need them in your application config. The UUID is the stable
> identifier for the secret. The name is human-readable only.

---

## Step 3: Configure Your Application

### Option A — Go application using the `vaultclient` package

The `internal/vaultclient` package is part of the `rocketvault` module. If your app is
a separate module, copy the package or vendor it.

**Config file (`config.yaml`):**

```yaml
vault:
  url: "http://localhost:8774"
  client_id: "my-app"            # service account NAME (not UUID)
  secrets:
    - name: DB_PASSWORD
      uuid: "paste-uuid-from-step-2b-here"
    - name: API_KEY
      uuid: "paste-uuid-from-step-2b-here"

server:
  listen: ":9000"
```

**Environment variable (never in the config file):**

```bash
export VAULT_CLIENT_SECRET="<secret from step 1b>"
```

**Go code:**

```go
import "rocketvault/internal/vaultclient"

client, err := vaultclient.New(vaultclient.Config{
    URL:          "http://localhost:8774",
    ClientID:     "my-app",           // service account name
    ClientSecret: os.Getenv("VAULT_CLIENT_SECRET"),
    Secrets: []vaultclient.SecretMapping{
        {Name: "DB_PASSWORD", UUID: "paste-uuid-here"},
        {Name: "API_KEY",     UUID: "paste-uuid-here"},
    },
})
if err != nil {
    log.Fatalf("vault client: %v", err)
}

// Fetch at startup
secrets, err := client.GetMany(ctx, []string{"DB_PASSWORD", "API_KEY"})
if err != nil {
    log.Fatalf("vault fetch: %v", err)
}

dbPassword := secrets["DB_PASSWORD"]
apiKey     := secrets["API_KEY"]
```

### Option B — Shell script (CI/CD, Docker entrypoints, any runtime)

```bash
export VAULT_URL="http://localhost:8774"
export VAULT_CLIENT_ID="my-app"
export VAULT_CLIENT_SECRET="<secret from step 1b>"

# Space-separated list of VAR_NAME=uuid pairs
export VAULT_SECRETS="DB_PASSWORD=<uuid> API_KEY=<uuid>"

# Source the script — exports secrets as env vars in the current shell
source scripts/rocketvault-fetch-secrets.sh

echo "DB_PASSWORD is set: ${DB_PASSWORD:+yes}"
```

To also write to a `.env` file:

```bash
export VAULT_ENV_FILE=".env"
source scripts/rocketvault-fetch-secrets.sh
# .env now contains: DB_PASSWORD="..." API_KEY="..."
```

### Option C — Direct HTTP (any language)

**Step 1: Get a token**

```bash
curl -X POST http://localhost:8774/api/v1/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-app&client_secret=<secret>"
```

Response:
```json
{"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 3600}
```

**Step 2: Fetch a secret**

```bash
curl http://localhost:8774/api/v1/secrets/<uuid> \
  -H "Authorization: Bearer <access_token>"
```

Response:
```json
{"id": "...", "name": "DB_PASSWORD", "value": "your-database-password", ...}
```

---

## Step 4: Test with the Consumer Service

The `examples/consumer-service/` demo service provides a visual end-to-end proof.

```bash
# Terminal 1 — RocketVault
./rocketvault serve

# Terminal 2 — Consumer service
export VAULT_CLIENT_SECRET="<secret from step 1b>"
go run ./examples/consumer-service/

# Terminal 3 — Verify
curl -s http://localhost:9000/healthz | jq .
curl -s http://localhost:9000/status  | jq .
```

Expected `/status` response when everything is working:

```json
{
  "vault_url": "http://localhost:8774",
  "client_id": "my-app",
  "secrets": {
    "DB_PASSWORD": {"loaded": true,  "masked": "your***"},
    "API_KEY":     {"loaded": true,  "masked": "your***"}
  },
  "frontend_config": {
    "feature_flags": {},
    "public_api_url": "http://localhost:8774",
    "sentry_dsn": ""
  }
}
```

---

## Step 5: Fetch Frontend Config (Web Apps)

`GET /api/v1/config` is public — no authentication required. It returns non-sensitive
config values safe to expose to a browser.

```bash
curl -s http://localhost:8774/api/v1/config | jq .
```

Response:
```json
{
  "feature_flags": {},
  "public_api_url": "http://localhost:8774",
  "sentry_dsn": ""
}
```

Configure these values in `.rocketvault.yaml`:

```yaml
frontend:
  public_api_url: "https://api.yourapp.com"
  sentry_dsn: "https://your-sentry-dsn"
```

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `connect: connection refused` | RocketVault not running, or wrong URL/port | Start `./rocketvault serve`, check `vault.url` |
| `token endpoint returned 404` | Wrong OAuth2 path | Must be `/api/v1/oauth2/token`, not `/oauth2/token` |
| `authentication failed` | Wrong `client_id` or `client_secret` | `client_id` is the service account **name**, not UUID |
| `secret not found` | UUID belongs to a different owner | Create the secret using the service account token (Step 2b), not the admin token |
| `insufficient permissions` | Role missing permission | Service accounts have `PermissionReadSecret` and `PermissionListSecrets` |
| `vault client init: Config.ClientSecret is required` | `VAULT_CLIENT_SECRET` env var not set | `export VAULT_CLIENT_SECRET="..."` |
| Server errors on `./rocketvault serve` | `vault_client.client_id` set in `.rocketvault.yaml` | Clear `client_id` — the server must not call itself |

---

## Security Checklist

- `VAULT_CLIENT_SECRET` is in env vars only — never in a config file or git
- `vault_client.client_id` is empty in `.rocketvault.yaml` on the RocketVault server
- Secrets are created using the service account token, not the admin token
- Each application has its own service account with the minimum required permissions
- Secret values are never logged (the `vaultclient` package logs names only)
- Rotate service account secrets periodically via `POST /api/v1/service-accounts/{id}/rotate`
