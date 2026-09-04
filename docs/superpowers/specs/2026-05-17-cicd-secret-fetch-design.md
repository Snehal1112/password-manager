# CI/CD Secret Fetch Script — Design Spec

**Date**: 2026-05-17
**Status**: Approved

## Overview

A single self-contained shell script (`scripts/rocketvault-fetch-secrets.sh`) that lets any CI/CD pipeline fetch secrets from RocketVault using the existing OAuth2 client credentials flow — the same pattern as Azure Key Vault's managed identity approach, but self-hosted.

**Dependencies**: `curl` and `jq` only. Both are standard in CI runner images.

---

## Authentication Model

The pipeline authenticates as a **service account** using the OAuth2 client credentials grant (RFC 6749 §4.4). This mirrors Azure Key Vault's managed identity pattern:

1. An admin creates a service account in RocketVault via `POST /api/v1/service-accounts`
2. The service account's `client_id` and `client_secret` are stored as protected CI/CD environment variables
3. At pipeline start, the script exchanges them for a short-lived Bearer token via `POST /oauth2/token`
4. The token is used for all subsequent secret fetches and discarded after

The token lifetime inherits `jwt.expiry` from RocketVault config (default 15m — sufficient for any pipeline run).

> **Correction (2026-09-04):** the default is **1h**, not 15m — `jwt.expiry` is
> optional and `internal/container/service_container.go:366-369` falls back to
> `time.Hour`. The conclusion is unchanged (still ample for any pipeline run),
> but a reader sizing a pipeline's token window against 15m would be planning
> with a figure four times too small.

---

## Script Location

```
scripts/rocketvault-fetch-secrets.sh
```

---

## Inputs

### Required environment variables

| Variable | Purpose |
|---|---|
| `VAULT_URL` | RocketVault base URL, e.g. `https://vault.internal:8774` |
| `VAULT_CLIENT_ID` | Service account client ID |
| `VAULT_CLIENT_SECRET` | Service account client secret |
| `VAULT_SECRETS` | Space-separated `ENV_VAR_NAME=secret-uuid` pairs |

### Optional environment variables

| Variable | Purpose |
|---|---|
| `VAULT_ENV_FILE` | Path to write secrets as a `.env` file (e.g. `.env`) |
| `VAULT_INSECURE` | Set to `1` to skip TLS verification (dev/self-signed certs only) |

### Example pipeline usage

```sh
export VAULT_URL=https://vault.internal:8774
export VAULT_CLIENT_ID=ci-runner
export VAULT_CLIENT_SECRET=$CI_VAULT_SECRET
export VAULT_SECRETS="DB_PASSWORD=<uuid> API_KEY=<uuid> SMTP_PASS=<uuid>"
export VAULT_ENV_FILE=.env

source scripts/rocketvault-fetch-secrets.sh
```

After sourcing, `$DB_PASSWORD`, `$API_KEY`, and `$SMTP_PASS` are available as environment variables for all subsequent pipeline steps.

---

## Script Execution Flow

### 1. Validate inputs
- Fail immediately (`exit 1`) if `VAULT_URL`, `VAULT_CLIENT_ID`, or `VAULT_CLIENT_SECRET` are unset
- Print a descriptive error message naming the missing variable

### 2. Authenticate
- `POST $VAULT_URL/oauth2/token` with form fields:
  - `grant_type=client_credentials`
  - `client_id=$VAULT_CLIENT_ID`
  - `client_secret=$VAULT_CLIENT_SECRET`
- Extract `access_token` from JSON response with `jq`
- If HTTP status is not 200 or token is empty, print server error and `exit 1`

### 3. Fetch secrets loop
For each `ENV_VAR_NAME=uuid` pair in `$VAULT_SECRETS`:
- `GET $VAULT_URL/api/v1/secrets/{uuid}` with `Authorization: Bearer <token>`
- Extract the secret value with `jq`
- `export ENV_VAR_NAME=value`
- If `VAULT_ENV_FILE` is set, append `ENV_VAR_NAME=value` to the file
- On any HTTP error (403, 404, 500), print which secret/var failed and `exit 1`

### 4. Cleanup
- `unset` the token variable after all fetches complete so it does not persist in the shell environment

---

## Security Requirements

- `set +x` at the top of the script — prevents shell trace mode from printing secret values in CI logs
- Secret values are never echoed or printed at any point
- `VAULT_ENV_FILE` is created with `chmod 600` before any writes
- `VAULT_INSECURE=1` is explicitly opt-in and should only be used in non-production environments

---

## API Endpoints Used

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/oauth2/token` | Exchange client credentials for Bearer token (public — no auth prefix) |
| `GET` | `/api/v1/secrets/{secret_id}` | Fetch a single secret by UUID |

Both endpoints already exist in RocketVault. No server-side changes are required.

---

## Out of Scope

- Secret rotation or creation from the script
- Manifest-file-based secret declaration (Option B — future work)
- GitHub Actions composite action wrapper (future work)
- GitLab CI include template (future work)
