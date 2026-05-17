# RocketVault API Collection

Bruno collection for testing the RocketVault REST API.

## Setup

1. Install [Bruno](https://www.usebruno.com/) (free, open-source API client)
2. Open Bruno → **Open Collection** → select this `docs/api/` directory
3. Select an environment from the top-right dropdown (Local / Staging / Production)

## First Request: Login

1. Open `auth/login`
2. Fill in `totp_code` in the environment variables (top-right → Manage Environments)
3. Send the request — the token is automatically saved to the `token` env var
4. All authenticated requests will now use this token

## Environment Variables

| Variable | Description |
|---|---|
| `base_url` | API base URL (e.g. `http://localhost:8080`) |
| `token` | JWT access token — auto-populated by the Login request |
| `username` | Login username |
| `password` | Login password |
| `totp_code` | TOTP code from your authenticator app — fill before login |

The following variables are used as path parameters — set them manually in the env or override per-request:

| Variable | Used in |
|---|---|
| `user_id` | users/get-user, update-user, delete-user |
| `secret_id` | secrets/get-secret, update-secret, delete-secret, versions |
| `key_id` | keys/get-key, update-key, delete-key, rotate, wrap, unwrap |
| `certificate_id` | certificates/get-certificate, update-certificate, delete-certificate |
| `policy_id` | access-policies/get-policy, update-policy, delete-policy |
| `principal_id` | access-policies/list-by-principal |
| `service_account_id` | oauth2/get, delete, rotate service account |
| `session_id` | users/revoke-session |
| `version` | secrets/get-version |
| `client_id` | oauth2/token |
| `client_secret` | oauth2/token |

## Collection Structure

```
auth/           Login and token refresh
users/          User CRUD + session management
secrets/        Secret CRUD + generate, export, import, versioning
keys/           Key CRUD + rotate, wrap, unwrap
certificates/   Certificate CRUD
access-policies/ Policy CRUD + list by principal
soft-delete/    List, restore, purge for secrets/keys/certificates
oauth2/         OAuth2 token endpoint + service account management
```

## Running the server locally

```bash
go run main.go serve
```

The server starts on `http://localhost:8080` by default.
