# RocketVault — Manual Testing Guide

> **This guide has been superseded by the [Administrator Manual](docs/admin-manual.html).**
> The manual is the canonical, interactive reference — every feature, with per-endpoint cards,
> live-captured request/response examples, search, and copy-paste commands. Open it over http
> (for example `python3 -m http.server`, then `http://localhost:8000/docs/admin-manual.html`).
>
> The complete endpoint table is retained below for quick reference.

---

## Quick Reference — All Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/health/live` | None | Liveness probe |
| GET | `/api/v1/health/ready` | None | Readiness probe |
| GET | `/api/v1/health` | None | Full health status |
| GET | `/api/v1/health/database` | JWT | Database health status |
| GET | `/api/v1/config` | None | Frontend config |
| GET | `/jwks.json` | None | JWKS public keys |
| POST | `/api/v1/users/login` | None | Login → JWT |
| POST | `/api/v1/users/refresh` | None | Refresh token |
| POST | `/api/v1/oauth2/token` | Basic (client creds) | OAuth2 token |
| GET | `/api/v1/users/sessions` | JWT | List sessions |
| DELETE | `/api/v1/users/sessions/{id}` | JWT | Revoke session |
| DELETE | `/api/v1/users/sessions` | JWT | Revoke all sessions |
| POST | `/api/v1/users` | JWT (admin) | Create user |
| GET | `/api/v1/users` | JWT (admin) | List users |
| GET | `/api/v1/users/{id}` | JWT | Get user |
| PUT | `/api/v1/users/{id}` | JWT (admin) | Update user |
| DELETE | `/api/v1/users/{id}` | JWT (admin) | Delete user |
| POST | `/api/v1/vaults` | JWT (admin) | Create vault |
| GET | `/api/v1/vaults` | JWT (admin) | List vaults (`?include_deleted=true`) |
| GET | `/api/v1/vaults/{name}` | JWT (admin) | Get vault |
| PATCH | `/api/v1/vaults/{name}` | JWT (admin) | Update vault |
| DELETE | `/api/v1/vaults/{name}` | JWT (admin) | Soft-delete vault (204; refuses `default`) |
| POST | `/api/v1/vaults/{vault_name}/secrets` | JWT | Create secret in vault |
| GET | `/api/v1/vaults/{vault_name}/secrets` | JWT | List vault secrets (members see all) |
| GET | `/api/v1/vaults/{vault_name}/secrets/{id}` | JWT | Get vault secret |
| PUT | `/api/v1/vaults/{vault_name}/secrets/{id}` | JWT | Update vault secret |
| DELETE | `/api/v1/vaults/{vault_name}/secrets/{id}` | JWT | Soft-delete vault secret |
| GET | `/api/v1/vaults/{vault_name}/deleted/secrets` | JWT | List soft-deleted vault secrets |
| POST | `/api/v1/vaults/{vault_name}/deleted/secrets/{id}/restore` | JWT | Restore vault secret (by vault membership) |
| DELETE | `/api/v1/vaults/{vault_name}/deleted/secrets/{id}/purge` | JWT | Purge vault secret |
| POST | `/api/v1/secrets` | JWT | Create secret |
| GET | `/api/v1/secrets` | JWT | List secrets |
| GET | `/api/v1/secrets/{id}` | JWT | Get secret |
| PUT | `/api/v1/secrets/{id}` | JWT | Update secret |
| DELETE | `/api/v1/secrets/{id}` | JWT | Soft-delete secret |
| POST | `/api/v1/secrets/generate` | JWT | Generate random secret |
| POST | `/api/v1/secrets/export` | JWT | Export secrets |
| POST | `/api/v1/secrets/import` | JWT | Import secrets |
| POST | `/api/v1/secrets/{id}/backup` | JWT | Backup secret item |
| POST | `/api/v1/secrets/restore` | JWT | Restore secret item |
| GET | `/api/v1/secrets/{id}/versions` | JWT | List versions |
| GET | `/api/v1/secrets/{id}/versions/{n}` | JWT | Get version n |
| GET | `/api/v1/secrets/{id}/versions/latest` | JWT | Get latest version |
| POST | `/api/v1/keys` | JWT | Create key |
| GET | `/api/v1/keys` | JWT | List keys |
| GET | `/api/v1/keys/{id}` | JWT | Get key |
| PUT | `/api/v1/keys/{id}` | JWT | Update key |
| DELETE | `/api/v1/keys/{id}` | JWT | Soft-delete key |
| POST | `/api/v1/keys/{id}/rotate` | JWT | Rotate key |
| GET | `/api/v1/keys/{id}/versions` | JWT | List key versions |
| POST | `/api/v1/keys/{id}/wrap` | JWT | Wrap (encrypt) data |
| POST | `/api/v1/keys/{id}/unwrap` | JWT | Unwrap (decrypt) data |
| POST | `/api/v1/keys/{id}/sign` | JWT | Sign payload |
| POST | `/api/v1/keys/{id}/verify` | JWT | Verify signature |
| POST | `/api/v1/keys/{id}/encrypt` | JWT | Encrypt payload |
| POST | `/api/v1/keys/{id}/decrypt` | JWT | Decrypt payload |
| POST | `/api/v1/keys/{id}/backup` | JWT | Backup key item |
| POST | `/api/v1/keys/restore` | JWT | Restore key item |
| POST | `/api/v1/certificates` | JWT | Create certificate |
| GET | `/api/v1/certificates` | JWT | List certificates |
| GET | `/api/v1/certificates/{id}` | JWT | Get certificate |
| PUT | `/api/v1/certificates/{id}` | JWT | Update certificate |
| DELETE | `/api/v1/certificates/{id}` | JWT | Soft-delete certificate |
| GET | `/api/v1/certificates/{id}/policy` | JWT | Get certificate policy |
| PUT | `/api/v1/certificates/{id}/policy` | JWT | Upsert certificate policy |
| DELETE | `/api/v1/certificates/{id}/policy` | JWT | Delete certificate policy |
| POST | `/api/v1/certificates/{id}/backup` | JWT | Backup certificate item |
| POST | `/api/v1/certificates/restore` | JWT | Restore certificate item |
| GET | `/api/v1/deleted/secrets` | JWT | List deleted secrets |
| POST | `/api/v1/deleted/secrets/{id}/restore` | JWT | Restore secret |
| DELETE | `/api/v1/deleted/secrets/{id}/purge` | JWT | Purge secret |
| GET | `/api/v1/deleted/keys/{id}` | JWT | Get deleted key |
| GET | `/api/v1/deleted/keys` | JWT | List deleted keys |
| POST | `/api/v1/deleted/keys/{id}/restore` | JWT | Restore key |
| DELETE | `/api/v1/deleted/keys/{id}/purge` | JWT | Purge key |
| GET | `/api/v1/deleted/certificates` | JWT | List deleted certs |
| POST | `/api/v1/deleted/certificates/{id}/restore` | JWT | Restore certificate |
| DELETE | `/api/v1/deleted/certificates/{id}/purge` | JWT | Purge certificate |
| GET | `/api/v1/access-policies` | JWT | List policies |
| POST | `/api/v1/access-policies` | JWT | Create policy |
| GET | `/api/v1/access-policies/{id}` | JWT | Get policy |
| PUT | `/api/v1/access-policies/{id}` | JWT | Update policy |
| DELETE | `/api/v1/access-policies/{id}` | JWT | Delete policy |
| GET | `/api/v1/access-policies/principal/{id}` | JWT | Policies by principal |
| GET | `/api/v1/audit/logs` | JWT (admin) | Query audit logs |
| GET | `/api/v1/audit/reports/soc2` | JWT (admin) | SOC 2 report |
| GET | `/api/v1/audit/reports/gdpr` | JWT (admin) | GDPR report |
| GET | `/api/v1/audit/config` | JWT (admin) | Get audit retention config |
| PATCH | `/api/v1/audit/config` | JWT (admin) | Update audit retention config |
| POST | `/api/v1/service-accounts` | JWT (admin) | Create service account |
| GET | `/api/v1/service-accounts` | JWT (admin) | List service accounts |
| GET | `/api/v1/service-accounts/{id}` | JWT (admin) | Get service account |
| DELETE | `/api/v1/service-accounts/{id}` | JWT (admin) | Delete service account |
| POST | `/api/v1/service-accounts/{id}/rotate` | JWT (admin) | Rotate SA secret |
| POST | `/api/v1/jwks/rotate` | JWT (admin) | Rotate JWT signing key |
