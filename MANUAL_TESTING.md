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
| GET | `/api/v1/health/database` | None | Database health status |
| GET | `/api/v1/config` | None | Frontend config |
| GET | `/jwks.json` | None | JWKS public keys |
| POST | `/api/v1/users/login` | None | Login → JWT |
| POST | `/api/v1/users/refresh` | None | Refresh token |
| POST | `/api/v1/oauth2/token` | Basic (client creds) | OAuth2 token |
| GET | `/api/v1/oidc/login` | None | Start OIDC authorization-code login |
| GET | `/api/v1/oidc/callback` | None | Complete OIDC login, issue session |
| GET | `/api/v1/users/sessions` | JWT | List sessions |
| DELETE | `/api/v1/users/sessions/{id}` | JWT | Revoke session |
| DELETE | `/api/v1/users/sessions` | JWT | Revoke all sessions |
| POST | `/api/v1/users` | JWT (admin) | Create user |
| GET | `/api/v1/users` | JWT (admin) | List users |
| GET | `/api/v1/users/{id}` | JWT | Get user |
| PUT | `/api/v1/users/{id}` | JWT (admin) | Update user |
| DELETE | `/api/v1/users/{id}` | JWT (admin) | Delete user |
| POST | `/api/v1/vaults` | JWT (admin or vault grant) | Create vault |
| GET | `/api/v1/vaults` | JWT (admin or vault grant) | List vaults (`?include_deleted=true`) |
| GET | `/api/v1/vaults/{name}` | JWT (admin or vault grant) | Get vault |
| PATCH | `/api/v1/vaults/{name}` | JWT (admin or vault grant) | Update vault |
| DELETE | `/api/v1/vaults/{name}` | JWT (admin or vault grant) | Soft-delete vault (204; refuses `default`) |
| DELETE | `/api/v1/vaults/{vault_name}/purge` | JWT (admin or vault grant) | Permanently purge a soft-deleted vault |
| GET | `/api/v1/vaults/{vault_name}/role-assignments` | JWT (admin or vault grant) | List vault role assignments |
| POST | `/api/v1/vaults/{vault_name}/role-assignments` | JWT (admin or vault grant) | Create vault role assignment |
| GET | `/api/v1/vaults/{vault_name}/role-assignments/{assignment_id}` | JWT (admin or vault grant) | Get vault role assignment |
| DELETE | `/api/v1/vaults/{vault_name}/role-assignments/{assignment_id}` | JWT (admin or vault grant) | Delete (revoke) vault role assignment |
| POST | `/api/v1/vaults/{vault_name}/secrets` | JWT | Create secret in vault |
| GET | `/api/v1/vaults/{vault_name}/secrets` | JWT | List vault secrets (members see all) |
| GET | `/api/v1/vaults/{vault_name}/secrets/{id}` | JWT | Get vault secret |
| PUT | `/api/v1/vaults/{vault_name}/secrets/{id}` | JWT | Update vault secret |
| DELETE | `/api/v1/vaults/{vault_name}/secrets/{id}` | JWT | Soft-delete vault secret |
| GET | `/api/v1/vaults/{vault_name}/deleted/secrets` | JWT | List soft-deleted vault secrets |
| POST | `/api/v1/vaults/{vault_name}/deleted/secrets/{id}/restore` | JWT | Restore vault secret (by vault membership) |
| DELETE | `/api/v1/vaults/{vault_name}/deleted/secrets/{id}/purge` | JWT | Purge vault secret |
| POST | `/api/v1/vaults/{vault_name}/keys` | JWT | Create key in vault |
| GET | `/api/v1/vaults/{vault_name}/keys` | JWT | List vault keys |
| GET | `/api/v1/vaults/{vault_name}/keys/{id}` | JWT | Get vault key |
| PUT | `/api/v1/vaults/{vault_name}/keys/{id}` | JWT | Update vault key |
| DELETE | `/api/v1/vaults/{vault_name}/keys/{id}` | JWT | Soft-delete vault key |
| POST | `/api/v1/vaults/{vault_name}/keys/{id}/rotate` | JWT | Rotate vault key |
| GET | `/api/v1/vaults/{vault_name}/keys/{id}/versions` | JWT | List vault key versions |
| POST | `/api/v1/vaults/{vault_name}/keys/{id}/wrap` | JWT | Wrap (encrypt) data with vault key |
| POST | `/api/v1/vaults/{vault_name}/keys/{id}/unwrap` | JWT | Unwrap (decrypt) data with vault key |
| POST | `/api/v1/vaults/{vault_name}/keys/{id}/sign` | JWT | Sign payload with vault key |
| POST | `/api/v1/vaults/{vault_name}/keys/{id}/verify` | JWT | Verify signature with vault key |
| POST | `/api/v1/vaults/{vault_name}/keys/{id}/encrypt` | JWT | Encrypt payload with vault key |
| POST | `/api/v1/vaults/{vault_name}/keys/{id}/decrypt` | JWT | Decrypt payload with vault key |
| GET | `/api/v1/vaults/{vault_name}/keys/{id}/rotationpolicy` | JWT (Crypto Officer/Administrator) | Get vault key rotation policy |
| PUT | `/api/v1/vaults/{vault_name}/keys/{id}/rotationpolicy` | JWT (Crypto Officer/Administrator) | Upsert vault key rotation policy |
| DELETE | `/api/v1/vaults/{vault_name}/keys/{id}/rotationpolicy` | JWT (Crypto Officer/Administrator) | Delete vault key rotation policy |
| GET | `/api/v1/vaults/{vault_name}/deleted/keys` | JWT | List soft-deleted vault keys |
| POST | `/api/v1/vaults/{vault_name}/deleted/keys/{id}/restore` | JWT | Restore vault key |
| DELETE | `/api/v1/vaults/{vault_name}/deleted/keys/{id}/purge` | JWT | Purge vault key |
| POST | `/api/v1/vaults/{vault_name}/certificates` | JWT | Create certificate in vault |
| GET | `/api/v1/vaults/{vault_name}/certificates` | JWT | List vault certificates |
| GET | `/api/v1/vaults/{vault_name}/certificates/{id}` | JWT | Get vault certificate |
| PUT | `/api/v1/vaults/{vault_name}/certificates/{id}` | JWT | Update vault certificate |
| DELETE | `/api/v1/vaults/{vault_name}/certificates/{id}` | JWT | Soft-delete vault certificate |
| GET | `/api/v1/vaults/{vault_name}/certificates/{id}/policy` | JWT | Get vault certificate policy |
| PUT | `/api/v1/vaults/{vault_name}/certificates/{id}/policy` | JWT | Upsert vault certificate policy |
| DELETE | `/api/v1/vaults/{vault_name}/certificates/{id}/policy` | JWT | Delete vault certificate policy |
| GET | `/api/v1/vaults/{vault_name}/deleted/certificates` | JWT | List soft-deleted vault certificates |
| POST | `/api/v1/vaults/{vault_name}/deleted/certificates/{id}/restore` | JWT | Restore vault certificate |
| DELETE | `/api/v1/vaults/{vault_name}/deleted/certificates/{id}/purge` | JWT | Purge vault certificate |
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
| GET | `/api/v1/keys/{id}/rotationpolicy` | JWT (Crypto Officer/Administrator) | Get key rotation policy |
| PUT | `/api/v1/keys/{id}/rotationpolicy` | JWT (Crypto Officer/Administrator) | Upsert key rotation policy |
| DELETE | `/api/v1/keys/{id}/rotationpolicy` | JWT (Crypto Officer/Administrator) | Delete key rotation policy |
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

Notes:
- "JWT (admin or vault grant)" (vault management, purge, role-assignments) means
  the global `admin` account role always passes, OR the caller holds the
  specific per-vault grant the handler checks — a `vaults:manage` access-policy
  grant for vault CRUD/role-assignments, or a Key Vault Purge Operator role
  assignment for purge. See `internal/services/authorization/vault_authz.go`
  (`CanManageVault`, `CanPurgeVault`, `CanManageRoleAssignments`). This
  replaced a global-admin-only gate on 2026-08-11 so per-vault role holders
  aren't blocked by a vault-blind check running ahead of the handler.
- Vault-scoped routes for secrets, keys, and certificates (`/vaults/{vault_name}/...`)
  mirror the flat routes 1:1 and are authorized per vault by `PolicyMiddleware`
  against the caller's role assignments in that vault, not by the global role.
- `rotationpolicy` routes are narrower than every other `/keys/{id}/*` route: only
  `Key Vault Crypto Officer` and `Key Vault Administrator` grant access (matching
  Azure's `keyrotationpolicies/*`) — `Key Vault Crypto User`, which can use the key
  for crypto operations, is deliberately denied here and gets `403`. Request body
  for `PUT` (all four fields required): `{"rotate_after_days": 90,
  "notify_before_expiry_days": 30, "expiry_days": 365, "enabled": true}`. `PUT` is
  an upsert (same `id` returned on repeat calls with the same key). `GET`/`DELETE`
  on a key with no policy set return `404`.

---

## Account Roles & Permissions

Every user account carries one global role. It controls the coarse, account-level
permissions checked by the RBAC service. Vault-scoped roles (`vault-reader`,
`secrets-officer`, etc.) are a separate, finer-grained layer assigned per vault.

Source of truth: `internal/services/authorization/rbac_service.go`.

| Role | Secrets | Keys | Certificates | Users | System |
|------|---------|------|--------------|-------|--------|
| `admin` | full CRUD + list | full CRUD + list | full CRUD + list | full CRUD + list | manage vaults + system |
| `user` | read, list | read, list | read, list | — | — |
| `secrets_manager` | full CRUD + list | — | — | — | — |
| `crypto_manager` | — | full CRUD + list | — | — | — |
| `certificate_manager` | — | — | full CRUD + list | — | — |
| `service_account` | read, list | read, list | read, list | — | — |

Notes:
- "full CRUD" = create, read, update, delete.
- `user` and `service_account` are read-only across all three resource types.
  They differ only in intent: `user` is a human login, `service_account` is a
  machine identity (Azure Key Vault model — admins create resources and grant
  finer access via access policies).
- A manager role grants full CRUD on its one resource type and nothing on the
  others. `secrets_manager` cannot even read keys or certificates.
- Unknown roles get zero permissions (deny by default).
