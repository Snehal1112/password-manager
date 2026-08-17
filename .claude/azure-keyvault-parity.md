# RocketVault ↔ Azure Key Vault — Feature Parity

Feature-by-feature comparison of RocketVault against Azure Key Vault (Standard/Premium
vaults). RocketVault columns are sourced from the codebase (`api/`, `internal/`,
`cmd/`, `model/`); Azure columns from Microsoft Learn (Key Vault overview and
`about-keys-details`, retrieved 2026-06-02).

**Legend:** ✅ full parity · 🟡 partial / with caveats · ❌ not supported ·
➕ RocketVault extra (no Azure equivalent)

> Scope note: RocketVault is a single self-hosted service. "Azure" here means the
> per-vault Key Vault resource, not Managed HSM. Cloud-platform features (geo-
> replication, Azure Monitor/Event Hubs, Entra ID, private endpoints) have no
> self-hosted equivalent by design — RocketVault substitutes local mechanisms.

---

## 1. Secrets management

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Store/retrieve secrets | ✅ | ✅ `POST/GET /api/v1/secrets` | ✅ |
| Update secret | ✅ | ✅ `PUT /secrets/{id}` | ✅ |
| Delete secret (soft) | ✅ | ✅ `DELETE /secrets/{id}` | ✅ |
| Secret versions (list/get/latest) | ✅ | ✅ `/secrets/{id}/versions[/{n}|/latest]` | ✅ |
| Content-type metadata | ✅ | ✅ `content_type` column | ✅ |
| Tags | ✅ (≤15) | ✅ tag service | ✅ |
| Enabled / nbf / exp lifecycle attrs | ✅ | ✅ `enabled`, `not_before`, `expires_at` | ✅ |
| Encryption at rest | ✅ HSM-backed | ✅ AES-256-GCM at rest | 🟡 (no HSM-sealed envelope) |
| Generate random secret | ❌ | ✅ `POST /secrets/generate` | ➕ |
| Bulk export / import | ❌ (per-secret only) | ✅ `POST /secrets/export`, `/import` | ➕ |
| Per-secret backup / restore | ✅ | ✅ `POST /secrets/{id}/backup`, `/secrets/restore` | ✅ |
| Rotation policy (auto-rotate) | ✅ | 🟡 `rotation_policies` table + CLI; user-scoped | 🟡 |

## 2. Key management — operations

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Create key | ✅ | ✅ `POST /keys` | ✅ |
| Import key | ✅ (JWK) | ❌ no import endpoint | ❌ |
| Get / List / List versions | ✅ | ✅ `GET /keys`, `/keys/{id}`, `/keys/{id}/versions` | ✅ |
| Update (attributes) | ✅ | ✅ `PUT /keys/{id}` | ✅ |
| Delete (soft) | ✅ | ✅ `DELETE /keys/{id}` | ✅ |
| Rotate (new version) | ✅ | ✅ `POST /keys/{id}/rotate` | ✅ |
| Sign / Verify | ✅ | ✅ `POST /keys/{id}/sign`, `/verify` | ✅ |
| Encrypt / Decrypt | ✅ | ✅ `POST /keys/{id}/encrypt`, `/decrypt` | ✅ |
| Wrap / Unwrap key | ✅ | ✅ `POST /keys/{id}/wrap`, `/unwrap` | ✅ |
| Backup / Restore | ✅ | ✅ `POST /keys/{id}/backup`, `/keys/restore` | ✅ |
| Get/Set rotation policy | ✅ | ✅ `GET/PUT/DELETE /keys/{key_id}/rotationpolicy`, granted to Crypto Officer + Administrator (matching Azure's `keyrotationpolicies/*`); a built-in scheduler (`internal/services/keys/rotation_executor.go`, wired via `rotation.keys.*` config) sweeps due, enabled policies and rotates automatically — full rotation-execution parity, not CRUD-only | ✅ |
| Release (confidential compute) | ✅ | ❌ no TEE attestation flow | ❌ |
| EXPORT blocked (keys non-extractable) | ✅ | ✅ private material never returned | ✅ |

## 3. Key management — types & algorithms

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| RSA key sizes | 2048 / 3072 / 4096 | 2048 / 3072 / 4096 | ✅ |
| EC curves | P-256, P-256K, P-384, P-521 | P-256, P-256K, P-384, P-521 | ✅ |
| Symmetric (oct/oct-HSM) keys | ❌ (vaults; Managed HSM only) | ❌ asymmetric only | ✅ (matches vault) |
| Sign/Verify — RSA | RS256/384/512, PS256/384/512, RSNULL | RS256/384/512, PS256/384/512 | 🟡 (no RSNULL TLS edge case) |
| Sign/Verify — EC | ES256, ES256K, ES384, ES512 | ES256, ES256K, ES384, ES512 | ✅ |
| Wrap/Encrypt — RSA | RSA-OAEP-256, RSA-OAEP, RSA1_5 | RSA-OAEP-256, RSA-OAEP | 🟡 (no legacy RSA1_5 — acceptable, deprecated) |
| Wrap/Encrypt — AES (KW/CBC) | Managed HSM only | A128/192/256 KW on software keys (➕, beyond Azure) **and** on HSM-backed AES keys (✅ matches Azure's Managed-HSM-only restriction); AES-KW requires 8-byte-aligned input (RFC 3394, matches Azure); A128/192/256 CBC on software keys only, no PKCS#11 mechanism exists for CBC wrap | ✅ (KW) / ➕ (CBC, software only) |

## 4. Certificate management

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Create / issue certificate | ✅ | ✅ `POST /certificates` (references a key_id) | ✅ |
| Get / List / Update / Delete | ✅ | ✅ full CRUD | ✅ |
| Certificate policy (get/set/delete) | ✅ | ✅ `/certificates/{id}/policy` GET/PUT/DELETE | ✅ |
| Auto-renewal | ✅ | ✅ `auto_renew`, `renewal_days`, renewal scheduler | ✅ |
| Backup / Restore | ✅ | ✅ `/certificates/{id}/backup`, `/certificates/restore` | ✅ |
| Public-CA integration (DigiCert/GlobalSign) | ✅ | ❌ self-signed / internal only | ❌ |
| ACME / external CA enrollment | ✅ (partner CAs) | ❌ | ❌ |

## 5. Multi-vault / namespacing

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Multiple isolated vaults | ✅ (per-resource) | ✅ `POST /vaults`, path-scoped routes | ✅ |
| Per-vault resource isolation | ✅ | ✅ `UNIQUE (vault_id, name)`, vault_id scoping | ✅ |
| Default vault for legacy flat routes | n/a | ✅ `default` vault | ➕ |
| Vault-scoped secrets / keys / certs | ✅ | ✅ all three resource types | ✅ |
| Vault-scoped deleted/restore/purge | ✅ | ✅ all three resource types | ✅ |
| Per-vault purge protection + retention | ✅ | ✅ `purge_protection`, `retention_days` | ✅ |

*Closed 2026-08-13: `KeyService.ListDeletedKeys/RecoverKey/PurgeKey` and
`CertificateService.ListDeletedCertificates/RecoverCertificate/PurgeCertificate`
now mirror `SecretService`'s scope-aware soft-delete methods, and
`api/soft_delete.go`'s key/certificate handlers resolve `model.Scope` via
`scopeFromRequest`/`vaultIDFromRequest` instead of calling the repository
directly — see `docs/superpowers/plans/2026-08-13-vault-scoped-soft-delete-keys-certs.md`.
The dead `KeyRepositoryInterface`/`CertificateRepositoryInterface.ListSoftDeleted(ctx, userID)`
methods (superseded by the scope-aware `List(ctx, scope, Filter{OnlyDeleted: true})`)
were removed. That removal also surfaced and fixed a latent bug: `keyColumns`/
`certificateColumns` never selected `deleted_at`/`purge_protection`, so every
`List` call — not just the new deleted-listing path — silently returned zero
values for both fields.*

## 6. Access control / authorization

*Re-verified 2026-07-25 against Microsoft Learn's "Azure built-in roles for Security"
(`dataActions` per role) and current `internal/services/authorization/roles.go` /
`access_policy_service.go`. Supersedes the 2026-06-02 pass below, which predates the
`feat/vault-scoped-users` merge (commit `5f16e75`) and didn't check role-by-role
`dataActions` precision.*

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Identity provider | Microsoft Entra ID | Local users + JWT (RS256/ES256) + TOTP MFA, **or** OIDC authorization-code flow (`GET /oidc/login`, `/oidc/callback`) against any standards-compliant IdP (Entra ID, Okta, Auth0, Keycloak, ...); both issue the same RocketVault session/JWT | ✅ (architecture matches: external IdP authenticates, RocketVault's existing vault-scoped role assignments still govern authorization) |
| Vault-scoped role assignment (Azure RBAC model) | ✅ role assignment scoped to vault resource, identity stays tenant-global | ✅ `role_assignments` table + `/vaults/{name}/role-assignments`; users stay tenant-global, no `vault_id` on `model.User` — confirmed against Microsoft Learn RBAC guide during design | ✅ architecture match |
| Access-policy engine (legacy model) | Separate, mutually-exclusive engine from RBAC (`enableRbacAuthorization` toggle picks one) | Same underlying `access_policies` table for both manual grants and role-assignment expansion — one engine, not two | 🟡 simplified (reasonable for single self-hosted product, but not a literal two-engine match) |
| Deny-overrides precedence | ✅ | ✅ confirmed in `access_policy_service.go`: "Explicit deny always wins. Falls back to RBAC when no matching policy exists." | ✅ |
| Machine identity (service principals) | ✅ | ✅ OAuth2 client-credentials service accounts | ✅ |
| MFA on human login | via Entra | ✅ TOTP enforced | ✅ |

### Built-in role permission boundaries — role-by-role against real Azure `dataActions`

*Corrected 2026-08-13: the 2026-07-25 pass below compared Azure's roles against
`internal/services/authorization/roles.go`'s **legacy** role vocabulary
(`vault-reader`, `crypto-officer`, `crypto-user`, ...). That vocabulary is
authorization-inert today — `PolicyMiddleware` only ever grants a vault-data-plane
request through `RoleAssignmentService.HasDataAction`, which looks a role up in
`model.azureRoleDataActions` (`model/azure_roles.go`); a legacy-named
`role_assignments` row isn't in that map and so grants zero data actions, and
`RoleAssignmentService.AssignRole` has rejected new grants of any legacy name since
the `feat/vault-scoped-users` merge (`IsLegacyRole`, `roles.go:126-130`). The table
below re-verifies against the roles that actually govern access: the eleven
`model/azure_roles.go` bundles.*

| Role | Azure grants (`dataActions`) | RocketVault grants (live `model/azure_roles.go`) | Status |
|---|---|---|---|
| Reader | `vaults/secrets/readMetadata` (metadata only — **not** the value), key/cert metadata + public material | `Key Vault Reader`: `ActionSecretsReadMetadata`, `ActionKeysRead`, `ActionCertificatesRead` — no secret-value action granted, so `GET /secrets/{id}` (which requires `ActionSecretsGet`) is denied | ✅ |
| Secrets Officer | `vaults/secrets/*` (full CRUD + lifecycle) | `Key Vault Secrets Officer`: readMetadata/get/set/delete/backup/restore/recover/purge | ✅ |
| Secrets User | `getSecret` + `readMetadata` | `Key Vault Secrets User`: `ActionSecretsReadMetadata`, `ActionSecretsGet` | ✅ |
| Crypto Officer | `vaults/keys/*` — **superset of Crypto User**, includes sign/verify/encrypt/decrypt/wrap/unwrap **plus** management, and `keyrotationpolicies/*` | `Key Vault Crypto Officer`: read/create/update/delete/backup/restore/recover/purge/import/rotate/encrypt/decrypt/wrap/unwrap/sign/verify, plus `ActionKeysRotationPolicyRead`/`ActionKeysRotationPolicyWrite` — every Crypto User action plus management, written out as an explicit superset (not derived by union) | ✅ superset relationship matches |
| Crypto User | `keys/read,update,backup,encrypt,decrypt,wrap,unwrap,sign,verify` | `Key Vault Crypto User`: read/update/backup/encrypt/decrypt/wrap/unwrap/sign/verify — `update`/`backup` added 2026-08-17 to close the last gap from the 2026-07-25 pass (which checked the legacy `PolicyOperation` enum instead of this live bundle) | ✅ |
| Certificates Officer | `certificates/*`, `certificatecas/*`, `certificatecontacts/*` | `Key Vault Certificates Officer`: full cert CRUD + lifecycle; no CA or contacts sub-resources (those RocketVault features don't exist at all) | 🟡 matches what exists; CA/contacts out of scope |
| Administrator | `vaults/*` — full data-plane, all types, all ops including wrap/unwrap | `Key Vault Administrator`: every secrets/keys/certificates action written out explicitly, including wrap/unwrap — not a union of other roles, so it carries no derived gaps | ✅ |

Four more built-in roles were added 2026-08-11 (see
`docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md`),
closing part of the gap between RocketVault's seven original roles and
Azure's full built-in set:

| Role | Azure grants (`dataActions`) | RocketVault grants | Status |
|---|---|---|---|
| Purge Operator | Purge a soft-deleted **vault** | `Key Vault Purge Operator`: `ActionVaultPurge` only | ✅ |
| Certificate User | Read a certificate **including its private-key portion** (Azure certs are a linked cert+key+secret object) | `Key Vault Certificate User`: `ActionCertificatesRead` only — RocketVault has no cert/key/secret linkage yet (P5), so this is currently identical to Reader's certificate slice | 🟡 placeholder parity — exists now, gains real meaning once P5 lands |
| Crypto Service Encryption User | Read key metadata + wrap/unwrap only (disk-encryption scenarios) | `Key Vault Crypto Service Encryption User`: `ActionKeysRead`, `ActionKeysWrap`, `ActionKeysUnwrap` | ✅ |
| Data Access Administrator | Manage role assignments for the other data-plane roles, scoped to the vault | `Key Vault Data Access Administrator`: `ActionRoleAssignmentsWrite`, `ActionRoleAssignmentsDelete` | ✅ — also closes the "role-assignment management is global-admin-only" known limitation from the v4.0.0 release notes |

**Not added:** `Key Vault Crypto Service Release User` (confidential-compute key release) — RocketVault has no TEE/attestation flow to gate at all (see §2's "Release (confidential compute)" row, still ❌). Adding the role name without a real capability behind it would repeat the exact anti-pattern the legacy vault-role vocabulary (`vault-reader`, `secrets-officer`, etc.) was retired for. **Not added either:** `Key Vault Contributor` — a control-plane role for Azure Resource Manager, not a data-plane concept RocketVault's self-hosted model has an equivalent for.

**Net:** the *architecture* (tenant-global identities + vault-scoped role assignments
expanding into an access-policy engine, deny-overrides-wins evaluation) is a genuine,
deliberate match to Azure's real RBAC model, and — per the 2026-08-13 correction above
— the *individual role boundaries* are now close to byte-for-byte too: Reader is
metadata-only, Crypto Officer is a true superset of Crypto User including wrap/unwrap,
and Administrator carries no derived gaps. Crypto User's `update`/`backup` gap (the
last live boundary gap from the 2026-08-13 pass) was closed 2026-08-17. RocketVault also
still ships a legacy, pre-Azure role vocabulary (`vault-reader`, `crypto-officer`,
`crypto-user`, etc., in `internal/services/authorization/roles.go`) that is retained
only for two purposes — CLI display of not-yet-upgraded historical `role_assignments`
rows, and the P2 upgrade migration's translation of those rows to Azure role names
(`internal/db/role_backfill.go`) — and can no longer be granted going forward. It has
no live authorization weight and is out of scope for parity comparison against Azure.

## 7. Soft-delete, purge protection, recovery

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Soft-delete (all object types) | ✅ | ✅ secrets/keys/certs `deleted_at` | ✅ |
| List deleted / recover | ✅ | ✅ `/deleted/...` restore | ✅ |
| Purge (permanent delete) | ✅ | ✅ `/deleted/.../purge` | ✅ |
| Purge protection (block early purge) | ✅ | ✅ `purge_protection` (per-key + per-vault) | ✅ |
| Configurable retention window | ✅ (7–90 days) | ✅ `retention_days` + purge scheduler | ✅ |

## 8. HSM & cryptographic protection

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Software crypto module | ✅ Standard (FIPS 140 L1) | ✅ Go crypto + AES-256-GCM | 🟡 (not FIPS-validated) |
| HSM-backed keys | ✅ Premium (FIPS 140-3 L3) | 🟡 PKCS#11 provider (`hsm.enabled`); RSA sign/verify/encrypt/decrypt, EC sign/verify (P-256/P-384/P-521), and AES-KW generate/wrap/unwrap all HSM-backed; P-256K and AES-CBC remain software-only | 🟡 |
| JWT signing key protection | n/a | ➕ OS keychain / self-PKI / external-PKI providers | ➕ |
| Keys non-extractable | ✅ | ✅ | ✅ |

## 9. Monitoring, audit & compliance

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Access/operation logging | ✅ (Azure Monitor) | ✅ structured audit logs (`/audit/logs`) | 🟡 (local, no cloud sink) |
| Tamper-evident audit chain | ❌ | ✅ `prev_hash` hash-chained audit rows | ➕ |
| Compliance reports | ❌ (raw logs only) | ✅ `/audit/reports/soc2`, `/audit/reports/gdpr` | ➕ |
| Configurable audit retention | via storage | ✅ `/audit/config` | ✅ |
| Stream to Event Hub / archive to storage | ✅ | ❌ no cloud sinks | ❌ |
| Health / readiness probes | platform-managed | ✅ `/health/live`, `/ready`, `/database` | ➕ |

## 10. Platform & operations

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| REST API | ✅ | ✅ `/api/v1/...` | ✅ |
| CLI | ✅ (az keyvault) | ✅ Cobra CLI (`rocketvault ...`) | ✅ |
| JWKS endpoint for token verification | n/a | ➕ `/jwks.json` + key rotation | ➕ |
| Rate limiting | platform-managed | ✅ per-IP (global + stricter auth limits) | ➕ |
| Geo-replication / regional failover | ✅ automatic | ❌ single instance | ❌ |
| Self-hosted, no cloud dependency | ❌ | ✅ | ➕ |
| Backup / restore (whole vault) | ✅ (per-object) | ✅ `rocketvault backup create/restore` | ✅ |

---

## Summary

**Strong parity (✅):** secret lifecycle + versioning, key CRUD + all crypto
operations (sign/verify/encrypt/decrypt/wrap/unwrap/rotate — operation *existence*,
via `api/keys.go`), per-key rotation-policy CRUD API (closed 2026-08-14, see §2), RSA & EC
type/algorithm coverage, certificate CRUD + policy + auto-renewal, multi-vault isolation,
deny-overrides access-policy evaluation, soft-delete/purge-protection/recovery,
vault-scoped deleted/restore/purge across all three resource types (closed 2026-08-13,
see §5), and — per the 2026-08-13 correction to §6 — RBAC role boundaries: the
vault-scoped role-assignment architecture matches Azure's real RBAC model, and the
live `model/azure_roles.go` role bundles are close to byte-for-byte too (Reader is
metadata-only, Crypto Officer is a true superset of Crypto User including wrap/unwrap,
Administrator carries no derived gaps).

**Partial (🟡):**
- **HSM**: PKCS#11 path exists but is not the default; covers RSA (sign/verify/
  encrypt/decrypt), EC P-256/P-384/P-521 (sign/verify), and AES-KW (generate/wrap/
  unwrap) — P-256K and AES-CBC remain software-only (P-256K: no PKCS#11 mechanism
  verified against real hardware in this environment; AES-CBC: no PKCS#11 mechanism
  exists at all). No FIPS 140-3 L3 validation (a certification process, not
  achievable through code).
- **Rotation policy**: rotation is user-scoped (a multi-vault deferral).
- **RBAC role boundaries, one residual gap** (see §6): `Key Vault Crypto User` is
  missing the `update`/`backup` actions Azure's real Crypto User grants.

**Not supported (❌):** key import, key release to confidential compute (TEE),
public-CA / ACME certificate enrollment, geo-replication, and cloud log sinks
(Event Hub / Azure Monitor archive). RSA1_5 and RSNULL are intentionally omitted
(deprecated / TLS-edge-case).

**RocketVault extras (➕) beyond Azure vaults:** secret generate + bulk export/import,
AES-KW/CBC wrapping on software keys, JWKS endpoint with rotating signing keys
(os_store / self_pki / external_pki), hash-chained tamper-evident audit log, built-in
SOC 2 / GDPR compliance reports, per-IP rate limiting, health probes, and fully
self-hosted operation with no cloud dependency.

---

*Sources: codebase (`api/`, `internal/services/keys`, `internal/crypto`, `model/`,
`cmd/`) and Microsoft Learn — Azure Key Vault Overview and "Key types, algorithms,
and operations" (`about-keys-details`), retrieved 2026-06-02.*
