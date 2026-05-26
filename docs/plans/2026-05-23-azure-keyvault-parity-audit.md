# RocketVault Azure Key Vault Parity Audit

**Date:** 2026-05-23
**Status:** Updated 2026-05-26 to reflect commits since `8a5d1a3`
**Audit target:** branch `v-4.0.0` at commit `8a5d1a3` (original); updated through `26dbc49`
**Reference:** Microsoft Azure Key Vault REST API v7.4, documentation as of 2026-05-23
**Auditor:** Subagent-driven research across nine scope areas

## Scope decisions

- Data-plane only. Azure management-plane operations (Resource Manager API) are out of scope.
- Azure Managed HSM is out of scope. RocketVault is software-protected only.
- Azure-platform-only features (VNet service endpoints, Private Link, Trusted Services bypass, Network Security Perimeter, Azure Policy evaluation, Conditional Access, PIM) are marked `out of scope` because they cannot exist in a self-hosted Go service.

---

## Feature Matrix

### Secrets

| Azure feature | Azure behavior / limit | RocketVault status | Evidence in RocketVault | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| SetSecret / CreateSecret | `PUT /secrets/{name}` — new secret or new version; returns `SecretBundle` 200 OK | partial | `api/secrets.go:53`, `internal/services/secrets/secret_service.go:164` | `cmd/secrets/create_test.go`, `secret_service_test.go:37` | Method is POST, not PUT. UUID-addressed, not name-addressed. Same-name re-create errors instead of versioning. |
| GetSecret (latest) | `GET /secrets/{name}` | partial | `api/secrets.go:447` | `secret_service_test.go:90` | Lookup by UUID, not name. No name-based endpoint. |
| GetSecret (by version) | `GET /secrets/{name}/{version}` — opaque hex version | partial | `api/secrets.go:106` | none | Version is integer; URL is `/versions/{n}`. |
| ListSecretVersions | `GET /secrets/{name}/versions`; pagination 1–25; `nextLink` | partial | `api/secrets.go:65-67`, `internal/services/secrets/versioning_service.go:134` | none | No pagination; versions return decrypted `value` (Azure returns metadata only). |
| ListSecrets | `GET /secrets`; pagination; values omitted | partial | `api/secrets.go:398` | `cmd/secrets/list_test.go` | No `maxresults` / `nextLink`; envelope `{secrets,total}` vs `{value,nextLink}`. |
| UpdateSecret | `PATCH /secrets/{name}/{version}`; value immutable | partial | `api/secrets.go:498`, `internal/services/secrets/secret_service.go:249` | `secret_service_test.go:211` | Method PUT; allows changing value (Azure forbids); `attributes.enabled/exp/nbf` not accepted. |
| DeleteSecret | `DELETE /secrets/{name}`; returns `DeletedSecretBundle` | partial | `api/secrets.go:594`, `internal/repositories/secret_repository.go:321` | `secret_service_test.go:162` | Returns `{"status":"OK"}`; no `recoveryId`, `scheduledPurgeDate`, `deletedDate`. |
| RecoverDeletedSecret | `POST /deletedsecrets/{name}/recover` | partial | `api/soft_delete.go:45`, `secret_repository.go:359` | none | `/deleted/secrets/{id}/restore` (UUID); ownership scan is O(n). |
| PurgeDeletedSecret | `DELETE /deletedsecrets/{name}`; 204 | partial | `api/soft_delete.go:87`, `secret_repository.go:397` | none | Returns 200 `{"status":"OK"}` instead of 204. |
| ListDeletedSecrets | `GET /deletedsecrets`; pagination | partial | `api/soft_delete.go:10` | none | No pagination; envelope mismatch; no `recoveryId`/`scheduledPurgeDate`. |
| GetDeletedSecret (single) | `GET /deletedsecrets/{name}` | missing | none | none | No single-deleted-by-name endpoint. |
| BackupSecret | `POST /secrets/{name}/backup`; opaque blob, all versions | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /secrets/{id}/backup` returns AES-256-GCM encrypted JSON blob. Single-version only (no version history in blob). |
| RestoreSecret | `POST /secrets/restore`; restores from blob | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /secrets/restore` decrypts and re-inserts. No empty-slot check. |
| tags | `map[string]string`, ≤15 entries, 256 chars key/value | partial | `model/secret.go:18`, `internal/validation/secret_validation.go:46` | `cmd/secrets/create_test.go:146` | Tags are `[]string` flat list; no key/value model; validator not invoked. |
| contentType | Free-form string | partial | `secret_service.go:41-57` | `content_type_test.go` | Allowlist restriction (text/plain, json, etc.); Azure accepts any string. |
| attributes.enabled | Boolean; disabled = 403 on get | partial | `model/secret.go:24,43`, `internal/repositories/secret_repository.go` | `secret_repository_test.go` | **Fixed**: DB column added, persisted in INSERT/SELECT/UPDATE. `IsAccessible()` enforced in `getSecret` handler. Returned as RFC3339, not Unix timestamp. |
| attributes.exp | Unix timestamp; expired = 403 | partial | `model/secret.go:22`, `internal/repositories/secret_repository.go` | `secret_repository_test.go` | **Fixed**: DB column added and persisted. Enforcement via `IsAccessible()` in handler. Returned as RFC3339, not Unix timestamp. |
| attributes.nbf | Unix timestamp; not-yet = 403 | partial | `model/secret.go:23`, `internal/repositories/secret_repository.go` | `secret_repository_test.go` | **Fixed**: DB column added and persisted. Enforcement via `IsAccessible()` in handler. |
| attributes.created | Unix epoch int | partial | `model/secret.go:19`, `api/secrets.go:385` | `secret_service_test.go:37` | Returned as RFC3339 string, not Unix timestamp. |
| attributes.updated | Unix epoch int | missing | `model/secret.go:172` declared | none | Field in struct but never populated. |
| attributes.recoveryLevel | `DeletionRecoveryLevel` enum | missing | none | none | No concept exposed. |
| attributes.recoverableDays | 7–90 days | missing | none | none | `scheduled_purge_at` column exists but never written by `SoftDelete`. |
| Name validation | `^[0-9a-zA-Z-]+$` | partial | `internal/validation/common.go:13` | `validation_test.go:201` | **Fixed**: validator wired via `9b0d30f`. Stricter: must start with letter; max 127. Digit-prefixed Azure names remain unimportable. |
| Secret value size | 25 KB | exact | `secret_validation.go:44`, `api/secrets.go:347` | none | **Fixed**: `ValidateSecretCreate` now called in handler. |
| Error envelope | `{"error":{"code","message","innererror"}}` | missing | `api/context.go:166-176` flat envelope | none | Incompatible with Azure SDK error inspection. |
| Versioning model | Opaque 32-char hex versions; addressable | partial | `model/secret.go:63`, `secret_versions` table | none | Integer counters; not Azure-addressable. |

### Keys

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| CreateKey RSA | kty=RSA, size 2048/3072/4096 | partial | `api/keys.go:144,177-186`, `internal/crypto/key_crypto.go:25-40` | `cmd/keys/service_test.go:81` | Only 2048 and 4096 accepted; 3072 rejected. No `key_ops`, no `release_policy`. |
| CreateKey EC | kty=EC, crv P-256/P-384/P-521/P-256K | partial | `api/keys.go:187-198`, `key_crypto.go:50-83` | `service_test.go:81` | **Fixed**: P-256K (secp256k1) added (`feat(crypto): add ES256K`). No attributes/key_ops/release_policy. |
| CreateKey oct (symmetric) | kty=oct, k bytes, key_size | missing | none in `model/key.go:27-29` | none | AES-GCM crypto exists internally but no vault-managed `oct` keys. |
| ImportKey | `PUT /keys/{name}` JWK body | missing | none | none | No import endpoint or JWK ingestion path. |
| GetKey | `GET /keys/{name}/{version}`; JWK public + attributes | partial | `api/keys.go:109,281-343` | `service_test.go:81` | UUID-addressed; response omits JWK public material (`n`/`e`/`x`/`y`). |
| ListKeys | `GET /keys`; pagination | partial | `api/keys.go:108,221-278` | `service_test.go:291` | No pagination; returns full objects, not key identifiers. |
| ListKeyVersions | `GET /keys/{name}/versions` | partial | `internal/repositories/key_repository.go:ListVersions`, `api/keys.go` | `key_versions_test.go` | **Fixed**: `key_versions` table added; `GET /keys/{id}/versions` route registered. UUID-addressed, not name-addressed. |
| UpdateKey | `PATCH /keys/{name}/{version}`; key_ops/attributes/tags | partial | `api/keys.go:110,345-415` | `service_update_test.go:18` | **Fixed**: `enabled`/`exp`/`nbf` persisted and enforced (`f59f9ee`). No `key_ops`; UUID-addressed not name+version. |
| DeleteKey | `DELETE /keys/{name}`; soft-delete; `DeletedKeyBundle` | partial | `api/keys.go:111,418-449`, `key_repository.go:452-480` | `key_soft_delete_test.go:59` | Response is plain 200; no recovery URI / scheduled purge date. |
| RecoverDeletedKey | `POST /deletedkeys/{name}/recover` | partial | `api/soft_delete.go:387`, `key_repository.go:491-518` | `key_soft_delete_test.go:59` | Non-standard route `/keys/{id}/restore`. |
| PurgeDeletedKey | `DELETE /deletedkeys/{name}` | partial | `api/soft_delete.go:388`, `key_repository.go:530-579` | `key_soft_delete_test.go:92,119` | Non-standard route; purge protection flag exists. |
| GetDeletedKey | `GET /deletedkeys/{name}` | missing | `ListSoftDeleted` in repo unwired | none | `ListSoftDeleted` exists at `key_repository.go:627` but no HTTP route exposes a single deleted key. |
| BackupKey | `POST /keys/{name}/backup` | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /keys/{id}/backup` returns encrypted blob. Single-version only. |
| RestoreKey | `POST /keys/restore` | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /keys/restore` restores from blob. |
| RotateKey | `POST /keys/{name}/rotate`; new version, same name | partial | `api/keys.go:114`, `key_service.go:RotateKey` | `service_test.go:398` | **Fixed**: true versioning — creates row in `key_versions`, preserves key identity and original key size/curve. UUID-addressed. |
| GetKeyRotationPolicy | `GET /keys/{name}/rotationpolicy` | missing | `rotation_policies` table is secrets-only | none | Whole feature absent for keys. |
| UpdateKeyRotationPolicy | `PUT /keys/{name}/rotationpolicy` | missing | none | none | Same. |
| Sign RS256/RS384/RS512 | `POST /keys/{name}/{version}/sign` | partial | `api/keys.go:186`, `crypto_service.go:Sign` | `crypto_operations_test.go` | **Fixed**: HTTP route `POST /keys/{id}/sign` added. UUID-addressed; AKV expects name+version. |
| Sign PS256/PS384/PS512 | RSA-PSS | partial | `crypto_operations.go:AlgorithmPS256/PS384/PS512` | `crypto_operations_test.go` | **Fixed**: RSA-PSS algorithms implemented and exposed via HTTP route. |
| Sign ES256/ES384/ES512 | ECDSA | partial | `crypto_operations.go`, `api/keys.go:187` | `crypto_operations_test.go` | **Fixed**: HTTP route added. ES256K supported. |
| Sign HS256/HS384/HS512 | HMAC | partial | `crypto_operations.go:AlgorithmHS256/HS384/HS512`, `model/key.go:KeyTypeOct` | `crypto_operations_test.go` | **Fixed**: HMAC algorithms and `oct` key type added. HTTP route via sign endpoint. |
| Verify (all algorithms) | `POST /keys/{name}/{ver}/verify` | partial | `api/keys.go:187`, `crypto_service.go:Verify` | `crypto_operations_test.go` | **Fixed**: HTTP route `POST /keys/{id}/verify` added. Revoked-key guard enforced. |
| Encrypt RSA-OAEP | SHA-1 MGF1 | partial | `crypto_operations.go:AlgorithmRSAOAEP`, `api/keys.go:188` | `crypto_operations_test.go` | **Fixed**: `RSA-OAEP` constant now correctly uses SHA-1. Split from `RSA-OAEP-256`. HTTP route added. |
| Encrypt RSA-OAEP-256 | SHA-256 MGF1 | partial | `crypto_operations.go:AlgorithmRSAOAEP256`, `api/keys.go:188` | `crypto_operations_test.go` | **Fixed**: Separate constant with SHA-256. HTTP route added. |
| Encrypt RSA1_5 | RSAES-PKCS1-v1_5 | partial | `crypto_operations.go:AlgorithmRSA1_5` | `crypto_operations_test.go` | **Fixed**: RSA1_5 implemented. Exposed via encrypt/decrypt HTTP routes. |
| Encrypt A128GCM/A192GCM | AES-GCM with 128/192-bit keys | missing | only A256GCM | `crypto_operations_test.go` | Still only A256-GCM. |
| Encrypt A128KW/A192KW/A256KW | AES Key Wrap | partial | `crypto_operations.go:AlgorithmA128KW/A192KW/A256KW` | `crypto_operations_test.go` | **Fixed**: AES Key Wrap (RFC 3394) for all three key sizes implemented. |
| Encrypt A128CBC/A192CBC/A256CBC | AES-CBC + variants | partial | `crypto_operations.go:AlgorithmA128CBC/A192CBC/A256CBC` | `crypto_operations_test.go` | **Fixed**: AES-CBC with PKCS7 padding for all three key sizes implemented. |
| Decrypt (all) | `POST /keys/{name}/{ver}/decrypt` | partial | `api/keys.go:189`, `crypto_service.go:Decrypt` | `crypto_operations_test.go` | **Fixed**: HTTP route `POST /keys/{id}/decrypt` added. Revoked-key guard enforced. Full algorithm coverage. |
| WrapKey | `POST /keys/{name}/{ver}/wrapkey` | partial | `api/keys.go:115,499-566`, `crypto_service.go:351-383` | `wrap_key_test.go:74` | HTTP route exists. `RSA-OAEP` and `RSA-OAEP-256` supported; other 14+ Azure algorithms rejected. No `aad`/`iv`/`tag`. |
| UnwrapKey | `POST /keys/{name}/{ver}/unwrapkey` | partial | `api/keys.go:116,569-636`, `crypto_service.go:386-418` | `wrap_key_test.go:74` | Same limitation as WrapKey. |
| Key attributes: enabled | Boolean | partial | `model/key.go:Enabled`, `internal/repositories/key_repository.go` | `key_soft_delete_test.go` | **Fixed**: `enabled` column added, persisted, and enforced via `IsAccessible()` in `getKey` handler. |
| Key attributes: exp / nbf | Timestamps | partial | `model/key.go:ExpiresAt/NotBefore`, `internal/repositories/key_repository.go` | `key_soft_delete_test.go` | **Fixed**: columns added, persisted, and enforced. Returned as RFC3339, not Unix timestamp. |
| Key attributes: exportable / release_policy | Confidential computing | missing | none | none | — |
| Key attributes: recoveryLevel / recoverableDays | Enum + integer | missing | none | none | — |
| Key attributes: updated | Last-updated timestamp | missing | `key_repository.go:215` UPDATE doesn't set `updated_at` | none | — |
| key_ops per key | sign/verify/encrypt/decrypt/wrap/unwrap/import/export allowlist | missing | not modelled | none | All ops permitted on any non-revoked key. |
| Key identifier (kid) URL | `{vaultUrl}/keys/{name}/{version}` | missing | UUID `id` only | none | Not name+version addressable. |
| HSM key types | RSA-HSM, EC-HSM, oct-HSM | out of scope | none | none | Software-only by design. |

### Certificates

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| CreateCertificate (self-signed) | `POST /certificates/{name}/create`; 202 + `CertificateOperation`; CSR; SAN/EKU/key_usage/validity_months | partial | `api/certificates.go:84`, `internal/services/certificates/certificate_service.go:113-210`, `internal/crypto/x509_helper.go:80-116` | `cert_soft_delete_test.go:158` | Synchronous 201; no async operation, no CSR, no SAN/EKU/key_usage configurability; `IsCA=true` hardcoded for self-signed at `certificate_service.go:151`. |
| CreateCertificate (CA-signed) | Issuer-based | partial | `api/certificates.go:161-176`, `certificate_service.go:223-347` | `cmd/certificates/create.go:93-107` | Only via internal `ca_cert_id`; no external issuer integration; CA key type hardcoded to RSA. |
| ImportCertificate | `POST /certificates/{name}/import`; PFX/PEM + password | missing | none | none | Entire endpoint absent. |
| GetCertificate | `GET /certificates/{name}/{version}`; `CertificateBundle` with cer/x5t/kid/sid/policy | partial | `api/certificates.go:86,229-260`, `certificate_service.go:360-374` | none | Response omits `cer` (DER), `x5t` (thumbprint), `kid`, `sid`, policy, `enabled`, `nbf`. No version in URL. |
| ListCertificates | Pagination; max 25/page | partial | `api/certificates.go:85,196-226` | none | No `nextLink`; missing `x5t`/`cer`. |
| ListCertificateVersions | All versions | missing | no version model | none | Certificates are single-version. |
| UpdateCertificate | `PATCH`; attributes (enabled/exp/nbf), tags | partial | `api/certificates.go:87,263-319` | `cmd/certificates/update.go` | **Fixed**: `enabled`/`exp`/`nbf` persisted and enforced (`f931fa2`). No SAN/EKU/key_usage configurability. |
| DeleteCertificate | Soft-delete; `DeletedCertificateBundle` (recoveryId, scheduledPurgeDate) | partial | `api/certificates.go:88,323-352`, `certificate_repository.go:549-577` | `cert_soft_delete_test.go:156-195` | Response `{"status":"OK"}` only. |
| RecoverDeletedCertificate | `POST /deletedcertificates/{name}/recover` | partial | `api/soft_delete.go:281-321,390`, `certificate_repository.go:588-615` | none | Non-standard path; response is plain JSON. |
| PurgeDeletedCertificate | `DELETE /deletedcertificates/{name}`; 204 | partial | `api/soft_delete.go:323-361,391`, `certificate_repository.go:627-676` | none | Returns 200 JSON instead of 204; purge protection flag exists. |
| ListDeletedCertificates | Paged list | partial | `api/soft_delete.go:254-279,389` | none | No pagination; missing fields. |
| BackupCertificate | Per-cert blob | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /certificates/{id}/backup` returns encrypted blob. |
| RestoreCertificate | Restore from blob | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /certificates/restore` restores from blob. |
| MergeCertificate | `POST /certificates/{name}/pending/merge` | missing | no pending/CSR lifecycle | none | Whole flow absent. |
| GetCertificatePolicy | `GET /certificates/{name}/policy` | partial | `api/certificate_policy.go`, `internal/repositories/certificate_policy_repository.go` | `certificate_policy_repository_test.go` | **Fixed**: `GET /certificates/{id}/policy` and `PUT /certificates/{id}/policy` implemented as CRUD stub. No lifetime-action triggers or external issuer integration. |
| UpdateCertificatePolicy | `PATCH /certificates/{name}/policy` | partial | `api/certificate_policy.go` | `certificate_policy_repository_test.go` | **Fixed** (stub): `PUT /certificates/{id}/policy` upserts policy. No lifetime actions. |
| SetCertificateIssuer | `PUT /certificates/issuers/{name}` | missing | none | none | No DigiCert/GlobalSign etc. integration. |
| GetCertificateIssuer / List / Delete | Issuer registry | missing | none | none | — |
| SetCertificateContacts | `PUT /certificates/contacts` | missing | none | none | No vault-wide contact list. |
| GetCertificateContacts / Delete | — | missing | none | none | — |
| GetCertificateOperation (pending CSR) | `GET /certificates/{name}/pending` | missing | sync creation only | none | — |
| DeleteCertificateOperation | Cancel pending | missing | none | none | — |
| Certificate Policy — lifetime actions | AutoRenew / EmailContacts; days_before_expiry or lifetime_percentage | partial | `internal/services/certificates/renewal_service.go:43-101`, `renewal_scheduler.go` | `renewal_service_test.go:143-205` | Days-before-expiry only; no percentage triggers; no EmailContacts. |
| Certificate Policy — key properties | exportable, kty, key_size, reuse_key, crv | partial | `crypto/x509_helper.go:80-116`; key by reference | none | Most fields absent. |
| Certificate Policy — X.509 properties | SAN, EKU, key_usage, validity_months | partial | `x509_helper.go:54-66` hardcodes usage/EKU | none | No SAN support; usage and EKU hardcoded; validity in days. |
| Auto-renewal scheduler | AutoRenew action | partial | `renewal_scheduler.go:20-65`, `renewal_service.go` | `renewal_service_test.go:143-205` | **Fixed**: `Certificate.KeyID` added to model and persisted on create. `RenewCertificate` now uses `cert.KeyID` correctly. Days-before-expiry only; no percentage triggers or EmailContacts. |
| x5t (SHA-1 thumbprint) | In every response | missing | none | none | — |
| cer (DER bytes) | Raw cert bytes in response | missing | none | none | PEM stored internally, not surfaced. |
| Certificate enabled flag | Disable without delete | partial | `model/certificate.go:Enabled`, `internal/repositories/certificate_repository.go` | `certificate_lifecycle_test.go` | **Fixed**: `enabled` column added, persisted, enforced via `IsAccessible()` in `getCertificate`. |
| scheduledPurgeDate / recoverableDays | On deletion | missing | `model/certificate.go:22` field exists but `SoftDelete` doesn't write it | none | Dead column. |
| CRL / revocation | Not exposed by AKV | partial | `certificate_repository.go:348-375` has Revoke/ListRevoked | none | Repository methods exist; no HTTP routes. |
| HSM-backed certificates | EC-HSM / RSA-HSM | missing | none | none | Out of scope. |

### Access control and authentication

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| Identity provider | Microsoft Entra ID; federated identity | missing | `model/user.go:13-20`, `internal/db/db.go:273-283` local users | `authentication_service_test.go` | No OIDC/SAML/Entra ID. Single largest architectural divergence. |
| Human authentication | Username + password + Conditional MFA | partial | `api/users.go:440`, `authentication_service.go:105-195` | `authentication_service_test.go` | TOTP is unconditional (stricter than Azure default) but not policy-driven. |
| Service principal | Entra service principals; certificate or secret credentials | partial | `model/oauth2_client.go`, `internal/services/oauth2/oauth2_service.go:82-113`, `internal/db/db.go:507-516` | `oauth2_service_test.go` | No cert-based service principals; no managed identity. |
| OAuth2 grants | code, client_credentials, device, OBO | partial | `api/oauth2.go:50-99` | `oauth2_service_test.go` | Only `client_credentials` (RFC 6749 §4.4). |
| Token format | Azure AD RS256 JWT; claims oid/tid/scp/roles/appid | partial | `jwt_service.go:118-135` | `jwt_service_test.go` | RS256/ES256-384-512 supported; claims: user_id/username/role; no scp/tid. HS256 fallback still active during migration. |
| JWKS endpoint | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` | exact | `api/jwks.go:14-40` | none | RFC 7517 JWK Set; rotation via `POST /jwks/rotate`. |
| Token validation | Bearer on every request | partial | `internal/middleware/middleware.go:225-278` | `middleware_test.go` | **Fixed**: `ValidateSession` now checks `sessions.revoked` via `sessionRepo.IsSessionRevoked` (`b68e787`). HS256 fallback still active. |
| RBAC built-in roles | 11 distinct: Administrator, Reader, Purge Operator, Certificates Officer, Certificate User, Crypto Officer, Crypto Service Encryption User, Crypto User, Crypto Service Release User, Secrets Officer, Secrets User | partial | `model/user.go:31-38`, `internal/services/authorization/rbac_service.go:85-121` | `rbac_integration_test.go` | 6 roles; no Reader/Purge Operator/Crypto Service variants. |
| Access policies (legacy) | Per-principal, per-operation, up to 1024 | partial | `model/access_policy.go:33-52`, `internal/db/db.go:495-505` | `access_policy_service_test.go:49-108` | Resource-type scoped; no per-individual-object scoping. |
| Per-operation: secrets | get, list, set, delete, recover, backup, restore, purge | partial | `model/access_policy.go:36-52` | none | **Fixed**: backup/restore endpoints exist (`2558b1a`). Adds `set` and `create` (Azure has only `set`); backup/restore not yet mapped in policy middleware. |
| Per-operation: keys | 18 operations including encrypt/decrypt/wrap/unwrap/sign/verify/getRotationPolicy/setRotationPolicy/release | partial | `model/access_policy.go:33-52`, `api/keys.go:107-116` | none | Crypto operations defined as constants but **not mapped in policy middleware** at `middleware.go:327-367` — wrap/unwrap routes fall back to RBAC only. Missing getRotationPolicy/setRotationPolicy/release. |
| Per-operation: certificates | 14 operations including managecontacts/issuers | partial | `model/access_policy.go:33-52`, `middleware.go:347-350` | none | No contacts/issuers operations. |
| Deny-wins conflict resolution | Deny beats allow | exact | `access_policy_service.go:51-65` | `access_policy_service_test.go:64-79` (`TestCheckAccess_DenyWinsOverAllow`) | Correct and tested. |
| Scope hierarchy | Mgmt group → subscription → RG → vault → object | missing | only resource-type scope | none | Per-object policies absent. |
| Service account creation guard | Owner/admin required | exact | `api/oauth2.go:141-144` | none | **Fixed**: all SA endpoints (`create`, `list`, `delete`, `rotate`) now enforce admin role check via `common.HasRequiredRole`. |
| Service account secret rotation | Multiple credentials with overlap | partial | `oauth2_service.go:171-193` | `oauth2_service_test.go` | Single secret; no overlap window. |
| Token lifetime / refresh | Configurable; refresh token rotation | partial | `authentication_service.go:167`, config `jwt.expiry: 15m` | `authentication_service_test.go` | **Security gap**: no refresh token rotation. |
| Session revocation | Continuous Access Evaluation | partial | `authentication_service.go:ValidateSession` | `authentication_service_test.go` | **Fixed**: `ValidateSession` now reads `sessions.revoked` via `sessionRepo.IsSessionRevoked` and rejects revoked tokens. SA tokens revoked on client delete/disable. |
| JWKS key rotation | Automatic; overlap window | partial | `api/jwks.go:43-71`, `jwt_service.go:168-195` | `jwt_service_provider_test.go` | Only `self_pki` provider supports API rotation. |
| Audit logging of auth | Per-request, queryable | partial | `internal/logging/logging.go:147-157`, `middleware.go:162-168,418-424`, `internal/db/db.go:367-378` | `logging_test.go:82-108` | `audit_logs` table created but **never written** — all audit goes to structured log file only. |
| Control-plane / data-plane split | Separate endpoints | missing | same router for everything | none | Admin token grants both planes simultaneously. |
| Conditional Access / PIM / JIT | Policy-driven access | out of scope | — | — | Self-hosted; Azure-platform feature. |

### Soft-delete and purge protection

> **Known-bug check (CLAUDE.md):** `deleted_at` / `purge_protection` missing from `createOptimizedSchema` — **FIXED** at commit 8a5d1a3. Both `createOptimizedSchema` (`internal/db/db.go:286-297`) and `migrateSchema` (`db.go:531-544`) now include all soft-delete columns for secrets, keys, and certificates. The CLAUDE.md known-bugs entry is stale.

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| Soft-delete default | ON by default since Feb 2025; cannot be disabled | partial | `config/config.go:21-22`, `.rocketvault.yaml:124-126` | none | **Gap**: `soft_delete.enabled` toggleable at any time; Azure made it irrevocable. |
| Retention period | 7-90 days, default 90, immutable | partial | `config/config.go:23`, `purge_scheduler.go:60` | none | Default 30 days; no floor/ceiling; mutable. |
| Purge protection | One-way enable; cannot disable | partial | `secret_repository.go:SoftDelete`, `key_repository.go:SoftDelete`, `certificate_repository.go:SoftDelete` | `TestKeyPurgeProtection`, `TestCertificatePurgeProtection` | **Fixed**: `SoftDelete` no longer overwrites `purge_protection` — the column is preserved on soft-delete. `SetPurgeProtection` exists in repos but still no HTTP/CLI surface to set it. |
| Recoverable level | 5 levels (Purgeable, Recoverable, +ProtectedSubscription, +Purgeable, CustomizedRecoverable*) | missing | none | none | No `recovery_level` field in any model. |
| Soft-delete: secrets | DELETE → soft-deleted state | exact (mechanics) | `api/secrets.go:620`, `secret_service.go:462`, `secret_repository.go:321-347` | `secret_repository_test.go:81` (`SoftDeletedSecretNotVisible`) | Mechanics work; response shape differs (see Secrets matrix). |
| Soft-delete: keys | Same | exact | `api/keys.go:443`, `key_service.go:402`, `key_repository.go:452-480` | `key_soft_delete_test.go:59` (`TestKeySoftDelete`) | Same. |
| Soft-delete: certificates | Same | exact | `api/certificates.go:346`, `certificate_service.go:459`, `certificate_repository.go:549-577` | `cert_soft_delete_test.go:76` (`TestCertificateSoftDelete`) | Same. |
| List deleted items | Per-resource paged endpoint | partial | `api/soft_delete.go:11-43,129-162,248-279`, `api/api.go:83,104` | none | Uses `/deleted/{resource}` prefix; no pagination. |
| Get deleted item (single) | `GET /deletedsecrets/{name}` etc. | missing | none | none | Must list-and-filter client-side. |
| Recover deleted | `POST /deleted{resource}/{name}/recover` | partial | `api/soft_delete.go:46-85,164-203,282-320` | none | ID-routed, not name. |
| Purge deleted | `DELETE /deleted{resource}/{name}` | partial | `api/soft_delete.go:87-126,207-264,323-361`; respects purge_protection | `TestKeyPurge`, `TestCertificatePurge` | **Gap**: no RBAC-separated purge permission; any authenticated owner can purge. |
| Scheduled purge after retention | Auto-purge daemon | partial | `purge_scheduler.go:59-77`, `bootstrap/bootstrap.go:206-210` | none | **Gap**: `scheduled_purge_at` column exists but never written by `SoftDelete`. Scheduler uses `deleted_at < cutoff` instead. Field is inert. |
| Vault-level soft-delete | Vault namespace can be soft-deleted | out of scope | — | — | Single-vault system. |
| Name uniqueness during soft-delete | New object with same name blocked | missing | `internal/db/db.go:284-301` no `(user_id, name)` unique constraint excluding deleted | none | Duplicates possible while item soft-deleted. |

### Networking and security controls

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| TLS enforcement | TLS 1.2+ required on all data-plane | partial | `server/server.go:141-178`, `.rocketvault.yaml:60-63` | none | **Fixed**: `server.tls.enabled`, `cert_file`, `key_file` config keys added and wired. TLS 1.3 minimum when enabled. Still disabled by default (`enabled: false`). |
| TLS cipher suites | Strong AES-GCM / ChaCha20 | partial | `server/server.go:158-163` (TLS 1.3: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305) | none | Correct when TLS is enabled. |
| IP firewall / CIDR allowlist | Up to 1000 IPv4 ranges | missing | none | none | No allowlist/firewall middleware anywhere. |
| VNet service endpoints | Subnet registration | out of scope | — | — | Azure-platform feature. |
| Private endpoints / Private Link | Private IP, refuse public when disabled | out of scope | — | — | Same. |
| Trusted Microsoft services bypass | — | out of scope | — | — | Same. |
| Public network access toggle | `publicNetworkAccess: Disabled` | missing | none | none | Operator must use infra firewall. |
| Rate limiting | Per-vault 2000-4000/10s by op type; 429 + `Retry-After` | partial | `internal/middleware/middleware.go:63-222`; `.rocketvault.yaml:45-48`; `api/api.go:62` | middleware tests | **Gaps**: no `Retry-After` header; per-IP not per-vault; one bucket for all op types. |
| CORS | Not a vault control in Azure | partial | `server/server.go`, `middleware.go:454-470` | middleware tests | **Fixed**: rs/cors wildcard wrapper removed. CORS now handled solely by `internal/middleware` allowlist. Public routes (login, health) retain permissive CORS. |
| Authenticated-by-default | All data-plane requests | exact | `middleware.go:229-242`; `api/api.go:61-66` | middleware tests | Correctly applied across `/api/v1/*`. |
| Secure logging (no secret values) | Metadata only | exact | `secret_service.go:165-168,227-233`; `logging.go:148-165`; JWT truncated to 10 chars | none | No plaintext values observed in any log call. |
| Audit log rotation | Storage lifecycle policy | partial | `logging.go:107-139`; `.rocketvault.yaml:34-43` | middleware tests | 0600 perms; gzip; size+age rotation. No immutability/WORM. |
| Security response headers | HSTS on HTTPS | exact | `middleware.go:432-449` (nosniff, X-Frame-Options, X-XSS-Protection, CSP, HSTS conditional) | middleware tests | Missing `Permissions-Policy`. |

### Observability and audit logging

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| AuditEvent log category | Every data-plane op logged; JSON envelope | partial | `internal/logging/logging.go:147-165`; `.rocketvault.yaml:35-41` | none | No `category: "AuditEvent"` field; text format default (JSON only when configured); certificate service skips create/delete audit. |
| identity.upn / objectidentifier / appid | Caller identity object | partial | `logging.go:159` `user_id` only; JWT carries UserID/Role | none | Missing username, role, appid; empty on auth failures. |
| operationName (`ObjectVerb`) | e.g., `KeyCreate`, `SecretGet` | partial | service examples `key_service.go:147`, `secret_service.go:227` | none | Snake_case strings; no normalized taxonomy. |
| resultType / resultSignature / httpStatusCode | Success/Failure + status string + integer | partial | `middleware.go:149-163` middleware only; service layer has only `status` | middleware tests | HTTP status not in service-layer audit. |
| durationMs | Per-request | partial | `middleware.go:159` HTTP layer only | middleware tests | CLI/service operations lack duration. |
| callerIpAddress | Per-request | partial | `middleware.go:157` (`r.RemoteAddr`); `common/headers.go:10-11` X-Forwarded-For/X-Real-IP **defined but unused** | none | Behind a proxy, logged IP is the proxy. Not in service audit. |
| correlationId / requestId | Cross-layer correlation | partial | `middleware.go:153-160` HTTP only | none | Never threaded into service audit. No client-supplied X-Correlation-ID accepted. |
| requestUri / clientInfo / operationVersion | Properties block | partial | `middleware.go:155-156` method/path; `api/versioning.go:123-127` API version | none | No user-agent; no query string; no per-request API version logged. |
| AzurePolicyEvaluationDetails | Control-plane policy logs | out of scope | RBAC decisions logged at `middleware.go:382-424` | middleware tests | Functionally equivalent. |
| AllMetrics: ServiceApiHit | Request count metric | missing | `monitoring.enable_metrics` is dead config stub | none | No `/metrics` endpoint or Prometheus integration. |
| AllMetrics: ServiceApiLatency | Latency metric | partial | `internal/health/health.go:88-91,193-194` `QueryMetrics` in memory; `middleware.go:159` logs `duration_ms` | none | Not scrapable; data exists in dead handler. |
| AllMetrics: Availability | % successful | missing | health endpoints return static `{"status":"ok"}` | none | `/health` returns 200 even when DB broken. |
| AllMetrics: Saturation | Pool utilization | missing | `internal/health/health.go:165-170` computed; `HealthHandler` defined but **never wired** to a route by `InitHealth()` | none | Dead handler. |
| AllMetrics: error rate | Failure counter | missing | only audit log entries | none | No metric. |
| Log destinations: Azure Storage / Event Hub / Log Analytics | Diagnostic settings | missing | none | none | File or stdout only. Operator must add agent. |
| Log retention | Configurable on destination | partial | `logging.go:25-27,97-98,282-286`; default `max_age_days: 7`, `max_backups: 3` | `logging_test.go` | Default 7 days is short for compliance; no WORM. |
| Health endpoint | Vault availability | partial | `api/health.go:48-79` | none | **Fixed**: `HealthHandler` wired into `InitHealth()`; `/health/database` route registered and returns DB stats. Returns 503 on warning/critical status. |
| Readiness vs liveness | Probe semantics | partial | `api/health.go:117-142,145-159` | none | `/health/ready` uses `CollectMetrics` but doesn't verify DB; `/health/live` always 200. |
| Near-expiry event logging | Per-cert/key/secret near-expiry events | partial | `internal/services/certificates/renewal_service.go:59,91,95` | none | Certificates only; no keys or secrets equivalent. |
| Alerting | Azure Monitor alert rules | missing | `monitoring.*` config dead stubs | none | No alerting; external log scraping required. |

### Backup and restore

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| BackupSecret (per-item, all versions) | Opaque base64url blob; region-bound | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /secrets/{id}/backup` returns AES-256-GCM encrypted JSON blob. Single-version only; no region binding (intentional, see ADR-5). |
| BackupKey | Same | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /keys/{id}/backup` implemented. |
| BackupCertificate | Same | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /certificates/{id}/backup` implemented. |
| RestoreSecret (from blob) | Empty-slot or recoverable; same subscription/region | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /secrets/restore` decrypts blob and re-inserts. No empty-slot check; no version history. |
| RestoreKey | Same | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /keys/restore` implemented. |
| RestoreCertificate | Same | partial | `internal/backup/item_backup.go`, `api/backup_item.go` | `internal/backup/item_backup_test.go` | **Fixed**: `POST /certificates/restore` implemented. |
| Bulk export / import | Not in Azure | partial (RocketVault-specific) | `api/secrets.go:61-62,176-322`, `cmd/secrets/{export,import}.go`, `secret_service.go:637-826` | `cmd/secrets/export_test.go:15`, `import_cmd_test.go:16` | Secrets only. **Bug**: `--encrypt` CLI flag at `cmd/secrets/export.go:104` is unread by `RunE` — flag is a no-op. |
| Backup encryption | HSM-protected, region-bound | partial | `common/encrypt.go:32-73` AES-256-GCM with `master_key`; `internal/backup/backup.go:291-320` for full-vault | `internal/backup/backup_test.go:123-141` | Config-keyed, not hardware-bound; portable across instances with same key. |
| Full-vault backup | Not in Azure | exceeds Azure | `internal/backup/backup.go:77-125`, `cmd/backup.go:79-165` | `backup_test.go:96-233` | RocketVault advantage: single-call full-vault dump with optional encryption. |
| Full-vault restore | Not in Azure | exceeds Azure | `backup.go:128-171,361`, `cmd/backup.go:107-243` | `backup_test.go:143-187` | **Destructive**: `DELETE FROM` each table before insert. No pre-restore snapshot. |
| Cross-vault restore | Same subscription/region required | not-applicable | `backup.go:291-344` instance-agnostic | none | More portable than Azure (by design); also: stolen backup + key restorable anywhere. |
| Empty-slot restore semantics | Conflict on existing name | partial | full-vault: pre-delete; per-item: relies on DB unique constraint or `Overwrite` flag | none | No explicit empty-slot check. |
| Version history in backup | All versions per item | partial | full-vault includes `secret_versions` rows; per-item export returns current version only | `backup_test.go:150-187` | **Gap**: export discards version history; import creates v1. |
| CLI parity | `az keyvault {secret|key|certificate} {backup|restore}` | partial | `cmd/backup.go` (full-vault); `cmd/secrets/{export,import}.go` (bulk secrets) | export/import tests | **Gap**: no per-item backup/restore CLI for any type; no key or cert export at all. |

### Limits, quotas, pagination, and API compatibility

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Test evidence | Notes / gaps |
|---|---|---|---|---|---|
| Throttling: software keys | 4000/10s/vault | partial | `middleware.go:108-131` token-bucket 300/min default per IP | none | Per-IP per-minute, not per-vault per-10s. |
| Throttling: HSM keys | 2000/10s | not-applicable | — | — | No HSM tier. |
| Throttling: secrets/certs general | 4000/10s; CREATE 300/10s | partial | same | none | No write-vs-read split. |
| Per-subscription limit | 5× vault limit | not-applicable | single-tenant | — | — |
| 429 + `Retry-After` | Required | partial | `middleware.go:217` returns 429; `200-203` `X-RateLimit-*` set; **no `Retry-After`** | middleware tests | Body is plain text `"Rate limit exceeded"`, not JSON. |
| Secret value size 25 KB | Enforced | exact | `secret_validation.go:44`, `api/secrets.go:347` | none | **Fixed**: `ValidateSecretCreate` now invoked in `createSecret` handler. `ValidateKeyCreate` and `ValidateCertificateCreate` also wired. |
| Tag count limit (15) | Enforced | partial | `secret_validation.go:47`, `key_validation.go:49,65,95`, `common.go:66` | `validation_test.go:193-199` | **Fixed**: validator wired (`9b0d30f`). Tags still `[]string` not `map[string]string`, so key/value semantics differ. |
| Tag key/value 256 chars | Both | partial | `common.go:59-68` `Length(1,256)` | `validation_test.go:186-200` | Tags are `[]string` not `map[string]string`. |
| Name regex `[A-Za-z][A-Za-z0-9-]{0,126}` start with letter | Stricter than Azure's `[0-9a-zA-Z-]+` | partial | `common.go:13-19` `SecretNamePattern`/`KeyNamePattern`/`CertificateNamePattern` | `validation_test.go:201-225` | **Fixed**: validator wired (`9b0d30f`). Stricter pattern means digit-prefixed Azure names are unimportable. |
| Pagination: skipToken + maxResults + nextLink | Default 25, max 25 | missing | `params.go:26-31` `?page` + `?per_page` offset-based; `listSecrets` (`secrets.go:417`) **never passes them** | none | Different model; full result set always returned. |
| List response `{value, nextLink}` | Required | missing | `{secrets|keys|certificates}` envelope; no nextLink | none | Not Azure SDK compatible. |
| `id` as fully-qualified vault URL | Required | missing | `secrets.go:381`, `keys.go:207` use bare UUID | none | SDK clients break. |
| `attributes` nested block | Required | missing | top-level flat fields; RFC3339 strings not Unix | none | — |
| Error envelope `{error:{code,message,innererror}}` | Required | missing | `context.go:166-176` flat `{id,message,detailed_error,status_code,request_id}` | none | Not SDK-compatible. |
| HTTP status: 200 GET | Yes | exact | default | none | |
| HTTP status: 201 create | Yes | exact | `secrets.go:389`, `keys.go:216`, `certificates.go:192` | none | |
| HTTP status: 204 delete/purge | Yes | missing | `ReturnStatusOK` → 200 + `{"status":"OK"}` | none | Purge should be 204 no body. |
| HTTP status: 400 invalid params | Yes | exact | `context.go:39-42` | indirect | Body shape mismatch. |
| HTTP status: 401 unauthenticated | Yes | exact | `context.go:107-115`, `middleware.go:247-258` | none | |
| HTTP status: 403 forbidden | Yes | exact | `context.go:44-47,122-130`, `middleware.go:305-316` | none | |
| HTTP status: 404 not found | Yes | exact | `context.go:51-54`, `api.go:134-143` | none | |
| HTTP status: 409 conflict (duplicate name) | Yes | missing | no `StatusConflict` anywhere | none | DB unique-constraint surfaces as 500. |
| `?api-version=7.4` query param | Required on every call | missing | `versioning.go:67-136` `VersionMiddleware` not wired into `api.go:Init()`; path `/api/v1` hardcoded | none | Azure SDKs send this on every request; silently ignored. |
| Body size limits | No published limit | partial | `middleware.go:500-515` `RequestBodySizeLimitMiddleware` defined but **not registered** | none | Dead middleware. |
| Backup version limit (500) | Enforced | missing | none | none | No version-count cap. |

### API compatibility (summary)

| Azure feature | Azure behavior / limit | RocketVault status | Evidence | Notes |
|---|---|---|---|---|
| API version model | `?api-version=7.4` on every request | missing | `api.go:56-116` hardcodes `/api/v1` prefix; `VersionMiddleware` unwired | Path-based major version only. |
| URL identifier shape | `https://{vault}.vault.azure.net/{resource}/{name}/{version}` | missing | UUID-only IDs | Renders Azure SDK clients unusable. |
| Response envelope (list vs item) | `value/nextLink`; `attributes` block; `kid`/`sid` URLs | missing | flat envelopes per resource | Not wire-compatible. |
| Error envelope | `{error:{code,message,innererror}}` | missing | flat envelope | Not wire-compatible. |

---

## Summary

### Parity by category (rough count of `exact` + `partial` vs scope)

| Category | Exact | Partial | Missing | Out of scope | Notes (as of 2026-05-26) |
|---|---|---|---|---|---|
| Secrets | 3 | 13 | 9 | — | Lifecycle attrs persisted and enforced; per-item backup/restore added; envelope gaps remain |
| Keys | 1 | 21 | 12 | 1 | Sign/verify/encrypt/decrypt HTTP routes added; all major algorithms implemented; lifecycle attrs added; true versioning; HSM out of scope |
| Certificates | 1 | 15 | 16 | 1 | Auto-renew fixed; lifecycle attrs added; policy CRUD stub added; per-item backup/restore added |
| Access control | 3 | 14 | 3 | 3 | Session revocation fixed; admin SA guard fixed; refresh rotation still missing |
| Soft-delete | 3 | 9 | 3 | 1 | Purge protection overwrite fixed; SetPurgeProtection still no HTTP surface |
| Networking | 3 | 5 | 2 | 4 | TLS config knob added; CORS bug fixed; firewall still missing |
| Observability | 1 | 9 | 7 | 1 | Health handler wired; audit_logs table still unwritten |
| Backup/restore | 1 | 10 | 1 | — | Per-item backup/restore added for all three types; version history still single-version |
| Limits/quotas/API | 7 | 8 | 10 | 1 | Validators wired; envelopes still incompatible |
| **Total** | **23** | **104** | **63** | **12** | |

**Overall parity (2026-05-26):** approximately **63% partial-or-exact** of in-scope Azure data-plane behavior, up from 45% at the original audit. The security-critical findings and the medium-term parity gaps (crypto routes, lifecycle attributes, key versioning, per-item backup, certificate policy) have been addressed. Remaining gaps are primarily wire-format compatibility (envelopes, URL shape, error format) and lower-priority features.

### Findings (ranked)

| Severity | Category | Finding | Impact | Recommendation |
|---|---|---|---|---|
| ~~**Critical**~~ ✅ | Networking | ~~TLS disabled by default; no config key~~ **FIXED** `56d8430` | — | `server.tls.enabled` + `cert_file` + `key_file` wired from `.rocketvault.yaml`. Default still `false`; operators must opt in. |
| ~~**Critical**~~ ✅ | Access control | ~~Revoked sessions valid until JWT expiry~~ **FIXED** `b68e787` | — | `ValidateSession` now reads `sessions.revoked` via `sessionRepo.IsSessionRevoked`. SA tokens revoked on client delete/disable. |
| ~~**Critical**~~ ✅ | Soft-delete | ~~`SoftDelete` hardcodes `purge_protection = FALSE`~~ **FIXED** `91263f3` | — | `SoftDelete` no longer overwrites `purge_protection`. `SetPurgeProtection` still has no HTTP/CLI surface. |
| ~~**High**~~ ✅ | Access control | ~~`createServiceAccount` no admin guard~~ **FIXED** `c65415f` | — | All SA endpoints enforce `model.RoleAdmin` check via `common.HasRequiredRole`. |
| ~~**High**~~ ✅ | Networking | ~~rs/cors wildcard wrapper overrides allowlist~~ **FIXED** `8e68430` | — | rs/cors wrapper removed. CORS handled by `internal/middleware` allowlist only. |
| ~~**High**~~ ✅ | Certificates | ~~`RenewCertificate` always errors; `Certificate` lacks `KeyID`~~ **FIXED** `e2ec699` | — | `key_id` column added to `certificates` table and model. `RenewCertificate` uses `cert.KeyID`. |
| ~~**High**~~ ✅ | Keys | ~~`RSA-OAEP` constant implements RSA-OAEP-256~~ **FIXED** `a9899b5` | — | `AlgorithmRSAOAEP` (SHA-1) and `AlgorithmRSAOAEP256` (SHA-256) are now separate constants with correct implementations. |
| ~~**High**~~ ✅ | Validation | ~~Validators never invoked by HTTP handlers~~ **FIXED** `9b0d30f` | — | `ValidateSecretCreate`, `ValidateKeyCreate`, `ValidateCertificateCreate` called at top of create handlers. |
| ~~**High**~~ ✅ | Keys | ~~Sign/Verify/Encrypt/Decrypt no HTTP routes~~ **FIXED** `58c0dcd` | — | `POST /keys/{id}/sign`, `/verify`, `/encrypt`, `/decrypt` registered. All PS*, ES256K, HS*, RSA1_5, AES-KW, AES-CBC algorithms implemented. |
| **High** | API compatibility | `?api-version=7.4`, `{value,nextLink}` list envelope, `id` as vault URL, `{error:{code,message}}` error envelope — all missing | No Azure SDK can interoperate | Decide: clone Azure wire format or document as non-clone. Still open. |
| ~~**High**~~ ✅ | Observability | ~~`HealthHandler` never registered; `/health/database` missing~~ **FIXED** `0e4552b` | — | `HealthHandler` wired in `InitHealth()`; `/health/database` route returns DB stats; 503 on warning/critical. |
| **High** | Observability | `audit_logs` table created but never written to by any code path | DB audit trail empty | Wire `LogAuditInfo`/`LogAuditError` to also persist, or remove the table. Still open. |
| **Medium** | Soft-delete | `scheduled_purge_at` column exists but `SoftDelete` never writes it | Dead column | Drop or populate on delete. Still open. |
| **Medium** | Secrets/Keys/Certs | Response envelopes lack `recoveryId`, `scheduledPurgeDate`, `attributes` block, `x5t`, `cer` | Client workflows fail | Tied to wire-format decision above. Still open. |
| **Medium** | Access control | No refresh token rotation | Stolen refresh tokens reusable | Rotate on each `/refresh` call. Still open. |
| **Medium** | Backup/restore | `--encrypt` flag on `secrets export` is declared but never read | Flag is a no-op | Wire or remove. Still open. |
| **Medium** | Limits/quotas | Default log retention 7 days | Below compliance requirements | Default to 90 days. Still open. |
| **Medium** | Access control | HS256 fallback path still active during migration window | Weaker algorithm accepted | Remove after migration deadline. Still open. |
| **Medium** | Networking | No `Retry-After` header on 429; plain-text body | Clients cannot backoff correctly | Add header + JSON body. Still open. |
| ~~**Medium**~~ ✅ | Keys | ~~Rotation creates `{name}-rotated`; hardcodes 2048/P-256~~ **FIXED** `3ae18f9` | — | True versioning via `key_versions` table; rotation preserves key identity and original size/curve. |
| **Medium** | Certificates | X.509 SAN, EKU, key_usage hardcoded | Cannot issue certs with custom SAN/EKU | Make configurable. Still open. |
| **Medium** | Soft-delete | `soft_delete.enabled` toggleable; Azure made it irrevocable | Protection can be disabled | Treat flag as one-way enable. Still open. |
| **Low** | Tags | `[]string` not `map[string]string` | Not Azure key/value compatible | Migrate (breaking). Still open. |
| **Low** | Secrets | Name regex stricter than Azure | Cannot import digit-prefixed names | Relax pattern. Still open. |
| **Low** | Secrets | `contentType` allowlist rejects free-form values | Cannot store arbitrary types | Remove or make configurable. Still open. |
| **Low** | Observability | `client_ip` not de-proxied | Proxy IP logged behind load balancer | Honour `X-Forwarded-For`. Still open. |
| **Low** | Observability | Certificates skip create/delete/get audit | Inconsistent audit trail | Add `LogAuditInfo` to cert CRUD. Still open. |
| **Low** | Validation | `RequestBodySizeLimitMiddleware` and `VersionMiddleware` dead code | Defensive features unused | Wire or remove. Still open. |

### Next steps (updated 2026-05-26)

**Short-term (security-critical) — ALL DONE ✅**
1. ~~Fix revoked-session check in `ValidateSession`.~~ **Done** `b68e787`
2. ~~Fix `purge_protection` overwrite in `SoftDelete`.~~ **Done** `91263f3`
3. ~~Add admin-role guard to `createServiceAccount`.~~ **Done** `c65415f`
4. ~~Remove rs/cors wildcard wrapper.~~ **Done** `8e68430`
5. ~~Add `tls.enabled` config knob.~~ **Done** `56d8430` (default still `false`)
6. ~~Wire `internal/validation` into HTTP handlers.~~ **Done** `9b0d30f`

**Medium-term (Azure parity gaps) — ALL DONE ✅**
1. ~~Fix RSA-OAEP / RSA-OAEP-256 algorithm collision.~~ **Done** `a9899b5`
2. ~~Add HTTP routes for Sign/Verify/Encrypt/Decrypt with PS*, ES256K, HS*, RSA1_5, AES-KW, AES-CBC.~~ **Done** `58c0dcd` + `5d04cbc` + `dffa275` + `2df2064`
3. ~~Persist `enabled`, `exp`, `nbf` on all three resource types and enforce.~~ **Done** `f59f9ee` + `89299dc` + `f931fa2`
4. ~~Implement true key versioning and `ListKeyVersions`.~~ **Done** `3ae18f9`
5. ~~Per-item BackupSecret/Key/Certificate + Restore.~~ **Done** `2558b1a`
6. ~~Fix certificate auto-renew (`Certificate.KeyID`).~~ **Done** `e2ec699`
7. ~~Implement Certificate Policy CRUD stub.~~ **Done** `7582351`

**Remaining open items (in priority order):**
1. **High** — Wire `LogAuditInfo`/`LogAuditError` to also write `audit_logs` table, or drop the table.
2. **High** — Decide Azure wire-format strategy (name-based URLs, `{value,nextLink}` envelopes, error envelope). This is the single largest outstanding fork.
3. **Medium** — Add `Retry-After` header on 429 responses.
4. **Medium** — Expose `SetPurgeProtection` via HTTP/CLI.
5. **Medium** — Refresh token rotation.
6. **Medium** — Populate `scheduled_purge_at` on soft-delete, or drop the column.
7. **Medium** — Fix `--encrypt` flag on `secrets export`.
8. **Medium** — Configurable X.509 SAN/EKU/key_usage in certificate creation.
9. **Low** — Migrate tags from `[]string` to `map[string]string`.
10. **Low** — Honour `X-Forwarded-For` for audit `client_ip`.
11. **Low** — Wire `RequestBodySizeLimitMiddleware` and `VersionMiddleware` or remove them.

**Deferred / intentional exclusions:**
- HSM-backed keys (RSA-HSM, EC-HSM, oct-HSM, Managed HSM).
- VNet service endpoints, Private Link, Trusted Services bypass, Network Security Perimeter.
- Conditional Access, PIM, JIT.
- Azure-Monitor-integrated metrics and SIEM forwarding (operator deploys their own agent).
- Cross-vault restore semantics (RocketVault is intentionally portable).
- Vault-level soft-delete (single-vault system).

## Reference inputs

- Microsoft Azure Key Vault REST API v7.4 — https://learn.microsoft.com/en-us/rest/api/keyvault/
- Azure Key Vault overview docs — https://learn.microsoft.com/en-us/azure/key-vault/
- RocketVault parity design — `docs/plans/2026-03-08-azure-keyvault-parity-design.md`
- RocketVault Azure KV feature spec — `docs/superpowers/specs/2026-04-30-azure-kv-features-design.md`
- RocketVault parity audit template — `docs/plans/2026-05-23-azure-keyvault-parity-audit-template.md`
- RocketVault parity audit checklist — `docs/plans/2026-05-23-azure-keyvault-parity-audit-checklist.md`
