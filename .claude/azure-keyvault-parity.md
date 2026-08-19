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
| Rotation policy (auto-rotate) | ✅ | ✅ vault-scoped `rotation_policies` (`vault_id` + `model.Scope`-based repo/service, closed 2026-08-17 — see `.claude/known-bugs.md` § B23 for a follow-on upgrade-path fix) + CLI `secrets rotation ...` (`--vault`, `vaultcli.RequireDataAction`); scheduler auto-rotates due, enabled policies (`internal/services/secrets/scheduler_service.go`) — CLI-only, no HTTP route, matching today's design | ✅ |

## 2. Key management — operations

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Create key | ✅ | ✅ `POST /keys` | ✅ |
| Import key | ✅ (JWK) | ❌ no import route — `ActionKeysImport` is declared in `model/azure_roles.go` and granted to Crypto Officer/Administrator, but no path maps to it in `MapRouteToDataAction` | ❌ |
| Get / List / List versions | ✅ (`GET /keys/{name}/{version}` returns the version's public JWK — `n`/`e` for RSA, `x`/`y`/`crv` for EC) | ✅ `GET /keys`, `/keys/{id}`, `/keys/{id}/versions`, and now `/keys/{id}/versions/{version}` (added 2026-08-19, § B26) for one version's metadata — but the response is `model.KeyVersion{KeyID, Version, CreatedAt}` only, no public JWK components at all, thinner than even the current-key `GET /keys/{id}` (which does emit them via `buildKeyResponse`); a version's public key material is reached only indirectly, by passing `version` to sign/verify/encrypt/decrypt/wrap/unwrap (see the Rotate row below), never by reading it back directly | 🟡 (route now exists, closing the missing-route gap, but it's bookkeeping-only — no public JWK — unlike Azure's real response) |
| Update (attributes) | ✅ | ✅ `PUT /keys/{id}` | ✅ |
| Delete (soft) | ✅ | ✅ `DELETE /keys/{id}` | ✅ |
| Rotate (new version) | ✅ | 🟡 `POST /keys/{id}/rotate` — `KeyService.RotateKey` still archives the old material into `key_versions` and overwrites `keys.value` in place (RSA/ECDSA/ES256K only; OCT has no branch), but old versions are no longer a dead end: all six crypto operations (`sign`/`verify`/`encrypt`/`decrypt`/`wrap`/`unwrap`) now accept an optional `version` field and resolve to the matching `key_versions` row, so data encrypted or signed before a rotation is usable again over REST (fixed 2026-08-19, `.claude/known-bugs.md` § B26). `GET /keys/{id}/versions/{version}` also now exists for reading one version's metadata. The one gap left open: none of the four crypto CLI commands (`rocketvault keys sign`/`verify`/`wrap`/`unwrap` — `cmd/keys/sign.go`, `verify.go`, `wrap.go`, `unwrap.go`) has a `--version` flag; each still calls its service method with `Version` unset, so all four only operate on the current version. REST is the only way to address an archived version today | 🟡 (full REST parity; CLI `--version` fast-follow not yet done) |
| Sign / Verify | ✅ | ✅ `POST /keys/{id}/sign`, `/verify` | ✅ |
| Encrypt / Decrypt | ✅ | ✅ `POST /keys/{id}/encrypt`, `/decrypt` | ✅ |
| Wrap / Unwrap key | ✅ | ✅ `POST /keys/{id}/wrap`, `/unwrap` | ✅ |
| Backup / Restore | ✅ | 🟡 `POST /keys/{id}/backup`, `/keys/restore` — registered on the flat routes only (`api/backup_item.go` `InitBackupItem` attaches to `BaseRoutes.Keys`, never to the vault-scoped subrouter, so `/vaults/{name}/keys/{id}/backup` 404s), and `ItemBackupService.BackupKey` gates on `key.UserID == caller` on top of `ActionKeysBackup`, so a Crypto User who does not own the key is refused. Key backups now also carry `key_versions` history (`BackupKey`/`RestoreKey`, fixed 2026-08-19, § B26): a rotated key that is backed up and restored keeps its archived versions instead of silently losing them | 🟡 |
| Get/Set rotation policy | ✅ | 🟡 `GET/PUT/DELETE /keys/{key_id}/rotationpolicy`, mapped to `ActionKeysRotationPolicyRead`/`Write` in `MapRouteToDataAction` (`mapKeyAction`) and granted only to Crypto Officer + Administrator, matching Azure's `keyrotationpolicies/*`. `RotationScheduler` → `RotationExecutor.Check` (`rotation.keys.*` config, started in `bootstrap.go`) sweeps `KeyRotationPolicyRepository.GetDuePolicies` — enabled, `rotate_after_days > 0`, `next_rotation_at` passed — and calls `RotateKey`, so the rotate action genuinely executes. `expiry_days` is now acted on too (fixed 2026-08-19, `.claude/known-bugs.md` § B27): `RotateKey` stamps `ExpiresAt` on every rotation when the policy is enabled and `expiry_days > 0`. `notify_before_expiry_days` is still only persisted and echoed back — no near-expiry notification exists, since RocketVault has no notification delivery mechanism anywhere in the codebase yet (roadmap Phase 3), so Azure's Notify lifetime action is now half-implemented rather than fully absent | 🟡 |
| Release (confidential compute) | ✅ | ❌ no TEE attestation flow | ❌ |
| EXPORT blocked (keys non-extractable) | ✅ | ✅ `buildKeyResponse` emits only JWK public components (`crypto.ExtractPublicComponents`) and `model.KeyVersion` omits `Value`; the one response carrying stored material is the backup blob, and that is the master-key AES-256-GCM ciphertext (`common.EncryptSecret`) or a bare `pkcs11:` handle — never plaintext PEM | ✅ |

*Re-verified 2026-08-19 against `api/keys.go`, `api/key_rotation_policy.go`,
`api/backup_item.go`, `internal/services/keys/{key_service,crypto_service,
rotation_executor,rotation_scheduler}.go`, `internal/backup/item_backup.go`,
`internal/repositories/key_rotation_policy_repository.go`,
`internal/services/authorization/data_actions.go` and `model/azure_roles.go`.
Four rows moved ✅ → 🟡. The largest correction is **key versions are archival
only**: nothing in the API takes a version — no `/keys/{id}/{version}` route,
and no `Version` field on `SignRequest`/`EncryptRequest`/`DecryptRequest`/
`WrapKeyRequest`/`UnwrapKeyRequest` — so `RotateKey` overwriting `keys.value`
in place makes every pre-rotation ciphertext permanently undecryptable, where
Azure keeps old versions addressable and usable. The 2026-08-14 "full
rotation-execution parity" claim was half right: the scheduler really does
rotate due policies, but only the rotate lifetime action is implemented;
`expiry_days`/`notify_before_expiry_days` are inert columns. **Not a change:**
`rocketvault keys verify` (`cmd/keys/verify.go`, added 2026-08-18) calls
`CryptoService.Verify` directly — the same service `POST /keys/{id}/verify`
uses — so it is a CLI front end on an existing capability and moved no row.
Also confirmed unchanged: no attestation/release code exists anywhere in the
tree (Release stays ❌). Note for §1/§9 owners: `model.KeyRotationPolicy`
carries `vault_id` and its CRUD is `model.Scope`-scoped, but
`RotationExecutor.Check` sweeps under `model.NewAdminScope(uuid.Nil)` — the
policies are vault-scoped, the sweep is deliberately vault-agnostic.*

*Corrected 2026-08-19 (second pass, same day): the "Rotate (new version)" and
"Backup / Restore" rows above were re-verified against the just-landed key
version addressability fix (`docs/superpowers/plans/2026-08-19-key-version-
addressability.md`, design at `docs/superpowers/specs/2026-08-19-key-version-
addressability-design.md`, commits `78ad152..f03957a`). The core gap this
section flagged earlier today — "no crypto op takes a version... a prior
version can never be used again" — is fixed: `SignRequest`/`VerifyRequest`/
`EncryptRequest`/`DecryptRequest`/`WrapKeyRequest`/`UnwrapKeyRequest` all gained
an optional `Version` field (`internal/services/keys/crypto_service.go`), a new
`KeyRepository.ReadVersionValue` reads the archived `key_versions.value` a
prior rotation already wrote but nothing previously read back, and a new
`GET /keys/{id}/versions/{version}` route (`api/keys.go`) exposes one version's
metadata directly, closing the `Get / List / List versions` row's "not
addressable" caveat above too. Backup/restore was extended in the same body of
work so a rotated key's `key_versions` history survives a backup/restore cycle
(previously it silently reintroduced the exact bug this fix closes). See
`.claude/known-bugs.md` § B26 for the full root-cause writeup, including a
bundled latent cache-key bug (`resolveKeyMaterial` hardcoding its cache key's
version to `0`) found and fixed during design. Left open: no CLI `--version`
flag on any of the four crypto CLI commands — `rocketvault keys sign`,
`keys verify`, `keys wrap`, and `keys unwrap` all call their service method
with `Version` unset — flagged as a fast-follow in the design's
"Not in scope" section, not done as part of this pass.*

## 3. Key management — types & algorithms

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| RSA key sizes | 2048 / 3072 / 4096 | 2048 / 3072 / 4096 | ✅ |
| EC curves | P-256, P-256K, P-384, P-521 | P-256 / P-384 / P-521 work over REST on both software and HSM-backed instances. P-256K's two REST bugs are both fixed: the validator rejection (`ValidateKeyCreate` blocking it before the handler's own four-curve check — `.claude/known-bugs.md` § B24, 2026-08-19) and the follow-up uncaught 500 on HSM-enabled instances (§ B25, 2026-08-19). `POST /keys {"curve":"P-256K"}` now returns 201 when `hsm.enabled: false` (verified live). On an HSM-enabled instance (`hsm.enabled: true`, this repo's own configured default) it now returns a clean 400 (`curve: curve not supported by PKCS#11 provider: P-256K`) instead of leaking a 500 — HSM-backed P-256K key creation itself remains genuinely unsupported (`ecOID`, `ErrUnsupportedCurve`; no PKCS#11 mechanism exists for it in this provider), but the failure mode is now correct | 🟡 (full REST support on software-backed instances; HSM-backed instances now fail cleanly instead of leaking a 500, but still can't create the key) |
| Symmetric (oct/oct-HSM) keys | 🟡 oct-HSM 128/192/256 on **Premium vaults, public preview** (Managed HSM: GA) | ✅ `POST /keys` `"type": "OCT"` with `bits` 128/192/256 → `KeyService.CreateOctKey`; HSM-only by design (`SoftwareKeyProvider.GenerateAESKey` always returns `ErrOctKeysRequireHSM`), stored as a `pkcs11:` label so no key material enters the process. No CLI support (`keys create` takes RSA/ECDSA only) | ✅ (HSM-gating matches Azure's HSM-only rule; algorithm coverage differs — see the AES row) |
| Sign/Verify — RSA | RS256/384/512, PS256/384/512, RSNULL | RS256/384/512, PS256/384/512 | 🟡 (no RSNULL TLS edge case) |
| Sign/Verify — EC | ES256, ES256K, ES384, ES512 | ES256/384/512 in software and on HSM keys (`signMechanisms`, `CKM_ECDSA` with a Go-side pre-hash); ES256K is software-only (secp256k1, key type `ES256K`) but now reachable end-to-end over REST — verified live: a REST-created P-256K key's `POST /keys/{id}/sign`/`verify` with `algorithm: ES256K` both work correctly (valid DER signature, correct accept/reject on tamper), on a software-backed instance. An HSM-enabled instance can't create a P-256K key at all (no PKCS#11 mechanism, now cleanly rejected — see the EC curves row above), so ES256K sign/verify is unreachable there | 🟡 (works fully on software-backed instances; unreachable on HSM-enabled ones because key creation itself is unsupported there) |
| Sign/Verify — symmetric (HMAC) | HS256, HS384, HS512 (oct-HSM) | ❌ in practice: `CryptoOperations.Sign`/`Verify` implement HS256/384/512 for `oct` keys, but every oct key is PKCS#11-backed and `PKCS11KeyProvider`'s `signMechanisms` map has no HMAC entry | ❌ |
| Wrap/Encrypt — RSA | RSA-OAEP-256, RSA-OAEP, RSA1_5 | RSA-OAEP-256 and RSA-OAEP on both wrap/unwrap and encrypt/decrypt, software and HSM (`CKM_RSA_PKCS_OAEP` with SHA-256/SHA-1 params); RSA1_5 is implemented for encrypt/decrypt on software keys only (`AlgorithmRSA1_5`, no PKCS#11 mechanism) and deliberately excluded from the wrap/unwrap allowlist | 🟡 (RSA1_5 encrypt/decrypt only — Azure marks it "not recommended" anyway) |
| Wrap/Encrypt — AES (KW/CBC/GCM) | AES-KW, AES-GCM, AES-CBC on oct-HSM (Premium preview / Managed HSM) | A128/192/256 KW on HSM-backed AES keys (`CKM_AES_KEY_WRAP` via C_WrapKey, with an algorithm↔`key.Bits` match check); AES-KW requires 8-byte-aligned input (RFC 3394, matches Azure). A128/192/256 CBC and AES256-GCM exist only in the software path (`crypto_operations.go`) and are unreachable today — no software-backed symmetric key can be created (`ErrOctKeysRequireHSM`), and the PKCS#11 path rejects both (`isHSMWrapAlgorithm`, `oaepMechParams`) | 🟡 (KW only; CBC/GCM code present but no key can reach it) |

*Corrected 2026-08-19 (third pass): both P-256K REST bugs are now fixed. The
validator rejection (`.claude/known-bugs.md` § B24) landed first; the follow-up —
an HSM-enabled instance (`hsm.enabled: true`, this repo's own configured default)
returning an uncaught HTTP 500 instead of a clean 400 for the same request, since
PKCS#11 has no P-256K mechanism and `crypto.ErrUnsupportedCurve` wasn't
special-cased in `api/keys.go`'s error switch — is now fixed too (§ B25). Both
fixes were re-verified: unit tests reproduce the exact real error values and
wrapping from `KeyService.CreateECDSAKey`/`RotateKey`, and the software-backed
(`hsm.enabled: false`) path was additionally confirmed live end-to-end against a
running server — `POST /keys {"curve":"P-256K"}` returns 201, and `sign`/`verify`
with `algorithm: ES256K` both work correctly on the resulting key. On an
HSM-enabled instance, the identical create request now returns a clean 400
(`curve: curve not supported by PKCS#11 provider: P-256K`) — HSM-backed P-256K
key creation remains genuinely unsupported (no PKCS#11 mechanism exists for it in
this provider), but the failure mode is now correct rather than leaking an
internal error. `RotateKey` hits the identical `GenerateECDSAKey` call for an
ES256K key and got the same fix via the shared `writeKeyError` helper in
`api/errors_key.go`, pinned by its own regression test even though it's currently
unreachable in practice (an HSM instance can never create the P-256K key it would
need to rotate in the first place). Also confirmed while testing this, but
unrelated to P-256K and **not fixed** — `POST /keys/{id}/encrypt` and `/wrap`
against *any* EC key (tested against both P-256 and P-256K) 500 with a leaked
internal parse error rather than a clean "not supported for EC keys" rejection;
Azure doesn't support encrypt/wrap on EC keys either, so this isn't a capability
gap, but the error handling is a pre-existing rough edge worth its own note if
RocketVault's error responses get audited for information leakage.*

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
| Per-vault resource isolation | ✅ | ✅ `idx_{secrets,keys,certificates}_vault_name` unique indexes on `(vault_id, name)`, vault_id scoping | ✅ |
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

*Corrected 2026-08-18: this section's "Per-vault purge protection" row covers
the vault's own `PurgeProtection` flag, which always correctly blocked purging
the vault itself. But `.claude/known-bugs.md` § B20's same-day follow-up found
`VaultService.PurgeVault`'s cascade (`cascadeAdapter.PurgeVaultContents`) ran
an unconditional delete of every contained secret/key/certificate with no
check of *their* individual `purge_protection` flags — so purging an
unprotected vault silently destroyed protected items inside it, bypassing the
exact per-item guarantee B20's main fix had just made real. Fixed the same
day: `PurgeVault` now also calls the new `CascadeRepository.HasProtectedContent`
(`internal/services/vaults/cascade_adapter.go`) before purging and refuses,
fail-closed, if any contained item is protected — see `vault_service.go`'s
`PurgeVault` and `.claude/known-bugs.md` § B20 for the full history.*

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
| Access-policy engine (legacy model) | Separate, mutually-exclusive engine from RBAC (`enableRbacAuthorization` toggle picks one) | Two *layers*, not two interchangeable engines: `role_assignments` is the only allow path on the data plane (`HasDataAction` → `model.azureRoleDataActions`), and `access_policies` survives there purely as an explicit-deny override, evaluated first. `access_policies` is still an allow path for the non-data-plane `(vaults, manage)` grant (`CanManageVault`/`CanManageRoleAssignments`) | 🟡 simplified (reasonable for a single self-hosted product, but not a literal two-engine match) |
| Deny-overrides precedence | ✅ | ✅ confirmed in `access_policy_service.go`: "Explicit deny always wins. Falls back to RBAC when no matching policy exists." | ✅ |
| Machine identity (service principals) | ✅ | ✅ OAuth2 client-credentials service accounts | ✅ |
| MFA on human login | via Entra | ✅ TOTP enforced | ✅ |

*Corrected 2026-08-19, two items.* **(1)** The access-policy row above previously
read "Same underlying `access_policies` table for both manual grants and
role-assignment expansion — one engine, not two." That stopped being true on
2026-08-02 (`049f962`): `ExpandRole` (`roles.go`) returns `nil` for every Azure
built-in role, so a role grant materialises **no** `access_policies` row, and
`PolicyMiddleware`'s own comment now states "access_policies survives only as an
explicit-deny override and is evaluated FIRST, so a deny cannot be outvoted by a
role grant." Only the legacy vocabulary ever expanded, and it can no longer be
granted (see the closing paragraph of this section). **(2)** Route shape no longer
changes either the authorization scope or the data scope. `scopeFromRequest`
(`api/context.go`) used to hand legacy flat routes (`/api/v1/secrets/{id}`, …) an
*owner* scope — SQL predicate `user_id = ?` with no vault term — while
`PolicyMiddleware` authorized those same requests against the **default** vault,
so a caller could read and write their own resources in any other vault and
survive revocation there. Fixed 2026-08-16 in `1e16aa5`: every route shape now
yields `model.NewVaultScope` against the vault `PolicyMiddleware` checked. No cell
in §6 asserted the old behavior, so this is recorded rather than corrected — see
`.claude/known-bugs.md` § B11 and
`docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md`.

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
| Data Access Administrator | Manage role assignments, scoped to the vault, **for eight named roles only** — Administrator, Reader, Secrets User/Officer, Crypto User/Officer, Certificates Officer, Crypto Service Encryption User. Azure's ABAC condition bars it from granting itself, Purge Operator, or Certificate User | `Key Vault Data Access Administrator`: `ActionRoleAssignmentsWrite`, `ActionRoleAssignmentsDelete`, plus the same eight-role allow-list (`nonAdminGrantableRoles`, `role_assignment_service.go`) enforced on **both** grant (`AssignRole`) and revoke (`RevokeAssignment`) via `ErrRoleNotGrantable` → HTTP 403. A global admin bypasses the allow-list (`CallerIsGlobalAdmin`) | ✅ exact allow-list match — also closes the "role-assignment management is global-admin-only" known limitation from the v4.0.0 release notes |

*Added 2026-08-19: the eight-role restriction is new — before 2026-08-18 any caller
who passed `CanManageRoleAssignments` could grant **any** role, so a Data Access
Administrator could grant itself Purge Operator or a second Data Access
Administrator, defeating the role's purpose. `ccdcb3d` closed the grant half,
`662781e` the revoke half (a non-global-admin could still revoke a role it could
not grant). RocketVault's allow-list is byte-for-byte Azure's documented Data
Access Administrator set. See `.claude/known-bugs.md` §§ B19, B21; pinned by
`TestAssignRole_NonAdminCannotGrant*` / `TestRevokeAssignment_NonAdminCannotRevoke*`
(`internal/services/authorization/role_assignment_service_test.go`),
`TestRoleAssignments_RevokeDeniedRoleNotGrantable_Returns403`
(`api/role_assignments_test.go`).*

**Not added:** `Key Vault Crypto Service Release User` (confidential-compute key release) — RocketVault has no TEE/attestation flow to gate at all (see §2's "Release (confidential compute)" row, still ❌). Adding the role name without a real capability behind it would repeat the exact anti-pattern the legacy vault-role vocabulary (`vault-reader`, `secrets-officer`, etc.) was retired for. **Not added either:** `Key Vault Contributor` — a control-plane role for Azure Resource Manager, not a data-plane concept RocketVault's self-hosted model has an equivalent for.

**Net:** the *architecture* (tenant-global identities + vault-scoped role assignments
evaluated directly against `model.azureRoleDataActions`, with an access-policy
explicit-deny override checked first) is a genuine, deliberate match to Azure's real
RBAC model, and — per the 2026-08-13 correction above — the *individual role
boundaries* are now byte-for-byte too. All eleven bundles were re-verified line by
line against `model/azure_roles.go` on 2026-08-19 with no discrepancy found: Reader is
metadata-only, Crypto Officer is a true superset of Crypto User including wrap/unwrap,
Administrator carries no derived gaps, and — new since the last pass — Data Access
Administrator now carries Azure's own grant restriction. Crypto User's `update`/`backup`
gap (the last live boundary gap from the 2026-08-13 pass) was closed 2026-08-17.

RocketVault also still ships a legacy, pre-Azure role vocabulary (`vault-reader`,
`crypto-officer`, `crypto-user`, etc., in
`internal/services/authorization/roles.go`) that is retained only for two purposes —
CLI display of not-yet-upgraded historical `role_assignments` rows, and the P2 upgrade
migration's translation of those rows to Azure role names
(`internal/db/role_backfill.go`) — and can no longer be granted going forward
(`IsLegacyRole`, rejected in `AssignRole`).

*Corrected 2026-08-19: this paragraph previously claimed the legacy vocabulary has
"no live authorization weight." Precisely, it has no live **data-plane** weight — a
legacy-named `role_assignments` row grants zero data actions, because
`RoleGrantsDataAction` knows only the eleven Azure names. But a legacy grant made
before the `IsLegacyRole` rejection landed also materialised `access_policies` rows
via `ExpandRole`, and revoking the assignment is the only thing that deletes them.
For `vault-admin` specifically, that bundle includes `(vaults, manage)`, which
`CanManageVault` and `CanManageRoleAssignments` still honour — so a historical
`vault-admin` row can still confer vault-management and role-assignment-management
authority even though it confers no secret, key, or certificate access. New grants
cannot create this state; only pre-existing rows carry it. Out of scope for parity
comparison against Azure either way.*

## 7. Soft-delete, purge protection, recovery

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Soft-delete (all object types) | ✅ | ✅ secrets/keys/certs `deleted_at` | ✅ |
| List deleted / recover | ✅ | ✅ `/deleted/...` restore | ✅ |
| Purge (permanent delete) | ✅ | ✅ `/deleted/.../purge` | ✅ |
| Purge protection (block early purge) | ✅ | ✅ `purge_protection` (per-key + per-vault) | ✅ |
| Configurable retention window | ✅ (7–90 days) | ✅ `retention_days` + purge scheduler | ✅ |

*Corrected 2026-08-18: the 2026-08-18 Azure Key Vault parity audit (Critical
Finding #2, `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`) found the
per-key half of this row was aspirational — the `purge_protection` DB column,
each repository's `SetPurgeProtection` method, and the enforcement check in
`PurgeSecret`/`PurgeKey`/`PurgeCertificate` all existed, but no API field,
service method, or CLI flag ever set the flag, and vault-level purge
protection didn't cascade to protect contained items. Fixed the same day: a
`--purge-protection` CLI flag and `purge_protection` API field on
create/update for all three resource types, plus a vault-level cascade check
in each `Purge*` service method — see `.claude/known-bugs.md` § B20 for the
full root cause and fix. The row's claim is now actually true, not
aspirational.*

*Extended 2026-08-18 (same day, commit `74dfab8`, `.claude/known-bugs.md` §
B22): closed the reverse-direction gap B20 left open. Bulk vault-level purge
(`VaultService.PurgeVault`'s cascade to `CascadeRepository.PurgeVaultContents`)
ran an unconditional `DELETE ... WHERE vault_id = ?` against secrets, keys,
and certificates with no `purge_protection` check at all, so purging a vault
silently destroyed every contained item regardless of its own protection
flag — the exact guarantee B20 had just made real for the single-item purge
path. `PurgeVault` now calls the new `CascadeRepository.HasProtectedContent`
(backed by a `HasProtectedContent` method on each of
`SecretRepository`/`KeyRepository`/`CertificateRepository`) after its own
vault-level `PurgeProtection` check and before `s.repo.Purge`, refusing with
`ErrVaultContentsPurgeProtected` if any contained item is still protected;
the check fails closed (refuses the purge) if the read itself errors, same
posture as B20's own cascade check.*

## 8. HSM & cryptographic protection

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Software crypto module | ✅ Standard (FIPS 140 L1) | ✅ Go crypto + AES-256-GCM | 🟡 (not FIPS-validated) |
| HSM-backed keys | ✅ Premium (FIPS 140-3 L3) | 🟡 PKCS#11 provider (`hsm.enabled`); RSA sign/verify/encrypt/decrypt, EC sign/verify (P-256/P-384/P-521), and AES-KW generate/wrap/unwrap all HSM-backed. P-256K has no PKCS#11 mechanism — `POST /keys {"curve":"P-256K"}` on an HSM-enabled instance (this repo's own configured default) correctly returns a clean 400 (fixed 2026-08-19, `.claude/known-bugs.md` § B25 — it previously leaked an uncaught 500); P-256K key creation only works end-to-end when `hsm.enabled: false` (see §3). AES-CBC/GCM code exists in the software crypto path but is unreachable in practice: no software-backed symmetric key can ever be created (`ErrOctKeysRequireHSM`), so real AES support is HSM-AES-KW only | 🟡 |
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
| Backup / restore (whole instance) | ✅ (per-object) | ✅ `rocketvault backup create/restore`; dumps every table across *all* vaults in one file — no `--vault` scoping flag exists (`cmd/backup.go`'s `requireBackupAdmin` comment: "operates on the whole database across every vault -- there's no vault to scope this to") | ✅ broader than Azure's per-object model, not vault-scoped |

---

## Summary

*Reconciled 2026-08-19 against a full section-by-section re-verification (see the
dated notes throughout §§1-3, 5-7, 10). Two rows moved out of Partial entirely
(rotation-policy vault-scoping, Crypto User's `update`/`backup` gap — both closed
before this pass and now confirmed live); several new Partial findings surfaced in
§2 and §3 that predate this pass but had never been rolled up here.*

**Strong parity (✅):** secret lifecycle + versioning, rotation policies (now
vault-scoped with a working auto-rotate scheduler, closed 2026-08-17, see §1),
certificate CRUD + policy + auto-renewal, multi-vault isolation, per-vault purge
protection that correctly cascades to contained items (closed 2026-08-18, see §5,
§7), vault-scoped deleted/restore/purge across all three resource types (closed
2026-08-13, see §5), and RBAC: the vault-scoped role-assignment architecture matches
Azure's real RBAC model, and — re-verified line-by-line against `model/azure_roles.go`
on 2026-08-19 — all eleven role bundles are byte-for-byte accurate (Reader is
metadata-only, Crypto Officer is a true superset of Crypto User including wrap/unwrap,
Administrator carries no derived gaps, and Data Access Administrator now enforces
Azure's own eight-role grant allow-list, closed 2026-08-18, see §6).

**Partial (🟡):**
- **Key operations beyond CRUD** (see §2): fixed 2026-08-19 (§ B26) — key
  *versions* are still archival by nature (`RotateKey` still archives the old
  material into `key_versions` and overwrites `keys.value` in place), but they
  are no longer a dead end: all six crypto operations
  (sign/verify/encrypt/decrypt/wrap/unwrap) now accept an optional `version`
  field and can address any archived version — pre-rotation ciphertexts and
  signatures are usable again over REST, matching Azure's model. The new `GET
  /keys/{id}/versions/{version}` route closes the missing-route gap for
  reading a version back, but only for bookkeeping metadata
  (`model.KeyVersion{KeyID, Version, CreatedAt}`); unlike Azure's real
  `GET /keys/{name}/{version}`, it returns no public JWK, so a version's
  public key is still only reachable indirectly via a crypto op with
  `version` set. Still open: none of the four crypto CLI commands
  (`rocketvault keys sign`/`verify`/`wrap`/`unwrap`) has a `--version` flag,
  so the fix is REST-only for now. Key backup/restore is
  still registered on the flat routes only (404s on the vault-scoped path) and
  is still additionally owner-gated on top of the RBAC check, but a backed-up
  and restored key now keeps its `key_versions` history instead of silently
  losing it (also part of the 2026-08-19 fix). Rotation-policy scheduling
  genuinely executes the rotate lifetime action, but
  `expiry_days`/`notify_before_expiry_days` are stored and never acted on —
  Azure's Notify lifetime action has no RocketVault equivalent.
- **Key types & algorithms** (see §3): P-256K's two REST bugs are both fixed — the
  validator rejection (2026-08-19, § B24) and the follow-up uncaught 500 on
  HSM-enabled instances (2026-08-19, § B25). Creation, sign, and verify now work
  end-to-end over REST, verified live, on software-backed instances
  (`hsm.enabled: false`). On HSM-enabled instances (`hsm.enabled: true`, this
  repo's own configured default), the same create request now returns a clean 400
  instead of leaking a 500 — HSM-backed P-256K key creation remains genuinely
  unsupported (no PKCS#11 mechanism exists for it in this provider), but the
  failure mode is now correct. RSA1_5 exists for encrypt/decrypt only, not wrap
  (matching Azure's own "not recommended" posture on that algorithm). AES-CBC/GCM
  software code exists but is unreachable in practice: no software-backed
  symmetric key can ever be created (`ErrOctKeysRequireHSM`), so real AES support
  is HSM-AES-KW only — matching, not exceeding, Azure's Managed-HSM/Premium-preview
  restriction.
- **HSM** (see §8): PKCS#11 path exists but is not the default; covers RSA
  (sign/verify/encrypt/decrypt), EC P-256/P-384/P-521 (sign/verify), and AES-KW
  (generate/wrap/unwrap) — P-256K has no PKCS#11 mechanism, and no AES-CBC/GCM
  PKCS#11 mechanism exists either. No FIPS 140-3 L3 validation (a certification
  process, not achievable through code).
- **Access-policy engine** (see §6): a genuine architectural match to Azure's
  deny-overrides model, but simplified to two layers under one table rather than
  Azure's two fully separate, switchable engines — reasonable for a single
  self-hosted product, not a literal match.
- **Certificate User role** (see §6): placeholder parity — `ActionCertificatesRead`
  only, identical to Reader's certificate slice today, because RocketVault has no
  cert/key/secret linkage yet (Azure's version also reads the linked private key).

**Not supported (❌):** key import (declared as a role action in
`model/azure_roles.go` but unroutable — no path maps to it), key release to
confidential compute (TEE), HMAC sign/verify on symmetric keys (implemented in the
crypto-operations layer but unreachable in practice — every oct key is HSM-backed and
the PKCS#11 provider has no HMAC mechanism), public-CA / ACME certificate enrollment,
geo-replication, and cloud log sinks (Event Hub / Azure Monitor archive). RSNULL is
intentionally omitted (TLS edge case, deprecated).

**RocketVault extras (➕) beyond Azure vaults:** secret generate + bulk export/import,
whole-instance backup/restore spanning every vault in a single file (broader than,
not a like-for-like match with, Azure's per-object backup model — see §10), JWKS
endpoint with rotating signing keys (os_store / self_pki / external_pki), hash-chained
tamper-evident audit log, built-in SOC 2 / GDPR compliance reports, per-IP rate
limiting, health probes, and fully self-hosted operation with no cloud dependency.

---

*Sources: codebase (`api/`, `internal/services/keys`, `internal/crypto`, `model/`,
`cmd/`) and Microsoft Learn — Azure Key Vault Overview and "Key types, algorithms,
and operations" (`about-keys-details`), retrieved 2026-06-02.*
