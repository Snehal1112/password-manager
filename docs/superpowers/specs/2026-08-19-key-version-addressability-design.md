# Key Version Addressability — Design

**Date:** 2026-08-19
**Status:** Proposed
**Branch target:** `v-4.0.0`
**Source finding:** `.claude/azure-keyvault-parity.md` §2 — "Rotate (new
version)" and the Summary's "Key operations beyond CRUD" paragraph: key
versions are archival metadata only; no crypto operation takes a version, so
`RotateKey` overwriting `keys.value` in place makes every pre-rotation
ciphertext (and every pre-rotation signature verification) permanently
unusable, where Azure keeps old versions addressable and usable.

## Goal

Make archived key versions usable again: `sign`/`verify`/`encrypt`/`decrypt`/
`wrap`/`unwrap` must be able to target a specific prior version of a key, not
only the current one. This closes a real data-loss bug — anything encrypted or
signed before a rotation becomes permanently unrecoverable today, because
verification and decryption always run against the *current* material.

## Current state (verified against source)

The archived material already exists in storage — this is a wiring gap across
the repository/service/API layers, not a data-recovery or migration problem.

- `KeyRepository.CreateVersion(ctx, keyID, version, value)`
  (`internal/repositories/key_repository.go:683`) inserts the **encrypted
  value** into `key_versions.value` on every rotation
  (`internal/services/keys/key_service.go:855,862`, `RotateKey`). The column
  exists (`internal/db/db.go:424-432`, `:776-784`) and is populated correctly
  today.
- Nothing reads it back. `model.KeyVersion` (`model/key.go:58-62`) has no
  `Value` field. `KeyRepository.ListVersions`
  (`internal/repositories/key_repository.go:702-724`) explicitly selects only
  `version, created_at` — its own doc comment says "Raw key material (value)
  is not returned." No method exists to fetch one version's value at all.
- No crypto operation accepts a version. All six service-layer request types —
  `SignRequest`/`VerifyRequest`/`EncryptRequest`/`DecryptRequest`/`WrapKeyRequest`/
  `UnwrapKeyRequest` — live together in
  `internal/services/keys/crypto_service.go:22-123` and none has a `Version`
  field; `cryptoService.loadAndAuthorize`
  (`internal/services/keys/crypto_service.go:257`) always reads the current
  row and every call site uses `key.Value` directly. **Correction from an
  earlier draft of this design:** the HTTP-facing request/response types for
  all six operations also live together, in `api/keys.go:96-172`
  (`WrapKeyRequest`/`WrapKeyResponse`/`UnwrapKeyRequest`/`UnwrapKeyResponse`
  at `:96-119`, `SignKeyRequest` through `DecryptKeyResponse` at `:121-172`) —
  not split across `model/key.go` as first written. `model/key.go` does
  separately declare types named `WrapKeyRequest`/`WrapKeyResponse`/
  `UnwrapKeyRequest`/`UnwrapKeyResponse` (`:130-158`), but `grep -rn
  "model\.WrapKeyRequest\|model\.UnwrapKeyRequest"` returns no matches
  anywhere in the tree — they are pre-existing dead code, unrelated to the
  six live HTTP handlers, and this design does not touch them.
- **HSM keys are not a blocker.** `RotateKey`
  (`internal/services/keys/key_service.go:783-888`) never calls any
  destroy/delete on the PKCS#11 provider — it only generates new material and
  archives the old handle string. Archived `pkcs11:<label>` values remain live
  token objects. `resolveKeyMaterial`'s existing PKCS#11 branch
  (`internal/services/keys/crypto_service.go:203-208`) works unmodified once
  it receives an archived handle.
- **Version numbering has an existing asymmetry that any fix must preserve.**
  `RotateKey` only starts writing to `key_versions` on the *first* rotation —
  it archives the pre-rotation value as version 1 and the new value as version
  2 in the same call (`key_service.go:854-864`). A never-rotated key has
  **zero** `key_versions` rows; its only material is `keys.value`, which is
  version 1 implicitly. After N rotations, `key_versions` holds exactly N+1
  rows (1..N+1), and the highest one always duplicates `keys.value`.
- **A latent cache bug, found during this investigation, must be fixed as
  part of this work.** `resolveKeyMaterial`
  (`internal/services/keys/crypto_service.go:197-236`) caches decrypted PEM
  material keyed on `(key.ID, 0)` — the version is **hardcoded to zero**,
  not derived from anything. `internal/keycache`'s `Get`/`Set`
  (`internal/keycache/memory_cache.go:34,38`) already take a real `version
  int` parameter; nothing currently passes anything but 0. Harmless today
  because only one version is ever resolved per key. Once this fix lands,
  a second version's material would be served from the first version's cache
  entry (or vice versa) without this being corrected — a silent
  wrong-plaintext / wrong-signature bug, not merely a missed cache.
- **Backup/restore doesn't carry version history.**
  `ItemBackupService.BackupKey`/`RestoreKey`
  (`internal/backup/item_backup.go:97-131`) marshal/restore only the current
  `*model.Key` row. A key backed up and restored today loses all
  `key_versions` history — silently reintroducing the exact bug this design
  fixes, for any key that goes through a backup/restore cycle after being
  rotated.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| How a caller specifies a version | Optional `"version"` int field on the existing six JSON request bodies. `0`/omitted = current (default, unchanged behavior). | Matches how these six ops already take structured JSON bodies; avoids 12 new route registrations (6 ops × flat/vault-scoped) an Azure-style `/keys/{id}/versions/{version}/sign` path shape would require, for the same outcome. |
| How "current version number" is tracked | Computed (`MAX(key_versions.version)`, or implicitly `1` if zero rows), not a new `keys.current_version` column. | Zero schema migration, zero migration risk. `RotateKey` already performs this exact computation today (`key_service.go:851`); a repository helper just needs to expose it. A denormalized column is deferred — it would mainly serve exposing "current version" on `GetKey`, which is not part of this fix's goal. |
| Per-version lifecycle attributes (Azure allows enable/disable per version) | Not introduced. Revocation/enabled/expiry stay key-level, applying uniformly to all versions. | Out of scope for this fix (the source finding is about *usability* of old ciphertexts/signatures, not per-version access control) and avoids a schema change. A revoked key blocks all its versions — the safer default. |
| New API-facing read surface | Add `GET /keys/{key_id}/versions/{version}` (flat + vault-scoped), mirroring the existing secrets pattern (`GET /secrets/{id}/versions/{version}`). | Requested in scoping: keys currently lack the single-version read that secrets already have; closes that asymmetry as part of the same body of work. |
| Response shape for the six crypto ops | Add `"version": N` to each response, echoing the version actually used. | Lets a caller who passed `0`/omitted discover what "current" resolved to, at negligible cost. |
| Material-carrying version type vs. the existing API type | New internal-only `model.KeyVersionRecord` (`{KeyID, Version, Value, CreatedAt}`), kept structurally separate from `model.KeyVersion` (which never gains a `Value` field). | The versions-list and versions-get *handlers* only ever construct `model.KeyVersion`, so they cannot leak material even by future mistake — a stronger guarantee than an `omitempty` field on the existing type. |
| Repository auth idiom for new version-reading methods | `key.UserID`-derived, matching the existing `ListVersions(ctx, keyID, userID)` convention — not a new `model.Scope`-based predicate. | `ListKeyVersions` (service layer) already authorizes via `GetKey(ctx, keyID, scope)` first, then calls the repository with `key.UserID` (`key_service.go:495-501`). The new methods sit next to that one and should match its idiom rather than introduce a second convention for the same table. |
| Backup/restore version history | In scope. Extend the key backup envelope to carry `key_versions`; restore re-inserts them under the new key ID. | Explicitly requested during scoping: leaving backup/restore untouched would let a restore silently reintroduce the bug this design fixes. |
| OCT (symmetric, HSM-only) keys | No change. | `RotateKey` has no case for `model.KeyTypeOCT` — it falls into the `default: unsupported key type for rotation` branch (`key_service.go:823-826`). OCT keys cannot be rotated at all today, so there is no multi-version OCT case to handle. Not introduced or worsened by this fix. |
| HSM object cleanup on purge | Not addressed. | Pre-existing, unrelated gap: `KeyRepository.PurgeKey` (`internal/repositories/key_repository.go:584-624`) only does `DELETE FROM keys` — it never destroys PKCS#11 token objects for the current *or* any archived version, and never did. Out of scope; noted for `.claude/known-bugs.md` as a candidate follow-up, not fixed here. |

## The changes

### 1. Repository (`internal/repositories/key_repository.go`)

```go
// ReadVersionValue returns the encrypted/handle material for one version of
// keyID, authorized against userID (the key's owner — see ListVersions for
// why this matches the existing convention rather than taking a model.Scope).
// Falls back to keys.value when version==1 and the key has never been
// rotated (zero key_versions rows), matching RotateKey's own versioning math.
func (r *KeyRepository) ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (string, error)

// GetVersion returns metadata (no material) for one version of keyID,
// authorized against userID. Same not-found semantics as ReadVersionValue.
func (r *KeyRepository) GetVersion(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (*model.KeyVersion, error)

// ListVersionRecords returns every version of keyID INCLUDING material,
// authorized against userID. Internal-use only (backup service) — never
// wired to an HTTP response.
func (r *KeyRepository) ListVersionRecords(ctx context.Context, keyID uuid.UUID, userID uuid.UUID) ([]model.KeyVersionRecord, error)
```

`ReadVersionValue` and `GetVersion` share one not-found path: `version < 1`,
or `version` matching neither a `key_versions` row nor the "implicit version
1" fallback, returns a sentinel `ErrKeyVersionNotFound` (new, alongside the
existing `ErrKeyPurgeProtected` in this package).

### 2. Model (`model/key.go`)

```go
// KeyVersionRecord carries a version's material for internal use (backup
// service) only. Never marshaled into an HTTP response — API responses use
// KeyVersion, which has no Value field.
type KeyVersionRecord struct {
	KeyID     uuid.UUID
	Version   int
	Value     string
	CreatedAt time.Time
}
```

### 3. Service layer (`internal/services/keys/`)

`crypto_service.go`:

- All six service-layer request types — `SignRequest`, `VerifyRequest`,
  `EncryptRequest`, `DecryptRequest`, `WrapKeyRequest`, `UnwrapKeyRequest`
  (all declared together in this file, `:22-123`) — gain `Version int`. Their
  paired result types — `SignResult`, `VerifyResult`, `EncryptResult`,
  `DecryptResult`, `WrapKeyResult`, `UnwrapKeyResult` (same file) — gain
  `Version int` to carry the resolved version back to the API layer.
- After `loadAndAuthorize` returns the authorized, lifecycle-checked key row
  (unchanged — authorization and revocation/enabled/expiry stay key-level, see
  the design-decisions table), a new helper resolves *material*:

  ```go
  func (s *cryptoService) resolveVersionValue(ctx context.Context, key *model.Key, requested int) (value string, resolvedVersion int, err error)
  ```

  If `requested == 0`, resolves to `(key.Value, currentVersionNumber(key), nil)` —
  no extra query for the *material* (still just `key.Value`, exactly as
  today). Computing `currentVersionNumber` to populate the new response field
  does cost one lightweight indexed lookup (`MAX(version)` /
  `COUNT(*)` on `key_versions` keyed by `key_id`) that the pre-fix code never
  ran — correcting an earlier draft of this design, which claimed this path
  added no query at all. Negligible next to the crypto operation itself
  (RSA/EC math, or an HSM round-trip), but real; the plan may choose to fuse
  it into the same read as `loadAndAuthorize` rather than a separate
  round-trip. If `requested` matches that current number, same
  single-lookup path — no `key_versions` *value* read either way. Otherwise
  calls `ReadVersionValue` and returns its value with `resolvedVersion = requested`.
- `resolveKeyMaterial` (`crypto_service.go:197-236`) changes its cache key
  from the hardcoded `(key.ID, 0)` to `(key.ID, resolvedVersion)` — the fix
  for the latent cache bug found during scoping. Also takes the *value to
  resolve* as a parameter instead of reading `key.Value` directly, since the
  value may now come from an archived version rather than the key row.
- `Sign`/`Verify`/`Encrypt`/`Decrypt`/`WrapKey`/`UnwrapKey`
  (`crypto_service.go:355,411,468,521,574,638`) each call
  `resolveVersionValue` after `loadAndAuthorize`, thread `resolvedVersion`
  into `resolveKeyMaterial`, and return it in their result structs so the API
  layer can echo it in the response.
- The new `repositories.ErrKeyVersionNotFound` sentinel (declared in the
  repository, see section 1) propagates unwrapped from `resolveVersionValue`
  — not re-wrapped into a `keyservices.Err*` sentinel. This matches the
  existing precedent of `repositories.ErrKeyPurgeProtected`
  (`internal/repositories/purge_protection_errors.go:12`), which likewise
  reaches `writeKeyError` (`api/errors_key.go:26`) directly from the
  repository layer with no service-layer wrapper. `loadAndAuthorize`'s own
  wrapping of the *key* read's not-found case into `ErrKeyNotFound`
  (`crypto_service.go:279-282`) is a separate, pre-existing pattern for a
  different error — not a precedent to follow here, since a real precedent
  for the unwrapped style already exists in this same package.

`key_service.go`:

- New `GetKeyVersion(ctx, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error)`,
  mirroring `ListKeyVersions`'s existing shape exactly
  (`key_service.go:495-501`): `GetKey(ctx, keyID, scope)` first for
  authorization, then `s.keyRepo.GetVersion(ctx, keyID, version, key.UserID)`.

### 4. API layer (`api/keys.go`)

- All six HTTP request types — `WrapKeyRequest`, `UnwrapKeyRequest`
  (`api/keys.go:96-119`), `SignKeyRequest`, `VerifyKeyRequest`,
  `EncryptKeyRequest`, `DecryptKeyRequest` (`:121-172`) — gain
  `Version int \`json:"version,omitempty"\``. (Not `model/key.go`'s
  identically-named `WrapKeyRequest`/`UnwrapKeyRequest` — see the correction
  note in "Current state" above; those are dead code, untouched.)
- `SignKeyResponse`, `VerifyKeyResponse`, `EncryptKeyResponse`,
  `DecryptKeyResponse`, `WrapKeyResponse`, `UnwrapKeyResponse` gain
  `Version int \`json:"version"\`` populated from the service result.
- The six handlers (`signKey`, `verifyKey`, `encryptKey`, `decryptKey`,
  `wrapKey`, `unwrapKey`) thread `req.Version` into the service request and
  add one new `switch` case to each of their existing inline error switches:
  `errors.Is(err, repositories.ErrKeyVersionNotFound) → c.SetNotFound("key version")`.
  `api/keys.go` already imports `rocketvault/internal/repositories`
  (`:37`), so no new import.
- `writeKeyError` (`api/errors_key.go:20-32`, used by `listKeyVersions` and
  the new `getKeyVersion` handler below, but not by the six crypto handlers,
  which keep their own separate inline switches as today) gains the same new
  case.
- New handler `getKeyVersion`, registered alongside the existing
  `listKeyVersions` route (`api/keys.go:239`):

  ```go
  k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getKeyVersion)).Methods("GET")
  ```

  on both the flat and vault-scoped key subrouters (mirroring how
  `registerKeyRoutes` already registers `/versions` on both — this is not the
  `InitBackupItem`-style gap fixed earlier; `registerKeyRoutes` already runs
  twice against `api.BaseRoutes.Keys` and `api.BaseRoutes.VaultScoped.PathPrefix("/keys")`,
  so the new route pattern needs no separate wiring fix).

### 5. Backup/restore (`internal/backup/item_backup.go`)

**Correction from an earlier draft:** the first version of this section
wrapped `*model.Key` inside a new payload type (`{Key, Versions}`) and
encoded *that* as the blob's `Data` field. That changes `Data`'s shape from
a flat `model.Key` object to a nested one, which breaks decoding every
key backup blob taken before this change — `payload.Key` would come back
`nil`, not `nil`-with-graceful-fallback, directly contradicting the
backward-compatibility guarantee below. Fixed by adding the version history
as a new *sibling* field on the shared envelope instead of nesting it inside
`Data` — purely additive, so old blobs (which simply lack the new field)
keep decoding exactly as before.

- `backupEnvelope` (`internal/backup/item_backup.go:46-50`, shared by
  secrets/keys/certificates) gains one new field:

  ```go
  type backupEnvelope struct {
  	ResourceType string                   `json:"resource_type"`
  	ResourceID   string                   `json:"resource_id"`
  	Data         json.RawMessage          `json:"data"`
  	Versions     []model.KeyVersionRecord `json:"versions,omitempty"` // keys only
  }
  ```
- `encodeBlob`/`decodeBlob` (`:169-183`, `:187-200`) gain a `versions` parameter/return
  value: `encodeBlob(resourceType, resourceID string, data interface{}, versions []model.KeyVersionRecord) (string, error)`
  and `decodeBlob(blob, expectedType string, out interface{}) (versions []model.KeyVersionRecord, err error)`.
  `Data` itself is unchanged — still the plain marshaled resource (`*model.Key`,
  `*model.Secret`, or `*model.Certificate`), exactly as today.
- `BackupSecret`/`BackupCertificate` and `RestoreSecret`/`RestoreCertificate`
  pass/discard `nil`/the extra return value — one-line changes, no behavior
  change (secrets and certificates have no version-material concept).
- `BackupKey` calls the new `ListVersionRecords` and passes its result as
  `encodeBlob`'s `versions` argument.
- `RestoreKey` receives `versions` from `decodeBlob`, creates the key row
  under `newID` as today, then calls `CreateVersion(ctx, newID, v.Version, v.Value)`
  for each entry — remapping to the new key's ID the same way the rest of
  restore remaps IDs.
- Backward compatibility: a blob produced before this change has no
  `versions` field on its envelope. Decoding treats it as optional —
  `decodeBlob` returns a `nil` slice, `Data` decodes exactly as it always
  has, and restore proceeds exactly as it does today (a key with no version
  history). Not an error, and no special-casing needed in `RestoreKey` beyond
  ranging over a possibly-empty slice.

## Behavior changes

1. **Old ciphertexts and signatures become recoverable again (the fix).** A
   caller who kept a ciphertext, wrapped key, or signature produced before a
   rotation can pass the matching `"version"` to decrypt/unwrap/verify it —
   previously impossible once the key had rotated.
2. **New read endpoint.** `GET /keys/{id}/versions/{version}` (flat +
   vault-scoped) is new API surface; 404 on a nonexistent or unauthorized
   version, same as an unauthorized `key_id` (doesn't leak existence to a
   caller without access).
3. **Response shape addition.** The six crypto responses gain `"version"`.
   Existing clients that decode into a struct with unknown-field tolerance
   (the Go JSON decoder's default) are unaffected; anything doing strict
   schema validation against the old shape would need updating — call out in
   release notes.
4. **Backup blob format for keys changes** (envelope gains `versions`).
   Old blobs still restore correctly (see above); new blobs restore full
   version history where old ones didn't.

## Not in scope

- **Per-version enable/disable/expiry attributes** (Azure supports these).
  RocketVault's lifecycle model stays key-level. A future request for
  per-version attributes would need its own schema change and design.
- **`keys.current_version` denormalized column** (Approach B, considered and
  rejected during scoping — see the design-decisions table).
- **HSM token object cleanup on purge.** Pre-existing gap, unrelated to this
  fix's goal; flagged for `.claude/known-bugs.md`, not fixed here.
- **OCT key rotation.** Not supported today; unaffected by this fix either
  way.
- **CLI surface.** `cmd/keys/verify.go` (the existing CLI verify command,
  `docs/superpowers/plans/2026-08-18-keys-verify-cli.md`) calls
  `CryptoService.Verify` directly — the implementation plan for this design
  should decide whether to thread a `--version` flag through at the same
  time, or track it as a fast-follow. Not decided in this design; flag it
  explicitly in the plan rather than silently deferring.

## Testing

- **Repository**: `ReadVersionValue` — hit an archived row, hit the implicit
  version-1-via-`keys.value` fallback, miss on a nonexistent version, miss on
  a wrong-owner `userID`. `GetVersion`, `ListVersionRecords` (empty for a
  never-rotated key; N+1 rows after N rotations).
- **Service**: each of the six crypto ops — version omitted (current,
  byte-identical to pre-fix behavior), version explicitly equal to current,
  version pointing at an archived version, version pointing at a nonexistent
  number (`ErrKeyVersionNotFound`), version request against a revoked/expired
  key (still denied — lifecycle stays key-level, applies before version
  resolution). Regression test for the cache-key bug found during design: two
  sequential calls for the same key at two different versions must not
  cross-contaminate — the second call's result must reflect its own
  requested version's material, not a cached hit from the first.
- **API**: JSON round-trip for `"version"` on request and response across all
  six handlers; the new `GET .../versions/{version}` handler (200 + shape,
  404 for missing/unauthorized); `ErrKeyVersionNotFound → 404` mapping;
  OpenAPI spec (`docs/api-specification.yaml`) and route inventory
  (`docs/api-routes.generated.txt`) updated for the new route, same drift
  tests exercised by the backup-routing fix earlier in this branch.
- **Backup/restore**: round-trip a key rotated twice (3 versions) through
  backup → restore; verify a crypto op against the *oldest* version still
  works post-restore. Decode a synthetic pre-change blob (no `versions` key
  in the JSON) and confirm it restores without error and with no version
  history, matching current behavior.

## Verification gate

```
go build ./...
go vet ./...
go test ./api/... ./internal/services/keys/... ./internal/repositories/... ./internal/backup/... ./model/...
```

Plus the OpenAPI/route-inventory drift tests:

```
go test ./api/... -run 'TestOpenAPISpecCoversAllRoutes|TestGenerateRouteInventory'
```

All must pass before claiming completion.

## Risks

- **Six request/response struct changes touch a lot of call sites** (both
  production handlers and their existing test suites, which construct these
  structs directly). Mechanical but wide — expect a large diff in
  `api/keys_crud_test.go` and the crypto-op test files even though the
  behavioral change per call site is small (default `Version: 0` preserves
  existing test expectations unless a test explicitly opts into a version).
- **`resolveKeyMaterial`'s signature change** (taking the value to resolve as
  a parameter instead of reading `key.Value`) touches every existing caller
  of that function — confirm via `grep -rn "resolveKeyMaterial"` before
  implementation that there are no callers outside `crypto_service.go`.
- **Backup envelope format change for keys is a compatibility surface.** Any
  external tooling that parses key backup blobs directly (rather than only
  round-tripping them through `rocketvault`) would see a new `versions` field
  appear. Base64url-JSON blobs are already documented as
  "opaque... treat as sensitive, plaintext-equivalent data, not as a secure
  export format" (`docs/usage-guide.md` §6), so this is consistent with
  existing guidance, but worth a release-note line.

## Documentation to update

- `.claude/azure-keyvault-parity.md` §2 — "Rotate (new version)" and "Backup /
  Restore" rows move from 🟡 toward ✅ (or a narrower 🟡, if the CLI `--version`
  fast-follow from "Not in scope" above is left open); the Summary's "Key
  operations beyond CRUD" paragraph needs its own re-verification pass once
  this ships, per that doc's own convention of dated correction notes.
- `.claude/known-bugs.md` — new entry for this fix (root cause: version
  archival without a read/select path); new entry (or an addition to this
  one) for the HSM-purge-cleanup gap noted as out of scope.
- `docs/usage-guide.md` §6 (Backup / restore tooling) — the key backup
  envelope format change.
- `docs/api-developer-guide.md` / `docs/api-specification.yaml` — the new
  `version` request/response fields and the new `GET .../versions/{version}`
  route.
