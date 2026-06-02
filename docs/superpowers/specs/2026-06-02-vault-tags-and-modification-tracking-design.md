# Vault Tags and Modification Tracking — Design

**Date:** 2026-06-02
**Status:** Approved (pending spec review)
**Branch target:** `v-4.0.0`

## Goal

Close the two implementable Azure Key Vault parity gaps in RocketVault's `Vault`
model identified in the vault-model gap analysis:

1. **`tags`** — an arbitrary key/value metadata map on a vault (Azure: `tags`).
2. **Modification tracking** — `updated_at` and `updated_by` (Azure:
   `systemData.lastModifiedAt` / `lastModifiedBy`).

Out of scope (Azure vault properties that are cloud-platform plumbing with no
self-hosted equivalent): `location`, `sku`, `tenantId`, `networkAcls`,
`privateEndpointConnections`, `publicNetworkAccess`, `provisioningState`,
`enabledForDeployment/DiskEncryption/TemplateDeployment`, `hsmPoolResourceId`,
`createMode`.

## Design decisions (from brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Tag shape | `map[string]string` (key/value) | True Azure parity; secret/key/cert `[]string` tags are a different convention, not reused. |
| Tag storage | JSON `TEXT` column on `vaults` | Tags are always read/written as a whole map; no DB-level tag querying required. |
| Long-term posture | "A now, B-ready" | JSON column now; migrate to a normalized `vault_tags(vault_id,key,value)` table **only if** tag-filtering (`GET /vaults?tag=env:prod`) becomes a real requirement. Confined to the repository layer so the swap is cheap. |
| Tag update semantics | Full replace (Azure-style) | `tags` nil = unchanged, `{}` = clear, non-empty = replace whole map. Mirrors existing `enabled`/`purge_protection`/`retention_days` pointer-nil convention. |
| Modification tracking | Both `updated_at` + `updated_by` | Full audit parity; requires threading the acting user into `UpdateVault`. |
| Tag limits | ≤15 tags, key/value each non-empty and ≤256 chars | Azure's documented vault tag limits. |

> **Historical note:** the migrations directory shows a prior add→drop→re-add→remove
> cycle of a `tags` column **on secrets** (`20241026000002`–`005`). That churn was for
> the secret resource and a different design; it does not affect this vault work, but is
> noted so reviewers don't conflate the two.

## Encapsulation boundary (key architectural rule)

The JSON-column representation is an implementation detail of the **repository layer
only**. The `model.Vault` exposes `Tags map[string]string`; the service and API layers
never see JSON. A future migration to a `vault_tags` join table changes only
`vault_repository.go` internals — not the model, service, API, or any test that goes
through those layers.

## Components and changes

### 1. Model — `model/vault.go`

```go
type Vault struct {
    // ... existing fields ...
    Tags      map[string]string `json:"tags,omitempty"`
    UpdatedAt *time.Time        `json:"updated_at,omitempty"`
    UpdatedBy *uuid.UUID        `json:"updated_by,omitempty"`
}

type CreateVaultRequest struct {
    // ... existing ...
    Tags map[string]string `json:"tags,omitempty"`
}

type UpdateVaultRequest struct {
    // ... existing ...
    Tags *map[string]string `json:"tags,omitempty"` // nil = unchanged, {} = clear, set = replace
}
```

- `VaultResponse` gains `Tags map[string]string`, `UpdatedAt string`, `UpdatedBy string`
  (all `omitempty`). `ToResponse()` populates them (timestamps RFC3339, UUIDs stringified).
- New `ValidateVaultTags(tags map[string]string) error` next to `ValidateVaultName`:
  rejects >15 tags, empty key, empty value, or key/value >256 chars.

### 2. Schema / migration — `internal/db/db.go`

- **`createOptimizedSchema`** (fresh DBs) — add to the `vaults` CREATE TABLE:
  ```sql
  tags        TEXT NOT NULL DEFAULT '{}',
  updated_at  TIMESTAMP NULL,
  updated_by  TEXT NULL
  ```
- **`migrateSchema`** (existing DBs) — three idempotent statements, placed AFTER the
  `vaults` table creation (honouring the index/column ordering rule):
  ```
  ALTER TABLE vaults ADD COLUMN tags TEXT NOT NULL DEFAULT '{}'
  ALTER TABLE vaults ADD COLUMN updated_at TIMESTAMP NULL
  ALTER TABLE vaults ADD COLUMN updated_by TEXT NULL
  ```
- **Migration file** — new `internal/db/migrations/20260602000001_add_vault_tags_modtracking.sql`
  with the same three columns, for the `migrate` CLI path.

### 3. Repository — `internal/repositories/vault_repository.go`

- `vaultCols` gains `tags, updated_at, updated_by`.
- `scanVault` unmarshals the `tags` JSON into `map[string]string` (treat `''`/`'{}'` as
  empty map), and scans `updated_at` (`sql.NullTime`→`*time.Time`) and `updated_by`
  (`sql.NullString`→`*uuid.UUID`). **JSON marshal/unmarshal lives only here.**
- `Create` marshals `v.Tags` (nil → `{}`) into the INSERT.
- `Update` SQL extended:
  ```sql
  UPDATE vaults
     SET enabled = ?, purge_protection = ?, retention_days = ?,
         tags = ?, updated_at = ?, updated_by = ?
   WHERE id = ?
  ```
  Repository stamps `updated_at = now(UTC)`; `updated_by` comes from `v.UpdatedBy`.

### 4. Service — `internal/services/vaults/vault_service.go`

- `CreateVault`: copy `req.Tags` (nil → empty map); call `ValidateVaultTags`.
- **Signature change** (interface + impl):
  ```go
  UpdateVault(ctx, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error)
  ```
  - `req.Tags` nil → leave `v.Tags` unchanged; non-nil → replace (validate first).
  - Set `v.UpdatedBy = &updatedBy`.

### 5. API — `api/vault.go`

- Create handler: pass `req.Tags` through; 400 on tag-validation error.
- Update handler: read caller UUID from context claims (`sub`, same source other
  handlers use) and pass to `UpdateVault`; 400 on tag-validation error.

### 6. Call-site updates for the new `UpdateVault` signature

All must be updated (found via grep):

- `internal/services/vaults/vault_service.go` (interface + impl)
- `api/vault.go:147`
- `cmd/vaults/update.go:47` (CLI — pass the authenticated user's UUID)
- `cmd/testutils/test_utils.go:548` (`MockVaultService`)
- `internal/middleware/middleware_test.go:93` (`stubVaultService`)
- `internal/services/vaults/vault_service_test.go` (existing update tests)

## Testing

- **Unit:** `ValidateVaultTags` (over-limit, empty key/value, oversize); `scanVault`
  tags round-trip + nullable `updated_at`/`updated_by`; `ToResponse` emits new fields.
- **Repository:** create-with-tags read-back; update replaces tags + stamps
  `updated_at`/`updated_by`; `{}` clears tags.
- **Service:** create validates tags; update with nil tags leaves them unchanged; update
  with map replaces and sets `updated_by`.
- **API:** `POST` with tags; `PATCH {"tags":{...}}` replaces; `PATCH` without tags
  unchanged; `PATCH {"tags":{}}` clears; over-limit → 400.
- **Live smoke:** create→get→patch→get round-trip against the running server.

## Verification gate

```
go build ./...
go vet ./...
go test ./internal/db/... ./internal/repositories/... ./internal/services/vaults/... ./api/... ./cmd/vaults/...
```
All must pass before claiming completion (no success claims without fresh evidence).

## Risks

- **Signature change ripples** to 6 call sites incl. two test doubles — enumerated above
  so none is missed; `go build ./...` will catch any straggler.
- **Migration ordering** — the ALTERs must follow the established pattern; verified
  against the audit-index ordering bug fixed earlier on this branch.
