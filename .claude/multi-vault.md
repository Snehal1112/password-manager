# Multi-Vault Architecture

RocketVault is now a multi-vault system with Azure Key Vault parity. A vault is a
named namespace and security boundary that contains secrets, keys, and
certificates, governed by per-vault access policies.

Spec: `docs/superpowers/specs/2026-05-29-multi-vault-design.md`
Plan: `docs/superpowers/plans/2026-05-29-multi-vault-support.md`

## Model (Approach A — vault as a routing + context-scoping layer)

A vault is resolved per request and its ID is injected into the request context,
exactly as `user_id` is. Handlers and services read `vault_id` from context;
repositories scope queries by `vault_id`. Resources are vault-scoped; the former
`user_id` column is retained as **created_by** audit metadata, not an access scope.

- **Vault addressing:** path-based `/api/v1/vaults/{vault_name}/secrets/...`, plus
  legacy flat routes `/api/v1/secrets/...` that resolve to the `default` vault.
- **Resource uniqueness:** `UNIQUE (vault_id, name)`.
- **Visibility model:** any caller authorized for a vault sees all items in it.
  Access is governed by vault access policies + RBAC, NOT per-user object
  ownership. This applies uniformly to secrets, keys, and certificates.

## Key components

- `model/vault.go` — `Vault` type, DTOs, `ValidateVaultName`, `DefaultVaultID`
  (`00000000-0000-0000-0000-00000000efa1`) and `DefaultVaultName` ("default").
- `internal/repositories/vault_repository.go` — vault CRUD.
- `internal/services/vaults/` — `vault_service.go` (lifecycle), `cascade_adapter.go`
  (fans soft-delete/recover out to secret/key/cert repos). `ErrVaultNotFound`
  sentinel is returned for missing vaults so the API maps them to 404.
- `internal/middleware/middleware.go` — `VaultResolutionMiddleware` resolves the
  vault (path var → default), injects `common.VaultIDKey`. Positioned in the chain
  AFTER authentication, BEFORE policy. `PolicyMiddleware` is vault-aware.
- `internal/db/db.go` — `vaults` table + `vault_id` columns in
  `createOptimizedSchema` (fresh DBs) and `migrateSchema` (existing DBs);
  `seedDefaultVault` + `finalizeVaultIndexes` wired into `InitializeDB`.
- `internal/db/vault_collision.go` — `ResolveNameCollisions` renames duplicate
  `(vault_id, name)` rows before the unique index is built (migration safety).
- `api/vault.go` — vault management endpoints (create/get/list/update/delete).
- `cmd/vaults/` — `vaults` CLI command group. `common.ResolveVaultName` is the
  single source of truth for the `--vault` precedence: flag > `ROCKETVAULT_VAULT`
  env > viper `vault` key > `default`.

## Access policies

Access policies gained a nullable `vault_id`. NULL = global (applies in every
vault); a set `vault_id` applies only in that vault. Lookup uses
`(vault_id = ? OR vault_id IS NULL)`. Deny-overrides-allow precedence is preserved
across mixed global/vault-specific rows. A `vaults` resource type with a `manage`
operation supports per-vault admin grants.

## Migration

On startup, `migrateSchema` adds the `vaults` table and `vault_id` columns to
existing databases; `seedDefaultVault` creates the `default` vault; existing rows
default to the default vault. Name collisions across users that would violate the
new `(vault_id, name)` uniqueness are auto-renamed to `{name}-{short-id}` and
logged. The `migrate` CLI path uses
`internal/db/migrations/20260529000001_add_vaults.sql`.

## Vault-scope inconsistency fixes (2026-07-26)

An audit found that several routes registered under `/vaults/{name}/...` were
silently ignoring the resolved vault and falling back to owner-scoped
(per-user) behavior instead of vault-wide "members see all" — violating the
codebase's own stated rule (see the deleted-flow bullet below) that a
vault-scoped route must never silently ignore its vault. Fixed in
`docs/superpowers/plans/2026-07-26-vault-scope-inconsistency-fixes.md`
(5 tasks, all reviewed): **secrets UPDATE**, **secret versions** (list/get/
latest), **secrets export/import**, **keys UPDATE**, and **certificate
policy** (GET/PUT/DELETE) are now genuinely vault-scoped on the explicit
`/vaults/{name}/...` path — any vault member can act on any resource in the
vault, matching the existing list/get/delete behavior. Legacy flat routes are
byte-for-byte unchanged (verified by dedicated regression tests per fix).

**B6 resolved (2026-08-02, commit `da6fb9b`).** This section previously said key
delete and all crypto operations (sign/verify/encrypt/decrypt/wrap/unwrap)
were deliberately left owner-gated even on a vault-scoped route. That's no
longer true: `da6fb9b` ("feat(api)!: gate crypto operations, key delete and
rotate by vault role") made every key operation follow `scopeFromRequest`
(`api/context.go`) like the rest of the vault-scoped surface. As of 2026-08-16
`scopeFromRequest` yields `ScopeVault` on **both** route shapes — the flat
routes carry the default vault — because the owner scope there was a cross-vault
authorization bypass (see `.claude/known-bugs.md` § B11). The
`ownerScoped`-branch code paths that used to enforce the old behavior
(`key_service.go` delete/rotate, `crypto_service.go`'s `loadAndAuthorize`)
still exist but are now unreachable from any HTTP route; they were left in
place deliberately rather than removed with the security fix. Verified
end-to-end against current source 2026-08-11; do not reintroduce this as a
known limitation without re-checking `git log -- internal/services/keys
api/keys.go` first.

## Known deferrals (intentional, not bugs)

These continue to work via the default vault; they were scoped out to keep
each change reviewable:

- **Secondary subsystems still user-scoped:** rotation and scheduler still
  key off `user_id`, using the still-present `ReadByOwner`/`ListByUser`
  repository methods (which is why those methods were NOT removed). Secrets
  versioning, secrets/keys UPDATE, and secrets export/import were vault-scoped
  by the 2026-07-26 fix above; item backup (`internal/backup/item_backup.go`)
  was vault-scoped separately on 2026-08-19 (`model.NewVaultScope`) and is no
  longer in this category either.
- **Keys/certs CLI `--vault` wiring:** only the `secrets` CLI commands
  (create/list/get/delete/update/export/import — all of them call
  `resolveVaultID` via `cmd/secrets/vault.go`) are vault-scoped. Keys and
  certificate CLI commands hardcode `model.NewOwnerScope`/`DefaultVaultID` and
  have no `--vault` flag at all — this is a **CLI-only** gap for keys: every
  keys operation the CLI exposes today (create/get/list/update/delete/rotate/
  wrap/unwrap) already has a vault-scoped HTTP path and vault-aware service
  method (see B6 resolution above), so wiring `--vault` into `cmd/keys` needs
  zero new service/repository code. For certificates the gap is not purely
  CLI-side: `list`/`get`/`delete` are the same story (backend already
  vault-scoped, just needs a CLI flag), but certificate **UPDATE** is still
  hardcoded owner-only at the HTTP handler itself (`api/certificates.go`,
  P3 item below) and **renew** ignores scope entirely inside the service —
  those two need backend work, not just a CLI flag, before `--vault` on them
  would mean anything.
- **Subdomain vault addressing:** designed but not implemented; path-based only.
- **Keys/certs deleted flow not vault-scoped:** only the *secrets* deleted flow
  (`/vaults/{name}/deleted/secrets`) is vault-aware — its LIST honours the
  resolved vault via `ListInVaultIncludeDeleted`. The key and certificate
  deleted-flow handlers (list/get/restore/purge) remain user-scoped because
  their `ListSoftDeleted` repository methods do not select/scope by `vault_id`.
  They are therefore registered ONLY on the legacy flat `/deleted/...` routes,
  not as vault-scoped routes.

Two vault-scoped routes still ignore their vault and are fixed in P3:
`PUT /vaults/{n}/certificates/{id}` and `GET /vaults/{n}/keys/{id}/versions`.
`POST /vaults/{n}/keys/{id}/rotate` was fixed in P2 (2026-07-26): it now builds
a genuine vault scope via `scopeFromRequest` and is gated by `Key Vault Crypto
Officer` at vault scope, verified end-to-end with real-repository tests.

## Pre-existing latent issue (predates multi-vault)

`certificate_repository.go` `ListByUser`/`ListInVault` filter by a `type` column
that does not exist in the certificates schema. Only triggered when a non-empty
`certType` is passed (default path is unaffected). Faithfully mirrored from the
existing `ListByUser`; not introduced by the multi-vault work. Fix: add the column
or drop the filter.
