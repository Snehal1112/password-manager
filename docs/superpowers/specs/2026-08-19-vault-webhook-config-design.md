# Per-Vault Webhook Configuration — Design

**Date:** 2026-08-19
**Status:** Proposed
**Branch target:** `v-4.0.0`
**Source finding:** `.claude/known-bugs.md` § B27 / `.claude/azure-keyvault-parity.md`
§2 "Get/Set rotation policy" row — `notify_before_expiry_days` is persisted
and echoed back but never acted on, because RocketVault has no notification
delivery mechanism anywhere in the codebase. This is sub-project 1 of a
6-part decomposition (per-vault webhook config → delivery primitive → keys'
near-expiry sweep → secrets' reminder wiring → certificates' warning wiring →
docs) closing that gap. This sub-project builds only the storage/CRUD layer:
no notification is ever sent yet.

## Goal

Let a vault's `CanManageVault`-authorized operator configure a webhook URL
and signing secret for that vault, stored durably, so a later sub-project
(the delivery primitive) has something to read when it needs to notify that
vault's operators about a near-expiry key, secret, or certificate.

Explicitly not this sub-project's job: sending anything. No `TestSend`, no
`WebhookSender` interface, no outbound HTTP call of any kind. Pure
create/read/delete for one config row per vault.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Per-vault vs. global config | Per-vault (already decided during brainstorming, overriding the initially-recommended global default) | RocketVault's multi-vault model is built around per-vault isolation and delegated admin; a single global webhook would leak every vault's expiry events to one operator regardless of who administers which vault. |
| Data model | New table `vault_webhook_configs`, one row per vault (unique on `vault_id`), not columns on `vaults` | Matches the existing precedent: `key_rotation_policies` is its own table keyed on the parent resource, not columns bolted onto `keys`. Keeps the hot-path `vaults` table lean and this feature's schema independently evolvable. |
| Signing secret storage | Encrypted at rest via `common.EncryptSecret` (master-key AES-256-GCM), decrypted only inside the future delivery primitive's send path | Reversed from the first-pass recommendation (an env-var-first convention, matching `vault_client.client_secret`) once the config became per-vault: an env var can't hold N secrets for vaults created dynamically at runtime. A per-vault secret RocketVault stores and later decrypts for its own use is exactly the shape `EncryptSecret` exists for — the same mechanism already protecting secret values and key material. |
| Secret visibility | Show-once: returned in the `PUT` response body only (create or rotate), never via `GET` | Considered three options during brainstorming: always-write-only (strictest, least convenient), readable anytime by `CanManageVault` (most convenient, but a standing read path that survives a later privilege change), and show-once (this choice) — the same pattern GitHub/AWS use for webhook secrets and access keys. Gets the "copy it down once" convenience without a durable read path. |
| Partial update | `PUT` on an existing config: `signing_secret` optional — omitted keeps the current encrypted secret; provided rotates it (and is returned once, same as create) | Lets an operator change just the URL without forcing a secret rotation (which would require updating the receiver's config too). |
| Authorization | The existing `CanManageVault` check (`internal/services/authorization/vault_authz.go`), same tier as vault lifecycle (create/update/delete/purge) | This is vault-level operational config, not a data-plane secret/key/cert grant — belongs with vault management, not with `RoleAssignmentService`'s per-vault Azure role data actions. |
| HTTP route shape | `/vaults/{name}/webhook` on `api.BaseRoutes.Vaults` (the `{name}` vault-management router), not `/vaults/{vault_name}/...` on `BaseRoutes.VaultScoped` | Verified against `api/vault.go:32-44`: `createVault`/`getVault`/`updateVault`/`deleteVault` all register on `r.Vaults` with a `{name}` path variable; only `purgeVault` is the one exception registered on `VaultScoped`. Webhook config is vault-management-tier like the first four, not a vault-scoped data-plane route, so it follows their pattern, not `purgeVault`'s. |
| Delete semantics | Hard delete, no soft-delete/purge-protection | This is operational config, not vault data (secrets/keys/certs) — none of the soft-delete/recovery machinery that protects user data applies to a webhook URL and secret. |
| `TestSend` | Deferred entirely to the next sub-project (the delivery primitive) | Decided during brainstorming: shipping a route/CLI command that's authorized and reachable but functionally inert until a later sub-project lands violates "no placeholders" in spirit, even across a multi-plan decomposition. `TestSend` becomes the delivery primitive's first real caller instead. |

## The change

### 1. Migration (`internal/db/db.go`)

New table, registered identically in both schema-creation paths — confirmed
required by this codebase's dual-registration convention (`key_rotation_policies`
itself needed this: `createOptimizedSchema` at `:486` and `migrateSchema` at
`:806` carry byte-identical `CREATE TABLE IF NOT EXISTS key_rotation_policies`
statements, because `migrateSchema` runs against a pre-existing database that
never had the table, while `createOptimizedSchema` only runs for a brand-new
database):

```sql
CREATE TABLE IF NOT EXISTS vault_webhook_configs (
    id                       TEXT PRIMARY KEY,
    vault_id                 TEXT NOT NULL UNIQUE REFERENCES vaults(id),
    url                      TEXT NOT NULL,
    signing_secret_encrypted TEXT NOT NULL,
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at               TIMESTAMP,
    updated_at               TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vault_webhook_configs_vault_id ON vault_webhook_configs(vault_id);
```

Both `id`/`vault_id` foreign-key columns follow this codebase's existing
`TEXT`-stored-UUID convention (matching every other table). Postgres/SQLite
dialect differences (if any arise for `BOOLEAN`/`TIMESTAMP` defaults) follow
whatever the nearest existing table's dialect-branching already does — the
plan should copy `key_rotation_policies`' exact dialect handling rather than
inventing new syntax.

### 2. Model (`model/vault_webhook.go`, new file)

```go
// VaultWebhookConfig is a vault's webhook notification target. The signing
// secret is stored encrypted (common.EncryptSecret) and is never populated
// by any read path that feeds an API response — only the create/rotate
// service call ever has the plaintext, and only for the one response that
// returns it.
type VaultWebhookConfig struct {
	ID        uuid.UUID
	VaultID   uuid.UUID
	URL       string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
	// SigningSecretEncrypted is populated by the repository layer but
	// deliberately has no json tag reachable from any API response type —
	// API responses are built from a separate, secret-less struct (below),
	// not by marshaling this type directly.
	SigningSecretEncrypted string
}
```

Separate, explicit HTTP response type (not a reused/trimmed
`VaultWebhookConfig`) to make "this type structurally cannot carry the
secret" true by construction, matching how `model.KeyVersion` vs.
`model.KeyVersionRecord` were kept structurally separate in the key-version
work (`.claude/known-bugs.md` § B26) for the identical reason:

```go
// VaultWebhookConfigResponse is the API-facing shape — never carries the
// signing secret except via the separate create/rotate response below.
type VaultWebhookConfigResponse struct {
	URL       string    `json:"url"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VaultWebhookConfigCreatedResponse is returned exactly once, from the PUT
// call that creates the config or rotates its secret — the only response
// shape in this feature that ever carries SigningSecret in plaintext.
type VaultWebhookConfigCreatedResponse struct {
	VaultWebhookConfigResponse
	SigningSecret string `json:"signing_secret"`
}
```

### 3. Repository (`internal/repositories/vault_webhook_repository.go`, new file)

```go
type VaultWebhookRepositoryInterface interface {
	// Upsert creates the vault's config if none exists, or replaces url/
	// enabled (and signingSecretEncrypted, if non-empty) if one does.
	// Returns whether this call created a new row (true) or updated an
	// existing one (false), so the service layer knows whether the secret
	// argument was required.
	Upsert(ctx context.Context, cfg *model.VaultWebhookConfig) (created bool, err error)
	// GetByVaultID returns the vault's config, or ErrNotFound-shaped error
	// if none exists. Includes SigningSecretEncrypted — callers that only
	// need the API-facing fields must not forward it into a response.
	GetByVaultID(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
	Delete(ctx context.Context, vaultID uuid.UUID) error
}
```

Mirrors `KeyRotationPolicyRepository`'s `Upsert` idiom (one config per
parent resource, created-or-replaced in one call) rather than inventing a
separate `Create`/`Update` pair.

### 4. Service (`internal/services/vaults/webhook_service.go`, new file)

```go
type VaultWebhookService interface {
	// Upsert authorizes via CanManageVault, then creates or updates the
	// vault's config. plaintextSecret is populated only when a secret was
	// actually generated/rotated by this call (i.e. always on create; on
	// update, only if req.SigningSecret was non-empty) — empty otherwise,
	// signaling the caller not to include it in the response.
	Upsert(ctx context.Context, vaultID uuid.UUID, req UpsertWebhookRequest, scope model.Scope) (cfg *model.VaultWebhookConfig, plaintextSecret string, err error)
	// Get authorizes via CanManageVault, then returns the config.
	// SigningSecretEncrypted is present on the returned model but the
	// caller (the HTTP handler) must build VaultWebhookConfigResponse, not
	// forward the model directly.
	Get(ctx context.Context, vaultID uuid.UUID, scope model.Scope) (*model.VaultWebhookConfig, error)
	Delete(ctx context.Context, vaultID uuid.UUID, scope model.Scope) error
}

type UpsertWebhookRequest struct {
	URL           string
	SigningSecret string // required on create; optional on update (empty = keep existing)
	Enabled       bool
}
```

`Upsert`'s encryption step: `common.EncryptSecret(req.SigningSecret)` when a
new secret is provided; when omitted on an update, read the existing row's
`SigningSecretEncrypted` first and carry it through unchanged (never
decrypt-then-re-encrypt an unrotated secret — no need to touch it at all).

### 5. API (`api/vault_webhook.go`, new file)

Routes registered in `InitVault` (`api/vault.go:32-44`), alongside the
existing four, on `api.BaseRoutes.Vaults` — **not** `VaultScoped`:

```go
v.Handle("/{name}/webhook", ApiSessionRequired(api.App, upsertVaultWebhook)).Methods("PUT")
v.Handle("/{name}/webhook", ApiSessionRequired(api.App, getVaultWebhook)).Methods("GET")
v.Handle("/{name}/webhook", ApiSessionRequired(api.App, deleteVaultWebhook)).Methods("DELETE")
```

Each handler follows `updateVault`/`deleteVault`'s exact resolve-then-authorize
shape (`api/vault.go:185-210`, `:244-264`): resolve the target vault by
`{name}` first (404 if not found), then `authz.CanManageVault(...)` (403 if
denied), before touching the body or the repository. `upsertVaultWebhook`
returns `VaultWebhookConfigCreatedResponse` when `plaintextSecret != ""`,
`VaultWebhookConfigResponse` otherwise; `getVaultWebhook` always returns
`VaultWebhookConfigResponse`.

### 6. CLI (`cmd/vault-webhook/`, new package)

New package, not folded into `cmd/vaults/` — mirrors `cmd/vault-access/`'s
existing precedent of a dedicated CLI package per vault-scoped management
concern:

```
cmd/vault-webhook/
├── set.go     # rocketvault vault-webhook set --vault <name> --url <url> [--secret <secret>] [--enabled=true|false]
├── get.go     # rocketvault vault-webhook get --vault <name>
├── delete.go  # rocketvault vault-webhook delete --vault <name>
└── authz.go   # thin wrapper reusing authz.CanManageVault via the container, same shape as cmd/vaults/authz.go
```

`set`'s output prints the signing secret with a clear one-time warning
banner when the response includes it (create or rotate), consistent with
how other CLI commands that reveal a credential once should behave — check
whether an existing precedent for this exists (e.g. `bootstrap_token`
generation output) and match its exact wording/formatting rather than
inventing new copy.

## Not in scope

- **`TestSend` / any outbound HTTP call.** Deferred to the next sub-project
  (the delivery primitive), which becomes its first real caller.
- **The delivery primitive itself**, keys' near-expiry sweep, secrets'
  `sendReminder` wiring, certificates' `cert_expiry_warning` wiring — all
  separate, later sub-projects in this 6-part decomposition.
- **Multiple webhooks per vault.** One config per vault (`UNIQUE` on
  `vault_id`) for this pass; a future need for multiple targets is a schema
  change, not implied here.
- **Webhook payload schema.** Not designed in this sub-project — belongs to
  the delivery primitive, which defines what a notification event looks
  like on the wire.

## Testing

- **Repository** (real SQLite, matching `key_versions_test.go`'s style):
  `Upsert` creates when no row exists, replaces when one does, returns the
  correct `created` bool in each case; `GetByVaultID` returns
  `SigningSecretEncrypted` (repository layer has no reason to hide it — the
  hiding happens at the API/service boundary); `Delete` removes the row;
  the `UNIQUE` constraint on `vault_id` is exercised (a second `Upsert`
  replaces, never duplicates).
- **Service**: encryption round-trip (plaintext in via `EncryptSecret`,
  never decrypted by `Get`); show-once semantics (`Upsert`'s
  `plaintextSecret` return is non-empty on create, empty on an update that
  didn't rotate, non-empty on an update that did); partial-update semantics
  (omitted `SigningSecret` on update leaves the stored encrypted value
  byte-identical); `CanManageVault` denial surfaces as an error before any
  repository call.
- **API**: `PUT`/`GET`/`DELETE` request/response shapes; `PUT` response
  includes the secret only on create/rotate; 403 for a caller without
  `CanManageVault`; 404 for a nonexistent vault name; route registration on
  `BaseRoutes.Vaults` (not `VaultScoped`) — a regression test analogous to
  the earlier `InitBackupItem` vault-scoped-registration fix, but proving
  the *opposite* placement is correct here.
- **CLI**: flag parsing for `set`/`get`/`delete`, output formatting
  (including the one-time-secret warning), authorization denial surfaced as
  a clear CLI error, matching `cmd/vault-access/`'s existing test patterns.

## Verification gate

```
go build ./...
go vet ./...
go test ./internal/repositories/... ./internal/services/vaults/... ./api/... ./cmd/vault-webhook/... ./model/...
```

## Documentation to update

- `.claude/azure-keyvault-parity.md` — no existing row covers this
  (webhooks are a RocketVault extra, not an Azure Key Vault capability);
  add a new row under the "RocketVault extras (➕)" summary once the full
  6-part decomposition lands and something actually sends a notification —
  premature to document a parity claim for pure CRUD with nothing wired to
  it yet.
- `.claude/known-bugs.md` § B27 — note that the storage layer for
  `notify_before_expiry_days` now exists, still open pending the delivery
  primitive and the keys/secrets/certs wiring.
- `docs/usage-guide.md` — new subsection once the full chain is usable
  end-to-end (deferred to whichever sub-project makes the first
  notification actually deliverable, likely sub-project 3).
- `docs/api-specification.yaml` — the three new routes, following this
  session's established pattern for adding new endpoints.
