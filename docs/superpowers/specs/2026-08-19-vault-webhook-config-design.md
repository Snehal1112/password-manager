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
| Secret origin | **Server-generated**, never client-supplied: `Upsert` mints 32 bytes from `crypto/rand`, base64-encodes them, and returns the plaintext once | Resolved during spec self-review, where an earlier draft contradicted itself (a client-supplied `signing_secret` field alongside show-once semantics). Show-once only means anything if the server is the origin — a secret the client sent is one the client already has, so there is nothing to "show once". Server generation also keeps the secret off the command line and out of shell history, and removes an entropy-quality decision from the operator. |
| Secret visibility | Show-once: returned in the `PUT` response body only (create or rotate), never via `GET` | Considered three options during brainstorming: always-write-only (strictest, least convenient), readable anytime by `CanManageVault` (most convenient, but a standing read path that survives a later privilege change), and show-once (this choice) — the same pattern GitHub/AWS use for webhook secrets and access keys. Gets the "copy it down once" convenience without a durable read path. |
| Partial update | `PUT` on an existing config: `rotate_secret` (bool, default false) mints and returns a new secret; omitted/false keeps the current encrypted value untouched. `enabled` is `*bool` — omitted keeps the current value | Lets an operator change just the URL without forcing a secret rotation (which would require updating the receiver's config too). `enabled` must be a pointer, not a bare `bool`: with a bare `bool`, `PUT {"url": "..."}` is indistinguishable from `PUT {"url": "...", "enabled": false}` and would silently disable the webhook. |
| URL validation | Service layer requires a parseable absolute URL with an `https` scheme and a non-empty host; anything else is a 400 | Storing an unvalidated string means the delivery primitive inherits garbage it cannot act on. Deliberately minimal: SSRF policy (private-range blocking, allowlists, redirect handling) belongs to the sub-project that actually makes the outbound call, not to a CRUD layer that never dials anything. |
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
    vault_id                 TEXT NOT NULL UNIQUE,
    url                      TEXT NOT NULL,
    signing_secret_encrypted TEXT NOT NULL,
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vault_webhook_configs_vault_id ON vault_webhook_configs(vault_id);
```

Three details corrected during spec self-review against `db.go:486-508`
(`key_rotation_policies`, the nearest structural precedent):

- The foreign key is a **trailing `FOREIGN KEY (...) REFERENCES ... ON DELETE
  CASCADE` clause**, not an inline column-level `REFERENCES`. Every FK in this
  schema is declared that way, and `ON DELETE CASCADE` is load-bearing here:
  without it, purging a vault leaves an orphaned webhook config row holding an
  encrypted secret for a vault that no longer exists.
- `created_at`/`updated_at` carry `DEFAULT CURRENT_TIMESTAMP`, matching the
  precedent.
- **No dialect branching is needed.** `key_rotation_policies` uses
  `BOOLEAN NOT NULL DEFAULT TRUE` and `TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
  verbatim in both `createOptimizedSchema` and `migrateSchema` with no
  SQLite/Postgres split, so this table can too. (The earlier draft hedged that
  the plan should "copy whatever dialect handling exists" — there is none to
  copy.)

Both `id` and `vault_id` follow this codebase's existing `TEXT`-stored-UUID
convention, matching every other table.

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
	// GetByVaultID returns the vault's config, or an error wrapping
	// repositories.ErrNotFound (internal/repositories/errors.go) if none
	// exists — the same sentinel VaultRepository.ReadByName/ReadByID wrap
	// with %w. Includes SigningSecretEncrypted — callers that only need the
	// API-facing fields must not forward it into a response.
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
	// vault's config. plaintextSecret is populated only when this call
	// actually minted a secret — always on create, and on update only when
	// req.RotateSecret is true. Empty otherwise, which is how the handler
	// knows not to include a signing_secret field in the response.
	Upsert(ctx context.Context, vaultID uuid.UUID, req UpsertWebhookRequest, scope model.Scope) (cfg *model.VaultWebhookConfig, plaintextSecret string, err error)
	// Get authorizes via CanManageVault, then returns the config.
	// SigningSecretEncrypted is present on the returned model but the
	// caller (the HTTP handler) must build VaultWebhookConfigResponse, not
	// forward the model directly.
	Get(ctx context.Context, vaultID uuid.UUID, scope model.Scope) (*model.VaultWebhookConfig, error)
	Delete(ctx context.Context, vaultID uuid.UUID, scope model.Scope) error
}

type UpsertWebhookRequest struct {
	URL          string
	RotateSecret bool  // ignored on create (a secret is always minted); on update, true mints a replacement
	Enabled      *bool // nil = keep current value (create defaults to true)
}
```

`Upsert`'s sequence:

1. **Authorize** via `CanManageVault` before any repository call.
2. **Validate the URL**: `url.Parse` must succeed, `Scheme` must be `https`,
   `Host` must be non-empty. Anything else returns a validation error the
   handler maps to 400.
3. **Read the existing row** (if any) to learn whether this is a create and to
   recover the current `SigningSecretEncrypted`.
4. **Mint or carry the secret.** On create, or on update with
   `RotateSecret: true`, generate 32 bytes via `crypto/rand.Read`,
   base64-encode them, and encrypt with `common.EncryptSecret` (`common/encrypt.go:152`).
   Otherwise carry the existing `SigningSecretEncrypted` through unchanged —
   never decrypt-then-re-encrypt an unrotated secret, since nothing in this
   sub-project needs its plaintext.
5. **Upsert** and return the plaintext only when step 4 minted one.

The plaintext secret is returned up the stack and must not be logged at any
layer — see the CLI note below, which is the one place the codebase's nearest
precedent does the wrong thing.

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
├── set.go     # rocketvault vault-webhook set --vault <name> --url <url> [--rotate-secret] [--enabled=true|false]
├── get.go     # rocketvault vault-webhook get --vault <name>
├── delete.go  # rocketvault vault-webhook delete --vault <name>
└── authz.go   # thin wrapper reusing authz.CanManageVault via the container, same shape as cmd/vaults/authz.go
```

Note there is no `--secret` flag: the server mints the secret (see the
Secret origin decision above), so nothing puts it on the command line or into
shell history. `--rotate-secret` is a bare bool.

`set` prints the signing secret when the response carries it (create or
rotate). Spec self-review searched for an existing "save this, it will not be
shown again" banner in this codebase and **found none** — so there is no
precedent to match and the plan defines the copy. Follow the shape of
`cmd/users/create.go:93-98`, the nearest analogue (a labeled field list
followed by a trailing instruction line):

```
Webhook configured for vault "<name>":
  URL: <url>
  Enabled: <bool>
  Signing Secret: <secret>

Store the signing secret now — it is not retrievable after this.
```

One deliberate divergence from that precedent: `cmd/users/create.go:91` also
writes the TOTP secret into the structured logger. Do **not** copy that here —
the webhook signing secret must never reach the logs.

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
- **Service**: encryption round-trip (the stored value decrypts back to the
  returned plaintext, and `Get` never decrypts); show-once semantics
  (`plaintextSecret` non-empty on create, empty on an update with
  `RotateSecret: false`, non-empty on an update with `RotateSecret: true`);
  partial-update semantics (an update without rotation leaves the stored
  encrypted value byte-identical, and a nil `Enabled` leaves the stored flag
  unchanged — the regression test for the bare-bool trap the pointer type
  exists to avoid); two successive creates never mint the same secret;
  URL validation rejects a non-`https` scheme, an unparseable string, and a
  scheme-only URL with no host; `CanManageVault` denial surfaces as an error
  before any repository call.
- **API**: `PUT`/`GET`/`DELETE` request/response shapes; `PUT` response
  includes the secret only on create/rotate; 403 for a caller without
  `CanManageVault`; 404 for a nonexistent vault name; route registration on
  `BaseRoutes.Vaults` (not `VaultScoped`) — a regression test analogous to
  the earlier `InitBackupItem` vault-scoped-registration fix, but proving
  the *opposite* placement is correct here. Also: `GET` never emits a
  `signing_secret` field, on any code path.
- **CLI**: flag parsing for `set`/`get`/`delete`, output formatting
  (including the one-time-secret notice), authorization denial surfaced as
  a clear CLI error, matching `cmd/vault-access/`'s existing test patterns.
- **Cascade**: deleting a vault removes its webhook config row, proving the
  `ON DELETE CASCADE` clause is present and effective (a repository-level
  test against real SQLite, since this is a schema guarantee, not Go logic).

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
