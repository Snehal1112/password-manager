# Multi-Vault Support — Design

**Date:** 2026-05-29
**Status:** Approved for planning
**Author:** Snehal Dangroshiya

## Goal

Transform RocketVault from a single-vault system into a multi-vault system with
Azure Key Vault parity. A vault becomes a named namespace and security boundary
that contains secrets, keys, and certificates, governed by per-vault access
policies. One organization, one storage realm, one encryption realm — vaults are
logical containers within a tenant, exactly as in Azure Key Vault.

### Design decisions (locked)

| Decision | Choice |
|----------|--------|
| Isolation model | Azure KV parity — vault = namespace within one storage/encryption realm |
| Vault addressing | Path-based default (`/vaults/{name}/...`); optional subdomain routing, config-gated |
| Ownership | Vault-scoped resources; `user_id` becomes `created_by` audit metadata |
| Resource uniqueness | `UNIQUE (vault_id, name)` (was per-user-name) |
| Migration | Auto-create a `default` vault; legacy flat routes preserved (implicit default) |
| Vault lifecycle | Full Azure-like: create/get/list/update/soft-delete/recover/purge |
| Vault delete | Cascade soft-delete of contents; recover restores contents |
| Resource recovery | Per-vault `/vaults/{name}/deleted` flow |
| Admin model | Global admin + per-vault admins (vault-scoped `vaults/manage` policy) |
| Collision handling | Auto-rename duplicates to `{name}-{short-id}` and log |
| CLI vault selection | `--vault` flag > `ROCKETVAULT_VAULT` env > config default > `"default"` |

## Architecture: Approach A — Vault as routing + context-scoping layer

A vault-resolution middleware resolves the target vault (from subdomain or path,
fallback `default`) and injects `vault_id` into the request context — exactly how
`user_id` is injected today. Handlers and services read `vault_id` from context;
repositories add `vault_id` to their `WHERE` clauses. This localizes the change to
the middleware and the data-access layer; handler and service logic change only in
the scope value they thread through.

Rejected alternatives:
- **B — explicit vault parameter through every service signature:** far more
  invasive (changes all interfaces and callers); context injection is the
  established pattern.
- **C — database/connection per vault:** physical separation, contradicts the
  Azure-KV-parity decision and the default-vault upgrade path; overkill.

---

## Section 1 — Data Model & Schema

### New `vaults` table

```sql
CREATE TABLE IF NOT EXISTS vaults (
    id                 TEXT PRIMARY KEY,
    name               TEXT UNIQUE NOT NULL,        -- URL-safe, e.g. "prod"
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    purge_protection   BOOLEAN NOT NULL DEFAULT FALSE,
    retention_days     INTEGER NOT NULL DEFAULT 90, -- soft-delete retention
    created_by         TEXT NOT NULL,               -- user id (audit)
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at         TIMESTAMP NULL,              -- vault soft-delete
    scheduled_purge_at TIMESTAMP NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name);
```

### Resource tables

`secrets`, `keys`, `certificates` each gain:

```sql
vault_id TEXT NOT NULL DEFAULT '<DEFAULT_VAULT_UUID>'
FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
```

- New `UNIQUE (vault_id, name)` index replaces the per-user-name index.
- The `user_id` column is retained (no destructive rename) but now means
  **`created_by`** (audit metadata), not the access scope.
- Child tables (`secret_tags`, `secret_versions`, `key_tags`, `key_versions`,
  `certificate_tags`, `certificate_policies`, rotation tables) inherit scope
  through their parent FK; they do not get their own `vault_id`.

### Access policies

```sql
ALTER TABLE access_policies ADD COLUMN vault_id TEXT NULL;
```

- `vault_id = NULL` → global policy (applies to all vaults).
- `vault_id = <id>` → vault-specific policy.
- Existing policies stay NULL on upgrade, so no access is silently lost.

---

## Section 2 — Routing & Vault Resolution

### Vault-scoped routes (path-based, default)

```
/api/v1/vaults/{vault_name}/secrets/...
/api/v1/vaults/{vault_name}/keys/...
/api/v1/vaults/{vault_name}/certificates/...
/api/v1/vaults/{vault_name}/access-policies/...
/api/v1/vaults/{vault_name}/deleted/...
```

### Legacy flat routes (preserved, resolve to `default`)

```
/api/v1/secrets/...   /api/v1/keys/...   /api/v1/certificates/...
```

### Vault management routes

```
POST   /api/v1/vaults
GET    /api/v1/vaults
GET    /api/v1/vaults/{vault_name}
PATCH  /api/v1/vaults/{vault_name}
DELETE /api/v1/vaults/{vault_name}        # soft-delete
```

Registration order: `/vaults` and exact `/vaults/{name}` register before the
`/vaults/{name}/secrets` subrouter so management routes are not shadowed.

### `VaultResolutionMiddleware`

Inserted into the chain after authentication, before policy:

```
CORS → RateLimit → Authentication → VaultResolution → Policy → Authorization
```

Responsibilities:
1. Determine vault name: subdomain (if `server.subdomain_vaults: true`) →
   `{vault_name}` path var → fallback `"default"`.
2. Look up the vault by name. Missing → 404; `enabled = false` or soft-deleted → 403.
3. Inject `common.VaultIDKey` (new context key) into the request context.

Subdomain routing is config-gated and off by default (no DNS/TLS burden for
self-hosters). When on, a host-matcher resolver extracts `{vault}` from
`{vault}.<base-domain>`.

---

## Section 3 — Vault Lifecycle Service & Handlers

### Model — `model/vault.go`

```go
type Vault struct {
    ID               uuid.UUID
    Name             string
    Enabled          bool
    PurgeProtection  bool
    RetentionDays    int
    CreatedBy        uuid.UUID
    CreatedAt        time.Time
    DeletedAt        *time.Time
    ScheduledPurgeAt *time.Time
}
// + CreateVaultRequest, UpdateVaultRequest, VaultResponse, ListVaultsResponse
```

### Repository — `internal/repositories/vault_repository.go`

```go
type VaultRepository interface {
    Create(ctx, *Vault) error
    ReadByName(ctx, name string) (*Vault, error)   // used by resolution middleware
    ReadByID(ctx, id uuid.UUID) (*Vault, error)
    List(ctx) ([]Vault, error)
    Update(ctx, *Vault) error
    SoftDelete(ctx, id) error
    Recover(ctx, id) error
    Purge(ctx, id) error                            // respects purge_protection
    ListDeleted(ctx) ([]Vault, error)
}
```

### Service — `internal/services/vaults/vault_service.go`

Registered in the DI container (`service_container.go`).

- `CreateVault` — validates name; sets creator.
- `GetVault` / `ListVaults` / `UpdateVault`.
- `DeleteVault` — soft-delete; sets `scheduled_purge_at = now + retention_days`;
  **cascade soft-deletes the vault's resources** (Azure-like).
- `RecoverVault` — clears `deleted_at`; **restores cascade-deleted resources**.
- `PurgeVault` — hard delete; **refused if `purge_protection = true`**.

Name validation: lowercase alphanumeric + hyphens, 3–63 chars (Azure rule).
Reserved name `default` cannot be deleted or purged.

### Caching

Vault name→ID is resolved on every request. Add a read-through cache (precedent:
`internal/cache`, `internal/keycache`) invalidated on update/delete so resolution
adds no per-request DB hit.

### Bootstrap

The `default` vault must exist before any resource operation. Created by the
migration for existing DBs, and seeded at startup (next to `seedBootstrapToken` in
`InitializeDB`) for fresh DBs. Both converge on the same fixed default-vault UUID.

---

## Section 4 — Access-Policy & RBAC Scoping

1. **Vault-scoped policy lookup** in `PolicyMiddleware`:

   ```sql
   WHERE principal_id = ?
     AND resource_type = ?
     AND operation = ?
     AND (vault_id = ? OR vault_id IS NULL)   -- vault-specific OR global
   ```

   The `?` vault is the resolved `vault_id` from context.

2. **Deny-overrides-allow** precedence preserved (vault-specific deny beats a
   global allow).

3. **New `vaults` resource type** in `PolicyResourceType`, with a `manage`
   operation, to govern vault management and per-vault admin grants.

4. **Two-gate model unchanged:** role check (`AuthorizationMiddleware`) + a passing
   vault-scoped policy check.

5. **Access-policy CRUD** under `/vaults/{name}/access-policies` creates
   vault-scoped policies; legacy `/access-policies` creates global (NULL-vault)
   policies (admin-only).

### Admin model

- **Global admin:** create/delete/update any vault; manage any policy.
- **Per-vault admin:** a vault-scoped policy row `resource_type = vaults`,
  `operation = manage`, `vault_id = <vault>`, `effect = allow`. Grants policy
  management within that vault only — not vault create/delete. No new table.
- **Vault create/delete:** global admin only (NULL-vault `vaults/create` +
  `vaults/delete`).

Existing global policies keep `vault_id = NULL` and continue to apply everywhere.

---

## Section 5 — Repository & Service Query Scoping

Resource queries become vault-scoped (replacing user-scoping).

```go
// Before
ReadByOwner(ctx, id, userID uuid.UUID) (*Secret, error)
  // ...WHERE id = ? AND user_id = ? AND deleted_at IS NULL
ListByUser(ctx, userID uuid.UUID, tags []string) ([]Secret, error)
  // ...WHERE user_id = ? AND deleted_at IS NULL

// After
ReadInVault(ctx, id, vaultID uuid.UUID) (*Secret, error)
  // ...WHERE id = ? AND vault_id = ? AND deleted_at IS NULL
ListInVault(ctx, vaultID uuid.UUID, tags []string) ([]Secret, error)
  // ...WHERE vault_id = ? AND deleted_at IS NULL
```

- `Create` sets `vault_id` (scope) and `user_id`/`created_by` (audit).
- Applies to `secret_repository.go`, `key_repository.go`,
  `certificate_repository.go` and their list/read/soft-delete/recover/purge/
  version/tag methods. Child queries join through the parent's `vault_id`.
- Services gain `vaultID` in request structs/method calls; encryption, versioning,
  rotation logic unchanged.
- Handlers read `vaultID` from `common.VaultIDKey` (middleware-injected) and pass it
  down. `user_id` from claims stays, now used as `created_by`.

Scale: ~3 repositories, ~3 services, ~3–4 handler files (`secrets.go`, `keys.go`,
`certificates.go`, `soft_delete.go`), plus tests and `internal/testutils/mocks.go`.
Mechanical and pattern-consistent, but broad.

---

## Section 6 — Migration & Bootstrap

### Migration `internal/db/migrations/20260529000001_add_vaults.sql`

(Run by `migration_runner.go`; collision step in Go.)

1. Create `vaults` table.
2. Seed `default` vault with a fixed well-known UUID (idempotent
   `WHERE NOT EXISTS`).
3. `ALTER TABLE ... ADD COLUMN vault_id TEXT NOT NULL DEFAULT '<DEFAULT_VAULT_UUID>'`
   on resource tables.
4. Backfill: `UPDATE ... SET vault_id = '<DEFAULT_VAULT_UUID>' WHERE vault_id = ''
   OR vault_id IS NULL`.
5. **Collision resolution (Go pre-step):** for each resource table, find duplicate
   `name`s, rename all-but-one to `{name}-{short-id}`, log each rename.
6. Add `CREATE UNIQUE INDEX idx_<table>_vault_name ON <table>(vault_id, name)`
   *after* collision resolution.
7. `ALTER TABLE access_policies ADD COLUMN vault_id TEXT NULL`.

### Fresh-DB path

`createOptimizedSchema` in `db.go` includes the `vaults` table and `vault_id`
columns built-in. A startup seed hook inserts the `default` vault if absent. Fresh
and migrated installs converge on the same fixed default-vault UUID.

### Ordering

Seed the default vault row before validating `vault_id` FKs (correct on Postgres
too). The existing `migrate` CLI command and server-startup migration both run this.

### Note

`createOptimizedSchema` already carries `deleted_at`/`purge_protection` on this
branch (the open known-bug appears already fixed here); verify during
implementation and do not regress.

---

## Section 7 — CLI & Testing

### CLI

**New `vaults` command group** — `cmd/vaults.go`, registered in `cmd/root.go`, using
`internal/vaultclient`:

```
rocketvault vaults create <name> [--enabled] [--purge-protection] [--retention-days N]
rocketvault vaults list [--include-deleted]
rocketvault vaults get <name>
rocketvault vaults update <name> [--enabled=false] [--purge-protection=true] [--retention-days N]
rocketvault vaults delete <name>            # soft-delete
rocketvault vaults recover <name>
rocketvault vaults purge <name>             # blocked if purge-protection
```

**`--vault` selector** on every existing resource command (`secrets`, `keys`,
`certificate`, `rotation`, `backup`, scoped `audit`). Resolution precedence:

```
--vault flag  >  ROCKETVAULT_VAULT env  >  config: vault: <name>  >  "default"
```

Implemented once as a shared helper (`resolveVault(cmd) string`). When the resolved
vault is `default`, behavior is identical to today; existing scripts keep working.

### Testing

Mirrors existing infra (testify/mock, `internal/testutils/mocks.go`, per-package
`_test.go`):

1. **Migration:** default-vault seeding, `vault_id` backfill, collision auto-rename
   (seed colliding names → assert rename + log).
2. **Resolution middleware:** path var, subdomain (when enabled), fallback to
   `default`, disabled/soft-deleted vault → 403/404, missing vault → 404.
3. **Vault repository + service:** lifecycle, cascade soft-delete of contents,
   recover-restores-contents, purge-protection refusal, reserved-name protection,
   name validation.
4. **Policy scoping:** vault-specific allow, global (NULL) policy everywhere,
   deny-overrides, per-vault-admin (`vaults/manage`) grant.
5. **Repository scoping:** `(vault_id, name)` uniqueness; cross-vault invisibility;
   legacy flat route resolves to `default`.
6. **CLI:** `vaults` subcommands; `--vault` flag and env/config precedence;
   back-compat (no `--vault` → default).
7. **API integration:** create-vault → set-secret-in-vault → cross-vault isolation.

### Verification gate

Before any commit/PR: `go build ./...`, `go vet ./...`, `gofmt`, and
`go test ./... -count=1` all pass with no lint errors. Maintain the ≥80% coverage
bar. All commits and tags GPG-signed (key 61D246B30285ED35).
