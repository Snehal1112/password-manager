# Vault-Scoped User Access (Role Assignments) — Design

**Date:** 2026-06-06
**Status:** Approved for planning
**Author:** Snehal Dangroshiya

## Goal

Make granting a global identity vault-scoped access a first-class, ergonomic
operation that matches Azure Key Vault's role-assignment model.

RocketVault already supports vault-scoped access through `access_policies` rows
with a non-NULL `vault_id`. What is missing is the ergonomics and the Azure
primitive on top of it: a **role assignment** ("grant user X role R on vault Y")
that expands to the underlying policy rows, plus a CLI and an audit view of who
can access a vault.

### Azure parity context (the model decision)

Azure Key Vault never places users inside a vault. Identities are tenant-global
(Microsoft Entra ID: user, group, service principal, managed identity). A
"vault user" is a tenant-global identity with a **role assignment scoped to the
vault resource**. Microsoft's recommendation is to assign roles at vault scope,
not per object.

This design mirrors that exactly:

- Users stay tenant-global (`model/user.go` is unchanged — no `vault_id`).
- A "vault-scoped user" = a global user + a role assignment with `vault_id` set.
- Deleting a vault does not delete the user; it removes their vault-scoped grants.

Two alternatives were rejected:

- **True vault-owned users** (users created inside / deleted with a vault):
  Azure has no such concept; it breaks the locked multi-vault parity model.
- **Hybrid vault_members table** (membership as a separate first-class concept):
  more tables than Azure uses; role assignments already express membership.

### Design decisions (locked)

| Decision | Choice |
|----------|--------|
| Identity model | Tenant-global users; access is vault-scoped role assignments (Azure parity) |
| Role definitions | Code-level constants (`map[Role][]Permission`), not a DB table |
| Grant unit | One role assignment expands to N `access_policies` rows |
| Grouping / revoke | `assignment_id` tag column on `access_policies`; revoke deletes by tag |
| Principal input | Username OR UUID — server resolves |
| Routing | New vault-scoped route `/vaults/{name}/role-assignments` (was spec'd, never built) |
| Raw policies | `/access-policies` flat routes unchanged — power-user fine-grained path |
| Effect | Role assignments only write `effect=allow`; deny-overrides precedence intact |

---

## Section 1 — Model & Roles

### Built-in vault roles

Mirror Azure KV data-plane roles, mapped onto RocketVault's existing
`PolicyResourceType` (`secrets|keys|certificates|vaults`) and the 18 operations
defined in `model/access_policy.go`.

| Role | Bundle (resource_type → operations) |
|------|-------------------------------------|
| `vault-reader` | secrets, keys, certificates → `get, list` |
| `secrets-user` | secrets → `get, list` |
| `secrets-officer` | secrets → `get, list, set, delete, backup, restore, recover, purge` |
| `crypto-user` | keys → `get, list, sign, verify, encrypt, decrypt` (+ `wrap, unwrap` if present as operations) |
| `crypto-officer` | keys → `get, list, create, delete, rotate, backup, restore, recover, purge, import` |
| `certificates-officer` | certificates → `get, list, create, delete, renew, backup, restore, recover, purge` |
| `vault-admin` | union of the above + `vaults/manage` for that vault |

Roles are defined in code (`internal/services/authorization/roles.go`) as a
static `map[RoleName][]Permission`, with helpers `IsValidRole(name)` and
`ExpandRole(role, vaultID) []AccessPolicy`. Keeping roles in code (not a table)
localizes the change and matches the "bundle expands to rows" approach.

> Implementation note: `wrap`/`unwrap` are listed in the parity doc but the
> current operation enum has `encrypt|decrypt|sign|verify|...`. During
> implementation, include only operations that exist in
> `model/access_policy.go`; do not invent operation strings. If `wrap`/`unwrap`
> are absent, `crypto-user` covers `sign, verify, encrypt, decrypt`.

### New table `role_assignments`

The only schema addition (plus one nullable column on `access_policies`).

```sql
CREATE TABLE IF NOT EXISTS role_assignments (
    id             TEXT PRIMARY KEY,
    principal_id   TEXT NOT NULL,
    principal_type TEXT NOT NULL,        -- user | service_account
    role           TEXT NOT NULL,        -- vault-reader, secrets-user, ...
    vault_id       TEXT NOT NULL,        -- always vault-scoped
    created_by     TEXT NOT NULL,        -- granting admin (audit)
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (principal_id, role, vault_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);
```

### `access_policies` gains one nullable column

```sql
ALTER TABLE access_policies ADD COLUMN assignment_id TEXT NULL;
```

When a role is assigned, the service writes the `role_assignments` row **and**
the expanded `access_policies` rows, each tagged with that `assignment_id`.
Revoke deletes by `assignment_id` — atomic and unambiguous. Hand-written
policies keep `assignment_id = NULL` and are never touched by this feature.

### Model types — `model/role_assignment.go`

- `RoleAssignment{ID, PrincipalID, PrincipalType, Role, VaultID, CreatedBy, CreatedAt}`
- `AssignRoleRequest{Principal, PrincipalType, Role}` (Principal = username or UUID)
- `RoleAssignmentResponse{ID, PrincipalID, PrincipalUsername, PrincipalType, Role, VaultID, VaultName, CreatedAt, ExpandedPolicyCount}`

---

## Section 2 — API & Routes

Build the missing vault-scoped route (spec'd in the multi-vault design at
`/vaults/{name}/access-policies` but never delivered — only flat
`/access-policies` exists in `api/api.go`) and add role-assignment endpoints.

### New endpoints (vault-scoped)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/vaults/{vault_name}/role-assignments` | Grant: `{principal, role}` → expands to policy rows |
| `GET` | `/api/v1/vaults/{vault_name}/role-assignments` | List grants in this vault (who-can-access audit view) |
| `GET` | `/api/v1/vaults/{vault_name}/role-assignments/{id}` | Get one assignment |
| `DELETE` | `/api/v1/vaults/{vault_name}/role-assignments/{id}` | Revoke (delete assignment + tagged policy rows) |

### Request body (POST)

```json
{
  "principal": "alice",
  "principal_type": "user",
  "role": "secrets-user"
}
```

- `principal`: username OR UUID. If it parses as a UUID, used directly and
  verified to exist; otherwise looked up by username via the user repo. Unknown
  principal → 404. This removes the "copy UUID from GET /users" friction.
- `principal_type`: optional, defaults `user`; `service_account` allowed.
- `role`: must be a known built-in role; unknown → 400.

### Response (assignment)

```json
{
  "id": "...", "principal_id": "...", "principal_username": "alice",
  "principal_type": "user", "role": "secrets-user",
  "vault_id": "...", "vault_name": "prod",
  "created_at": "...", "expanded_policy_count": 2
}
```

### Routing wiring (`api/api.go`)

Register a `RoleAssignments` subrouter on the vault-scoped path, alongside the
existing `/vaults/{name}/secrets` subrouter and after the exact `/vaults/{name}`
management routes (so it is not shadowed). It passes through the standard
middleware chain; `VaultResolutionMiddleware` resolves `{vault_name}` →
`vault_id` into `common.VaultIDKey`, and the handler reads it from context (no
manual lookup).

### Authorization to manage assignments

Creating/deleting a role assignment is gated: global admin OR a `vaults/manage`
policy on that vault (the per-vault admin from the multi-vault design). Same
two-gate model (role check + vault-scoped policy check); no new mechanism.

Privilege-escalation caveat (mirrors Azure's Contributor warning): granting
`vault-admin` includes `vaults/manage`. Only a global admin or an existing
vault-manager can grant `vault-admin`. Enforced by the endpoint's authz gate;
documented in the admin manual.

### Flat `/access-policies` routes

Unchanged. Power users keep raw single-operation grants. Role assignments are
the ergonomic layer on top, not a replacement.

### Repository read-side addition

`access_policy_repository.go` gains `ListByVault(ctx, vaultID)` (currently
missing) and `DeleteByAssignmentID(ctx, assignmentID)`. `ListByVault` backs both
the assignment service and any future "who has access to vault X" auditing.

---

## Section 3 — CLI

New command group `cmd/vault-access/`, registered in `cmd/root.go`. This is the
first CLI for access management (none exists today).

```
rocketvault vault-access grant <principal> --role <role> [--vault <name>]
rocketvault vault-access list [--vault <name>]
rocketvault vault-access revoke <assignment-id> [--vault <name>]
rocketvault vault-access roles
```

- `--vault` resolution reuses `common.ResolveVaultName` (flag >
  `ROCKETVAULT_VAULT` env > viper `vault` > `default`) — same precedence as the
  `secrets` CLI; no new logic.
- `grant <principal>` accepts username or UUID (server resolves).
- `list` calls `GET /vaults/{name}/role-assignments`; table output (id,
  principal, role, created_at). Honors `--output json|yaml|table` if the output
  formatter is wired.
- `roles` is client-side static: prints the role→bundle map so admins can see
  what a role grants before assigning.

### Examples

```
rocketvault vault-access grant alice --role secrets-user --vault prod
rocketvault vault-access grant svc-ci --role crypto-user --vault prod
rocketvault vault-access list --vault prod
rocketvault vault-access revoke 3f2a... --vault prod
```

Out of scope: a full CLI for raw single-operation `/access-policies`. Role
assignments cover the common case; raw policy management stays HTTP-only.

---

## Section 4 — Service Logic & Data Flow

New service `internal/services/authorization/role_assignment_service.go` (next
to `access_policy_service.go`, registered in the DI container). Role definitions
in `internal/services/authorization/roles.go`.

### Grant — `AssignRole(ctx, req)`

```
1. Validate role name          → unknown => ErrInvalidRole (400)
2. Resolve principal           → username? lookup user repo. UUID? verify exists.
                                 not found => ErrPrincipalNotFound (404)
3. Verify vault exists+enabled (vault_id from ctx; resolution middleware)
4. Idempotency                 → UNIQUE(principal_id, role, vault_id) hit:
                                 return existing assignment, 200 (not an error)
5. BEGIN TX:
     a. INSERT role_assignments row (new assignment_id)
     b. ExpandRole(role, vaultID) → INSERT each access_policies row,
        effect=allow, assignment_id=<id>
   COMMIT  (rollback on any failure => no partial grant)
6. Return assignment + expanded_policy_count
```

### Revoke — `RevokeAssignment(ctx, assignmentID, vaultID)`

```
1. Read assignment; verify it belongs to the resolved vault
   (cross-vault id => 404; cannot revoke another vault's grant)
2. BEGIN TX:
     a. DELETE access_policies WHERE assignment_id = ?
     b. DELETE role_assignments WHERE id = ?
   COMMIT
```

### List — `ListAssignments(ctx, vaultID)`

Reads `role_assignments WHERE vault_id = ?`, joins username from the user repo
for display. The "who can access vault X" audit view.

### Decisions / edge cases

- **Transactions:** grant and revoke are atomic across two tables. Use the
  existing tx pattern if present; otherwise add a minimal tx-aware path on the
  affected repos. No partial grants.
- **`assignment_id` is the join key.** Revoke never guesses which rows belong to
  a grant; it deletes by tag. Hand-written policies (`assignment_id IS NULL`)
  are never affected.
- **Deny semantics unchanged.** Role assignments only ever write `effect=allow`.
  Existing deny-overrides-allow precedence in `CheckAccess` still wins — a
  vault-specific or global deny beats a role-granted allow. The evaluation
  engine is untouched.
- **Vault delete cascade:** `role_assignments.vault_id` is `ON DELETE CASCADE`.
  `access_policies` rows are not FK'd to vaults today, so on `PurgeVault` the
  cascade adapter additionally deletes `access_policies WHERE vault_id = ?`. On
  soft-delete, policies are left in place (recover restores access), mirroring
  the resource cascade behavior.
- **`vault-admin` self-grant guard:** assigning `vault-admin` includes
  `vaults/manage`; only a global admin or existing vault-manager may grant it
  (the endpoint authz gate, Section 2).

### Files

- New: `roles.go`, `role_assignment_service.go`, `model/role_assignment.go`,
  `api/role_assignments.go`, `cmd/vault-access/*`,
  `internal/repositories/role_assignment_repository.go`,
  `internal/db/migrations/20260606000001_add_role_assignments.sql`.
- Edited: `api/api.go` (route), `cmd/root.go` (CLI reg),
  `internal/container/service_container.go` (DI),
  `internal/repositories/access_policy_repository.go` (+`ListByVault`,
  +`DeleteByAssignmentID`, `assignment_id` in insert/scan),
  `internal/db/db.go` (schema + migrate), the vault cascade adapter (purge
  cleanup), `internal/testutils/mocks.go`.

---

## Section 5 — Migration & Schema

Dual-write pattern (fresh-DB schema + idempotent `migrateSchema`) so existing
databases do not hit "no such column". Index creation lives inside
`migrateSchema` after the table/column exist — the ordering bug class that
already bit this repo (audit-index ordering).

### Fresh DB — `createOptimizedSchema` (`internal/db/db.go`)

- `CREATE TABLE IF NOT EXISTS role_assignments (...)` (Section 1).
- Add `assignment_id TEXT NULL` to the `access_policies` CREATE TABLE.
- Indexes: `idx_role_assignments_vault ON role_assignments(vault_id)`,
  `idx_access_policies_assignment ON access_policies(assignment_id)`.

### Existing DB — `migrateSchema` (`internal/db/db.go`)

Idempotent, ordered after vaults exist (FK target):

```
CREATE TABLE IF NOT EXISTS role_assignments (...)
ALTER TABLE access_policies ADD COLUMN assignment_id TEXT NULL   -- guarded if present
CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ...
CREATE INDEX IF NOT EXISTS idx_access_policies_assignment ...
```

### Standalone migration file

`internal/db/migrations/20260606000001_add_role_assignments.sql` for the
`migrate` CLI path (matches the `20260529000001_add_vaults.sql` precedent). The
`20260606...` timestamp sorts after the vaults migration, guaranteeing the FK
target exists first.

### Backward compatibility

- `assignment_id IS NULL` = every pre-existing hand-written policy. Untouched,
  fully functional.
- No backfill — no existing data maps to a role assignment.
- Zero behavior change until an admin issues a grant.

---

## Section 6 — Testing

Mirrors existing infra (testify/mock, `internal/testutils/mocks.go`, per-package
`_test.go`). Coverage bar ≥80%.

1. **Roles unit** (`roles_test.go`): each built-in role expands to the expected
   (resource, operation) set; `vault-admin` includes `vaults/manage`; unknown
   role rejected.
2. **Service** (`role_assignment_service_test.go`):
   - grant happy path → assignment row + N tagged policy rows.
   - grant idempotent → duplicate returns existing, no extra rows.
   - principal resolution: username→uuid, raw uuid, unknown → 404.
   - revoke → deletes exactly the tagged rows; NULL-tagged policies intact.
   - cross-vault revoke (id from another vault) → 404.
   - tx rollback: simulated mid-grant failure → no partial rows.
3. **Repository** (`role_assignment_repository_test.go` + extend
   `access_policy_repository_test.go`): `UNIQUE(principal_id, role, vault_id)`;
   `ListByVault`; `DeleteByAssignmentID`; `assignment_id` insert/scan round-trip.
4. **Authz integration:** grant `secrets-user` on `prod` → principal passes
   `CheckAccess(secrets, get, prod)`, fails on `dev` (cross-vault isolation),
   fails on `secrets/delete` (not in bundle). A deny policy still overrides a
   role-granted allow.
5. **API** (`role_assignments_test.go`): POST/GET/LIST/DELETE; vault resolution
   via path; authz gate (non-admin without `vaults/manage` → 403); unknown vault
   → 404.
6. **Migration:** fresh schema has table+column; `migrateSchema` on a
   pre-feature DB adds them idempotently (run twice → no error); index ordering
   correct.
7. **CLI** (`cmd/vault-access/*_test.go`): grant/list/revoke/roles; `--vault`
   precedence; username and uuid forms.

### Verification gate (before any commit/PR)

`go build ./...`, `go vet ./...`, `gofmt` on touched files,
`go test ./... -count=1` green, ≥80% coverage. All commits and tags GPG-signed
(key `61D246B30285ED35`).

---

## Out of scope (deferred, not bugs)

- Groups as principals (Azure has groups; RocketVault `principal_type` is
  `user|service_account` only). Future work.
- Custom user-defined roles (Azure custom roles). Built-in roles only here.
- A CLI for raw single-operation `/access-policies`. HTTP-only as today.
- Time-bound / JIT assignments (Azure PIM). Not modeled.
- Subdomain vault addressing (already deferred in the multi-vault design).
