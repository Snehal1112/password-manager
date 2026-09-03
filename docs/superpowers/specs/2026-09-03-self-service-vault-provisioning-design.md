# Self-Service Vault Provisioning — Design

**Date**: 2026-09-03
**Status**: Proposed
**Scope**: `internal/db/db.go`, `model/vault_provisioning_grant.go` (new),
`internal/repositories/vault_provisioning_grant_repository.go` (new),
`internal/repositories/vault_repository.go`,
`internal/repositories/access_policy_repository.go`,
`internal/repositories/role_assignment_repository.go`,
`internal/services/vaults/vault_service.go`,
`internal/services/authorization/vault_authz.go`,
`internal/services/authorization/access_policy_service.go`,
`internal/services/provisioning/` (new),
`internal/container/service_container.go`, `api/vault.go`,
`api/vault_provisioning_grants.go` (new), `cmd/vaults/authz.go`,
`cmd/vault-provisioning/` (new)
**Branch target**: v-4.0.0
**Source finding**: `.claude/roadmap-azure-parity-and-beyond.md`, "High priority
— multi-tenancy gaps", first bullet ("Self-service vault provisioning")

> **Not an Azure parity item.** Azure delegates vault creation through Azure
> Resource Manager — `Microsoft.KeyVault/vaults/write` scoped to a subscription
> or resource group, bounded by subscription quotas and Azure Policy. That
> machinery lives *above* Key Vault, and RocketVault has no platform above the
> vault. Nothing here moves a row in `.claude/azure-keyvault-parity.md`; this is
> Phase 3-shaped work promoted by priority, exactly as the roadmap classifies it.

---

## Problem

Creating a vault requires a **global** `vaults:manage` grant. `createVault`
(`api/vault.go:77`) and `listVaults` (`api/vault.go:121`) both call
`CanManageVault(ctx, roles, policies, userID, uuid.Nil)`. Passing `uuid.Nil`
deliberately matches only a global grant (see the explanatory comment at
`api/vault.go:63`), so exactly two things satisfy it: the global `admin` account
role, or an `access_policies` row with `resource_type=vaults`,
`operation=manage`, `effect=allow`, `vault_id=NULL`.

A tenant administrator therefore cannot create a vault. A platform operator has
to provision it for them — a support ticket per vault, which is the blocker for
the MSP / hosting-provider use case.

There is no safe middle ground today, because the global grant is far wider than
"may create vaults":

**`FindEffects` widens a NULL-scoped policy to every vault.**
`internal/repositories/access_policy_repository.go:90-96` queries
`... AND (vault_id = ? OR vault_id IS NULL)`. A NULL-scoped allow therefore
satisfies *every* vault-scoped `CheckAccess`, so a global `vaults:manage` holder
also gets get/update/delete on every existing vault via `CanManageVault`
(`vault_authz.go:30`).

**And it confers role-assignment management everywhere.**
`CanManageRoleAssignments` (`vault_authz.go:72`) runs the identical
`CheckAccess(..., PolicyResourceVaults, OpManage, vaultID)`, and its doc comment
records the global match as intentional ("scoped to vaultID or global (preserves
the pre-existing documented behavior)"). Because `nonAdminGrantableRoles`
(`role_assignment_service.go:37`) permits a non-admin to grant
`Key Vault Administrator`, a global `vaults:manage` holder can call
`POST /vaults/{any}/role-assignments` and award themselves full data-plane
access in every vault on the instance.

So handing the MSP's automation the only permission that lets it create vaults
also hands it the entire instance.

### What is *not* broken

`updateVault` (`api/vault.go:191`, checking `target.ID` at line 218), `getVault`
(line 180) and `deleteVault` (line 275) are already correctly vault-scoped. The
roadmap entry originally claimed `updateVault` was global; that was wrong and was
corrected on 2026-09-03. Only **create** and **list** demand a global grant.

## Goals

1. A non-admin principal can create vaults, bounded by an explicit quota, without
   holding any authority over vaults it did not create.
2. The creator of a vault becomes its full manager: vault-scoped `vaults:manage`
   plus a `Key Vault Administrator` role assignment on the new vault.
3. A global `vaults:manage` grant stops conferring management of every existing
   vault, and stops conferring role-assignment management everywhere.
4. Grantees can list the vaults they can actually reach.
5. The model extends to per-tenant naming and quotas without a rewrite.

## Non-goals

- **Name prefixes / namespacing.** Deferred deliberately. Today one MSP
  automation principal creates every vault, so there is no cross-customer
  contention and no collision-probing leak. Prefixes become necessary when
  customers get their own logins; the grant record is shaped so `name_prefix`
  is an added column, not a redesign. Recorded here so the omission is a
  decision, not an oversight: until then, a grantee's vault names share one flat
  namespace with admin-created ones and can collide.
- **The `tenants` entity.** Separate roadmap item. When it lands, `quota` and the
  future `name_prefix` move from the grant to the tenant row; the enforcement
  code does not change.
- **Delegated issuing of provisioning grants.** Global admin only, permanently —
  see Design §4.
- **Per-vault metering or billing.** Out of scope.

## Design

### 1. Three rights where there is one

| Right | Meaning | Check |
|---|---|---|
| `vaults:manage` scoped to a vault | get / update / delete that vault | `CanManageVault(..., vaultID)` — unchanged |
| `vaults:manage` global (`vault_id NULL`) | create vaults, list vaults — **and nothing else** | `CanManageVault(..., uuid.Nil)` — call sites unchanged, semantics narrowed |
| Provisioning grant (new) | create vaults up to a quota | `CanCreateVault(...)` |

The global `admin` account role continues to short-circuit every check
(`vault_authz.go:24`), so platform operators are unaffected throughout.

### 2. Narrowing the global grant — without breaking global denies

The narrowing must **not** be implemented in `FindEffects` or `CheckAccess`.
Those are shared by `PolicyMiddleware` (`internal/middleware/middleware.go:536`)
and `vaultcli.RequireDataAction` (`cmd/vaultcli/vault.go:47`) for
secrets/keys/certificates, where `OR vault_id IS NULL` is precisely what makes a
**global explicit deny** work. Removing it there would silently disable every
global deny — a security regression far worse than the problem being fixed.

Instead, add to `AccessPolicyService`:

```go
// CheckVaultScopedAccess evaluates a policy for a specific vault. A
// NULL-scoped DENY still matches -- a global deny must keep blocking every
// vault. A NULL-scoped ALLOW does not: an instance-wide allow is a grant to
// operate on the vault collection (create, list), never authority over a
// vault someone else owns.
CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID,
    resourceType model.PolicyResourceType, operation model.PolicyOperation,
    vaultID uuid.UUID) (AccessDecision, error)
```

The asymmetry is the whole point: deny widens, allow does not.

Both `CanManageVault` and `CanManageRoleAssignments` call it when
`vaultID != uuid.Nil`, and keep calling `CheckAccess` when `vaultID == uuid.Nil`.
**Changing only `CanManageVault` would leave the escalation path in the Problem
section fully open**, since role-assignment management alone is enough to award
oneself `Key Vault Administrator` anywhere.

### 3. The provisioning grant

```sql
CREATE TABLE IF NOT EXISTS vault_provisioning_grants (
    id           TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL UNIQUE,
    quota        INTEGER NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vaults_created_by ON vaults(created_by);
```

Added in both the `CREATE TABLE` block and `migrateSchema`, per the project's
dual-write migration convention.

**`principal_id` carries no foreign key to `users`.** The MSP's automation is an
OAuth2 service account, whose tokens carry `client.ID` as the subject
(`oauth2_service.go:106`), and service accounts are not `users` rows. The CLI
`grant` command therefore accepts a principal UUID as well as a username;
`resolvePrincipal` (`role_assignment_service.go:233`) resolves usernames only and
cannot be the sole path.

**`idx_vaults_created_by` is required, not an optimisation** — the quota check
counts by `created_by` on every provisioned create, and only `idx_vaults_name`
exists today (`db.go:382`).

### 4. Issuing grants — admin-only, permanently

```
PUT    /api/v1/vault-provisioning-grants/{principal_id}   upsert (issue / adjust quota)
DELETE /api/v1/vault-provisioning-grants/{principal_id}   revoke
GET    /api/v1/vault-provisioning-grants                  list
```

Keyed on `principal_id`, which is `UNIQUE`, so there is no separate grant id in
the URL and no read-one route.

Gated to the global `admin` account role, mirroring `requireAccessPolicyAdmin`
(`api/access_policies.go:32-38`). **This tier is deliberately non-delegable** —
unlike role assignments, where `Key Vault Data Access Administrator` may delegate
within an allow-list. A grantee able to amend grants could raise its own quota,
and the bound would be decorative.

CLI: `cmd/vault-provisioning/` with `grant` / `revoke` / `list`, each calling a
package-local authz helper. Per the CLI-authorization contract in `CLAUDE.md`,
the CLI bypasses `PolicyMiddleware` entirely, so that helper is the only
enforcement point on this path.

Every issue and revoke is audit-logged, as is every quota-denied create.

### 5. Creating a vault under a grant

`CanCreateVault` (new, `internal/services/authorization`) returns which right
applied — admin, global grant, or provisioning grant — so the handler and the CLI
share one decision and callers can attribute it in the audit trail. It is called
from `api/vault.go:77` and `cmd/vaults/authz.go:55`.

The **quota check runs inside the creation transaction**, in `VaultService`. Not
the handler (it would race with the insert) and not the repository (business
rule). Sequence:

1. Open tx.
2. `UPDATE vault_provisioning_grants SET quota = quota WHERE principal_id = ?` —
   a deliberate no-op write that takes a row lock on PostgreSQL and a `RESERVED`
   lock on SQLite. **This is the concurrency control, not a redundant statement.**
   Without it, two concurrent creates under READ COMMITTED both count `N` and both
   insert, yielding `N+2` against a quota of `N+1`. SQLite is accidentally safe
   via `SQLITE_BUSY`; PostgreSQL is not.
3. Count the principal's vaults via `CountByCreatedBy` — every row still present
   in `vaults` with that `created_by`, soft-deleted ones included. Only a purge
   removes the row and so releases the slot.
4. Refuse with `ErrVaultQuotaExceeded` if `count >= quota`.
5. Insert the vault, the creator's vault-scoped `access_policies` row, and the
   creator's `Key Vault Administrator` `role_assignments` row.
6. Commit.

**Soft-deleted vaults count against quota.** They still hold their name and are
recoverable; excluding them would let a grantee cycle delete-and-create past the
bound indefinitely. They stop counting at purge, and the existing purge scheduler
(`internal/services/softdelete/purge_scheduler.go`) auto-purges soft-deleted
vaults past `retention_days`, so a slot frees itself without operator action.

**A grantee may not set `purge_protection`.** `PurgeVault` refuses a protected
vault, so a grantee could otherwise protect a vault, soft-delete it, and pin the
quota slot permanently — requiring an admin to unstick it. The field is
admin-only on the provisioned path; grantees keep every other management
capability on their vaults.

**Retroactivity:** a principal's pre-existing vaults count against the quota,
because the count is by `created_by`. Issue quotas accordingly.

### 6. Transaction plumbing

Three repositories need tx-aware siblings; all three `Create` methods currently
run on the pooled handle:

- `VaultRepository.Create` (`vault_repository.go:104`)
- `accessPolicyRepository.Create` (`access_policy_repository.go:40`)
- `roleAssignmentRepository.Create` (`role_assignment_repository.go:37`)

Each gains `CreateTx(ctx, ex db.DBTX, ...)`, following the established
`ReadByIDTx` pattern (`vault_repository.go:135`). `vaultService` already holds a
`txBeginner` (`vault_service.go:101,203`), so no new transaction machinery is
introduced.

**The creator's role assignment is written directly, not through
`RoleAssignmentService.AssignRole`.** That method is not tx-aware, performs its
own compensating deletes on failure (`role_assignment_service.go:162-176`), and
its `nonAdminGrantableRoles` gate is irrelevant here — the grant is made by the
system on the creator's behalf, not by one principal to another.

### 7. Listing for grantees

`listVaults` (`api/vault.go:121`) and `requireCanListVaults`
(`cmd/vaults/authz.go:70`) both check `CanManageVault(..., uuid.Nil)`, which a
grantee does not satisfy — so without this section a grantee cannot see the
vaults it just created, and the feature is unusable.

`ListVaults` gains a scoped path: global admin and global-grant holders see
everything; any other caller sees vaults where they hold vault-scoped
`vaults:manage`. Filtering on the policy rather than on `created_by` means a
customer's whole team sees the same set once more than one principal is involved
— which is the direction of travel.

Note the deliberate asymmetry with §5: **quota counts by `created_by`, listing
filters by policy.** Quota bounds what a principal *created*, which is a fact
about history that must not change when rights are granted or revoked. Listing
answers what a principal can *reach today*, which must follow current rights.
Using one field for both would either let a grantee escape its quota by handing
a vault off, or hide a vault from someone who legitimately manages it.

### 8. Two pre-existing bugs fixed en route

**`PurgeVault` strands `role_assignments`.** It explicitly cleans
`access_policies` and `vault_webhook_configs` (`vault_service.go:503-516`) but
not `role_assignments`, and the FK cascade (`db.go:718`) is inert on SQLite,
where `foreign_keys` is off. Today that leaks occasionally; once every
provisioned vault carries a creator assignment, it leaks on every purge. Add
`DeleteByVault` to the role-assignment repository and call it alongside the
existing two.

**DI ordering.** `vaultService` is constructed at
`service_container.go:297`, before `accessPolicyRepository` and
`roleAssignmentRepository` at `:429`/`:434`. The new dependencies must be
setter-injected, following the existing `SetPolicyCleaner` pattern (`:433`).
Constructor injection here reproduces the nil-interface runtime breakage
previously hit during `feat/vault-scoped-users`.

### 9. Sequencing — two releases

**Release 1 (additive, no break).** The grants table, `CanCreateVault`, quota
enforcement, scoped `ListVaults`, the admin API and CLI, and both §8 bug fixes.
Plus a startup diagnostic in `migrateSchema` — modeled on the `secret_policies`
diagnostic at `db.go:1099-1127` — that logs every principal holding a NULL-scoped
`(vaults, manage, allow)` policy. Nothing breaks; the MSP can move its automation
onto a provisioning grant.

**Release 2 (breaking).** `CheckVaultScopedAccess` and the narrowing of both
`CanManageVault` and `CanManageRoleAssignments`, once the diagnostic has reported
from the field.

This ordering is safe because global `vaults:manage` rows are only ever created
by hand through the admin-only `createAccessPolicy`
(`api/access_policies.go:32-38, 115-121`) — `ExpandRole` always sets a concrete
`VaultID` (`roles.go:182`) and Azure roles expand to nothing (`:163`). So the
affected population is small, known, and enumerable before the change ships.

## Testing

- `CheckVaultScopedAccess`: NULL-scoped deny matches; NULL-scoped allow does not;
  vault-scoped rows behave as before. Table-driven.
- Regression: a global `vaults:manage` holder is refused
  `POST /vaults/{other}/role-assignments` after the narrowing — the escalation
  path from the Problem section, pinned.
- Regression: global explicit-**deny** on secrets/keys/certs still applies
  through `PolicyMiddleware` and `vaultcli.RequireDataAction` after the change.
- Quota: at limit refuses; below limit succeeds; soft-deleted counts; purged does
  not; pre-existing vaults count retroactively.
- Concurrency: two parallel creates at `quota-1` produce exactly one success and
  one `ErrVaultQuotaExceeded`. Run against both SQLite and PostgreSQL — the race
  only manifests on PostgreSQL.
- Transaction: an induced failure at each of the three inserts leaves no vault,
  no policy and no role assignment behind.
- Grantee lifecycle: create → appears in the grantee's `ListVaults` → grantee can
  manage it → grantee cannot touch a vault it did not create → grant revoked →
  cannot create, but retains rights over existing vaults.
- Service-account principal: a grant issued to an OAuth2 service account works
  end to end.
- Non-delegation: a grantee cannot `PUT` or `DELETE` its own grant.
- `purge_protection` refused on the provisioned path.
- `PurgeVault` removes the creator's role assignment.

## Documentation

- `.claude/manual-testing-plan.md`: new subsection under §5.
- `docs/release-notes/`: a note for release 2, naming the two behaviours a global
  `vaults:manage` holder loses.
- `.claude/roadmap-azure-parity-and-beyond.md`: mark the item shipped, and record
  that prefixes and the tenant entity remain open.
- `CLAUDE.md`: the new CLI package in the CLI Authorization section.
