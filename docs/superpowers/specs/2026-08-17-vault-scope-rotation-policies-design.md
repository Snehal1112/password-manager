# Vault-Scope Rotation Policies — Design

**Date:** 2026-08-17
**Branch:** v-4.0.0
**Status:** Approved design, ready for implementation planning
**Covers:** Vault-scoping `rotation_policies` (secrets) and `key_rotation_policies` (keys)
**Part of:** Spec A of a two-part rotation-policy initiative. Spec B — a unified
scheduler that actually executes rotation policies (`internal/schedulerkit`, a
new key-rotation scheduler, migrating the existing secrets/certificate
schedulers onto it) — is deliberately deferred and specced separately once
this lands.

---

## 1. Goal

Both rotation-policy tables are unscoped by vault today, by two different
routes described in §3. This means a principal holding a rotation-policy role
grant in one vault can read, assign, or act on rotation policies belonging to
secrets/keys in *any* vault — the same class of cross-vault bypass that
`docs/superpowers/specs/2026-07-26-vault-scope-azure-parity-design.md` closed
for secrets, keys, and certificates, and explicitly deferred for this case
(its §10 names "P5: key rotation policies" as out of scope). This spec closes
that gap for both tables and gives the planned rotation scheduler (Spec B) a
vault-scoped foundation to build on from day one, instead of building the
scheduler against a soon-to-be-migrated data model and touching the same
files twice.

## 2. Decisions

| Decision | Choice | Consequence |
|---|---|---|
| Which tables | Both `rotation_policies` (secrets) and `key_rotation_policies` (keys) | Two migrations from two different starting points — see §3 |
| Backfill strategy | Asymmetric. `rotation_policies` gets a blind `DEFAULT`-vault backfill. `key_rotation_policies` gets a JOIN-derived backfill from its parent key's `vault_id`. | `rotation_policies` predates `vault_id` existing anywhere in the schema, so every existing row is genuinely default-vault. `key_rotation_policies` launched 2026-08-13 — *after* keys were already vault-scoped — so a blind default would silently misassign any policy row whose parent key already lives in a non-default vault. |
| `KeyRotationPolicy.VaultID` | Derived from the parent key's own `vault_id` at write time; never independently supplied by a caller | A rotation policy cannot outlive or diverge from its key's vault — enforced structurally, not by convention |
| Repository duplication | New generic helpers in `internal/repositories/scoped_crud.go` (`ScopedGet[T]`, `ScopedExec`, `ScopedList[T]`), used only by the two repositories this spec touches | Removes the literal "build predicate → concat → exec → scan" duplication between the two new/changed repos without retrofitting the already-working, already-tested secret/key/certificate repos — that's a separate, higher-risk decision this spec does not make |
| CLI authorization for `rotation_policies` | Gate writes on the existing `ActionSecretsSet`, reads on `ActionSecretsReadMetadata` | `RotationPolicy` is a RocketVault-only feature with no Azure data-action equivalent; reusing existing secrets actions avoids inventing Azure-shaped action names for a non-Azure concept |
| HTTP API for `rotation_policies` | Not added | Stays CLI-only, matching today. Adding a new HTTP surface is out of scope for a vault-scoping migration |
| Policy execution (the scheduler) | Deferred entirely to Spec B | This spec only makes the data vault-aware. The only thing that currently executes any rotation policy is the existing secrets scheduler (`internal/services/secrets/scheduler_service.go`), which is untouched here and keeps working exactly as it does today, just now reading vault-scoped data at the repository layer |

## 3. Starting point — the two tables are not symmetric

**`rotation_policies` (secrets)** — `model/rotation.go`,
`internal/repositories/rotation_repository.go`,
`internal/services/secrets/rotation_service.go`, `cmd/rotation.go`. This is
the oldest rotation surface in the codebase and predates the entire
`model.Scope` refactor. No API exists for it — CLI-only. Every
repository/service method takes a bare `userID uuid.UUID`; there is no
`model.Scope` concept anywhere in this stack. It needs the full migration:
schema, repository collapse onto scope, service signature changes, and a CLI
retrofit for authorization (today `cmd/rotation.go` has no vault flag and no
`vaultcli.RequireDataAction` call at all).

**`key_rotation_policies` (keys)** — `model/key_rotation_policy.go`,
`internal/repositories/key_rotation_policy_repository.go`, folded into
`internal/services/keys/key_service.go`, `api/key_rotation_policy.go`. Shipped
2026-08-13 (`docs/superpowers/plans/2026-08-13-per-key-rotation-policy-api.md`)
and **already accepts `model.Scope` end-to-end at the service and API
layers** — `KeyService.GetKeyRotationPolicy/UpsertKeyRotationPolicy/DeleteKeyRotationPolicy(ctx,
keyID, scope, ...)`, wired through `api/key_rotation_policy.go` via
`scopeFromRequest`, registered on both the flat and vault-scoped routers. But
the scope is not enforced where it matters: the *repository* has no
`vault_id` column and no scope predicate. Isolation today comes only
indirectly, from pre-authorizing against the parent key
(`s.GetKey(ctx, keyID, scope)`) before touching the policy repo — the policy
row itself is fetched by `GetByKeyIDAny(ctx, keyID)`, unscoped. This table
needs schema + repository work only; the service and API layers need no
signature changes, just a swap of which repository methods they call.

## 4. DB migration (`internal/db/db.go`)

Both tables already exist in `createOptimizedSchema` (`db.go:486` and
`db.go:561`). `key_rotation_policies` already has the dual-write treatment —
an identical `CREATE TABLE IF NOT EXISTS` also appears in `migrateSchema`
(`db.go:785`). `rotation_policies` does **not** appear in `migrateSchema` at
all; it predates the dual-write convention entirely, so this migration adds
its first `migrateSchema` entry.

**Fresh-install schema (`createOptimizedSchema`).** Add the column inline to
both `CREATE TABLE` bodies, following the `secrets`/`keys`/`certificates`
precedent:

```sql
CREATE TABLE IF NOT EXISTS rotation_policies (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
    name TEXT NOT NULL,
    ...
);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_vault_id ON rotation_policies(vault_id);

CREATE TABLE IF NOT EXISTS key_rotation_policies (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
    ...
);
CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_vault_id ON key_rotation_policies(vault_id);
```

Mirror the existing warning comment at `db.go:332` that these hardcoded
literals must stay equal to `model.DefaultVaultID`.

**Existing-install migration (`migrateSchema`).** Add to the idempotent
statement list, guarded by the existing `isDuplicateColumnError` loop:

```go
"ALTER TABLE rotation_policies ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
"ALTER TABLE key_rotation_policies ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
"CREATE INDEX IF NOT EXISTS idx_rotation_policies_vault_id ON rotation_policies(vault_id)",
"CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_vault_id ON key_rotation_policies(vault_id)",
```

For `rotation_policies`, the `ALTER TABLE ... DEFAULT <DefaultVaultID>` *is*
the backfill — every existing row is correctly default-vault, so no further
statement is needed (matching how `secrets`/`keys`/`certificates` were
originally backfilled on 2026-07-26).

For `key_rotation_policies`, the blind `ALTER TABLE` default is **not**
sufficient and must be immediately followed by a corrective `UPDATE` sourced
from the parent key's real vault:

```go
"UPDATE key_rotation_policies SET vault_id = (SELECT vault_id FROM keys WHERE keys.id = key_rotation_policies.key_id) WHERE key_id IN (SELECT id FROM keys)",
```

This runs unconditionally on every migration pass (idempotent — it only ever
sets `vault_id` to what it already should be) and must be ordered *after* the
`ALTER TABLE ADD COLUMN` for this table and *after* `keys.vault_id` is known
to exist (it already does, from the 2026-07-26 migration, which runs earlier
in the same `migrateSchema` list).

No new uniqueness constraints — neither table has vault+name uniqueness
today (`rotation_policies` has none at all; `key_rotation_policies` has
`UNIQUE(key_id)`, unaffected by adding `vault_id`). `finalizeVaultIndexes`/
`ResolveNameCollisions` (the per-vault-unique-name machinery used for
secrets/keys/certificates) does not apply here and is not invoked.

## 5. Repository layer

### 5.1 Generic scoped-CRUD helper — `internal/repositories/scoped_crud.go` (new)

```go
package repositories

import (
    "context"
    "database/sql"

    "rocketvault/model"
)

// ScopedGet runs query (a "SELECT ... WHERE <predicate>" missing only its
// scope clause) with the scope predicate appended, and scans the single
// resulting row with scan. Returns ErrInvalidScope for an unauthorizable
// scope, sql.ErrNoRows for no match.
func ScopedGet[T any](ctx context.Context, db *sql.DB, query string, args []any, scope model.Scope, scan func(*sql.Row) (T, error)) (T, error)

// ScopedExec runs query (an "UPDATE ..." or "DELETE ..." missing only its
// scope clause) with the scope predicate appended.
func ScopedExec(ctx context.Context, db *sql.DB, query string, args []any, scope model.Scope) (sql.Result, error)

// ScopedList runs query (a "SELECT ... WHERE <predicate>" missing only its
// scope clause) with the scope predicate appended, scanning every row with
// scan.
func ScopedList[T any](ctx context.Context, db *sql.DB, query string, args []any, scope model.Scope, scan func(*sql.Rows) (T, error)) ([]T, error)
```

Each function calls the existing `scopePredicate(scope)` (unchanged,
`internal/repositories/scope_predicate.go`), appends `" AND " + predicate` to
the caller-supplied query, appends `predArgs` to `args`, executes, and hands
rows to the caller's scan closure. Table names, column lists, joins, and
scanning stay in each repository — this only removes the repeated
predicate-then-execute glue, not the SQL itself. Matches the existing
"generic core, explicit domain wrapper" shape already used by `cachekit` for
the cache layer.

### 5.2 `rotation_repository.go` — collapse onto scope

`RotationPolicyRepositoryInterface` methods keyed on bare `userID` become
scope-based, mirroring the P1 collapse `secret_repository.go` already went
through:

```go
Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error)
Update(ctx context.Context, policy *model.RotationPolicy, scope model.Scope) error
Delete(ctx context.Context, id uuid.UUID, scope model.Scope) error
List(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) // replaces ListByUser

GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error)
GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error)
```

`GetDueRotations`'s join query gains a `rp.vault_id = ?` (or `1=1` for
`ScopeAdmin`) term matching `scopePredicate`'s fragment — this is the query
the eventual Spec B scheduler will call under `model.NewAdminScope`, exactly
as `model.Scope.String()`'s existing doc comment already anticipates ("the
vault cascade, backup/restore, and the rotation scheduler" as `ScopeAdmin`'s
named trusted callers).

`Create` is unaffected by scope (a create has nothing to authorize against
yet — same rationale as `SecretService.CreateSecret`) but gains a `VaultID`
field on `model.RotationPolicy`, defaulted the same way
`resolveVaultID`/`SecretService.CreateSecret` already do: `if vaultID ==
uuid.Nil { vaultID = uuid.MustParse(model.DefaultVaultID) }`.

`AssignToSecret`/`RemoveFromSecret`/`GetSecretPolicies`/
`GetPoliciesForSecret`/`UpdateSecretPolicyRotation` operate on the
`secret_policies` join table, which has no `vault_id` of its own and isn't
gaining one — the secret and the policy already each carry their own
`vault_id`. `AssignPolicyToSecret` (service layer, §6) is where the two are
checked for consistency: assignment is refused if the secret's vault and the
policy's vault differ, exactly analogous to how `KeyRotationPolicy.VaultID`
is derived from its key rather than independently settable.

### 5.3 `key_rotation_policy_repository.go` — real filtering, not pre-auth-only

```go
Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error // policy.VaultID now required, set by the service from the parent key
GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error)
DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
```

`GetByKeyIDAny`/`DeleteByKeyIDAny` — currently the only two methods
`KeyService` actually calls; the owner-scoped `GetByKeyID(ctx, keyID,
userID)`/`DeleteByKeyID` pair is unused dead code today — are removed and
replaced by the scope-aware versions above. `WHERE key_id = ? AND
<scopePredicate>` gives real vault filtering at the data layer instead of
relying entirely on the pre-authorization check one layer up.

## 6. Service layer

**`RotationServiceInterface`** (secrets): every method's `userID`/`callerID`
parameter and every request struct's `UserID` field become a `model.Scope`,
matching the shape `SecretService`/`KeyService` already use:

```go
type CreatePolicyRequest struct {
    Scope        model.Scope // replaces UserID; VaultID comes from Scope.ResolvedVaultID()
    Name         string
    Description  string
    IntervalDays int
    Enabled      bool
    ReminderDays int
    AutoRotate   bool
}
```

(`UpdatePolicyRequest`, `AssignPolicyRequest`, `ManualRotationRequest`,
`CreateReminderRequest` follow the same `UserID` → `Scope` field swap.)

`AssignPolicyToSecret` gains the cross-vault consistency check described in
§5.2: read the secret and the policy (each under `req.Scope`), compare their
resolved vault IDs, refuse with a new `ErrPolicyVaultMismatch` if they
differ. This is a new check — nothing prevented cross-vault assignment
before because neither side had a `vault_id` to compare.

**`KeyService`**'s three rotation-policy methods
(`GetKeyRotationPolicy`/`UpsertKeyRotationPolicy`/`DeleteKeyRotationPolicy`)
keep their existing signatures — no caller-visible change. Internally:
`GetByKeyIDAny(ctx, keyID)` → `GetByKeyID(ctx, keyID, scope)`;
`DeleteByKeyIDAny` → `DeleteByKeyID(ctx, keyID, scope)`; and
`UpsertKeyRotationPolicy` sets the new `policy.VaultID` field from the
already-fetched parent key (`existing.VaultID`, from the `s.GetKey` call
already at the top of the method), never from an independent value.

## 7. CLI layer (`cmd/rotation.go`)

Every subcommand gains `--vault` and a `vaultcli.RequireDataAction` call,
following `cmd/keys/update.go`'s shape exactly:

| Subcommand | Data action |
|---|---|
| `create`, `update`, `delete`, `assign`, `unassign` | `ActionSecretsSet` |
| `list`, `history`, `status` | `ActionSecretsReadMetadata` |
| `rotate` | `ActionSecretsSet` (it writes a new secret value) |

```go
vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpSet)
if err != nil {
    return fmt.Errorf("vault authorization failed: %w", err)
}
req := secrets.CreatePolicyRequest{
    Scope: model.NewVaultScope(vaultID, claims.UserID),
    ...
}
```

`key_rotation_policies` has no CLI surface today and gains none here — its
existing HTTP API already exercises the fixed repository once §5.3 lands, no
CLI changes needed.

## 8. Testing

- **Cross-vault denial, real SQLite**, following `api/vault_cross_denial_test.go`'s exact template: seed a `RotationPolicy` (and separately a `KeyRotationPolicy`) in vault B, request/act on it via vault A's scope, assert not-found/denied. Two new test functions, e.g. `TestCrossVaultDenial_RotationPolicy_RealSQLite`, `TestCrossVaultDenial_KeyRotationPolicy_RealSQLite`.
- **`TestScopePredicateBindArity`-style coverage** is already generic over `scopePredicate` and needs no new cases — but add a repository-level rejection test per new scoped method (`model.Scope{}` → `ErrInvalidScope`, not rows), matching the existing per-repository pattern.
- **Backfill migration tests**: seed a pre-migration SQLite DB with (a) `rotation_policies` rows with no `vault_id` column and (b) `key_rotation_policies` rows whose parent keys are split across the default vault and a second vault; run `migrateSchema`; assert every `rotation_policies` row lands on the default vault, and every `key_rotation_policies` row's `vault_id` matches its parent key's actual vault (not blindly the default). This is the test that would have caught the asymmetric-backfill bug if it were done wrong.
- **`AssignPolicyToSecret` cross-vault refusal**: assign a policy from vault A to a secret in vault B, assert `ErrPolicyVaultMismatch`.
- **CLI**: extend the existing `cmd/rotation_test.go`-equivalent suite (or add one if none exists) with `--vault` flag coverage and an authorization-denial case per subcommand, matching the CLI test patterns used for `cmd/keys/update_test.go`.

Verification gates: `go build ./... && go test ./...` (per this codebase's
standing rule that `go vet` alone misses interface/mock mismatches).

## 9. Error handling

| Condition | Response |
|---|---|
| Rotation policy not found, or outside the caller's scope | Not found (matches existing `Read`/`GetByKeyID` not-found handling; CLI surfaces this as a plain error, there being no HTTP layer for `rotation_policies`) |
| Assigning a policy to a secret in a different vault | New error, `ErrPolicyVaultMismatch` |
| Invalid or uninitialized scope reaching a repository | `ErrInvalidScope` — a programming error, never reachable from a well-formed CLI invocation |
| `key_rotation_policies` scope check | Unchanged from today: `KeyService.GetKey(ctx, keyID, scope)` is still the first check in all three methods; the repository-level scope filter is defense in depth, not a new user-facing error path |

## 10. Out of scope

- **The scheduler itself** (Spec B) — `internal/schedulerkit`, a new key
  rotation scheduler, migrating the secrets and certificate schedulers onto
  the shared core, and the unified `rotation:` YAML config section. This spec
  only makes the underlying data vault-aware; Spec B is written and
  implemented after this lands.
- **New HTTP API for `rotation_policies`** — stays CLI-only.
- **Retrofitting `secret_repository.go`/`key_repository.go`/
  `certificate_repository.go` onto the new `scoped_crud.go` generic
  helpers** — those repositories work and are tested today; folding them
  onto the new helper is a separate, purely-DRY-motivated change with real
  regression risk, not undertaken here.
- **A `rotationpolicy` CLI subcommand for keys** — `key_rotation_policies`
  is reachable only via HTTP today; adding CLI coverage is unrelated to
  vault-scoping and not addressed here.

## 11. References

- `docs/superpowers/specs/2026-07-26-vault-scope-azure-parity-design.md` —
  the original vault-scope refactor; defines `model.Scope`, `scopePredicate`,
  and explicitly defers this exact gap as "P5: key rotation policies"
- `docs/superpowers/plans/2026-08-13-per-key-rotation-policy-api.md` — built
  `key_rotation_policies` scope-aware at the service/API layer only,
  explicitly deferring the schema-level vault_id migration this spec performs
- `docs/superpowers/specs/2026-08-11-vault-cli-extension-design.md` — the
  `--vault` / `vaultcli.RequireDataAction` CLI retrofit pattern this spec
  applies to `cmd/rotation.go`
- `docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md` —
  why any new resource route must build `NewVaultScope`, never `NewOwnerScope`
  (informs §6's scope handling even though this spec adds no new HTTP routes)
- `.claude/azure-keyvault-parity.md` §2, §6 — current parity status for
  rotation policies and RBAC role boundaries
- `.claude/roadmap-azure-parity-and-beyond.md` — names the rotation-policy
  scheduler as Phase 1's highest-priority item; this spec is the prerequisite
  work identified during that item's design discussion
