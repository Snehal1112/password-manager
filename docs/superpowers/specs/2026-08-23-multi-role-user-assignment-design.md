# Multi-Role User Assignment — Design

**Date:** 2026-08-23
**Status:** Approved for planning
**Author:** Snehal Dangroshiya

## Goal

Let a user hold more than one global role (e.g. `secrets_manager` + `crypto_manager`)
at creation and update time, correctly and consistently everywhere a role is
checked. This isn't new ground: comma-separated roles were built intentionally on
2025-10-26 (`6f8f63d`/`f6686f8`, "Support multiple roles in user creation and
update API") and `common.HasRequiredRole` was written the same week specifically
to make role checks comma-aware. But the rollout was never finished — several
strict-equality gates (`api/users.go`, `cmd/master_key.go`, `cmd/backup.go`,
`cmd/users/{delete,get,list,update}.go`, `cmd/keys/update.go`) were never
converted, and a 2026-04-30 security fix (`aafa8c7`, self-promotion guard) added a
*third*, still-inconsistent validator in the update path. `.claude/e2e-manual-testing-guide.md`
Finding 6 already flags the symptom ("harmless today, contradicts intent") without
it ever being tracked as a real bug.

This design finishes the job properly instead of patching the string-splitting
further.

### Design decisions (locked)

| Decision | Choice |
|----------|--------|
| Storage | New `user_roles` join table (Option A), not a smarter string parser (Option B) |
| Legacy `users.role` column | Kept, unused after migration — deprecate-in-place, matching how `jwt_secret` was handled before its later removal. Not dropped here. |
| JWT claims | Embed the full role list (`Claims.Roles []string`), matching how the single role is embedded today. No extra DB round-trip per request; staleness window unchanged (bounded by `jwt.expiry`, same as today). |
| API shape | Breaking change: `"roles": [...]` (JSON array) replaces `"role": "x"` (string). Documented with release notes, same as other breaking API changes in this project (v4.0.0, v4.1.0). |
| CLI shape | `--role` becomes a repeatable flag (`StringArray`), e.g. `--role admin --role secrets_manager` |
| Authorization | One canonical `common.HasAnyRole(userRoles []string, required ...string) bool` replaces `HasRequiredRole` and every remaining strict-equality gate |
| Role combinations | Unrestricted — any combination of the five roles is allowed; permissions simply union. No new "admin is exclusive" rule. |
| Self-promotion guard | Re-verified against the new multi-role update path: adding `admin` to your own role list must still be blocked the same way it is today for a single-role change. |
| Vault-scoped role assignments (`role_assignments` table) | Out of scope — already supports multiple roles per user per vault (`UNIQUE(principal_id, role, vault_id)` already includes `role`). Nothing to change there. |

## Architecture: Approach A — normalize into `user_roles`

A new table stores one row per `(user, role)` pair, mirroring the existing
`role_assignments` table's already-proven pattern for exactly this "multiple
grants to one principal" shape. Every authorization check reads a real `[]string`
instead of parsing a string that was never guaranteed to be well-formed.

Rejected alternative — **Option B: keep the scalar `role` column, finish making
every check comma-aware.** Smaller migration (no new table), but perpetuates the
root cause: a single TEXT column standing in for a list, parsed ad hoc wherever
it's read. The Oct 2025 attempt at this is exactly why the bug exists today —
"make the string-splitting consistent" has already been tried once and drifted
out of sync within the same year. Normalizing removes the failure mode instead of
disciplining it.

---

## Section 1 — Data Model & Schema

```sql
CREATE TABLE IF NOT EXISTS user_roles (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    role       TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
```

Added to both `createOptimizedSchema()` (fresh installs) and `migrateSchema()`
(upgrades) — the same dual-write pattern already used for every other table in
this codebase (see how `role_assignments` itself is duplicated at
`internal/db/db.go:694-706` and `:954-966`).

**Backfill** (part of the `migrateSchema()` step, runs once, idempotent): for
every row in `users`, split `role` on `,`, trim whitespace, dedupe, insert one
`user_roles` row per resulting role name — `INSERT OR IGNORE` so re-running the
migration is a no-op. This correctly absorbs the existing partially-broken
comma-joined accounts (e.g. the `"secrets_manager, crypto_manager"` case from the
Oct 2025 commit history) into clean, real multi-role rows.

The old `users.role` column is left in place, untouched, unread by new code.
Cleanup (drop the column) is explicitly deferred to a later, separate task — not
bundled here, matching how `jwt_secret` was deprecated-then-later-deleted in two
separate steps.

---

## Section 2 — Model & Repository

- `model.User.Role string` → `model.User.Roles []string`.
- `model.Claims.Role string` → `model.Claims.Roles []string`.
- `UserRepository` gains role-aware methods: reading a user now joins/queries
  `user_roles`; creating/updating a user's roles is a transactional
  delete-all-then-insert-all against `user_roles` for that `user_id` (simplest
  correct semantics for "replace the role set," avoids diffing).

## Section 3 — Service Layer

`UserService.CreateUser`/`UpdateUser` accept `Roles []string` instead of
`Role string`:
- Validate every entry against the existing allowlist (`secrets_manager`,
  `crypto_manager`, `certificate_manager`, `admin`, `user`) — reuse whatever
  constant list `model` already exposes (e.g. `model.RoleAdmin` and siblings),
  don't re-hardcode the list a third time.
- Reject empty list, dedupe silently (not an error — repeats are harmless).
- Self-promotion guard: re-check `aafa8c7`'s logic against a list add of `admin`
  rather than a single-value change to `admin`.

## Section 4 — API

`CreateUserRequest`/`UpdateUserRequest` (`api/users.go`, `model/user.go`):
`"roles": ["admin", "secrets_manager"]` (JSON array) replaces `"role": "x"`.
Clean break, no dual-field transition period — matches how this project has
handled breaking API changes before (documented in `docs/release-notes/`, not
silently shimmed). `UserResponse.Role` → `UserResponse.Roles []string`.

## Section 5 — CLI

`cmd/users/create.go` / `cmd/users/update.go`: `--role` flag changes from
`Flags().String(...)` to `Flags().StringArray(...)`, so
`rocketvault users create --username alice --role admin --role secrets_manager`
works. `cmd/users/admin.go` (bootstrap admin) is unaffected — it hardcodes a
single `model.RoleAdmin`, no multi-role need there.

## Section 6 — JWT Claims

`Claims.Roles []string`, populated at login/token-issuance time from
`user_roles`. No other change to token issuance/refresh flow — same expiry,
same signing path.

## Section 7 — Authorization Call Sites

New helper in `common/auth_helper.go`:

```go
func HasAnyRole(userRoles []string, requiredRoles ...string) bool
```

Replaces `HasRequiredRole` (deleted — internal helper, not a public API, no
deprecation period needed) and every strict-equality gate found in the earlier
investigation:

- `api/users.go` (3 sites: create/update/delete-or-similar admin checks)
- `cmd/master_key.go`
- `cmd/backup.go`
- `cmd/users/{delete,get,list,update}.go`
- `cmd/keys/update.go`

This list is what the investigation surfaced; the implementation plan should
re-grep for `claims.Role\b` and `\.Role ==` / `\.Role !=` project-wide as a final
completeness check rather than trusting this list alone — a stale grep is exactly
how the Oct 2025 rollout stayed incomplete for ten months.

## Section 8 — Testing

- Migration test: seed `users` with plain roles, comma-joined roles (including
  the exact `"secrets_manager, crypto_manager"` shape from the historical
  commit), and duplicate/whitespace-messy variants; assert `user_roles` ends up
  correct and deduped after `migrateSchema()`.
- Repository test: create/update replaces the full role set correctly,
  `ON DELETE CASCADE` removes `user_roles` rows when a user is deleted.
- Service test: validation rejects unknown role names, empty list; self-promotion
  guard blocks adding `admin` to one's own roles.
- Re-run/extend the existing 15-case `HasRequiredRole` test suite (from
  `620e2c8`) against `HasAnyRole`'s new signature.
- Regression test per call site listed in Section 7 — a multi-role user must pass
  every one of them consistently, closing the exact gap this design exists to fix.

## Open items for the implementation plan

- Confirm whether OAuth2 service accounts (`internal/services/oauth2`) carry a
  role concept that also needs this treatment, or are genuinely out of scope.
- Confirm the OIDC-provisioned-user path (`FindOrCreateExternalUser`) is updated
  to write into `user_roles`, not the legacy column.
