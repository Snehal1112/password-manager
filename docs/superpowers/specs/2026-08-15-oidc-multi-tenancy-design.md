# Per-Vault OIDC Tenancy — Design Spec

**Date**: 2026-08-15
**Status**: Approved by user, ready for implementation planning

## Summary

RocketVault should support the same multi-tenant capability Azure Key Vault actually has —
not the one an early draft of this design mistakenly invented. Azure Key Vault has **no
built-in identity system**: every vault carries a single `tenantId` naming which Azure AD
(Entra ID) directory is trusted to authenticate callers, and RBAC does the rest. There is no
"Tenant" object in Key Vault's own data model, no self-service signup, no tenant-scoped user
accounts — those are patterns a SaaS vendor builds *on top of* Key Vault, not features Key
Vault provides.

RocketVault already has Key Vault's real isolation unit: **the vault**. Secrets/keys/certs
are scoped by `vault_id` at the SQL level, RBAC is per-vault, names don't collide across
vaults, and "one vault per customer" already works today via `POST /vaults` +
`vault-access grant`. What RocketVault is missing is the literal analogue of `tenantId`:
**the ability for a vault to trust a specific external identity directory (OIDC issuer),
independently of every other vault.** Today there is exactly one OIDC issuer, configured
once, for the entire instance.

This spec adds that — a shared, reusable `OIDCProvider` entity that vaults reference — plus
one small, separate permission-model change (delegated/quota'd vault creation) that makes
the already-working "vault per customer" pattern genuinely self-service for a non-global-admin
operator.

## Background: how we got here

An earlier draft of this design proposed a brand-new `Tenant` entity that owned multiple
vaults and multiple users, with its own self-service signup flow and tenant-scoped user
accounts (username unique per-tenant instead of instance-wide). That was rejected after
verification against Azure's actual architecture: Key Vault has zero local accounts of any
kind — 100% of its identity is delegated to Entra ID, a separate product. Tenant-scoping
RocketVault's local username/password accounts would have built parity with a feature Azure
Key Vault does not have. See "Non-Goals" below for the full list of what was correctly
scoped out, and why.

## Capability mapping (source of truth for scope)

| Azure mechanism | RocketVault today | Gap | This spec addresses it? |
|---|---|---|---|
| `tenantId` (which Entra directory authenticates a vault's callers) | One global OIDC issuer, instance-wide | Real, concrete gap | **Yes — this is the spec** |
| Vault-per-tenant (a *pattern*, not a Key Vault feature) | Fully works today (`POST /vaults` + `vault-access grant`) | Only "who can self-service create one" is missing | **Yes — small addition** |
| RBAC scoped to vault/RG/subscription/object | Vault-level + a global tier; no object level | Object level exists in Azure but is Microsoft's own discouraged path | No — non-goal |
| Cross-tenant app registration + SP + RBAC (SaaS vendor reaching a customer's *own* Azure tenant) | `internal/vaultclient` + OAuth2 service accounts cover the realistic case | No cross-instance federation protocol | No — non-goal for a single-instance product |
| Managed HSM (dedicated single-tenant hardware) | One shared instance-wide PKCS#11 token | Azure caps this at 5/region precisely because it doesn't scale as a "per-tenant" unit | No — non-goal |
| Local username/password accounts | Instance-global | N/A — **Azure has no equivalent to have parity with** | No — explicit non-goal |
| Per-vault/subscription request throttling | Per-IP only, no vault dimension | Real gap, but Azure's own lesson is it should be per-principal, not per-vault | Deferred, not in this spec |

## Data model

### New: `oidc_providers` table

```go
// model/oidc_provider.go
type OIDCProvider struct {
    ID           uuid.UUID
    Name         string     // display name, e.g. "Acme Corp SSO" — required, non-empty
    IssuerURL    string     // required, must parse as a valid https:// URL (http allowed only for loopback, matching internal/vaultclient's existing AllowInsecureHTTP precedent)
    ClientID     string     // required
    ClientSecret string     // required; encrypted at rest via the same CryptographyService used for secret values — never stored or returned in plaintext
    RedirectURL  string     // required, valid URL — fixed per provider, registered once at the IdP
    Scopes       []string   // defaults to ["openid"] if empty
    CACertPath   string     // optional, mirrors OIDCConfig.CACertPath's existing semantics
    Enabled      bool       // default true
    CreatedAt    time.Time
    UpdatedAt    time.Time
    DeletedAt    *time.Time // soft-delete, matches existing vault/secret/key pattern
}
```

Migration follows this codebase's established dual-write pattern exactly: the `CREATE TABLE
oidc_providers` statement goes in `createOptimizedSchema`, and existing databases get the
same table via `migrateSchema` (see `.claude/database-init-patterns.md`'s pattern, already
used for every prior schema addition in this codebase). The implementation plan must verify
this with the same rigor `migration-auditor` already applies to other schema changes.

### `vaults` table

Gains a nullable `oidc_provider_id uuid.UUID` (FK to `oidc_providers.id`, `ON DELETE SET
NULL` — deleting a provider un-binds any vault that referenced it rather than cascading
deletion of the vault itself). No provider bound = no OIDC login available for that vault
(today's global-disabled state, now expressed per-vault). A vault trusts **exactly one**
provider at a time, matching `tenantId`'s single-valued nature. One provider **can** be
referenced by many vaults, matching how many Azure vaults can share one Entra tenant.

### `users` table

The existing `UNIQUE(auth_provider, external_idp_subject)` index widens to
`UNIQUE(auth_provider, oidc_provider_id, external_idp_subject)` — `oidc_provider_id` is
nullable (NULL for local accounts, which don't use this uniqueness dimension at all). This
is the concrete fix for the collision the verification step identified: two different IdPs
can legitimately issue the same `sub` value, and today's schema would incorrectly treat them
as the same user.

`FindOrCreateExternalUser`'s behavior is otherwise **unchanged** — a user authenticating via
a vault's bound provider is created (or matched) exactly as today, with `model.RoleUser` and
**no automatic vault role grant**. This matches Azure's real behavior precisely: being from
a trusted directory never implies any RBAC role — an explicit grant is always required
afterward. Do not "improve" this by auto-granting a role on first login; that would diverge
from the system being modeled.

### `model.User`

Gains `MaxVaultsOwned int` (default `0`). See "Delegated vault creation" below.

## Authentication flow

**Login initiation** — new, vault-scoped: `GET /vaults/{vault_name}/oidc/login`. Resolves
the vault, reads its `oidc_provider_id`; if null, returns 404 (no OIDC configured for this
vault) rather than falling back to any default. If set, looks up the corresponding
`OIDCService` from the runtime registry (see below) and builds the authorization redirect
exactly as today's `AuthCodeURL` does, except the `state` parameter now additionally encodes
the provider ID (base64-encoded alongside the existing CSRF/nonce value) so the callback can
resolve which issuer's keys to verify against without needing that information in the URL
path.

**Callback** — stays a single route, `GET /oidc/callback`, unchanged in URL shape. This is
deliberate: an IdP admin registers one fixed `redirect_url` per provider (per today's
`OIDCConfig.RedirectURL` semantics, now sourced from `OIDCProvider.RedirectURL` instead of
global config) — nothing about how they configure their side of the app registration changes.
The handler decodes the provider ID from `state`, looks up that provider's `OIDCService` in
the registry, and completes `HandleCallback` exactly as today.

**Backward compatibility**: `GET /oidc/login` and `GET /oidc/callback` (today's unscoped
routes) are kept as **deprecated aliases** for the `default` vault's bound provider. On
upgrade, if `.rocketvault.yaml`'s `oidc.enabled: true`, the migration auto-creates one
`OIDCProvider` row from that exact config (issuer/client id/secret/redirect/scopes/CA path)
and binds it to the `default` vault. Every existing OIDC login continues to work unchanged;
new integrations should use the vault-scoped routes. The old `oidc:` YAML block is read
one final time by the migration and then ignored on subsequent boots (the provider row is
now the source of truth) — `oidc.enabled: false` or an absent block means no auto-created
provider, matching a fresh install with nothing configured.

## Runtime architecture

`internal/container/service_container.go`'s single `oidcService authServices.OIDCService`
field becomes `oidcServices map[uuid.UUID]authServices.OIDCService`, built at startup by
iterating every enabled, non-deleted `OIDCProvider` row and calling `NewOIDCService` for
each (unchanged per-provider construction — one discovery round trip, one `oidc.Provider`,
one verifier, exactly as today but per provider instead of singleton).

**Per-provider graceful degradation**, preserving today's operational behavior at a finer
grain: if one provider's issuer is unreachable at boot, that *one* provider logs a warning
and is left out of the registry (its bound vault(s) simply have no working OIDC login until
fixed) — other providers and the server itself are unaffected. Today, a single bad issuer
disables OIDC instance-wide; after this change the blast radius shrinks to just that
provider's vaults.

`api/oidc.go`'s handlers change from holding a single `OIDCService` reference to resolving
one from the registry per-request (by vault, for login; by decoded provider ID from `state`,
for callback).

## Authorization

**`OIDCProvider` CRUD** (`POST/GET/PATCH/DELETE /api/v1/oidc-providers[/{id}]`): **global
admin only**, deliberately not delegable via the access-policy mechanism in this version.
Provider records hold client secrets — the blast radius of a compromised or over-broadly-
delegated grant here is high, and there's no existing product requirement pulling toward
delegation. Client secrets are never returned in any read response (redacted, matching how
`OAuth2Client.ClientSecret` is already handled). If delegated provider management is wanted
later, it should reuse the access-policy `vaults/manage`-style pattern with a new
`oidc_providers` resource type — not designed here (YAGNI).

Secret rotation follows the same shape as `OAuth2Client`'s existing
`POST /api/v1/service-accounts/{id}/rotate` — a dedicated endpoint, not an optional `PATCH`
field — for the same reason: a plain `PATCH` accepting an optional secret makes it easy to
accidentally omit it and silently no-op a rotation, or accidentally include a stale cached
value and silently revert one. `PATCH /oidc-providers/{id}` therefore never accepts
`client_secret` at all; only `POST /oidc-providers/{id}/rotate-secret` can change it.

**Binding a provider to a vault** (`PATCH /api/v1/vaults/{vault_name}` with
`oidc_provider_id`): this is a vault-*management* operation (like renaming a vault or
setting `purge_protection`), not a data-plane operation, so it goes through the existing
`CanManageVault(ctx, ..., vaultID)` check — the vault-scoped variant, which today already
passes for global admin **or** a vault-scoped `vaults/manage` access-policy grant. See the
next section for why a self-service vault creator needs that same access-policy grant (not
just a data-plane role) to be able to do this on their own vault.

## Delegated (quota'd) vault creation

Separate, smaller feature, addressing the one real gap in "vault-per-tenant is already a
fully-working pattern."

`model.User.MaxVaultsOwned` (new field, default `0`) is set by an admin via
`rocketvault users update <username> --max-vaults-owned <N>`. `CanManageVault`'s
vault-creation check (`vaultID: uuid.Nil` today, admin-or-global-policy-only) gains a third
passing condition: the actor's `MaxVaultsOwned > 0` **and** their current count of
vaults where they are the recorded creator is below that quota.

On successful self-service creation, the creator is granted **two** things on their new
vault, not one — this is a correction from an earlier pass of this design, which only
granted the data-plane `Key Vault Administrator` role and would have left the creator unable
to actually manage (rename, configure OIDC binding on) the vault they just made:
1. `Key Vault Administrator` (data-plane role, via `role_assignments`) — so they can manage
   secrets/keys/certs inside it.
2. A vault-scoped `vaults/manage` access-policy grant (`VaultID` set to the new vault, not
   global) — so they can perform vault-management operations (including binding an
   `OIDCProvider` to it) without needing global admin.

Both grants are scoped to exactly the one vault just created; the creator's quota is
unaffected by vaults they didn't create (e.g. ones they were later invited into via a normal
role grant).

## Non-Goals

Carried forward from the capability mapping, each with its reasoning restated so this spec
is self-contained:

1. **Object-level (single-secret) RBAC.** Microsoft's own guidance discourages this in
   Azure — control-plane operations still require vault-level access regardless, so it
   "cannot be used for true team isolation." Vault stays RocketVault's finest authorization
   grain, matching Azure's actual recommended practice, not just its theoretical ceiling.
2. **Per-tenant dedicated HSM hardware.** Azure hard-caps Managed HSM at 5 instances per
   subscription per region specifically because dedicated-hardware-per-tenant doesn't scale
   economically or numerically. A self-hosted RocketVault operator has one physical HSM,
   shared across every vault — that's the correct posture, not a limitation to work around.
3. **Tenant-scoped local username/password accounts.** Azure Key Vault has no local
   accounts at all — there is no parity target. Local accounts remain instance-global
   operator/bootstrap credentials, exactly as today.
4. **Cross-instance "customer's vault lives in the customer's own environment."** Azure's
   CMK-style cross-tenant pattern (vault in the *customer's* subscription/tenant) maps to
   "the customer runs their own RocketVault instance" — a deployment topology decision, not
   a feature this codebase needs to build.
5. **Shared-vault-with-tenant-prefixed-secret-names.** Actively rejected, not merely
   deferred: this Azure pattern exists as a workaround for vault-count cost/quota pressure
   Azure customers face. RocketVault vaults are free database rows with real SQL-enforced
   `vault_id` isolation — deliberately choosing weaker application-layer string-prefix
   isolation over what already exists would be a regression, not a feature.
6. **Per-vault/per-principal request-rate quotas.** Deferred, not rejected. Azure's own
   documented lesson is that request throttling is subscription-wide regardless of vault
   count, so per-vault quotas wouldn't even buy the thing they'd appear to buy. If this is
   wanted later, it should key off the authenticated principal, not the vault — a distinct
   design, out of scope here.

## API surface (new/changed)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/v1/oidc-providers` | Global admin | Create; client secret in request body only |
| `GET` | `/api/v1/oidc-providers` | Global admin | List; secrets redacted |
| `GET` | `/api/v1/oidc-providers/{id}` | Global admin | Get; secret redacted |
| `PATCH` | `/api/v1/oidc-providers/{id}` | Global admin | Update; does **not** accept `client_secret` (immutable via this route — see rotation below) |
| `POST` | `/api/v1/oidc-providers/{id}/rotate-secret` | Global admin | Rotates `client_secret`; new value in request body, returned once |
| `DELETE` | `/api/v1/oidc-providers/{id}` | Global admin | Soft-delete; bound vaults' `oidc_provider_id` set NULL |
| `PATCH` | `/api/v1/vaults/{vault_name}` | `CanManageVault(vaultID)` | Extended to accept `oidc_provider_id` |
| `GET` | `/vaults/{vault_name}/oidc/login` | Public | New, vault-scoped |
| `GET` | `/oidc/login` | Public | Deprecated alias → `default` vault |
| `GET` | `/oidc/callback` | Public | Unchanged path; now provider-aware via `state` |

## CLI surface (new/changed)

- `rocketvault oidc-providers create --name --issuer-url --client-id --client-secret --redirect-url --scopes --ca-cert-path`
- `rocketvault oidc-providers list`
- `rocketvault oidc-providers get <id>`
- `rocketvault oidc-providers update <id> [...]` — never accepts `--client-secret`
- `rocketvault oidc-providers rotate-secret <id>`
- `rocketvault oidc-providers delete <id>`
- `rocketvault vaults update <name> --oidc-provider <id> | --clear-oidc-provider`
- `rocketvault users update <username> --max-vaults-owned <N>`

New command group `cmd/oidc-providers/` mirrors the existing `cmd/vaults/`/`cmd/vault-access/`
package structure and authorization-helper pattern (package-local `authz.go`, per the CLI
Authorization conventions already documented in this codebase).

## Security considerations

- Client secrets: encrypted at rest (same `CryptographyService` as secret values), never
  returned in plaintext by any read endpoint, never logged.
- `state` parameter now carries a provider ID in addition to the existing CSRF/nonce value —
  this must not weaken CSRF protection; the nonce/CSRF check is unchanged, the provider ID is
  additive data riding alongside it, not a replacement for any existing check.
- Authenticating via vault X's bound provider grants **no** implicit access to vault X or any
  other vault — this is unchanged from today and must be covered by a regression test (see
  Testing below), since it's the single most important invariant this whole design rests on.
- Cross-provider isolation: a JWT/session verified against provider A's issuer/keys must
  never validate against provider B's keys, even if both providers happen to be bound to
  vaults the same user has access to. Covered by the two-fake-IdP test described below.

## Testing strategy (for the implementation plan to expand into concrete test cases)

- `OIDCProvider` repository/service unit tests: CRUD, soft-delete, secret encryption
  round-trip, redaction on read.
- Two-fake-IdP integration test (extends the existing `callbackFakeIdP` pattern in
  `oidc_service_test.go`): two separate fake IdPs, two vaults each bound to a different one,
  proving (a) login via vault A's `/oidc/login` only ever redeems tokens against provider A's
  keys, (b) a token minted by fake IdP B is rejected if somehow presented against provider
  A's verifier, (c) a user created via provider A has no access to a vault bound to provider
  B without an explicit role grant.
- Migration test: seed a database with the legacy global `oidc:` config, run the migration,
  assert exactly one `OIDCProvider` row exists, bound to `default`, and that the deprecated
  `/oidc/login` alias still completes a full login round-trip.
- Quota enforcement tests: `MaxVaultsOwned` boundary (0 quota → denied; at-quota → denied;
  under-quota → allowed and both grants — data-plane role and `vaults/manage` policy — are
  present afterward); a vault the user was merely invited into (not created) doesn't count
  against their quota.
- Authorization tests: non-admin cannot CRUD `OIDCProvider`; a vault's `vaults/manage`
  policy holder (but not a Key-Vault-Administrator-only principal) can bind/unbind that
  vault's provider.
