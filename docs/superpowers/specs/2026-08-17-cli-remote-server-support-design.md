# CLI Remote Server Support — Design

## Problem

RocketVault's CLI cannot talk to a remote RocketVault server today. Every
resource command (`cmd/secrets/*.go`, `cmd/keys/*.go`, `cmd/certificates/*.go`,
`cmd/vaults/*.go`, and more — 22+ files) calls `internal/container` directly,
booting a local service container that connects straight to whatever database
`.rocketvault.yaml` points at. There is no network hop to a "RocketVault
server" for any resource operation — the only code that makes a real HTTP call
today is the OIDC login flow (`cmd/users/login_oidc.go`).

This means an operator running the CLI from their laptop against a team's
shared RocketVault deployment, or a CI pipeline automating against a remote
instance, cannot do so at all — not because a flag is missing, but because the
capability doesn't exist. This is the CLI-equivalent gap to `az keyvault`
(always talks to Azure's cloud API) or HashiCorp Vault's CLI (`VAULT_ADDR`
points it at any server) — RocketVault, being self-hosted, has no single
global endpoint, so this gap is more consequential than it would be for a
cloud-native product.

## Goals

1. Let the CLI target a remote RocketVault server over its existing REST API,
   for both interactive human use and CI/automation, without requiring a local
   `.rocketvault.yaml` or local database access.
2. Preserve today's behavior exactly when no remote target is configured — a
   user who never touches this feature sees zero change.
3. Support named, switchable server contexts (`rocketvault context use prod`)
   for interactive convenience, alongside a stateless `--server`/env-var path
   that CI can use without any local context state.
4. Fix the session cache's existing username-only collision bug
   (`admin@serverA` and `admin@serverB` currently overwrite each other) as
   part of this work, since remote-server support makes the bug immediate
   rather than theoretical.

## Non-goals

- Rearchitecting `serve` (the API server process) — unaffected by this design.
- Extending `internal/vaultclient` (the embeddable secret-consumption library
  used by `examples/consumer-service`) — it solves a different problem
  (fetching known secrets by UUID from within another Go application) and is
  left as-is. This design's remote clients may share its low-level HTTP/retry
  plumbing where convenient, but are a separate, CLI-facing component.
- Adding new HTTP API endpoints for operations that don't have one today.
  Where a CLI command has no server-side HTTP route to call (see the Command
  Support Matrix below), it stays local-only in this design; adding the
  missing route is out of scope and can be proposed separately if needed.
- An exhaustive, file-by-file audit of exactly which of the 22+ command files
  need what change. This design fixes the *pattern* (an adapter interface plus
  a mode resolver); enumerating each command against its HTTP route is
  implementation-time work, done per resource group when the plan is broken
  into tasks.

## Architecture: dual-mode CLI

The CLI gains two operating modes, chosen per-invocation by whether a remote
target resolves:

```
              rocketvault <command>
                       │
        ┌──────────────▼──────────────┐
        │ Does a remote target resolve?│
        │ (--server / ROCKETVAULT_ADDR │
        │  / current context)          │
        └──────┬────────────────┬─────┘
               │ no             │ yes
               ▼                ▼
        ┌─────────────┐  ┌──────────────────┐
        │ LOCAL MODE   │  │ REMOTE MODE       │
        │ (unchanged)  │  │ (new)             │
        │ boots        │  │ REST calls to     │
        │ container,   │  │ target server's   │
        │ local DB     │  │ /api/v1/...       │
        └─────────────┘  └──────────────────┘
```

Local mode is byte-for-byte today's behavior: no change to
`internal/container`, `internal/services/*`, or `.rocketvault.yaml` handling.
This is the important backward-compatibility property — a user who never sets
`--server`, `ROCKETVAULT_ADDR`, or a context is unaffected.

### The adapter pattern (avoiding 22+ duplicated command files)

Each resource group (secrets, keys, certificates, vaults, vault-access, users,
audit) gets a small CLI-facing interface in a new package, `internal/cliclient`,
mirroring exactly the operations its commands need — not a generic passthrough,
a purpose-built interface per resource group. Example shape for secrets:

```go
// internal/cliclient/secrets.go
type SecretsClient interface {
    List(ctx context.Context, filter secrets.ListFilter) ([]*model.Secret, error)
    Get(ctx context.Context, id uuid.UUID) (*model.Secret, error)
    Create(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error)
    Update(ctx context.Context, id uuid.UUID, req secrets.UpdateSecretRequest) (*model.Secret, error)
    Delete(ctx context.Context, id uuid.UUID) error
    // ... versions, generate, export/import, backup/restore
}
```

Two implementations per interface:

- **`local*Client`** — a thin adapter wrapping today's exact
  `container.GetSecretService()` calls. This is mostly *extraction*, not new
  logic: today's command bodies move into this adapter unchanged.
- **`remote*Client`** — makes HTTP calls to the corresponding
  `/api/v1/secrets/...` routes, using the resolved target server and an
  authenticated bearer token (from the session cache or a fresh login/service-
  account exchange). Response bodies decode into the same `model.*` types the
  local path already returns, so command code downstream (formatting, output)
  is identical either way.

Each `cmd/<resource>/*.go` file changes in exactly one way: instead of calling
`container.GetSecretService()` directly, it calls
`cliclient.ResolveSecretsClient(cmd)`, which internally runs the mode-resolver
above and returns whichever implementation applies. The command body — flag
parsing, calling the interface method, formatting output — does not change
based on mode. This is what keeps the 22+ file count from becoming 22+
duplicated implementations: the branching happens once, in the resolver, not
per command.

## Component design

### 1. Target resolution (`internal/cliclient/resolve.go`)

Precedence, highest to lowest:

1. `--server <url>` flag (per-invocation override)
2. `ROCKETVAULT_ADDR` environment variable
3. Current named context's server (see below)
4. *(none of the above)* → local mode

This chain is identical regardless of which resource group's client is being
resolved — it's implemented once and shared.

### 2. Session cache — server-aware key, non-breaking migration

Today (`common/session.go`): sessions are keyed by username only —
`~/.rocketvault/sessions/<username>.json` — which collides across servers.

New key: a **server key**, either the literal string `local` (representing
local-mode's implicit "server" — i.e., no remote target resolved) or the
sanitized remote server URL (scheme stripped, `:`/`/` replaced with `_`,
lowercased — e.g. `https://vault.prod.example.com:8443` →
`vault.prod.example.com_8443`). New filename format:
`<server-key>__<username>.json`.

**Non-breaking migration for the common case**: `LoadSession(serverKey,
username)` for `serverKey == "local"` first tries the new path
(`local__<username>.json`); if that doesn't exist, it falls back to today's
old-format path (`<username>.json`) and lazily rewrites it in the new format
on next `SaveSession`. A user who has only ever used local mode — the
overwhelming majority of today's installs — is never forced to re-login. Only
brand-new remote-mode sessions use the new format from the start, since
there's no old data to migrate for a server key that never existed before.

`currentPointerPath()` (`~/.rocketvault/sessions/current`) changes from
storing a bare username to storing `<server-key>|<username>`, so "the current
session" is unambiguous across servers too. Same non-breaking fallback
applies here: if the pointer file's content contains no `|`, treat it as the
old format — the whole content is the username, server key is `local` — and
lazily rewrite it in the new format on the next `SaveSession`. Without this,
every existing local-mode user's `LoadCurrentSession()` would break on
upgrade, since the old pointer content wouldn't parse as
`<server-key>|<username>`.

### 3. Named contexts (`common/context.go`, new file alongside `common/session.go`)

Storage: `~/.rocketvault/contexts.json`.

```json
{
  "current": "prod",
  "contexts": {
    "prod":    { "server": "https://vault.prod.example.com", "username": "admin" },
    "staging": { "server": "https://vault.staging.example.com", "username": "admin" }
  }
}
```

A context is a named pointer to a server (+ optional default username and/or
default vault) — it holds no credentials itself; those still live in the
server-aware session cache above. This keeps one source of truth for tokens.

New subcommand group, `cmd/context/`:

```
rocketvault context add <name> --server <url> [--username <user>] [--vault <name>]
rocketvault context list
rocketvault context use <name>
rocketvault context current
rocketvault context remove <name>
```

`context use <name>` writes `name` as `"current"` in `contexts.json`.
`context remove` of the current context also clears the `"current"` pointer
(mirroring `DeleteSession`'s existing current-pointer-clearing behavior for
consistency). `context use` on a context with no cached session for its
default username does **not** auto-trigger a login — it just becomes the
active target; the next command that needs auth prompts the normal
`resolveAuthentication` flow (flag-based login, cached session, or an
explicit error telling the user to run `users login`), same as today.

Contexts are resolved *after* `--server`/`ROCKETVAULT_ADDR` in the precedence
chain, so CI never needs to touch this file — it always uses the stateless
flag/env path, which requires zero local setup and works identically on a
fresh, ephemeral runner every time.

### 4. Authentication in remote mode

- **Human login**: `--username/--password/--totp-code` (or a cached session)
  authenticates against `POST /api/v1/users/login` on the *target* server —
  not the local instance. Resulting JWT + refresh token cache under the
  resolved `(server-key, username)`.
- **Service accounts (the CI path)**: new flags/env vars,
  `--client-id`/`--client-secret` and `ROCKETVAULT_CLIENT_ID`/
  `ROCKETVAULT_CLIENT_SECRET`, exchanged via the *existing*
  `POST /api/v1/oauth2/token` client-credentials endpoint — no server-side
  changes needed, this endpoint already exists. This is the credential path CI
  should use; TOTP-gated human login cannot work unattended.
- **OIDC** (`users login --oidc`): already makes real HTTP calls
  (`cmd/users/login_oidc.go`). It needs the same target-resolution precedence
  applied to it (today it implicitly assumes a fixed server) — the smallest
  incremental change of anything in this design, since the HTTP-calling
  scaffolding already exists here.

### 5. TLS trust for self-signed / internal-CA deployments

Since ACME/public-CA support (Phase 1 of the parity roadmap) hasn't shipped
yet, many real deployments this feature targets will be running self-signed or
internal-CA certificates. The remote HTTP client needs:

- Default: standard TLS verification against the system trust store (public
  CAs) — safe default, works once ACME lands.
- `--ca-cert <path>` (or `ROCKETVAULT_CA_CERT`): trust an additional CA
  certificate, for internal-CA deployments.
- `--insecure-skip-verify`: explicit, loud escape hatch for self-signed certs
  in dev/test — CLI prints a prominent warning to stderr every time this is
  used, never silent.

Without this, the feature would be impractical for exactly the self-hosted,
no-public-cert-yet deployments most likely to need it first.

### 6. Explicit refusal for local-only operations

Some commands have no server-side HTTP route and cannot be remoted without new
API work (out of scope here — see Non-goals):

| Command | Why local-only |
|---|---|
| `backup create`/`restore` (whole-database) | No "download/restore the whole remote DB" endpoint, and shouldn't be one — this is a local-disk operation by design. |
| `master-key rotate` | Explicitly local-only today (`.claude/known-bugs.md` § B12 / the runbook); operates directly on the local DB and requires the server process to be stopped first — conceptually cannot run "against a remote instance." |
| `vaults purge`/`vaults recover` | No HTTP route exists for these today (README's API table already notes this) — remoting them requires new API endpoints, tracked as a possible future follow-up, not part of this design. |

When one of these commands is invoked with a remote target resolved
(`--server`/env var/context all present), the CLI **errors immediately and
explicitly** — e.g. `"master-key rotate is a local-only operation and cannot
target a remote server; unset --server / ROCKETVAULT_ADDR / the active context
to run it against this machine's own instance."` It must never silently fall
back to operating on the local instance when the user's evident intent was a
remote one — that would risk rotating or restoring the wrong instance's data.

`vault-access roles` (static role/data-action listing, no auth, no DB access
at all) needs no local/remote distinction — it already behaves identically
regardless of target, since it never touches a service or database.

## Command support matrix (scope for this design)

| Resource group | Remote-capable? |
|---|---|
| `secrets` | Yes — full CRUD, versions, generate, export/import, backup/restore all have existing HTTP routes |
| `keys` | Yes — full CRUD, crypto ops, rotate, backup/restore, rotation-policy CRUD all have existing HTTP routes |
| `certificates` | Yes — full CRUD, policy, backup/restore all have existing HTTP routes |
| `vaults` | Partial — create/list/get/update/delete are remote-capable; purge/recover stay local-only (see above) |
| `vault-access` | Yes for grant/list/revoke (existing HTTP routes); `roles` works identically either way |
| `users` | Login and standard CRUD are remote-capable; whether bootstrap admin-creation has an equivalent HTTP route is an implementation-time check, not a design blocker |
| `audit` | Remote-capable — `/audit/logs`, `/audit/reports/*`, `/audit/config` routes already exist |
| `backup`, `master-key` | Local-only (see above) |
| `health` | Whether this already calls `GET /api/v1/health` over HTTP or inspects local state directly is an implementation-time check |

## Backward compatibility

- Local mode is unchanged; nothing breaks for a user who sets none of
  `--server`/`ROCKETVAULT_ADDR`/a context.
- Existing local-mode session cache files continue to work via the fallback
  path described above — no forced re-login for the common case.
- `.rocketvault.yaml`'s role is unchanged for local mode. It plays no role at
  all in remote mode (a remote-mode invocation needs no local config file to
  exist, closing the original gap this design responds to).

## Testing strategy

- Unit tests for the resolver precedence chain (flag > env > context > local).
- Unit tests for the session cache's server-aware key and the local-mode
  migration fallback (old-format file present / absent / both present).
- Unit tests for the context store (`add`/`list`/`use`/`current`/`remove`,
  including current-pointer clearing on removal of the active context).
- Contract tests per resource group: run the same test scenarios against both
  the `local*Client` and `remote*Client` implementations (the latter against
  an in-process `httptest.Server` wrapping the real API router) and assert
  identical results — this is what actually proves functional parity between
  the two modes, not just that both compile.
- Explicit tests that each local-only command refuses to run under a resolved
  remote target, with the expected error message.
- TLS trust tests: default verification rejects a self-signed cert;
  `--ca-cert` accepts one signed by the supplied CA; `--insecure-skip-verify`
  accepts anything and emits the warning.

## Open items deferred to implementation (not design gaps)

- Exact enumeration of every command file touched per resource group (the
  pattern is fixed here; the file list is task-breakdown work).
- Whether `users admin` (bootstrap) and `health` already have or need HTTP
  routes for remote-mode parity (flagged above, not blocking the pattern).
