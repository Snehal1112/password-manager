# MCP Interactive Login — Design

**Date**: 2026-08-25
**Status**: Approved, not yet implemented
**Branch target**: `v-4.0.0`

## Problem

`rocketvault mcp` resolves its identity once at process startup
(`buildMCPServer` in `cmd/mcp.go`) from either a service account or the
session `rocketvault users login` cached to disk. There is no way to
authenticate — or re-authenticate — from within an MCP client conversation.
Two concrete frictions motivated this spec, both hit in the same manual
session on 2026-08-24:

1. **No self-serve login.** A user who wants the assistant to act under their
   own identity has to leave the chat, run `rocketvault users login`, and
   restart the MCP subprocess.
2. **Stale in-process identity after a fresh CLI login.** The MCP server
   subprocess had been running since before a new `rocketvault users login`
   was performed in a terminal. Its `SessionSource` held a refresh token from
   an earlier session; the server rejected refreshes with "session not found
   or expired" even though a perfectly valid session existed on disk. The fix
   required manually killing the subprocess.

A third idea was raised and investigated — configuring username, password and
a TOTP value directly in `.mcp.json` so the server self-authenticates at
startup — and rejected; see "Rejected approach" below.

## Goals

1. Let a user authenticate (or switch identity) mid-conversation via a `login`
   tool, without leaving the chat or restarting the process.
2. Make the MCP subprocess recover automatically when its in-memory session is
   stale relative to what's on disk, eliminating the manual-restart failure
   mode above.
3. Keep both mechanisms strictly additive to the existing identity model —
   no change to how service-account or startup-session identity resolution
   works when neither feature is exercised.

## Non-goals

- **No credentials in `.mcp.json` or any other config file.** See "Rejected
  approach."
- **No `logout` or `whoami` tool.** Restarting the MCP subprocess already
  resets to the startup identity; `login`'s own success response already
  confirms the new identity. Both can be added later if a real need appears.
- **No change to `vaultapi.Client`'s public API or its per-request auth
  logic.** `Client.Do` keeps calling `c.tokens.Token(ctx)` exactly as today.
- **No new persistence.** A chat-triggered login lives only in the running
  process's memory.

## Rejected approach: credentials in `.mcp.json`

Investigated as a way to let the server self-authenticate at startup instead
of via a `login` tool call. Rejected for three independent reasons, any one
of which is sufficient on its own:

1. **It cannot work as literally specified.** A TOTP code is valid for ~30
   seconds; a static config field goes stale before the file is even saved.
   The only way to make it functional is to store the TOTP *seed* instead, so
   the server derives live codes on demand.
2. **The fix breaks the point of MFA.** A seed stored next to the password in
   the same file collapses two-factor auth into one factor with extra steps
   — both "factors" become "something you have," and that something is one
   file.
3. **No precedent for it, here or in reference material.** The sibling
   project `../e4a-mcp` was investigated as a reference and turned out to use
   the opposite shape entirely: it never stores or validates credentials
   itself, forwarding whatever the *calling client* sent per-request to a
   separate `reauth` service. RocketVault's own config already establishes a
   secrets-out-of-YAML convention — `mcp.client_secret` and
   `vault_client.client_secret` are both documented as "keep this out of the
   file, use an env var instead" — and `.rocketvault.yaml` itself is
   gitignored specifically because a secret (`jwt_secret`) was once committed
   from it (`.claude/known-bugs.md` § B10). `.mcp.json` is a *worse* location
   than `.rocketvault.yaml` for a live password: it's designed to be
   project-scoped and checked into git for team sharing, whereas
   `.rocketvault.yaml` at least started from being a local, single-operator
   file.

The already-supported service-account path (`mcp.client_id` +
`ROCKETVAULT_MCP_CLIENT_SECRET` env var, never written to any file) covers
the legitimate "self-authenticate at startup, no human in the loop" case
without any of the above problems, and needs no new code — see "Service
account, unchanged" below.

## Decision summary

| Decision | Choice | Rationale |
|---|---|---|
| Runtime identity swap | New `vaultapi.SwappableSource` wraps the resolved `TokenSource` | `Client` already only depends on the `TokenSource` interface; no change needed there |
| Login transport | New unauthenticated `Client.Login` method, same shape as `SessionSource.refresh`'s call to `/users/refresh` | Reuses an established pattern; login is unauthenticated by nature |
| Login session persistence | In-memory only, never written to `~/.rocketvault/sessions/` | A chat-triggered identity shouldn't silently overwrite the user's CLI session |
| Login tool availability | New `mcp.allow_interactive_login` config flag (default `false`), AND only under session-identity mode | Consistent with existing tier-gating; structurally impossible to use under a service account |
| Stale-session recovery | `SessionSource` reloads from disk once when a refresh is rejected | Fixes the exact failure hit in the 2026-08-24 session; no new config, no new tool |
| Credentials-in-config | Rejected | See above |

## Architecture

```
┌─────────────────────────── rocketvault mcp process ───────────────────────────┐
│                                                                                 │
│   startup:                                                                     │
│   resolveMCPTokenSource() ──► SwappableSource(initial: Session|ServiceAccount) │
│                                        │                                       │
│                                        │ implements TokenSource                │
│                                        ▼                                       │
│                              ┌───────────────────┐                            │
│   every tool call ─────────► │  vaultapi.Client   │──► HTTP ──► RocketVault API│
│   (list_secrets, etc.)       │  .tokens = swap.   │                            │
│                              └───────────────────┘                            │
│                                        ▲                                       │
│                                        │ .Set(newSource)                       │
│                              ┌───────────────────┐                            │
│   login(user,pass,totp) ───► │  handleLogin tool  │                            │
│   [only if allow_interactive_login=true                                       │
│    AND identity != service-account]                                           │
│                              └───────────────────┘                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

- **`vaultapi.SwappableSource`** (new, `internal/vaultapi/swappablesource.go`)
  — implements `TokenSource`. Holds a mutex-guarded "current" `TokenSource`
  and delegates `Token(ctx)` to it. `Set(TokenSource)` atomically swaps it.
  `vaultapi.Client` receives this wrapper instead of the raw resolved source;
  `Client.Do` is unchanged, since it only ever calls `.Token()` on whatever it
  was given.

- **`Client.Login`** (new, `internal/vaultapi/login.go`) — 
  `func (c *Client) Login(ctx context.Context, username, password, totpCode string, expiry time.Duration) (TokenSource, LoginIdentity, error)`.
  Sends one unauthenticated `POST /api/v1/users/login` using `c.http` and
  `c.baseURL` directly (bypassing `c.tokens`, the same way
  `SessionSource.refresh` bypasses it for `/users/refresh`). On success,
  builds an in-memory `common.SessionCache` (`ExpiresAt: time.Now().Add(expiry)`,
  matching how the CLI itself computes it in `cmd/root.go`) and wraps it via a
  new `NewSessionSourceFromCache` constructor. On failure, returns a generic
  error without echoing the response body — matches `SessionSource.refresh`'s
  existing precedent, and avoids leaking whether a username exists.

- **`NewSessionSourceFromCache`** (new, `internal/vaultapi/sessionsource.go`)
  — like `NewSessionSource`, but seeded with an already-known
  `*common.SessionCache` instead of loading one from disk, and defaulting
  `SaveSession` to a no-op instead of `common.SaveSession`. This is what
  makes the login-tool identity in-memory-only: its own future token
  refreshes never touch `~/.rocketvault/sessions/`.

- **`TierLogin`** (new, `internal/mcpserver/gating.go`) — 
  `TierEnabled(TierLogin)` returns `s.cfg.AllowInteractiveLogin &&
  !s.isServiceAccountIdentity`. `isServiceAccountIdentity` is a new
  `Server` field set once from `Deps` at construction (`cmd/mcp.go` already
  knows which branch `resolveMCPTokenSource` took; it now also returns that
  as a bool). This is a construction-time fact, not a per-call check, so it
  cannot be influenced by any tool call.

- **`login` tool** (new, `internal/mcpserver/tools_login.go`) — 
  args `{username, password, totp_code}` (all required, matching
  `loginUser`'s own validation in `api/users.go`). On success, calls
  `s.identity.Set(source)` (`Deps.Identity *vaultapi.SwappableSource`, a new
  field alongside the existing `Deps.Client`) and returns
  `{username, roles, expires_at}` — never the token, matching `set_secret`'s
  existing precedent of not echoing back what it was just given.

- **New config**: `mcp.allow_interactive_login` (bool, default `false`),
  documented in `.rocketvault.yaml`/`.rocketvault.yaml.example` and
  `docs/mcp-server.md` next to the other tiers.

### Stale-session recovery (bounds the second friction)

`SessionSource` (`internal/vaultapi/sessionsource.go`) gains a `load func()
(*common.SessionCache, error)` field, set in `NewSessionSource` from the same
`load` value already resolved there (today it's used once and discarded).
`NewSessionSourceFromCache` sets it to a function that always returns
`vaultapi.ErrNoSession`, since an in-memory login-tool session has no disk
backing to recover from.

In `Token()`, when `s.refresh(ctx, refreshToken)` fails, and only then, `load()`
is called once. If it returns a session whose `RefreshToken` differs from the
one just used, `s.session` is replaced with the freshly loaded session
*before* retrying `refresh` — `refresh` copies whatever is currently in
`s.session` to carry forward fields the response doesn't return (e.g.
`ServerKey`), so the base it copies must already be the newer session, not
the stale one. This is the minimal change that fixes the exact failure from
2026-08-24: a CLI login performed after the MCP subprocess started now gets
picked up on the very next tool call, no restart required. A session with no
newer disk state, or an in-memory login-tool session, falls straight through
to the existing error path — behavior for those cases is unchanged.

## Data flow (login tool)

```
model          mcpserver.handleLogin        vaultapi.Client.Login        RocketVault API
 │  login(u,p,totp)   │                              │                          │
 ├───────────────────►│                              │                          │
 │                     │  Login(ctx,u,p,totp,expiry)  │                          │
 │                     ├─────────────────────────────►│  POST /users/login       │
 │                     │                              ├─────────────────────────►│
 │                     │                              │◄─────────────────────────┤
 │                     │                              │  {token, refresh_token}  │
 │                     │  TokenSource (in-memory)      │                         │
 │                     │◄─────────────────────────────┤                          │
 │                     │  Identity.Set(source)         │                         │
 │                     │──────────► SwappableSource                              │
 │  {username, roles,  │                              │                          │
 │   expires_at}       │                              │                          │
 │◄────────────────────┤                              │                          │
```

Every tool call after a successful `login` flows through the same
`vaultapi.Client`, now authenticating as whoever just logged in. No other
tool's code changes.

## Error handling / security

- Credentials are tool call *arguments*. `withLifecycle` already never logs
  arguments (they can carry secret values) — this required no new code, but
  the tool's description says so explicitly, since a host UI might otherwise
  display arguments in a transcript view.
- `login` is registered only when `allow_interactive_login` is true and the
  server did not start under a service account — checked once, at
  registration, the same structural pattern every other tier already uses
  (`registerIf`, `gating.go`): a disabled tool is absent from `tools/list`
  entirely, not present-and-refusing.
- A failed login returns one generic message, not the underlying HTTP status
  or body — mirrors `SessionSource.refresh` and avoids leaking whether a
  username exists or which factor was wrong.
- The stale-session recovery path only ever reads the session cache
  (`common.LoadCurrentSession`); it does not write anything, so it can't
  interact badly with the in-memory-only guarantee for login-tool sessions.

## Service account, unchanged

No code changes needed for the "self-authenticate at startup, no human in
the loop" case — it's already fully supported:

```yaml
mcp:
  client_id: "mcp-agent"
  require_service_account: true
```

```bash
export ROCKETVAULT_MCP_CLIENT_SECRET='<client_secret>'
```

set in the shell before launching Claude Code, so the MCP subprocess inherits
it via the environment and it never touches `.mcp.json` or any other file.
`docs/mcp-server.md`'s existing "Identity" section already documents this;
this spec adds a cross-reference from the new `login` tool's docs section
back to it, so a reader who wants non-interactive startup auth is pointed at
the right (already-built) mechanism instead of reaching for `login`.

## Testing

- `internal/vaultapi`: table tests for `SwappableSource.Set`/`Token` under
  concurrent access (race detector); `Client.Login` against a fake HTTP
  server (success, 401, malformed body); `NewSessionSourceFromCache`
  confirming `SaveSession` defaults to a no-op; a `Token()` test that forces
  a refresh rejection and asserts the disk-reload retry path (both the
  "newer session found" and "no newer session, still fails" cases).
- `internal/mcpserver`: extend the existing gating-table test
  (`gating_table_test.go`) with `login` present/absent under every
  combination of `allow_interactive_login` × service-account identity;
  `tools_login_test.go` following the `tools_secrets_write_test.go` pattern;
  an integration test asserting a `list_secrets` call after `login` uses the
  new token (fake server records which bearer token it received).
- Manual: repeat the exact 2026-08-24 scenario (start `rocketvault mcp`, log
  in via a separate terminal, call a read tool without restarting) and
  confirm it now succeeds without intervention.

## Documentation updates

- `docs/mcp-server.md`: new subsection under "Identity" for the `login` tool
  — what it does, the `allow_interactive_login` flag, why it's unavailable
  under a service account, and the explicit recommendation to prefer the
  service-account path for anything non-interactive.
- `.rocketvault.yaml.example`: add `allow_interactive_login: false` next to
  the other `mcp:` tier flags, with the same one-line comment style.
