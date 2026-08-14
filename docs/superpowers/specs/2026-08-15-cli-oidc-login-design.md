# CLI Login for OIDC Users — Loopback Browser Flow + Per-User Session Cache

**Date**: 2026-08-15
**Status**: Approved
**Scope**: `api/oidc.go`, `cmd/root.go`, `cmd/users/login.go` (new `logout.go`), `common/` (new
`session.go`, `browser.go`)

---

## Problem

RocketVault's CLI authenticates on every single command invocation via `--username`/`--password`/
`--totp-code` flags (`cmd/root.go`'s `persistentPreRun`, calling `AuthenticationService.
AuthenticateUser`). There is no session persistence at all today — not even for local
username/password users.

This breaks entirely for OIDC-provisioned users. `UserService.FindOrCreateExternalUser`
(`internal/services/users/user_service.go:197-198`) explicitly sets `PasswordHash: ""` and
`TOTPSecret: ""` for OIDC accounts — by design, they have no local credentials. A command like:

```
./rocketvault secrets list --username user14@exchange4all.local --password "" --totp-code 220969
```

fails before authentication logic even runs: `persistentPreRun` (`cmd/root.go:197-205`) rejects
empty `--password` outright. Even with a non-empty dummy password, bcrypt comparison against an
empty hash fails cleanly (`"invalid credentials"`). There is no CLI-reachable path today that
doesn't require a local password: `AuthenticationService.IssueSessionForUser` (the
password/TOTP-free session issuer used by the OIDC HTTP callback) is wired only into
`api/oidc.go`, never into any `cmd/` package. The OAuth2 client-credentials grant
(`internal/services/oauth2/`) is a separate, unrelated identity model for service accounts, not
human users, and isn't CLI-wired either.

## Goals

- OIDC-provisioned users can obtain a CLI session without ever having a local password, using the
  same browser-based OIDC login they already use for the web app.
- The provider-registered `oidc.redirect_url` (`.rocketvault.yaml:187`, fixed and pre-registered
  with the IdP) never changes — no dependency on the IdP allowing arbitrary `localhost` redirect
  URIs.
- Sessions persist across CLI invocations — closes the "re-authenticate every command" gap for
  local username/password users too, as a natural side effect of building the cache.
- Multiple RocketVault users' sessions can be cached on the same machine simultaneously (e.g. an
  admin account and a personal OIDC account) without one login overwriting the other.
- No new secret-at-rest posture beyond what already exists on disk for this deployment (DB file,
  signing keys) — session cache files are `0600`, same class of trust as those.

## Non-goals

- No server-side session revocation wired into `logout` (would need a session ID not currently
  exposed on `AuthenticationResult`, and revoking by user ID would kill unrelated sessions like an
  open browser tab). `logout` is local-cache-only; the JWT still expires naturally via `jwt.expiry`.
- No true RFC 8628 device-authorization-grant flow — the two-hop loopback-relay design achieves
  the same UX without requiring IdP-side device-flow support, which this or other enterprise IdPs
  may not offer at all.
- No change to the existing `--username`/`--password`/`--totp-code` flag-based flow's behavior for
  scripts that already pass explicit credentials every time — it keeps working exactly as today,
  and additionally now also populates the session cache as a side effect.
- No distributed/multi-machine session store — local file cache only, matching the CLI's existing
  fully-local, in-process architecture (it already opens the DB and service container directly,
  not via HTTP).

---

## Architecture

```
rocketvault users login --oidc
  1. CLI starts a loopback HTTP listener: net.Listen("tcp", "127.0.0.1:0")  (OS-assigned port)
  2. CLI opens the system browser (common/browser.OpenBrowser) to:
       {frontend.public_api_url}/oidc/login?cli_redirect_uri=http://127.0.0.1:<port>/callback
     If the browser can't be opened (headless), the URL is printed instead; the listener keeps
     waiting either way.
  3. Browser: existing provider auth flow, unchanged →
       GET /oidc/callback   (fixed, provider-registered redirect_url — unchanged)
  4. Server (api/oidc.go), after IssueSessionForUser succeeds:
       - if an `oidc_cli_redirect` cookie is present (see below), mint a one-time exchange code,
         store it server-side for 60s, redirect the browser to
         http://127.0.0.1:<port>/callback?code=<code>
       - if absent, unchanged: return the LoginResponse JSON directly (today's browser-login path)
  5. CLI's loopback listener receives ?code=..., POSTs it to
       {frontend.public_api_url}/oidc/cli/exchange
     gets back {token, refresh_token, user_id, username, role}, serves the browser a "you can
     close this tab" page, and shuts the listener down.
  6. CLI writes ~/.rocketvault/sessions/<username>.json and updates the
     ~/.rocketvault/sessions/current pointer file. Process exits 0.
```

Existing password-based `rocketvault users login` (no `--oidc`) is unchanged authentication-wise
but now also writes the same session cache on success.

### Server-side (`api/oidc.go`)

- `oidcLoginHandler`: accepts an optional `?cli_redirect_uri=` query param. Validated against a
  strict allow-list — scheme `http`, host exactly `127.0.0.1` or `localhost`, nothing else. Invalid
  values are rejected with `400` (this is the one new externally-reachable input, so it's the
  primary new attack surface — see Security below). If present and valid, stashed in a new
  `HttpOnly` cookie `oidc_cli_redirect`, same 5-minute TTL as the existing `oidc_state`/
  `oidc_nonce` cookies.
- `oidcCallbackHandler`: after `IssueSessionForUser` succeeds, checks for `oidc_cli_redirect`.
  - Absent → unchanged: return `model.LoginResponse` JSON directly.
  - Present → generate a 32-byte `crypto/rand` hex exchange code (same construction as the
    existing `randomOIDCToken`), store `code → LoginResponse` in a new in-memory, mutex-guarded map
    with 60s TTL and single-use semantics (deleted on first read), clear all three cookies, and
    `http.Redirect` (302) the browser to `<cli_redirect_uri>?code=<code>`.
- New route `POST /oidc/cli/exchange` (public, same unauthenticated router as `/oidc/login` and
  `/oidc/callback`). Body `{"code": "..."}`. Looks up and deletes the code; returns the stored
  `LoginResponse` JSON on success. `400` for a missing code, `410 Gone` for unknown/expired/
  already-consumed.
- The exchange-code map needs no persistent storage or cleanup goroutine beyond a lazy
  expiry check on read — codes are gone (consumed or expired) within 60s regardless, so there's no
  unbounded-growth risk even under load, and losing the map on server restart is harmless (the
  user just retries login).

### CLI-side

- `common/browser.go` (new): `OpenBrowser(url string) error` — `xdg-open` (Linux), `open`
  (macOS), `rundll32 url.dll,FileProtocolHandler` (Windows) via `exec.Command`. Failure is
  non-fatal — the URL is printed and the listener keeps waiting.
- `common/session.go` (new):
  - `SessionCache{ Token, RefreshToken, UserID, Username, Role, ExpiresAt }` — `ExpiresAt` is
    parsed from the JWT's own `exp` claim (via the existing `JWTService`/claims parsing), not
    guessed, so expiry checks are exact.
  - `SaveSession(*SessionCache) error` — writes `~/.rocketvault/sessions/<sanitized-username>.json`
    (dir `0700`, file `0600`, explicit mode on `os.WriteFile` — not umask-dependent) and updates
    `~/.rocketvault/sessions/current` (plain text, just the username) to point at this user.
  - `LoadSession(username string) (*SessionCache, error)` — loads a specific user's file.
  - `LoadCurrentSession() (*SessionCache, error)` — reads the pointer file, then loads that user's
    session. Corrupt/unreadable files are treated as "no session," not an error that aborts the
    command.
- `cmd/users/login.go`: new `--oidc` bool flag. When set, `--username`/`--password`/`--totp-code`
  are ignored; a new `runOIDCLogin` path runs the loopback flow above instead of `AuthenticateUser`.
  Both the password path and the `--oidc` path call `SaveSession` on success.
- `cmd/users/logout.go` (new): `rocketvault users logout` deletes the current user's session file
  (via the pointer, or a specific one via `--username`) and clears the pointer if it pointed at the
  deleted user. Client-side only (see Non-goals).

### `persistentPreRun` (`cmd/root.go`)

Precedence, replacing today's hard `username == "" || password == ""` rejection:

1. `--username` **and** `--password` both given → existing `AuthenticateUser` flow, unchanged,
   then `SaveSession`.
2. `--username` given, `--password` absent/empty → `LoadSession(username)` — loads that specific
   user's cached session, for switching between cached users without re-running login.
3. Neither given → `LoadCurrentSession()` via the pointer file — same zero-flag convenience as
   passing credentials today.
4. In both cache-load cases (2, 3): if the loaded token is expired (checked against its own `exp`)
   but the refresh token isn't, call `AuthenticationService.RefreshAccessToken` in-process (no HTTP
   hop — the CLI already runs in-process against the service layer), `SaveSession` the refreshed
   result, and proceed transparently.
5. No flags, no cache, or refresh also fails → existing error path, message updated to mention
   `rocketvault users login` / `rocketvault users login --oidc`.

---

## Security considerations

- `cli_redirect_uri` is the one new externally-reachable input on an otherwise-unauthenticated
  route. Strict host/scheme allow-list (`127.0.0.1`/`localhost` only) prevents it from becoming an
  open redirect.
- Exchange codes: `crypto/rand`, single-use (deleted on first read), 60s TTL, never logged. A
  replay after consumption gets `410 Gone`.
- The access/refresh token never appears in a URL or query string at any point in the CLI flow —
  only the opaque exchange code does. This avoids the token leaking via browser history, the local
  listener's request log, or a `Referer` header — the same reason OAuth uses authorization codes
  instead of returning tokens in the front channel.
- The loopback listener binds `127.0.0.1` only (never `0.0.0.0`) — unreachable from the network,
  only the user's own browser/local processes can reach it.
- Session cache files: `0600`/`0700`, explicit mode on write. Same trust model as the existing
  unencrypted SQLite DB file and signing keys already on disk for this deployment — no new
  secret-at-rest posture introduced.

## Error handling

- Loopback listener port-bind failure → clear error, no silent fallback.
- Browser fails to open → URL printed, listener keeps waiting (see above).
- User abandons/denies the provider consent screen → existing `oidcCallbackHandler` error handling
  is unchanged; the CLI's listener times out after 5 minutes with "no callback received."
- `/oidc/cli/exchange` returns `410`/`400` → CLI surfaces "login exchange failed, please try again"
  rather than a raw HTTP error body.
- Corrupt/unreadable session cache file → treated as "no session" (falls through to the existing
  missing-credentials error), not a crash.

## Testing

- `common/session.go`: save/load round-trip, per-user filename sanitization, pointer read/update,
  corrupt-file handling — no network needed.
- `api/oidc.go` exchange-code store: issue, single-use consumption, expiry — pure in-memory, no
  HTTP.
- `api/oidc_test.go` additions: `cli_redirect_uri` accept/reject cases; callback redirects with a
  code when the cookie is present vs. returns JSON when absent (unchanged case); `/oidc/cli/
  exchange` success/expired/already-used/missing-code cases.
- `cmd/users` tests: `--oidc` flag wiring, `login`/`logout` cache-file side effects, using a
  fake/mock loopback exchange (no real browser or real IdP in CI — same mocking pattern the
  existing CLI test suite already uses for the service container).
- No end-to-end real-browser test (not CI-feasible); manual verification against the
  `exchange4all.local` test issuer already configured in `.rocketvault.yaml` before calling this
  done.
- Standard bar: `go build ./...`, `go vet ./...`, `gofmt -l` on changed files, full `go test ./...`.

## Migration checklist

1. `common/session.go` + tests — no dependents yet, safe first step.
2. `common/browser.go` — small, independent.
3. `api/oidc.go`: `cli_redirect_uri` validation, cookie, exchange-code store, `/oidc/cli/exchange`
   route, callback branching — plus its test additions.
4. `cmd/users/login.go`: `--oidc` flag, `runOIDCLogin` (loopback listener + browser open + exchange
   call), `SaveSession` wiring on both paths.
5. `cmd/users/logout.go` (new).
6. `cmd/root.go` `persistentPreRun`: new precedence (flags → named cache → current-pointer cache →
   refresh-on-expiry → existing error).
7. Manual end-to-end verification against `exchange4all.local`.
