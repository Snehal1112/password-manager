# CLI Remote Mode on `internal/vaultapi` — Design

## Problem

RocketVault has two HTTP clients for its own REST API, and the CLI is wired to
the smaller one.

`internal/vaultapi` was built for the MCP server and covers keys, certificates,
vaults, role assignments, audit, crypto and soft-delete, with name resolution,
error classification and three token sources. `internal/cliclient` covers
secrets plus login/refresh, and nothing else.

The result is that `rocketvault vault-access grant --vault payments` fails with
`remote mode ... is not yet supported`, even though `vaultapi.CreateRoleAssignment`
(`internal/vaultapi/access_write.go:25`) already performs exactly that call.
Across the ten resource groups there are 59 subcommands; 7 have remote adapters
and 2 are local-only by nature, so an active context blocks 50 of 59.

Three forces make this the moment to consolidate rather than continue:

1. **The adapter pattern does not scale.** Each of the seven `secrets` command
   files repeats its own context type-assertions and vault resolution, and the
   group carries its own `secretsBaseURL` and `secretsAPIError`. Six more groups
   on that pattern is roughly fifty hand-written command twins. One group landed
   on 2026-08-24 and nothing has followed.

2. **The duplicated auth path is broken.** `cliclient.RefreshRemote`
   (`internal/cliclient/auth.go:67`) posts to `/api/v1/refresh`. That route does
   not exist: `refreshToken` is registered on the `/users` subrouter
   (`api/users.go:55`, `api/api.go:112`), so the real path is
   `/api/v1/users/refresh` — which `vaultapi` uses correctly
   (`internal/vaultapi/sessionsource.go:221`). Once a cached remote session
   passes `ExpiresAt`, refresh 404s and the user is forced to re-authenticate
   with full credentials.

3. **The tests hide it.** `internal/cliclient/auth_test.go:65` and
   `cmd/root_test.go:692` both assert `"/api/v1/refresh"` against an `httptest`
   server that answers any path. They were written against the implementation
   rather than the API, so they pass while the feature cannot work against a
   real server. `vaultapi`'s equivalent path is exercised against the running
   server through `rocketvault mcp`.

The codebase already states the intended end state.
`internal/vaultapi/client.go:2-4`: "deliberately independent of any consumer:
the MCP server uses it today and the CLI's remote mode is expected to use it
next."

## Goals

1. Make `internal/vaultapi` the only package in the tree that speaks HTTP to the
   RocketVault API, and delete `cliclient`'s competing REST implementation.
2. Unblock remote mode for the five groups whose client methods already exist:
   `vault-access`, `keys`, `certificates`, `audit`, and `vaults` (partially).
3. Fix the refresh-path defect and the test pattern that concealed it.
4. Deliver unattended service-account authentication for CI, which
   `vaultapi.ServiceAccountSource` already implements but the CLI never exposes.
5. Keep local mode byte-for-byte unchanged, and keep remote output identical to
   local output for the same command.

## Non-goals

- **Rearchitecting how commands dispatch.** The existing
  `if target != nil { return runXRemote(...) }` branch stays. Replacing it with
  a per-group client interface was considered and rejected for this design: it
  touches every local code path for a benefit this work does not need.
- **`users` remote support.** `vaultapi` has no user coverage at all — no CRUD,
  no bootstrap admin. That surface has never been designed and belongs in its
  own spec.
- **`vaults update` / `vaults delete`.** The routes exist server-side
  (`api/vault.go:223,280`) but `vaultapi` has no methods for them. Deferred with
  `users`.
- **Whole-database `backup`/`restore` and `master-key rotate`.** Local-only by
  design; no server route exists and none is proposed.
- **Name-based addressing.** `vaultapi.Resolver` offers it, but the CLI has
  always taken UUIDs in both modes. Adopting the resolver is additive and would
  be a separate feature.

## Architecture

`internal/vaultapi` owns every HTTP call. `internal/cliclient` retains only the
concerns that are not REST:

| Component | Fate |
|---|---|
| `cliclient.ResolveTarget` | Kept — target precedence is a CLI concern |
| `cliclient.NewHTTPClient`, `HTTPClientOptions`, `WarnIfInsecure` | Kept — TLS trust config, already reused by `cmd/mcp.go:194-197` |
| `cliclient.RequireLocal` | Kept — local-only refusal |
| `cliclient/secrets.go` | Deleted at phase 7 |
| `cliclient/auth.go` | Deleted at phase 1 |

This is not a speculative arrangement. `cmd/mcp.go` runs it today: it resolves
its target with `cliclient.ResolveTarget` (`cmd/mcp.go:109`), builds its
transport with `cliclient.NewHTTPClient` (`cmd/mcp.go:194-197`), and
authenticates as the CLI's own logged-in user through
`vaultapi.NewSessionSource` reading the same `~/.rocketvault/sessions` files
(`cmd/mcp.go:160-166`). The CLI adopts the arrangement its own MCP command
already proves.

`remotePersistentPreRun` changes shape. Today it authenticates, then stashes a
bearer token (`common.TokenKey`) and an `*http.Client`
(`common.RemoteHTTPClientKey`) for command bodies to assemble requests from.
After this work it builds a `*vaultapi.Client` and stashes that. Commands stop
handling tokens entirely.

## Component design

### 1. Token source selection (`cmd/root.go`)

`resolveRemoteAuthentication` returns a `vaultapi.TokenSource` instead of a raw
token string:

- `--client-id`/`--client-secret`, or `ROCKETVAULT_CLIENT_ID`/`ROCKETVAULT_CLIENT_SECRET`
  → `vaultapi.ServiceAccountSource` (OAuth2 client-credentials against
  `POST /api/v1/oauth2/token`). No session file is written; nothing is cached to
  disk. This is the CI path the 2026-08-17 spec scoped and never delivered.
- Otherwise → `vaultapi.SessionSource`, backed by the existing server-aware
  session cache.

The refresh defect is fixed by construction: `SessionSource` already calls the
route that exists, and shares one in-flight refresh across concurrent callers.

Existing behaviour that must survive: the server-key guard at
`cmd/root.go:446-448`, which discards a cached "current" session whose
`ServerKey` does not match the resolved target. `SessionSource` must be
constructed against the resolved target's key, not the ambient current session.

### 2. Type conversion (`internal/cliclient/convert.go`, new)

`vaultapi` deliberately defines its own types rather than importing `model.*` —
`vaultapi.Secret.Value` is a redacting `SecretValue`, not a `string`, so an LLM
tool response cannot leak a value by accident. That decision stays; the CLI
converts at the boundary instead:

```go
func SecretFromAPI(s *vaultapi.Secret) *model.SecretResponse
func KeyFromAPI(k *vaultapi.Key) *model.KeyResponse
func CertificateFromAPI(c *vaultapi.Certificate) *model.CertificateResponse
func VaultFromAPI(v *vaultapi.Vault) *model.VaultResponse
func RoleAssignmentFromAPI(r *vaultapi.RoleAssignment) *model.RoleAssignmentResponse
func AuditEntryFromAPI(e *vaultapi.AuditEntry) *audit.AuditEvent
```

The five resource mappers target `model.*` response types that exist today
(`model/secret.go:243`, `model/key.go:130`, `model/certificate.go:98`,
`model/vault.go:122`, `model/role_assignment.go:36`). Audit is the exception:
there is no `model.AuditLogResponse`. The local command formats
`audit.AuditEvent` (`internal/services/audit/audit_service.go:18`), a service-layer
type, so `AuditEntryFromAPI` targets that instead. This is the one mapper that
crosses a layer boundary the others do not, and phase 5 should confirm the local
`audit` command's actual formatting input before committing to the signature.

Formatter and table/json/yaml code is untouched, and local and remote output for
the same command stay identical — a user-facing property worth protecting.

The cost of a mapper is drift: add a field to `model.SecretResponse` and remote
output silently loses it. Each mapper therefore carries a test that reflects
over the destination struct and fails on any field the mapper does not set.
Fields intentionally absent remotely are named in an explicit allowlist in that
test, so skipping one is a deliberate edit rather than an omission.

Secret values need one explicit `.Reveal()` at the single place `secrets get`
prints a value. That call site gets a comment explaining why it is safe there
and not by default.

### 3. Shared remote vault resolution

Remote commands currently resolve the vault as flag → `target.Vault` → `""`
(`cmd/secrets/get.go:142-145` and five siblings), skipping the
`ROCKETVAULT_VAULT` environment variable that local mode honours via
`common.ResolveVaultName` (`common/vault_selector.go:15-28`). A user with
`ROCKETVAULT_VAULT=prod` set gets a different vault depending on mode, silently.

One helper, called from each remote branch, resolves flag → `ROCKETVAULT_VAULT`
→ `target.Vault` → `"default"`. Because dispatch stays an if-branch, this is the
piece that prevents the defect being re-fixed wrong in six places.

### 4. Error mapping

`vaultapi.APIError` classifies by status into `ErrorKind` and attaches an
operator-facing `Hint` derived only from the request line — it never reads the
response body, so a secret value cannot be echoed into an error string.

CLI copy differs from operator copy. `cliclient`'s current 401 tells the user to
re-run with `--username/--password/--totp-code`; its 403 explains that no role
assignment grants the required data action. A `cliclient` helper maps
`ErrorKind` → CLI-phrased error, preserving today's wording.

Exit codes are unaffected. `run(cmd)` returns 1 on any non-nil error and 0
otherwise, with no per-status mapping anywhere and no test asserting one.

## Command support matrix (this design)

| Group | Remote after this work | Still guarded |
|---|---|---|
| `vault-access` | grant, list, revoke | — |
| `keys` | CRUD, rotate, rotation policy | — |
| `certificates` | create, list, get, policy | update, renew (no `vaultapi` method; real backend gap) |
| `audit` | query | — |
| `vaults` | list, get, create, purge | update, delete (no `vaultapi` method); purge/recover local-only refusal, see below |
| `secrets` | unchanged behaviour, migrated off `cliclient` | — |
| `users` | — | all (deferred spec) |
| `backup`, `master-key` | — | local-only by design |

`certificates update`/`renew` and `vaults update`/`delete` still error under a
remote target after this work. That is a pre-existing gap surfacing, not a
regression introduced here, and is stated so it does not read as one.

## Local-only refusal, and why it cannot fully defer

`cliclient.RequireLocal` exists to refuse a remote target for operations with no
server route. Its doc comment names five call sites; the code has one
(`cmd/vaults/preview_migration.go:55`). `backup`, `master-key`, `vaults purge`
and `vaults recover` are protected today only by the blanket guard in
`cmd/root.go:593-598`.

That protection disappears group by group as this work carves the guard away.
When `vaults` gains an adapter in phase 6, `vaults purge` and `vaults recover`
would silently operate on local state with a remote target set — precisely the
failure `RequireLocal` prevents. So `RequireLocal` wiring for those two commands
is **in scope for phase 6**, not deferred. `backup` and `master-key` keep their
blanket-guard protection because no adapter in this design touches them; their
wiring defers to the follow-up spec.

One further trap: `cmd/vaults/preview_migration.go:39-44` overrides
`PersistentPreRunE` outright, and Cobra does not chain parent hooks, so
`cmd/root.go`'s guard never runs for it. It reimplements the refusal correctly,
but any future command that overrides the hook inherits no guard at all. The
phase-8 guard rework must account for this rather than assume root's hook always
runs.

## Testing strategy

The refresh defect is the design driver. Two tests asserted a path against mock
servers that agreed with the client, so both passed while the feature could not
work. Mocks that agree with the client prove nothing about the API.

1. **Route-contract test.** Walk the real `mux.Router` the server builds and
   assert every path the clients call is registered with the expected method.
   This catches the class of defect, not the instance — it would have failed on
   `/api/v1/refresh` the day it was written.
2. **Correct the two tests** that assert `/api/v1/refresh` to the real path.
3. **Per-group integration tests** against an in-process server. None of
   `vaultapi`'s five groups has ever been exercised from a CLI code path; the
   methods are proven only against the MCP tool surface.
4. **Mapper completeness tests** as described in §2.
5. **Local-mode regression check.** Every phase asserts that an invocation with
   no `--server`, no `ROCKETVAULT_ADDR` and no current context behaves exactly
   as before.

## Phasing

| Phase | Work |
|---|---|
| 0 | Fix `/api/v1/users/refresh`; correct the two tests; add the route-contract test |
| 1 | Token source selection; `--client-id`/`--client-secret`; delete `cliclient/auth.go` |
| 2 | `vault-access` — proves the pattern end to end |
| 3 | `keys` |
| 4 | `certificates` (create/list/get/policy) |
| 5 | `audit` |
| 6 | `vaults` (list/get/create/purge) **+ `RequireLocal` on purge/recover** |
| 7 | `secrets` migrates to `vaultapi`; delete `cliclient/secrets.go` |
| 8 | Guard carve-away; replace the blanket check with a per-command capability check |

Phase 0 is independently valuable and ships alone: it fixes a live defect
regardless of whether the rest proceeds. Phase 2 is the pattern proof — if the
conversion-plus-if-branch shape is wrong, it is cheaper to learn there than at
phase 6.

## Backward compatibility

- Local mode is untouched in every phase.
- Session files, their server-aware keying, and the legacy `username.json`
  migration path are unchanged. Sessions written before this work keep working.
- `contexts.json` and the `context` command group are unchanged.
- `--ca-cert` and `--insecure-skip-verify` keep their current meaning and now
  apply to every remote-capable group rather than `secrets` alone.
- Remote output for `secrets` must not change when phase 7 migrates it; the
  mapper tests and the local/remote parity property enforce that.

## Documentation debt to clear alongside

Three documents describe the current state incorrectly and will mislead anyone
reading them during this work:

- `docs/usage-guide.md` states "no resource command ... actually talks to a
  remote server yet" — untrue since the secrets adapter landed 2026-08-24.
- `~/data/rocket/Nl-knowledge-base/rocketvault/known-issues-gotchas.md` cites
  the guard at `cmd/root.go:343-386` (now 593-598) and claims only the `context`
  group and Cobra built-ins are exempt, missing both the local-only exemptions
  and the secrets carve-out.
- `cmd/context/use.go:16-17` help text claims "no other command yet acts on the
  current context," which the secrets adapters made false.

Additionally, `context add` validates only that `--server` is non-empty
(`cmd/context/add.go:42-44`). A missing scheme is saved as-is and surfaces later
as an opaque Go transport error. Adding a URL parse with a clear message is
small and belongs with phase 1.

## Open items deferred to implementation

- Whether `AuditEntryFromAPI` should target `audit.AuditEvent` directly or a new
  `model.*` type introduced for it, given that every other mapper stays inside
  `model` (see §2).
- Whether `ServiceAccountSource` needs a `--vault` default, since a service
  account has no context to carry one.
