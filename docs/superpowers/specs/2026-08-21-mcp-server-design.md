# RocketVault MCP Server — Design

**Date**: 2026-08-21
**Status**: Approved, not yet implemented
**Branch target**: `v-4.0.0`

## Problem

RocketVault has no Model Context Protocol interface. An operator who wants an
AI assistant to help run their vault — "which secrets in `prod` expire this
month?", "rotate the signing key and show me the new version", "who was granted
Crypto Officer last week?" — has no option but to have the assistant shell out
to the CLI, parse human-formatted output, and hope. That is brittle, unauditable,
and gives the assistant an admin shell on a secrets product.

An MCP server closes that gap with a typed, capability-gated tool surface whose
authorization is enforced by the same middleware every other API client goes
through.

Two facts about the current codebase shape this design:

1. **There is no typed REST client for resources.** `internal/cliclient` landed
   the foundation for remote CLI mode (`ResolveTarget`, `NewHTTPClient`,
   `RequireLocal`, `WarnIfInsecure`) but every resource command in `cmd/secrets`,
   `cmd/keys`, `cmd/certificates` still pulls `ServiceContainerInterface` out of
   context and calls services in-process. `internal/vaultclient` is not a
   general client — it fetches known secrets by UUID for embedding in another Go
   application.
2. **The CLI path has no authorization enforcement point other than the command
   itself.** As `CLAUDE.md` states, a CLI command that skips its
   `vaultcli.RequireDataAction` check "bypasses authorization entirely". A tool
   surface driven by an LLM is the worst possible place to re-litigate that
   per-tool.

## Goals

1. Expose a curated, workflow-oriented MCP tool surface over RocketVault's
   existing REST API, with authorization enforced server-side by
   `PolicyMiddleware` rather than re-implemented in tool code.
2. Ship as `rocketvault mcp` over stdio, with the tool layer written
   transport-agnostically so streamable HTTP is an additive phase.
3. Default to least privilege: read-only, no secret values, no crypto, no
   mutations, until explicitly enabled in config.
4. Be production-grade: attributable in the audit log, resistant to prompt
   injection, bounded in resource consumption, observable, and verified under
   the race detector and against a real server.
5. Build the typed REST client as a reusable package, since the CLI
   remote-server work needs exactly this component.

## Non-goals

- **No new HTTP API endpoints.** Where no route exists, no tool exists. Most
  notably: keys have `/rotationpolicy`, secrets do not, so there is no
  `rotate_secret` tool — secret rotation stays CLI/scheduler-driven.
- **No MCP-level permission model** beyond the capability flags. Fine-grained
  authorization is the backend's job, via Azure-parity role assignments.
- **No MCP prompts or resources in v1.** Tools only. Host support for resources
  is uneven, and nothing in the goals requires them.
- **No changes to `internal/vaultclient`.** It solves a different problem and is
  left alone, exactly as the CLI remote-server spec decided.
- **No streamable HTTP transport in this spec.** Phase 4, separate design.
- **No rearchitecting of `serve`.**

## Decision summary

| Decision | Choice | Rationale |
|---|---|---|
| Backend access | HTTP to the REST API | Authorization enforced once, by existing middleware |
| Identity | Service account (prod) or cached session (dev) | Both reduce to a bearer token; one code path |
| Transport | stdio now, HTTP later | Tool layer transport-agnostic from day one |
| Tool granularity | ~26 curated workflow tools, tier-gated | Tool-selection accuracy; disabled tiers cost zero context |
| Capability gating | 4 independent flags, all default false | Config narrows; it can never widen past RBAC |
| Addressing | Names, resolved to UUIDs internally | Models reason in names; routes are UUID-keyed |

## Architecture

### Package layout

```
internal/vaultapi/        # typed REST client — knows nothing about MCP
  client.go               # request/response plumbing, retry, error mapping
  tokensource.go          # TokenSource interface + two implementations
  resolve.go              # name -> UUID resolution with per-invocation cache
  secrets.go keys.go certificates.go vaults.go access.go audit.go deleted.go
internal/mcpserver/       # MCP layer — knows nothing about HTTP
  server.go               # builds *mcp.Server, registers tools per enabled tier
  tools_secrets.go tools_keys.go tools_certificates.go
  tools_vaults.go tools_access.go tools_audit.go tools_crypto.go
  gating.go               # tier -> registered tool set
  redact.go               # the single egress point for secret values
  envelope.go             # untrusted-content wrapping
  ratelimit.go lifecycle.go
cmd/mcp.go                # `rocketvault mcp` — stdio wiring and --check only
config/config.go          # LoadMCPConfig()
```

The split is load-bearing. `internal/vaultapi` never imports the MCP SDK, so it
is directly reusable by the CLI remote-mode work. `internal/mcpserver` never
constructs an HTTP request, so its tests run against a fake client with no
network. `cmd/mcp.go` contains transport wiring only, which is what makes phase
4 an added file rather than a refactor.

### Data flow

```
MCP host (Claude Code/Desktop)
  │  JSON-RPC over stdio (stdout = protocol; logs go to stderr)
  ▼
internal/mcpserver
  │  gating → arg validation → rate limit → vaultapi call → redact → envelope
  ▼
internal/vaultapi
  │  bearer token, correlation header, retry + circuit breaker
  ▼
RocketVault REST API  →  AuthenticationMiddleware → PolicyMiddleware → handler
                                                     (deny-by-default)
```

Authorization happens exactly once, at `PolicyMiddleware`, for MCP calls just as
for any other API client. No tool re-implements an authorization decision.

### Authentication

```go
// TokenSource yields a bearer token for the RocketVault API.
type TokenSource interface {
    Token(ctx context.Context) (string, error)
}
```

Both identities reduce to a bearer token, because `middleware.go:270` accepts
`Authorization: Bearer <jwt>` and `common.SessionCache.Token` already holds a
JWT. There is one request path, not two.

- **`serviceAccountSource`** — `POST /api/v1/oauth2/token` with
  `grant_type=client_credentials`, caching the token until expiry minus a skew
  margin. Credentials are sent as **HTTP Basic**, not as form fields. The
  endpoint accepts either, but prefers Basic per RFC 6749 §2.3.1
  (`extractClientCredentials`, `api/oauth2.go:143`), and Basic keeps the client
  secret out of the request body and out of anything that logs bodies. Same
  shape as `vaultclient.ensureToken`, reimplemented rather than reused because
  `vaultclient` is hardwired to UUID-keyed secret fetches.
- **`sessionSource`** — reads `common.LoadCurrentSession()`, refreshes via
  `POST /api/v1/users/refresh` when past `ExpiresAt`, persists with
  `common.SaveSession`. Server-keyed, so `common.SanitizeServerKey` disambiguates
  `admin@serverA` from `admin@serverB`.

  **Refresh tokens rotate.** `refreshToken` returns a *new* `refresh_token`
  alongside the access token (`api/users.go:501`), so `sessionSource` must
  persist both back through `common.SaveSession`. Persisting only the access
  token leaves a stale refresh token on disk and the *next* refresh fails —
  a bug that would surface an hour later, far from its cause.

### There is no end-user authentication

The MCP server does not authenticate a human. It authenticates *itself* as a
single principal, resolved once at startup and held for the process lifetime.

This is a property of the stdio transport, not a shortcut: stdio JSON-RPC has no
user-identity concept and no channel for an interactive prompt, and a server
that tried to prompt would simply hang the host. The user boundary is therefore
the **OS process boundary** — one server process per person, running as them,
acting as exactly one RocketVault principal. There is no impersonation and no
per-tool-call identity.

Two consequences follow:

1. The session path makes the agent act *as you*. Its actions land in the audit
   log under your `UserID`, indistinguishable from your own — which is the
   second reason (after forgeable `Source`) that production requires a dedicated
   service account.
2. Per-connection identity becomes mandatory only in phase 4, when multiple
   clients share one server over a network. That is a different authentication
   model — OAuth resource-server metadata, per-request token validation, origin
   checks — not a transport swap, which is why it has its own spec.

Resolution at startup: service account if `mcp.client_id` and
`mcp.client_secret` (or `ROCKETVAULT_MCP_CLIENT_SECRET`) are set; else the
cached session; else **fail fast** with an actionable message. There is no
silent fallback — commit `795ecd4` already established that silent remote
fallback is a bug in this codebase.

When `mcp.require_service_account` is true (the production posture), the session
path is refused outright at startup.

Token refresh is **single-flight**. MCP hosts issue concurrent tool calls, so
without it, N in-flight calls stampede `/oauth2/token` the moment a token
expires.

Base URL comes from `cliclient.ResolveTarget(serverFlag)`, so `rocketvault mcp
--server prod` works immediately and MCP inherits the named-context store rather
than inventing its own endpoint configuration. TLS handling and the
insecure-HTTP warning come from `cliclient.NewHTTPClient` / `WarnIfInsecure`.

### Vault scoping and name resolution

All calls use **vault-scoped routes** (`/api/v1/vaults/{vault_name}/...`), never
the flat equivalents. Flat routes silently resolve to the `default` vault, which
is precisely the ambiguity an autonomous agent must not operate under.

Every route is UUID-keyed (`{secret_id:[A-Fa-f0-9-]+}`) but a model reasons in
names. Tools therefore accept `name`, and `vaultapi/resolve.go` maps name → UUID
via a list call with a per-invocation cache. An ambiguous name returns an error
enumerating the candidates; it never guesses.

Vault selection precedence: explicit tool `vault` argument → `mcp.vault` →
error. If `mcp.allowed_vaults` is non-empty, any vault outside it is refused
locally before any request is made.

## Tool surface

Registration is tier-conditional: a disabled tier's tools are never registered,
so they consume zero context in the host. The default posture exposes 10 tools;
everything enabled exposes 27 (10 read, 9 write, 4 destructive, 4 crypto).

### Read tier — always registered

| Tool | Route |
|---|---|
| `list_vaults` | `GET /api/v1/vaults` |
| `list_secrets` | `GET /api/v1/vaults/{v}/secrets` |
| `get_secret` | `GET /api/v1/vaults/{v}/secrets/{id}` (+ `/versions`) |
| `list_keys` | `GET /api/v1/vaults/{v}/keys` |
| `get_key` | `GET /api/v1/vaults/{v}/keys/{id}` (+ `/versions`, `/rotationpolicy`) |
| `list_certificates` | `GET /api/v1/vaults/{v}/certificates` |
| `get_certificate` | `GET /api/v1/vaults/{v}/certificates/{id}` (+ `/policy`) |
| `list_deleted` | `GET /api/v1/vaults/{v}/deleted/{secrets,keys,certificates}` |
| `list_role_assignments` | `GET /api/v1/vaults/{v}/role-assignments` |
| `query_audit_log` | `GET /api/v1/audit/logs` — **requires global admin**, see below |

**`query_audit_log` cannot work under the recommended posture.**
`GET /api/v1/audit/logs` gates on the global `admin` role, not on a data
action:

```go
if role != string(model.RoleAdmin) {
    c.SetPermissionError("admin role required")
```
(`api/audit.go:66-71`)

No per-vault Azure role grants it — not `Key Vault Reader`, not even
`Key Vault Data Access Administrator`. So a least-privilege service account,
which this design otherwise recommends, receives 403 from this tool every
time. That is the server's design, not a defect in the MCP layer.

The trade-off is real and belongs to the operator: reading audit logs through
MCP means running the agent as a global admin, which is a far larger grant
than everything else here needs. Many deployments should rationally leave
`query_audit_log` unusable rather than pay that price. The operator runbook
must state this, and the tool's 403 message says it directly rather than
suggesting a vault role that could not help.

`list_role_assignments` has a softer version of the same constraint — it
accepts admin, `vaults/manage`, *or* `Key Vault Data Access Administrator`
(`api/role_assignments.go:139`), and the last is grantable per vault, so a
least-privileged principal can hold it.

`get_secret` returns metadata, tags, version list and expiry. It exposes an
`include_value` argument **only** when `mcp.allow_secret_values` is true — the
schema itself is different, so a value cannot be requested when disabled.

**A server constraint qualifies this, and it should not be glossed over.**
`GET /api/v1/vaults/{v}/secrets/{id}` returns the plaintext value
unconditionally — the handler sets `Value: secret.Value` under the comment
"include value for get operation" (`api/secrets.go:462-465`), with no query
parameter to suppress it. So:

- The value **enters the MCP server process** regardless of
  `allow_secret_values`. Redaction governs what reaches the *model*, which is
  the threat this design is defending against, but it cannot stop the value
  crossing the wire.
- Metadata-only reads cannot ask for less. `ListSecrets` does omit values, but
  it also omits `expires_at`, `enabled` and `content_type` — and expiry is
  precisely what operators ask about — so `get_secret` must use the get route.

This is why `vaultapi.SecretValue` redacts on `String`, `GoString` and
`MarshalJSON`: the plaintext arrives whether or not anyone wants it, so
discarding it is the default and revealing it is the deliberate act.

Closing the gap properly would mean adding `?include_value=false` to the
existing get route. That is a modification to an existing endpoint rather than
a new one, but it is still a server change, which this design's non-goals
exclude. It should be proposed separately.

### Write tier — `mcp.allow_write`

| Tool | Route |
|---|---|
| `set_secret` | `POST` to create, `PUT /{id}` to update (upsert by name) |
| `create_key` | `POST /api/v1/vaults/{v}/keys` |
| `rotate_key` | `POST /api/v1/vaults/{v}/keys/{id}/rotate` |
| `set_key_rotation_policy` | `PUT /api/v1/vaults/{v}/keys/{id}/rotationpolicy` |
| `create_certificate` | `POST /api/v1/vaults/{v}/certificates` |
| `set_certificate_policy` | `PUT /api/v1/vaults/{v}/certificates/{id}/policy` |
| `create_vault` | `POST /api/v1/vaults` |
| `grant_vault_role` | `POST /api/v1/vaults/{v}/role-assignments` |
| `recover_deleted` | `POST /api/v1/vaults/{v}/deleted/{type}/{id}/restore` |

`recover_deleted` is a write, not a destructive operation — it *undoes* a
deletion.

### Destructive tier — `mcp.allow_destructive`

| Tool | Route |
|---|---|
| `delete_item` | `DELETE /api/v1/vaults/{v}/{type}/{id}` (soft delete) |
| `purge_item` | `DELETE /api/v1/vaults/{v}/deleted/{type}/{id}/purge` (irreversible) |
| `revoke_vault_role` | `DELETE /api/v1/vaults/{v}/role-assignments/{id}` |
| `purge_vault` | `DELETE /api/v1/vaults/{v}/purge` (irreversible) |

`delete_item` and `purge_item` take `type: secret|key|certificate` rather than
becoming six separate per-type tools; the argument shape is identical across
types, so this is genuine deduplication, not a union-shaped catch-all.

### Crypto tier — `mcp.allow_crypto`

| Tool | Route |
|---|---|
| `sign` | `POST /api/v1/vaults/{v}/keys/{id}/sign` |
| `verify` | `POST /api/v1/vaults/{v}/keys/{id}/verify` |
| `encrypt` | `POST /api/v1/vaults/{v}/keys/{id}/encrypt` |
| `decrypt` | `POST /api/v1/vaults/{v}/keys/{id}/decrypt` |

Crypto is a separate flag rather than part of `allow_write` because "use the
vault's private key on my behalf" is a distinct authority from writing metadata:
it mutates nothing, yet produces artifacts that authenticate as the principal.
`decrypt` additionally requires `allow_secret_values`, since its output *is*
plaintext.

Wrap/unwrap are deferred — they serve key-encryption-key workflows an assistant
rarely drives, and each added tool costs context in every request.

### Response shaping

- Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`) so hosts can prompt appropriately.
- Every list tool takes `limit` (default `mcp.max_results`, hard ceiling 200).
  An unbounded `query_audit_log` would otherwise pour thousands of rows into the
  model's context. Truncated responses state that they were truncated; they
  never silently cut off.
- Responses declare output schemas so hosts can validate them.

## Configuration

`config.LoadMCPConfig() (MCPConfig, error)` follows the error-returning shape of
`LoadCacheConfig`, since it validates. New section in
`.rocketvault.yaml.example`, everything off:

```yaml
mcp:
  vault: default
  allowed_vaults: []              # empty = any vault the principal can reach
  allow_write: false
  allow_destructive: false
  allow_crypto: false
  allow_secret_values: false
  require_service_account: false  # set true in production
  confirm_destructive: true
  max_results: 50                 # per-list cap; hard ceiling 200
  request_timeout: "30s"
  rate_limit:
    reads_per_minute: 120
    writes_per_minute: 20
  client_id: ""
  client_secret: ""               # prefer the env var below
```

`ROCKETVAULT_MCP_CLIENT_SECRET` takes precedence over the YAML key, and the
`.example` file ships empty — consistent with the post-incident posture recorded
in `.claude/known-bugs.md` § B10.

Validation is strict: unknown keys, a `max_results` above the ceiling, an empty
`vault` with a non-empty `allowed_vaults`, or `require_service_account: true`
with no client credentials all fail at startup rather than at first tool call.

## Error handling

Tool failures return MCP results with `isError: true` and actionable text, never
protocol-level errors — the model should be able to recover and retry sensibly.

| Upstream | Tool result |
|---|---|
| 401 | "session expired — run `rocketvault users login`" (session mode) or token-fetch failure detail (service-account mode) |
| 403 | "principal lacks `<data action>` in vault `<v>`; grant e.g. `<role>`" |
| 404 | not found, with near-miss names from the resolution cache |
| 409 | conflict, with the competing resource identified |
| 5xx / transport | retried under `retry.ExternalServicePolicy()`, then reported |

The 403 mapping is where this earns its keep: naming the missing data action and
a role that would grant it turns a dead end into a one-step fix for the operator.

Upstream response bodies are **sanitized, never passed through** — error
payloads can echo request material, including secret values.

## Production hardening

### Threat model

The principal threats, in priority order:

1. **Prompt injection via vault-resident content** — an attacker who can write a
   secret description, tag, certificate subject or audit `Details` field can
   place instructions into the model's context.
2. **Over-broad capability** — an assistant granted more authority than the task
   requires.
3. **Credential exposure** — secret values reaching logs, host transcripts, or
   error payloads.
4. **Resource exhaustion** — a looping agent hammering the vault.
5. **Unattributable actions** — inability to distinguish agent from human in the
   audit log.

### Audit attributability

In production the server runs as its **own dedicated service account** (e.g.
`mcp-agent`), so `AuditLog.UserID` identifies agent-originated actions and
`mcp.require_service_account` enforces it.

A `Source: "mcp"` value was considered and rejected. `AuditLog.Source` is
`"api" | "cli" | "system"`, hardcoded to `"api"` in
`internal/middleware/middleware.go:297`. Populating it from a client-supplied
header would make it forgeable — unacceptable against a `PrevHash`-chained audit
log. Deriving attribution from the authenticated principal requires no server
change and cannot be spoofed.

### Prompt injection

Defense in depth, on the assumption that some injected text *will* reach the
model:

- **Capability gates are unreachable from tool calls.** Flags are read once at
  startup. No injected instruction can widen capability, because there is no
  code path from a tool to the gate.
- **Untrusted content is enveloped.** Vault-resident free text (descriptions,
  tags, subjects, audit `Details`) is returned inside a delimited
  untrusted-data envelope with an explicit marker, never as bare prose that
  reads like instruction.
- **Destructive tools require confirmation.** With `confirm_destructive` (default
  true), `delete_item`, `purge_item`, `purge_vault` and `revoke_vault_role`
  require a `confirm` argument echoing the exact resource name. A drive-by call
  fails closed.
- **Blast radius is pinned.** `allowed_vaults` bounds reachable vaults
  regardless of what the principal's role assignments would otherwise permit.
- **Least-privilege grants are documented.** The operator runbook recommends the
  narrowest Azure-parity role per intended use, so an over-permissive service
  account is a deliberate choice rather than the default.

### Resource consumption

Token-bucket rate limiting per tool class (`rate_limit.reads_per_minute`,
`writes_per_minute`), plus `retry.CircuitBreaker` (already present in
`internal/retry`, `DefaultCircuitBreaker()`) on the `vaultapi` client. A looping
agent degrades its own tool calls rather than the vault.

### Concurrency

Single-flight token refresh, as described above. All shared state in
`mcpserver` (resolution cache, rate limiter, token cache) is mutex- or
`sync.Map`-guarded. CI runs the package under `-race`.

### Memory hygiene

Plaintext buffers are zeroized after marshalling, following the existing
`cachekit.Zeroable` convention. Redaction is enforced **at the logger**, so a
secret value cannot reach a log line even through a mistaken field. `redact.go`
is the single egress point for values: a new tool cannot leak by omission,
because the schema has no `include_value` unless the flag is on.

### Lifecycle

- SIGINT/SIGTERM trigger a graceful drain of in-flight calls.
- Each tool call runs under a `mcp.request_timeout` deadline.
- Panic recovery per tool call — a malformed call returns an error result rather
  than killing the session.

### stdio hazard

**stdout is the protocol channel.** All logging goes to stderr, wired explicitly
in `cmd/mcp.go`. A stray `fmt.Println` anywhere in the call path corrupts the
JSON-RPC stream, so a test asserts stdout carries only well-formed frames.

### Preflight

`rocketvault mcp --check` validates configuration, connectivity and
authentication, then prints the exact tool set that would be exposed and the
identity it would act as. Without it, a misconfiguration surfaces as an opaque
handshake failure inside Claude Desktop with no diagnostic.

### Observability

Structured logs to stderr via `internal/logging`, one entry per tool call with
tool name, vault, outcome, duration and a correlation ID. The correlation ID is
sent as a request header so a tool call can be traced to its API request and the
resulting audit entry.

## Testing strategy

TDD throughout, per the project's `test-driven-development` skill.

**`internal/vaultapi`** — `httptest.Server` table tests per endpoint: happy
path, each mapped error status, token refresh on expiry, single-flight refresh
under concurrency, name→UUID resolution including the ambiguous case, retry and
circuit-breaker behavior.

**`internal/mcpserver`** — the SDK's in-memory transport pair drives *real* MCP
calls against a fake `vaultapi`, so tests exercise the actual protocol surface.

The two security-critical tests:

1. **Gating table** — every tool × every flag combination, asserting the
   **exact** registered tool set. This is the test that prevents a future tool
   from being silently reachable in the default posture.
2. **Redaction** — no secret value appears in any response byte, log line, or
   error payload when `allow_secret_values` is false, asserted over the full
   serialized output rather than a field check.

**Integration** — against a real server via `testcontainers`, already in
`go.mod`, covering the service-account flow end to end.

**CI** — the gating table runs alongside the existing `scope-gate` job; the
package is run under `-race`; a `security-review` pass is required before merge.

## Phasing

Each phase is independently useful and independently shippable.

| Phase | Content | Done when |
|---|---|---|
| 1 | `internal/vaultapi` + `TokenSource`, read endpoints | Unit tests green, race clean |
| 2 | `internal/mcpserver` + `cmd/mcp.go` stdio, read tier | Usable end to end in Claude Code |
| 3 | Write, destructive, crypto tiers | Gating table complete |
| 3.5 | Production hardening (all of the above section) | Integration + security review pass |
| 4 | Streamable HTTP transport | Separate spec |

Phases 1–3 deliver a working read/write MCP server; phase 3.5 is what makes it
production-grade and is not optional for a production deployment.

## Deferred

- Wrap/unwrap crypto tools.
- MCP prompts and resources.
- `rotate_secret` — blocked on a secret rotation-policy HTTP route, which does
  not exist. Proposing that route is a separate piece of work.
- Streamable HTTP transport, and with it OAuth resource-server metadata, CORS
  and origin validation.
- Storing the service-account secret in the OS keyring via `internal/signing`'s
  keychain pattern, rather than env/YAML.

## References

- `github.com/modelcontextprotocol/go-sdk` v1.7.0 (official, stable v1)
- `docs/superpowers/specs/2026-08-17-cli-remote-server-support-design.md` —
  `internal/cliclient` foundation this design builds on
- `.claude/azure-keyvault-parity.md` — role and data-action vocabulary used in
  403 error mapping
- `.claude/known-bugs.md` § B10 — secrets-in-config posture
- `CLAUDE.md` § CLI Authorization — why the HTTP path is the correct enforcement
  point
