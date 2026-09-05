# In-Process API Test Harness — Design

**Status:** approved in brainstorming 2026-09-05, not yet implemented.

**Goal:** close the response-shape gap in remote-adapter tests before plan 04
copies the adapter pattern across `keys`, `certificates`, `audit` and `vaults`.

**Problem.** Every remote-adapter test today stands up an `httptest` server
whose handler returns JSON the test author typed by hand:

```go
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    _ = json.NewEncoder(w).Encode(map[string]any{
        "id": ..., "principal_id": ..., "role": ..., // hand-written shape
    })
}))
```

A mock that agrees with the client proves nothing about the server. If
`model.RoleAssignmentResponse` renames a JSON tag, the real API changes, the
client breaks in production, and every one of these tests stays green. Plan
01's route-contract test catches wrong *paths*; nothing catches wrong
*shapes*.

`docs/superpowers/plans/2026-09-03-cli-remote-vaultapi-03b-vault-access-adapter.md`
states this gap in its Self-Review and its Post-Execution Review recommends
building the harness once, before plan 04, rather than retrofitting it across
five groups afterwards.

---

## 1. Scope

**In scope:** response-shape drift, status-code handling, route existence, and
auth-header plumbing, for CLI remote adapters.

**Out of scope, deliberately:** business logic, persistence, and real
authorization decisions. Those stay stubbed. A full-stack variant backed by
in-memory SQLite was considered and rejected for this iteration — it costs
per-test DB setup and seeding, and carries the documented `:memory:` pooling
gotcha (`internal/container/container_test.go:636-641`), for coverage the
existing `api/` service-level tests already provide from the other side.

This harness closes one class of defect well. It is not an end-to-end suite,
and the spec should not be read as claiming otherwise.

---

## 2. Architecture

```
test  →  runXRemote(cmd, client, target, …)
              │
              ▼
        *vaultapi.Client  ──HTTP──▶  httptest.Server
                                          │
                                     real mux router      (api.Init)
                                          │
                                     real middleware chain
                                          │
                                     real handler          ← marshals the
                                          │                  real response
                                     stub service           struct
```

The single load-bearing property: **the response JSON is produced by the
production handler marshalling the production response struct**, not by the
test. Rename a field and the client's decode fails.

### Package

New test-only package `internal/apitest`.

No import cycle. `cmd/<group>`'s *test* files import `internal/apitest`, which
imports `rocketvault/api` and `rocketvault/cmd/testutils`. Neither `api` nor
`cmd/testutils` imports `cmd/<group>`, and `api` does not import
`cmd/testutils`. Verified against the import block at
`cmd/testutils/test_utils.go:14-32`.

### Public surface

```go
// New starts an in-process server backed by the real router and returns a
// handle. The server is closed via t.Cleanup; callers do not defer Close.
func New(t *testing.T, opts Options) *Server

type Options struct {
    // RoleAssignments stubs the role-assignment service. Nil leaves it unset,
    // which is only valid for tests that never reach a role-assignment route.
    RoleAssignments authzServices.RoleAssignmentService

    // DenyDataAction, when non-empty, makes the authorization stub deny that
    // data action, so a test can assert the CLI's 403 mapping. Empty means
    // allow everything.
    DenyDataAction model.DataAction
}

func (s *Server) Client() *vaultapi.Client   // authenticated, pointed at s
func (s *Server) Target() *cliclient.Target  // {Server: s.URL}
func (s *Server) URL() string
```

`Options` carries only what `vault-access` needs. Plan 04 adds one field per
group as that group's adapter lands. This is deliberate: the first real
consumer of each field should shape it, rather than guessing five groups ahead.

---

## 3. Components

### 3.1 Server construction

Build the router exactly as production does — `api.Init` with
`WithAPP`/`WithRouter`/`WithBasePath`/`WithLogger` — backed by
`cmd/testutils.MockServiceContainer`, and serve it through
`httptest.NewServer`. This mirrors the construction
`api/route_contract_test.go` already uses to walk the real route table, so the
two agree on what "the real router" means.

### 3.2 Authentication stub

The chain wired in `api.Init` includes `AuthenticationMiddleware`. Without a
working auth service every request 401s before reaching a handler, so the
harness supplies a stub that validates **any** bearer token into fixed admin
claims (a stable UUID and `model.RoleAdmin`).

The harness's `Client()` is seeded with a static token source, so the real
`Authorization: Bearer …` header is set and traverses the real middleware —
which is how auth-header plumbing gets covered rather than assumed.

### 3.3 Authorization stub

`PolicyMiddleware` and `AuthorizationMiddleware` also run. Default is
**allow**, so tests exercise the happy path without ceremony.

`Options.DenyDataAction` flips one action to deny. This converts a wrinkle
into coverage: `TestGrantRemote_ForbiddenIsReadable` currently asserts
`CLIError`'s 403 mapping against a hand-written `w.WriteHeader(403)`; with the
harness it asserts against a genuine authorization denial travelling the real
error path.

### 3.4 Rate limiting

`RateLimitMiddleware` is per-IP and every test shares `127.0.0.1`. Limits are
read from viper at construction (`internal/middleware/middleware.go:114-122`),
so the harness raises `rate_limit.default`, `rate_limit.auth` and
`rate_limit.per_vault` to an effectively unbounded value, restoring the prior
values via `t.Cleanup`.

**To verify during implementation, not assume:** whether the default 300/min
actually bites in a package's test run. If it does not, drop this and let the
real limiter run — fewer knobs is better. The spec states the mechanism so the
implementer does not have to rediscover it either way.

---

## 4. What tests look like after

`grant_remote_test.go`'s hand-written 40-line handler becomes:

```go
roleSvc := &mockRoleAssignmentService{}
roleSvc.On("AssignRole", mock.Anything, mock.Anything).Return(assignment, nil)

srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

cmd, out := remoteTestCmd(t, "payments")
err := runGrantRemote(cmd, srv.Client(), srv.Target(), "alice", "Key Vault Administrator", "user")
require.NoError(t, err)
assert.Contains(t, out.String(), "granted Key Vault Administrator to alice")
```

The `runXRemote` call site is unchanged from today, so migrating the three
existing `vault-access` tests is a swap of the server-construction block, not a
rewrite.

What the test no longer states — and therefore can no longer get wrong — is
the wire shape.

---

## 5. Error handling

The harness fails the test directly (`t.Fatalf`) on any construction error:
router build, `vaultapi.New`, or `httptest` startup. A harness that returns an
error for the caller to check invites tests that ignore it.

`Options` validation is deliberately absent. A nil service for a route the
test never calls is legitimate; a nil service for a route it *does* call
surfaces as a panic in the handler, which is a clear enough signal and does
not require the harness to model which routes need which services.

---

## 6. Testing the harness

The harness needs its own small test proving it does the one thing it exists
for:

- **Shape guard bites.** A test that decodes a known route's response through
  the real client and asserts a field that only the production struct
  supplies. If someone renames the JSON tag, this fails.
- **403 path.** `Options.DenyDataAction` produces a genuine 403 that
  `cliclient.CLIError` maps to the expected text.
- **Auth header travels.** The stub auth service observes a non-empty bearer
  token.

---

## 7. Migration

1. Build `internal/apitest` with the surface above.
2. Migrate `vault-access`'s three `*_remote_test.go` files onto it, deleting
   their hand-written handlers. Existing assertions stay.
3. Plan 04 uses it from the start for `keys`, adding `Options.Keys`.

Steps 1 and 2 land together — a harness with no consumer proves nothing, and
`vault-access` is the group whose tests already exist to be converted.

---

## Self-Review

**Placeholder scan:** no TBDs. One item is explicitly conditional (§3.4 rate
limiting) and states both branches and how to decide, rather than deferring.

**Internal consistency:** §1's scope exclusion (no real authz) and §3.3's
`DenyDataAction` are compatible — the stub decides allow/deny by
configuration, it does not evaluate real role assignments.

**Scope check:** one package, one consumer group to migrate. Small enough for
a single plan.

**Ambiguity check:** "real middleware chain" is pinned to `api.Init` rather
than left to interpretation, and the no-cycle claim names the file and lines
checked.

**Known limitation, stated rather than hidden:** because services are stubbed,
a handler that never calls its service — returning a hardcoded or
default-valued response — would still satisfy a shape assertion. The harness
proves the *server* produced the shape, not that the shape reflects real data.
Closing that needs the full-stack variant.
