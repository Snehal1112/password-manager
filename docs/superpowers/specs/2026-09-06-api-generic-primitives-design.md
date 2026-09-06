# `api/` Generic-Primitive Refactor — Design

**Date:** 2026-09-06
**Branch:** `refactor/api-generics`
**Worktree:** `/home/numericlabs/data/rocket/rocketvault-api-refactor`
**Base:** `v-4.0.0` @ `4dc0285`

## Problem

The `api/` package is 29 non-test files, 7,214 lines, 97 handlers, 16 route
registrars. Every handler hand-rolls the same prologue and epilogue. Measured
across the non-test files:

| Idiom | Sites |
|---|---|
| `uuid.Parse(c.Params.X)` followed by `SetInvalidParam` | 51 |
| `scopeFromRequest(c, r)` followed by `if !ok { return }` | 36 |
| `svc := c.xSvc(); if svc == nil { return }` | 31 |
| `w.Header().Set("Content-Type", ...)` + `json.NewEncoder(w).Encode(...)` + `//nolint:errcheck,gosec` | 78 |
| `json.NewDecoder(r.Body).Decode(&req)` | 20 |
| `base64.StdEncoding.DecodeString` + "must be valid base64" | 8 |
| `map[string]any{...}` used as a response body | 21 |

Four structural problems sit on top of that:

1. **`keys.go` is 1,193 lines** doing four unrelated jobs: wire types, CRUD,
   crypto operations, and version/rotation-policy wiring.
2. **The crypto sextet** (`keys.go:822-1193`, ~370 lines). `wrapKey`,
   `unwrapKey`, `signKey`, `verifyKey`, `encryptKey`, `decryptKey` share one
   spine — parse id, build scope, decode body, validate required fields, apply
   a default algorithm, base64-decode inputs, nil-guard the service, invoke,
   map the error through `writeKeyError`, encode. They differ only in the
   request/response types, the default algorithm, and which fields are base64.
3. **The soft-delete triple** (`soft_delete.go`). Secrets, keys and
   certificates each get a list, a recover and a purge handler written out
   longhand — nine handlers, three shapes.
4. **21 untyped `map[string]any` response bodies.** These carry no compile-time
   contract and are invisible to `openapi_drift_test.go`, which can only see
   registered routes and typed shapes.

The six `c.xSvc()` accessors in `context.go:231-277` are six copies of the same
six lines, and `ApiHandler`/`ApiSessionRequired` duplicate ~40 lines of Context
construction, logging and error writing.

## Non-goals

Deliberately out of scope. Each of these is load-bearing and pinned by tests;
changing them is a different piece of work.

- **Route paths and registration.** Pinned by `route_contract_test.go`,
  `openapi_drift_test.go` and `router_authorization_matrix_test.go`.
- **Middleware ordering in `api.go`.** `VaultRateLimitMiddleware` must stay
  after `VaultResolutionMiddleware` — the target vault is not known before it.
- **Any authorization decision.** `scopeFromRequest` remains the only scope
  constructor on the data plane. That is load-bearing: pentest finding B11
  found flat routes yielding an owner scope, which let a caller authorized
  against the default vault reach resources in any other vault.
- **`//nolint:errcheck,gosec` semantics.** Centralized into helpers, not dropped.
- **`ApiHandler` / `ApiSessionRequired` consolidation.** Tempting, but these
  two wrap every route in the package; merging them is its own risk budget.

## Regression strategy

This is the part that makes everything else safe.

The suite is 21,976 lines of tests over 97 handlers at **86.0% statement
coverage**, plus three structural contract tests. Baseline on `4dc0285`, in
the worktree, all green:

```
go build ./...                       # exit 0
go vet ./api/...                     # exit 0
go test ./api/... -count=1 -cover    # ok, 86.0% of statements
```

**Plans 02 through 08 must not modify a single test file.** A mechanical
dedup that is genuinely behavior-preserving leaves every test passing
untouched. Therefore:

> A test that needs editing during plans 02-08 is proof that behavior changed.
> Stop, revert the change, and report — do not adjust the test to fit.

That inverted rule is the whole regression guarantee. It only works because
the tests are frozen, which is why the behavioral fixes are quarantined into
plans 09-11, where test changes are expected and legitimate.

**Verification gate.** Runs after every plan; all four must pass before commit:

```
go build ./...
go vet ./api/...
go test ./... -count=1                 # whole repo — api symbols are used elsewhere
go test ./api/... -count=1 -cover      # must not fall below 86.0%
```

## The primitives

Seven. Only #6 and #7 are heavily generic; the rest are thin wrappers whose
value is the site count they collapse.

### 1. `respond.go` — response writing

```go
func writeJSON[T any](w http.ResponseWriter, v T)
func writeJSONStatus[T any](w http.ResponseWriter, status int, v T)
```

Sets `Content-Type`, encodes, carries the single `//nolint:errcheck,gosec`.
Collapses 78 sites. `writeJSONStatus` exists because a handful of handlers
write 201 or 202 before encoding.

### 2-4. `request.go` — request parsing

```go
func decodeBody[T any](c *Context, r *http.Request) (T, bool)
func resourceID(c *Context, raw, param string) (uuid.UUID, bool)
func b64Field(c *Context, value, name string) ([]byte, bool)
```

`decodeBody` sets `SetInvalidParam("request body")` and returns false on a
decode failure, matching what all 20 current sites do. `resourceID` takes the
raw string and the parameter name so the error message stays exactly what each
site produces today (`"key_id"`, `"secret_id"`, ...). `b64Field` produces
`"<name>: must be valid base64"`, matching the 8 existing messages verbatim.

`resourceID` is deliberately not generic over the parsed type — UUID is the
only type any of the 51 sites parses, and a `parseParam[T]` would be
speculative generality.

### 5. `context.go` — generic service accessor

```go
func svc[T any](c *Context, get func(container.ServiceContainerInterface) T) (T, bool)
```

`App.ServiceContainer` is already `container.ServiceContainerInterface`
(`app/app.go:44`), so a getter function parameterizes cleanly. Replaces six
identical accessors and forces the 31 call sites into a checked
`(value, ok)` form instead of a nil comparison that is easy to omit.

The existing accessors set `SetInternalError(nil)` and return nil on a missing
container; the generic version preserves that exactly — same error, same
status — and only changes the call shape.

### 6. `keys_crypto.go` — the crypto-operation runner

The highest-value piece. A declarative spec per operation:

```go
type cryptoOp[Req any, Res any] struct {
    DefaultAlgorithm string
    Required         func(req Req) string   // "" when satisfied, else the message
    Invoke           func(ctx context.Context, svc keyservices.CryptoService,
                          keyID uuid.UUID, scope model.Scope, req Req) (Res, error)
}

func (op cryptoOp[Req, Res]) handler() func(*Context, http.ResponseWriter, *http.Request)
```

Six ~55-line handlers become six short specs plus one shared spine. Base64
decoding stays inside each `Invoke` (the fields differ per operation and
`decryptKey`'s nonce is conditional), which keeps the generic parameters at
two rather than four.

`verifyKey` is the one operation with no default algorithm and two required
fields; `Required` returning a message string rather than a bool is what lets
it keep its exact current error text.

### 7. `soft_delete.go` — the generic triple

```go
type deletedResource[T any] struct {
    Noun     string                     // "secret" / "key" / "certificate"
    ListKey  string                     // "deleted_secrets" / ...
    IDParam  func(*ApiParams) string
    Service  func(*Context) (deletedService[T], bool)
    Item     func(T) any                // per-type response projection
    WriteErr func(*Context, error)
}
```

Three instances replace nine longhand handlers. The per-type response
projections differ (secrets expose `version`, keys expose `type`, certificates
expose neither), so `Item` stays a function rather than being unified — the
response shapes are a wire contract and must not drift.

## Deferred behavioral fixes

Found during review, **not** fixed in the mechanical plans:

- **`getDeletedKey` (`soft_delete.go:169`)** lists every soft-deleted key in
  the vault and linear-scans for one ID. An O(n) full listing to serve a
  single-item GET. Fixed in plan 09.
- **21 `map[string]any` response bodies** → typed structs, bringing them under
  the OpenAPI drift test. Plan 10. This is the one change with real wire risk
  (field ordering, `omitempty` behavior), which is why it is last and alone.
- **`SessionRequired` (`context.go:153`)**, a backward-compat alias with no
  in-package caller found. Removal verified against the whole repo in plan 11.

## Plan chain

Eleven plans, each at most three tasks, each naming its successor so the chain
runs without prompting. Plans live in `docs/superpowers/plans/`.

| Plan | Work | Tests may change |
|---|---|---|
| 01 | Worktree + baseline | no |
| 02 | `respond.go`, adopt 78 sites | no |
| 03 | `request.go`, adopt parse sites | no |
| 04 | Generic `svc[T]`, adopt 31 guards | no |
| 05 | Split `keys.go` (pure file move) | no |
| 06 | `cryptoOp[Req,Res]` sextet | no |
| 07 | `deletedResource[T]` triple | no |
| 08 | Shared error-mapper case table | no |
| 09 | Fix `getDeletedKey` O(n) scan | **yes** |
| 10 | Typed responses for 21 map bodies | **yes** |
| 11 | Dead-alias removal, final verification, docs | **yes** |

Plans 05 and 06 are separate on purpose: a file split makes a noisy diff even
when no symbol changes package, and mixing it with the `cryptoOp` rewrite
would bury the one diff that most needs careful reading.

## Success criteria

- `go build ./...`, `go vet ./api/...` and `go test ./... -count=1` green after
  every plan.
- `api/` statement coverage at or above 86.0% throughout.
- Zero test-file modifications across plans 02-08.
- Net reduction in `api/` non-test lines, with no file over ~600 lines.
