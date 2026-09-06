# `api/` Generic-Primitive Refactor — Outcome

**Branch:** `refactor/api-generics`, based on `v-4.0.0` @ `4dc0285`
**Spec:** `2026-09-06-api-generic-primitives-design.md`
**Plans:** 01-11, all committed. 20 commits, `9ce5f8c..83d7c83`.

## What changed

### The headline number went the wrong way

The spec listed "net reduction in non-test lines" as a success criterion.
**It is not met.** Non-test `api/` lines went **up**:

| | baseline `4dc0285` | now | delta |
|---|---|---|---|
| non-test lines in `api/` | 7214 | **7320** | **+106 (+1.5%)** |
| non-test files in `api/` | 29 | 37 | +8 |

Two causes, both understood and neither a surprise in hindsight:

1. **The two file splits.** Plan 05 split `keys.go` into four files and plan 08
   split `secrets.go` into three. Each new file carries the 21-line MIT
   copyright header and its own import block. Eight new files is roughly 170
   lines of pure header and import overhead before a single statement moves.
2. **The generic abstractions cost about what the duplication did.** A
   `cryptoOp` value with its `Required`, `Decode` and `Invoke` closures is not
   much shorter than the handler it replaces, and the spine plus its doc
   comments must be paid for once. Measured directly: plan 06 (six crypto
   handlers into one spine) saved **2 lines**. Plan 07 (nine soft-delete
   handlers into three descriptions) saved **38 lines**.

Line count was the wrong success criterion to have chosen. It measures volume,
and this refactor was not about volume.

### The real win: untested code

| | baseline | now | delta |
|---|---|---|---|
| uncovered statements in `api/` | 406 | **353** | **-53 (-13.1%)** |

353 uncovered of 2624 total statements; **86.5% coverage**. This is the metric
the gate (`scripts/verify-api-refactor.sh`) enforces, and it is an absolute
count rather than a ratio precisely so it cannot be gamed by adding statements.

13% less untested code in the package that terminates every authenticated
request is worth more than 106 lines of copyright header.

### Duplicated logic eliminated

This is what the line count fails to show. In every row, the "before" column is
the same logic written out N times:

| Logic | Before | After |
|---|---|---|
| JSON response writing | 78 sites | 1 helper pair (`writeJSON` / `writeJSONStatus`) |
| Request parsing | 79 sites | 3 helpers (`decodeBody`, `resourceID`, `b64Field`) |
| Service accessors | 6 copies + 57 call sites | 1 generic (`svc[T]`) |
| The ten-step crypto order | 6 copies | 1 spine (`cryptoOp`) |
| Soft-delete handlers | 9 handlers | 3 descriptions (`deletedResource[T]`) |

Raw idiom counts, baseline to now:

| idiom | baseline | now |
|---|---|---|
| `json.NewEncoder(w).Encode` | 78 | 3 |
| `json.NewDecoder(r.Body).Decode` | 20 | 6 |
| `uuid.Parse(c.Params...)` | 51 | **0** |
| `map[string]any{` response bodies | 21 | 11 |

The crypto step order in particular is behavior, not style: it decides which
error a malformed request receives. It is now written once instead of six
times, so the six cannot drift apart.

### File sizes

| | baseline | now |
|---|---|---|
| largest non-test file | **1193** (`keys.go`) | **571** (`users.go`) |
| files over 600 lines | 2 (`keys.go` 1193, `secrets.go` 748) | **0** |

Current top five: `users.go` 571, `keys.go` 523, `secrets.go` 501,
`soft_delete.go` 418, `certificates.go` 391.

### The test suite was a valid oracle

`git diff --name-only 4dc0285 a1db355 -- 'api/*_test.go'` is **empty**: zero
`api/*_test.go` files were modified across plans 02-08. That is what makes the
suite an independent oracle for that phase rather than a description of its own
result — the tests that passed before the mechanical refactors are the
identical bytes that passed after them.

Test files were touched only in plan 10 (`4be3685`, `80d91c3`), which added
`api/response_shape_test.go` and tightened one assertion in `api/config_test.go`.
Both were written and run green against the **map** bodies first, then run green
again against the structs, so they too are oracles rather than post-hoc
descriptions.

## Primitives added

Eight, not the seven the spec projected — `request.go` needed three helpers
rather than two, because base64 field decoding and path-id parsing do not
share a shape.

| Primitive | File | What it absorbs |
|---|---|---|
| `writeJSON[T]` | `api/respond.go` | header set, encode, `//nolint:errcheck` |
| `writeJSONStatus[T]` | `api/respond.go` | the same, with an explicit status code |
| `decodeBody[T]` | `api/request.go` | body decode plus the 400 on malformed JSON |
| `resourceID` | `api/request.go` | `uuid.Parse` on a path param plus its 400 |
| `b64Field` | `api/request.go` | base64 decode of a named field plus its 400 |
| `svc[T]` | `api/context.go` | nil-App / nil-container guard and service lookup |
| `cryptoOp[Req, In, Res]` | `api/keys_crypto.go` | the ten-step crypto handler order |
| `deletedResource[T]` | `api/soft_delete.go` | list / recover / purge for the three resources |

`deletedOps[T]` (`api/soft_delete.go`) is the per-resource operation set
`deletedResource[T]` is configured with, not a primitive in its own right.

## Behavior changes

**None.** No plan in the chain changed observable behavior.

The spec anticipated that plans 09-11 would change behavior deliberately, and
they did not. Recording what actually happened:

- **Plan 09** was to fix `getDeletedKey`'s full-vault scan. It did not. The
  `KeyService` interface fan-out measured seven files against the plan's
  five-file bar, so the gate held and the finding was filed as **B61**
  (`31485e0`, renumbered from a colliding B39 in `e5b2a33`) instead of fixed.
  Docs-only commits.
- **Plan 10** typed five response bodies and asserted each is **byte-identical**
  to the map it replaced — field order matches the map's sorted key order and
  nothing is `omitempty`. `deleted_at` in particular still emits `null` rather
  than disappearing.
- **Plan 11** made the `cryptoOp` spine tolerate a nil `Required` or `Decode`
  (`9a5c4c0`). All six existing specs set both fields, so nothing changes
  today; it closes a footgun where a future seventh spec omitting either would
  compile and then panic at request time, turning every request to that route
  into a 500.

Two structural changes in plan 11 that touch no behavior:

- **`AuditLog` moved to `model/`** (`e54de6f`). Plan 10's typed audit envelope
  made `api/` import `internal/repositories` in production code for the first
  time, crossing a boundary commit `18e9f4f` deliberately established when it
  moved the filter types into `model/` and left aliases behind. `AuditLog` had
  been missed by that move. It now lives in `model/audit.go` with
  `type AuditLog = model.AuditLog` left in `internal/repositories`, so every
  existing consumer compiles unchanged. Field order and the absent json tags are
  byte-identical, so the response shape does not move. `api/` non-test files now
  name no repository type at all.
- **A false claim was corrected in the spec** (`83d7c83`). The spec asserted
  that untyped map bodies were "invisible to `openapi_drift_test.go`" and that
  typing them would bring them under it. That is wrong in both directions:
  `openapi_drift_test.go` unmarshals only `paths` and their method keys from
  `docs/api-specification.yaml` and never reads a response schema, so it sees no
  response body of any kind, typed or untyped. The real benefit of typing them
  is a compile-time contract plus the byte assertions in the new
  `api/response_shape_test.go`.

## Found but not fixed

- **B61 — `getDeletedKey` lists an entire vault to serve one id**
  (`.claude/known-bugs.md`). `api/soft_delete.go`'s `getDeletedKey` calls
  `ListDeletedKeys` for the whole vault and linear-scans for one id: O(n) for a
  single-item GET. **Performance only** — no correctness or authorization
  defect. Rejected by plan 09's fan-out gate at seven files against a five-file
  bar; four of the seven are hand-rolled test doubles that must each be edited
  by hand. The entry carries the measured fan-out for whoever picks it up.

- **B62 — `KeyRepository.ReadDeleted` takes no `model.Scope`** (filed by this
  plan). Scope is the authorization predicate everywhere else in this codebase
  and every sibling read takes one, so this method returns any key in any vault
  to any caller holding its id. The audit B61 asked for is now done: there is
  exactly one production caller, `keyService.DeleteKey`, and it is **safe** —
  it performs the scoped `keyRepo.Read(ctx, keyID, scope)` first and returns
  `ErrKeyNotFound` if that fails, then calls `ReadDeleted` on the same
  already-authorized id purely to re-read post-delete metadata. Latent, not
  live. It matters because B61's own fix recipe invites a second caller:
  anyone implementing a scoped by-id read who reaches for the existing
  `ReadDeleted` instead of adding `ReadDeletedScoped` turns this into a live
  cross-vault read on a GET handler. Fix the two together — they need the same
  new repository method.

- **Six response bodies still `map[string]any`, deferred by plan 10.** Each was
  deferred because **no test asserts its shape**, and converting one blind is
  precisely how a client breaks silently (a struct encodes in declaration order
  and honours `omitempty`; a map encodes sorted and always emits every key):
  - `soft_delete.go` `getDeletedKey` — the obvious conversion is to reuse
    `deletedKeyItem`, but that type's fields are not in alphabetical order
    (`id, name, type, deleted_at, purge_protection`) while the map sorts to
    `deleted_at, id, name, purge_protection, type`. The two representations of
    the same resource already disagree on byte order today, which is arguably
    the real defect. Reconciling them is a wire change needing its own decision.
  - `access_policies.go` `listAccessPolicies` and `listPoliciesByPrincipal` —
    trap: `model.ListAccessPoliciesResponse` already has the right key names but
    its items are `[]AccessPolicyResponse`, while these handlers write
    `[]*model.AccessPolicy`. Reusing it changes the item shape, not just the
    envelope.
  - `oauth2.go` `createServiceAccount` — carries `client_secret`, returned
    exactly once. A wrong `omitempty` loses the only copy of a credential.
  - `oauth2.go` `listServiceAccounts` and `users.go` `listSessions` — no test
    asserts either body and no other package consumes either envelope.

- **Pre-existing and unrelated to this branch:** a repo commit hook reports
  `docs/usage-guide.md` stale in 8 sections (`cli-human-driven`,
  `rest-api-programmatic`, `oauth2-service-accounts`, `jwks-endpoint`,
  `backup-restore-tooling`, `health-monitoring`, `hsm-pkcs11-section`,
  `deployment`). It fires on every commit on this branch and predates it.
  Refresh via the `usage-guide-refresh` skill; out of scope here.

## Remaining work

- **Five response bodies deliberately kept as maps**, and they should stay maps:
  the shared error envelope (`context.go` `writeError` and the two inline auth
  failures in `ApiSessionRequired`, plus `api.go` `Handle404`) is already pinned
  by every error assertion in the suite, so a struct adds no contract and would
  touch the whole suite; and `jwks.go` `buildJWKSet` builds an RFC 7517 JWK Set
  whose member key set varies by key type and whose `map[string]any` return is
  itself type-asserted by `api/jwks_test.go`.
- **`ApiHandler` / `ApiSessionRequired` consolidation** — a spec non-goal, still
  open. They duplicate roughly 40 lines of Context construction, logging and
  error writing, but they wrap every route in the package, so merging them is
  its own risk budget.
- **`SessionRequired` was NOT removed.** Plan 11 Task 1 was to delete it as
  dead. It is not dead: `api/context_test.go` calls `api.SessionRequired(...)`
  at lines 249, 276 and 303. The alias is **intentionally retained**. A wider
  sweep of all 140 unexported and 46 exported non-test `api/` symbols found no
  orphan either, and the five `c.xSvc()` accessors in `context.go` are kept as
  one-line delegations to `svc` because `api/context_accessors_test.go` calls
  them directly. **The cleanup task removed nothing** — a legitimate result, and
  better than inventing a deletion.
- **No file is over 600 lines**, so the size target needs no further work.

## Verification

Run from clean at `83d7c83`:

- `go clean -testcache` then `go build ./...` — OK.
- `go vet ./...` (**whole repo**, not just `api/`) — OK.
- `go test ./... -count=1` — **59 packages ok, zero failures**, no package
  reporting anything but `ok` or `no test files`.
- `go test ./api/... -count=1 -run 'Route|Contract|OpenAPI|Inventory|Authorization' -v`
  — all pass, including `TestOpenAPISpecCoversAllRoutes`,
  `TestGenerateRouteInventory` and `TestAuthorizationMatrixOpsAreRealRoutes`.
  **The route surface did not move.**
- `gofmt -l` clean on all non-test files across `api/`, `internal/`, `cmd/` and
  `model/`. (13 `api/*_test.go` files were already unformatted before this
  branch and are untouched.)
- `./scripts/verify-api-refactor.sh` — `PASS`, run before every commit.
