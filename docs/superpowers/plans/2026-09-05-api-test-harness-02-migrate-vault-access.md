# Migrate vault-access Tests onto the Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert `cmd/vault-access`'s three remote-adapter tests off their hand-written `httptest` handlers and onto `internal/apitest`, so they assert against JSON the production handler marshalled.

**Architecture:** Each test's server-construction block is replaced by one `apitest.New` call; the `runXRemote` call sites and the existing assertions are unchanged. The hand-written handlers — and with them every hand-typed field name — are deleted.

**Tech Stack:** Go 1.24, testify (mock + require + assert), `internal/apitest`.

**Spec:** `docs/superpowers/specs/2026-09-05-in-process-api-test-harness-design.md`

**Depends on:** `2026-09-05-api-test-harness-01-core.md` — `apitest.New`, `Options`, `(*Server).Client()`, `(*Server).Target()` and `Options.DenyAccessPolicy` must all exist.

> **Corrected 2026-09-05, after plan 01 shipped.** This plan originally used
> `Options.DenyDataAction: model.ActionRoleAssignmentsWrite` for the
> forbidden-path test. That cannot work and was proven not to: role-assignment
> routes are `RouteUnmanaged`, so `PolicyMiddleware` never consults
> `HasDataAction`, and `CanManageRoleAssignments` short-circuits to allow for
> the global-admin caller the harness stubs
> (`internal/services/authorization/vault_authz.go:67-69`). The request reaches
> the handler and panics on an unregistered `AssignRole` instead of returning
> 403. Plan 01's fix wave added `Options.DenyAccessPolicy`, which denies at
> `(vaults, manage)` — the policy those routes actually resolve to — producing
> a genuine 403 from `PolicyMiddleware` before any handler runs. Use it.
> `DenyDataAction` remains correct for `RouteVaultData` routes (secrets, keys,
> certificates data-plane), which is what plan 04's groups will need.

## Global Constraints

- Adapter behaviour must not change. This plan touches `_test.go` files only; if a change here appears to require editing `grant.go`, `list.go` or `revoke.go`, stop — that is a real defect the old tests were hiding, and it deserves its own fix and its own commit.
- Existing assertions are preserved. The point is to change what produces the response, not what the test checks.
- No hand-written response JSON may remain in `cmd/vault-access`. That pattern is the defect this work exists to remove.
- All commits are GPG-signed (`git commit -S`). The repo requires it.
- Run `go build ./...`, `go test ./cmd/vault-access/...` and `golangci-lint run ./cmd/vault-access/` before every commit.

---

### Task 1: Migrate the grant tests

**Files:**
- Modify: `cmd/vault-access/grant_remote_test.go`

**Interfaces:**
- Consumes: `apitest.New`, `Options{RoleAssignments, DenyAccessPolicy}`, `(*Server).Client()`, `(*Server).Target()`, and `(*Server).TestContext()` from plan 01.
- Produces: nothing importable. `remoteTestCmd` (already in this file) survives unchanged and is still shared by Task 2's files.

- [ ] **Step 1: Replace the happy-path test's server**

In `TestGrantRemote_PostsToTheVaultScopedRoute`, delete the
`httptest.NewServer(...)` block and the `gotPath`/`gotAuth`/`gotBody`
captures, and drive the harness instead. Path and auth assertions move to the
harness's own tests (plan 01 Tasks 1 and 2 cover them once, for every group,
rather than per test):

```go
func TestGrantRemote_PostsToTheVaultScopedRoute(t *testing.T) {
	created := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Administrator",
	}

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).Return(created, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, out := remoteTestCmd(t, "payments")

	err := runGrantRemote(cmd, srv.Client(), srv.Target(),
		"alice", "Key Vault Administrator", "user")
	require.NoError(t, err)

	assert.Contains(t, out.String(), "granted Key Vault Administrator to alice")
	assert.Contains(t, out.String(), created.ID.String(),
		"the assignment id must come back through the real response shape")
}
```

The last assertion is the one that earns the migration: `created.ID` reaches
stdout only if the handler marshalled it into `id` and
`cliclient.RoleAssignmentFromAPI` read it back out.

- [ ] **Step 2: Replace the forbidden test's server**

`TestGrantRemote_ForbiddenIsReadable` currently asserts against a
hand-written `w.WriteHeader(http.StatusForbidden)`. Point it at a genuine
denial:

```go
func TestGrantRemote_ForbiddenIsReadable(t *testing.T) {
	roleSvc := &testutils.MockRoleAssignmentService{}

	srv := apitest.New(t, apitest.Options{
		RoleAssignments:  roleSvc,
		DenyAccessPolicy: true,
	})

	cmd, _ := remoteTestCmd(t, "payments")

	err := runGrantRemote(cmd, srv.Client(), srv.Target(),
		"alice", "Key Vault Administrator", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}
```

- [ ] **Step 3: Fix the imports**

Remove now-unused imports: `encoding/json`, `net/http`, `net/http/httptest`,
and `context` if nothing else in the file uses it. Add:

```go
	"rocketvault/cmd/testutils"
	"rocketvault/internal/apitest"
	"rocketvault/model"
```

`staticToken` and `remoteTestClient` in this file become dead once Task 2 also
stops using them — leave both in place until Task 3 removes them, or the other
two test files stop compiling.

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/vault-access/ -run TestGrantRemote -v`
Expected: PASS, both.

If `AssignRole` panics on an unregistered call, the handler is passing an
`AssignRoleInput` the `mock.Anything` matcher should already accept — check
the mock is registered on the *same* instance passed to `apitest.Options`.

- [ ] **Step 5: Commit**

```bash
go build ./... && go test ./cmd/vault-access/... && golangci-lint run ./cmd/vault-access/
git add cmd/vault-access/grant_remote_test.go
git commit -S -m "test(vault-access): drive the grant tests through the real API

The hand-written handler returned JSON this test typed, so a rename on
model.RoleAssignmentResponse would have left it green. It now asserts
against a response the production handler marshalled, and the forbidden
case exercises a real authorization denial rather than a hand-written
403."
```

---

### Task 2: Migrate the list and revoke tests

**Files:**
- Modify: `cmd/vault-access/list_remote_test.go`
- Modify: `cmd/vault-access/revoke_remote_test.go`

**Interfaces:**
- Consumes: the same `apitest` surface as Task 1.
- Produces: nothing importable.

- [ ] **Step 1: Migrate the list test**

Replace `TestListRemote_PrintsSameColumnsAsLocal`'s server block. The column
assertions are unchanged — they are what pins remote output to local output:

```go
func TestListRemote_PrintsSameColumnsAsLocal(t *testing.T) {
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Administrator",
	}

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{assignment}, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, out := remoteTestCmd(t, "payments")
	require.NoError(t, runListRemote(cmd, srv.Client(), srv.Target()))

	got := out.String()
	assert.Contains(t, got, "ASSIGNMENT-ID")
	assert.Contains(t, got, "ROLE")
	assert.Contains(t, got, "PRINCIPAL-ID")
	assert.Contains(t, got, assignment.ID.String())
	assert.Contains(t, got, "Key Vault Administrator")
}
```

Imports: drop `encoding/json`, `net/http`, `net/http/httptest`; add
`rocketvault/cmd/testutils`, `rocketvault/internal/apitest`,
`rocketvault/model`, and `github.com/stretchr/testify/mock`.

- [ ] **Step 2: Migrate the revoke tests**

`TestRevokeRemote_DeletesByAssignmentID` loses its path/method capture — the
harness proves the route exists by serving it, and plan 01's tests cover the
path shape:

```go
func TestRevokeRemote_DeletesByAssignmentID(t *testing.T) {
	id := uuid.New()

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("RevokeAssignment", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, out := remoteTestCmd(t, "payments")
	require.NoError(t, runRevokeRemote(cmd, srv.Client(), srv.Target(), id.String()))
	assert.Contains(t, out.String(), "revoked assignment "+id.String())
}
```

`TestRevokeRemote_RejectsPrincipalName` asserts that a non-UUID argument is
rejected *before* any request is made. Its hand-written handler existed only
to fail the test if a request arrived. Keep that guarantee by giving the
harness a role service with **no** `RevokeAssignment` expectation — an
unregistered testify call panics, so a request that should never happen fails
loudly:

```go
func TestRevokeRemote_RejectsPrincipalName(t *testing.T) {
	// No RevokeAssignment expectation: if a request reaches the handler, the
	// mock panics on the unregistered call rather than passing silently.
	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, _ := remoteTestCmd(t, "payments")

	err := runRevokeRemote(cmd, srv.Client(), srv.Target(), "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assignment id")
}
```

- [ ] **Step 2b: Run both files' tests**

Run: `go test ./cmd/vault-access/ -run "TestListRemote|TestRevokeRemote" -v`
Expected: PASS, all three.

- [ ] **Step 3: Commit**

```bash
go build ./... && go test ./cmd/vault-access/... && golangci-lint run ./cmd/vault-access/
git add cmd/vault-access/list_remote_test.go cmd/vault-access/revoke_remote_test.go
git commit -S -m "test(vault-access): drive list and revoke through the real API

Both lose their hand-written handlers. The list test's column assertions
now run against a response the production handler marshalled, and the
non-UUID revoke case keeps its no-request guarantee through an
unregistered mock call rather than a handler that fails the test."
```

---

### Task 3: Remove the dead scaffolding and record completion

**Files:**
- Modify: `cmd/vault-access/grant_remote_test.go`
- Modify: `docs/superpowers/plans/2026-09-03-cli-remote-vaultapi-03b-vault-access-adapter.md`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing importable.

- [ ] **Step 1: Delete the now-unused helpers**

`staticToken` and `remoteTestClient` in `grant_remote_test.go` exist only to
build a client against a hand-written server. Nothing uses them once Tasks 1
and 2 land — `apitest` builds the client now.

Confirm before deleting:

Run: `grep -rn "staticToken\|remoteTestClient" cmd/vault-access/`
Expected: hits only inside `grant_remote_test.go`'s own declarations.

Delete both, and drop `rocketvault/internal/vaultapi` from the file's imports
if nothing else references it.

- [ ] **Step 2: Prove no hand-written response JSON survives**

Run: `grep -rn "httptest.NewServer" cmd/vault-access/`
Expected: **no results.** Every server in this package is now the real one.

Run: `go test ./cmd/vault-access/... -v`
Expected: PASS, all 15 tests — the 5 remote ones plus the 10 pre-existing
local ones, which this plan never touched.

- [ ] **Step 3: Record completion on plan 03b**

03b's Post-Execution Review closes by saying the response-shape gap should be
sequenced before plan 04. Append to that section so a later reader knows it
was:

```markdown
**Closed 2026-09-05.** The harness landed as `internal/apitest`
(`docs/superpowers/specs/2026-09-05-in-process-api-test-harness-design.md`,
plans `2026-09-05-api-test-harness-01-core.md` and `-02-migrate-vault-access.md`),
and `vault-access`'s three remote tests were migrated onto it. Plan 04 should
use `apitest.New` from the start for `keys`, adding an `Options` field for the
key service rather than hand-writing a handler.
```

- [ ] **Step 4: Commit**

```bash
go build ./... && go test ./... && golangci-lint run ./cmd/vault-access/
git add cmd/vault-access/grant_remote_test.go docs/superpowers/plans/2026-09-03-cli-remote-vaultapi-03b-vault-access-adapter.md
git commit -S -m "test(vault-access): drop the hand-written server scaffolding

staticToken and remoteTestClient existed only to build a client against a
hand-written handler; apitest builds both now. No httptest.NewServer
remains in the package.

Records on 03b that the response-shape gap it flagged is closed, so plan
04 starts from the harness rather than repeating the pattern."
```

---

## Self-Review

**Spec coverage:** this plan is spec §7 step 2. §4 ("what tests look like
after") is realised in Tasks 1 and 2. The spec's claim that migration is "a
swap of the server-construction block, not a rewrite" is what Task 1 Step 1
and Task 2 Step 1 demonstrate — the `runXRemote` call sites and assertions are
unchanged.

**Placeholder scan:** no TBDs. Every step carries the code it needs in final
form. Task 1 Step 4 and Task 3 Steps 1–2 give exact commands with expected
output rather than "verify it works".

**Type consistency:** `apitest.Options{RoleAssignments: roleSvc}` takes
`authzServices.RoleAssignmentService`, satisfied by
`*testutils.MockRoleAssignmentService`. `srv.Client()` returns
`*vaultapi.Client` and `srv.Target()` returns `*cliclient.Target`, matching
the second and third parameters of all three `runXRemote` functions as merged
in `661a4d6`. `Options.DenyAccessPolicy` is a `bool`; the grant route resolves
to the `(vaults, manage)` policy, which is what that flag denies — see the
correction note at the top of this plan for why `DenyDataAction` does not work
here.

**Coverage deliberately relocated, not lost:** the old tests asserted the
request path, HTTP method and `Authorization` header per test. Those move to
plan 01's harness tests, where they are asserted once for every group rather
than re-typed per command. What each adapter test keeps is what is specific to
it: the vault-scoped route being reachable, the output text, and the error
mapping.

**Known risk:** `TestRevokeRemote_RejectsPrincipalName` now depends on a
testify panic as its failure mode for "no request should have been made". That
is a blunter signal than the old `t.Error` inside a handler — it fails the
test, but the message names an unregistered mock call rather than the intent.
The comment in the test body carries the intent; if this proves confusing in
practice, an explicit request-counting `http.RoundTripper` on the harness
client would be the cleaner replacement.
