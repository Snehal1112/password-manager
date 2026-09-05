# CLI Remote Refresh Fix and Route Contract — Implementation Plan

> **Status: COMPLETE (2026-09-04).** Tasks 2 and 3 shipped on `v-4.0.0` in
> commits `ab42b05` / `2b5e1f1` (route-contract test) and `0924ba5` (the refresh
> path fix). Task 1 was **superseded, not skipped** — see its note below.
>
> Verified on 2026-09-04: `go build ./...` clean; `./api/`,
> `./internal/cliclient/` and `./cmd/` all pass; and the contract test was
> confirmed to still bite by temporarily re-adding the wrong
> `POST /api/v1/refresh` entry, which failed as intended before being removed.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the CLI's broken remote session refresh, and add a route-contract test that would have caught it.

**Architecture:** `cliclient.RefreshRemote` posts to `/api/v1/refresh`, which no router registers — the real route is `/api/v1/users/refresh`. Two tests assert the wrong path against `httptest` servers that answer any path, so they pass. This plan adds a test that checks client paths against the server's actual route table, then fixes the path.

**Tech Stack:** Go 1.24, gorilla/mux, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets none of `--server`, `ROCKETVAULT_ADDR`, or a current context.
- A command that resolves a remote target must never silently fall back to operating on the local instance.
- Existing local-mode session cache files must keep working without forcing a re-login.
- All commits are GPG-signed (`git commit -S`). The repo requires it.
- Run `go build ./...` and `golangci-lint run` before every commit.

---

### Task 1: Register the full route table in the test seam — SUPERSEDED, NOT DONE

> **Not implemented, deliberately.** This task assumed a test could not build
> the real route table without a service container. That stopped being true:
> `WalkRoutes` and the `routerWalkContainer` stub landed with the
> route-inventory work (`c3dc191`, `4c1aa69`), so `api/route_contract_test.go`
> walks the router built by the *production* `Init` itself. That is strictly
> stronger than walking a test-only seam, because it cannot drift from `Init`.
> `InitForTest` therefore still registers only `/config` (`api/api.go:177-190`),
> which is correct — no consumer needs more. Its steps are left unticked below
> as a record that they were considered and dropped.

`api.InitForTest` (`api/api.go:177`) wires "a minimal API onto router for unit tests (no middleware, no auth)" but registers only `/config`. Task 2's contract test needs the real route table without the middleware chain, which `api.Init` (`api/api.go:58`) cannot provide because it dereferences `api.App.ServiceContainer` to build middleware.

**Files:**
- Modify: `api/api.go:176-190`
- Test: `api/api_test.go`

**Interfaces:**
- Produces: `api.InitForTest(application *app.App, router *mux.Router) *API` — unchanged signature, now registering every route `Init` registers.

- [ ] **Step 1: Write the failing test**

Add to `api/api_test.go`:

```go
// TestInitForTest_RegistersRoleAssignmentRoutes verifies InitForTest wires the
// full route table, not just /config, so route-contract tests can walk it.
func TestInitForTest_RegistersRoleAssignmentRoutes(t *testing.T) {
	application := &app.App{}
	router := mux.NewRouter()
	api.InitForTest(application, router)

	var found bool
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil // routes without a path template are not our concern
		}
		if strings.Contains(tmpl, "/role-assignments") {
			found = true
		}
		return nil
	})
	require.NoError(t, err)
	assert.True(t, found, "InitForTest must register role-assignment routes")
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./api/ -run TestInitForTest_RegistersRoleAssignmentRoutes -v`
Expected: FAIL — `InitForTest must register role-assignment routes`.

- [ ] **Step 3: Extend InitForTest to register the full table**

In `api/api.go`, replace the body of `InitForTest` after `a.BaseRoutes.ApiRoot` is created. Build the same subrouter tree `Init` builds (`api/api.go:92-125`), then call the same `InitXxx()` registration methods. Keep the existing `/config` registration — `api/api_test.go:53` depends on it.

```go
// InitForTest wires an API onto router for unit tests (no middleware, no
// auth). It registers the same route table Init does, so tests can assert
// which paths exist without constructing a service container.
func InitForTest(application *app.App, router *mux.Router) *API {
	a := &API{
		App:        application,
		BaseRoutes: &Routes{},
		basePath:   authzServices.DataPlaneBasePath,
		rootRouter: router,
	}
	r := a.BaseRoutes
	r.ApiRoot = router.PathPrefix(authzServices.DataPlaneBasePath).Subrouter()

	// Register config handler without auth for testing.
	r.ApiRoot.Handle("/config", ApiHandler(application, getConfig)).Methods("GET")

	a.initRoutes()
	return a
}
```

Extract the subrouter construction and every `a.InitXxx()` call from `Init` into a new unexported `func (a *API) initRoutes()`, and call it from both `Init` and `InitForTest`. This is a pure move: no route may change prefix, method, or handler.

Handler registration must not dereference `application`. `ApiSessionRequired` and `ApiHandler` only wrap — they read `App` when serving, not when registering. If any `InitXxx` panics at registration with a zero `App`, that specific initializer is the bug; fix it there rather than skipping it in the test seam.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./api/ -run TestInitForTest -v`
Expected: PASS, including the pre-existing `TestInitForTest_ConfigRoute_Returns200`.

- [ ] **Step 5: Verify no route changed for the real server**

Run: `go build ./... && go test ./api/...`
Expected: PASS. `Init` and `InitForTest` now share one registration path, so a diff in behaviour would surface here.

- [ ] **Step 6: Commit**

```bash
git add api/api.go api/api_test.go
git commit -S -m "test(api): register the full route table in InitForTest

InitForTest wired only /config, so a test could not ask which paths the
server actually serves. Route registration moves to a shared initRoutes
method that both Init and InitForTest call, leaving the middleware chain
to Init alone."
```

---

### Task 2: Route-contract test for client-called paths

**Files:**
- Create: `api/route_contract_test.go`
- Test: same file

**Interfaces:**
- Consumes: `api.InitForTest` from Task 1.
- Produces: nothing importable — this is a test-only guard.

- [x] **Step 1: Write the failing test**

Create `api/route_contract_test.go`:

```go
package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/api"
	"rocketvault/app"
)

// clientPath is one path a Go client in this repo calls, with the source that
// calls it. Every entry must be registered by the server; a client calling an
// unregistered path gets a 404 that no mock-based test can catch, because a
// mock answers whatever path it is asked for.
//
// This is the guard for the class of defect found on 2026-09-03: cliclient
// posted refresh to /api/v1/refresh while the route lives at
// /api/v1/users/refresh, and two tests asserted the wrong path against
// permissive httptest servers.
type clientPath struct {
	method string
	path   string
	caller string
}

func clientPaths() []clientPath {
	return []clientPath{
		{http.MethodPost, "/api/v1/users/login", "cliclient.LoginRemote, vaultapi.Login"},
		{http.MethodPost, "/api/v1/users/refresh", "cliclient.RefreshRemote, vaultapi.SessionSource.refresh"},
		{http.MethodPost, "/api/v1/oauth2/token", "vaultapi.ServiceAccountSource"},
		{http.MethodGet, "/api/v1/vaults/{vault_name}/role-assignments", "vaultapi.ListRoleAssignments"},
		{http.MethodPost, "/api/v1/vaults/{vault_name}/role-assignments", "vaultapi.CreateRoleAssignment"},
		{http.MethodDelete, "/api/v1/vaults/{vault_name}/role-assignments/{assignment_id}", "vaultapi.DeleteRoleAssignment"},
	}
}

// registeredPaths returns every path template the server registers, with the
// methods allowed on it.
func registeredPaths(t *testing.T) map[string]map[string]bool {
	t.Helper()

	router := mux.NewRouter()
	api.InitForTest(&app.App{}, router)

	out := map[string]map[string]bool{}
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			// A route with no explicit method matches any method.
			methods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}
		}
		if out[tmpl] == nil {
			out[tmpl] = map[string]bool{}
		}
		for _, m := range methods {
			out[tmpl][m] = true
		}
		return nil
	})
	require.NoError(t, err)
	return out
}

// stripConstraints removes mux regex constraints from a path template so a
// client's literal "{assignment_id}" matches the server's
// "{assignment_id:[A-Fa-f0-9-]+}".
func stripConstraints(tmpl string) string {
	var b strings.Builder
	inVar, seenColon := false, false
	for _, r := range tmpl {
		switch {
		case r == '{':
			inVar, seenColon = true, false
			b.WriteRune(r)
		case r == '}':
			inVar, seenColon = false, false
			b.WriteRune(r)
		case inVar && r == ':':
			seenColon = true
		case inVar && seenColon:
			// drop constraint characters
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestClientPathsAreRegistered(t *testing.T) {
	registered := registeredPaths(t)

	normalized := map[string]map[string]bool{}
	for tmpl, methods := range registered {
		normalized[stripConstraints(tmpl)] = methods
	}

	for _, cp := range clientPaths() {
		t.Run(cp.method+" "+cp.path, func(t *testing.T) {
			methods, ok := normalized[cp.path]
			require.Truef(t, ok,
				"%s calls %s %s but the server registers no such path",
				cp.caller, cp.method, cp.path)
			assert.Truef(t, methods[cp.method],
				"%s calls %s %s but the server registers that path without %s",
				cp.caller, cp.method, cp.path, cp.method)
		})
	}
}
```

- [x] **Step 2: Run it to verify the harness works**

Run: `go test ./api/ -run TestClientPathsAreRegistered -v`
Expected: PASS for all six entries. The list above already names the *correct* refresh path, so this test is green before the fix — it proves the harness works.

- [x] **Step 3: Add the entry that fails**

Temporarily add the path `cliclient` actually calls today, to prove the test catches it:

```go
{http.MethodPost, "/api/v1/refresh", "cliclient.RefreshRemote (WRONG PATH — proves the test bites)"},
```

- [x] **Step 4: Run it to verify it fails**

Run: `go test ./api/ -run TestClientPathsAreRegistered -v`
Expected: FAIL — `cliclient.RefreshRemote (WRONG PATH ...) calls POST /api/v1/refresh but the server registers no such path`.

- [x] **Step 5: Remove the temporary entry**

Delete the line added in Step 3. The test returns to green and now guards the real contract.

- [x] **Step 6: Commit**

```bash
git add api/route_contract_test.go
git commit -S -m "test(api): assert client-called paths are registered routes

A client calling an unregistered path gets a 404 that mock-based tests
cannot catch, because a mock answers whatever path it is asked for. This
walks the real route table and checks the paths cliclient and vaultapi
call against it."
```

---

### Task 3: Fix the refresh path and the two tests that hid it

**Files:**
- Modify: `internal/cliclient/auth.go:59-67`
- Modify: `internal/cliclient/auth_test.go:65`
- Modify: `cmd/root_test.go:692`

**Interfaces:**
- Consumes: nothing new.
- Produces: `cliclient.RefreshRemote` unchanged in signature, corrected in path.

- [x] **Step 1: Correct the two path assertions to the real route**

In `internal/cliclient/auth_test.go:65` and `cmd/root_test.go:692`, change:

```go
require.Equal(t, "/api/v1/refresh", r.URL.Path)
```

to:

```go
require.Equal(t, "/api/v1/users/refresh", r.URL.Path)
```

- [x] **Step 2: Run them to verify they fail**

Run: `go test ./internal/cliclient/ -run TestRefreshRemote_Success -v && go test ./cmd/ -run TestResolveRemoteAuthentication_ExpiredCache_RefreshesTransparently -v`
Expected: both FAIL — the client still posts to `/api/v1/refresh`, so the assertion sees the old path.

- [x] **Step 3: Fix the client**

In `internal/cliclient/auth.go`, line 67:

```go
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/users/refresh", bytes.NewReader(body))
```

And correct the doc comment on line 60:

```go
// RefreshRemote exchanges a refresh token for a new access token against
// target's POST /api/v1/users/refresh. The route is registered on the users
// subrouter (api/users.go), not at the API root.
```

- [x] **Step 4: Run them to verify they pass**

Run: `go test ./internal/cliclient/... ./cmd/... ./api/...`
Expected: PASS.

- [x] **Step 5: Verify against a real server** *(done when the fix shipped in `0924ba5`; not re-run during the 2026-09-04 status pass, which covered the automated tests only)*

```bash
go build -o rocketvault . && ./rocketvault serve &
# In another shell, with a context pointing at that server:
./rocketvault users login --username admin --password <pw> --totp-code <code>
# Force the cached session to look expired, then run a remote secrets command
# and confirm it refreshes rather than demanding credentials.
./rocketvault secrets list
```

Expected: the command succeeds without re-prompting for credentials. Before this fix it failed with `cached session expired and refresh failed`.

- [x] **Step 6: Commit**

```bash
git add internal/cliclient/auth.go internal/cliclient/auth_test.go cmd/root_test.go
git commit -S -m "fix(cli): post remote refresh to the route that exists

RefreshRemote posted to /api/v1/refresh, which no router registers --
refreshToken is on the users subrouter, so the path is
/api/v1/users/refresh. Every expired remote session therefore failed to
refresh and demanded full credentials.

Two tests asserted the wrong path against httptest servers that answer
any path, so both passed while the feature could not work. They now
assert the real route."
```

---

## Self-Review

**Spec coverage:** This plan implements spec phase 0 — the refresh fix, the two test corrections, and the route-contract test — plus the `InitForTest` change that phase 0 needs. Nothing else in the spec is in scope here.

**Placeholder scan:** No TBDs. Every code step carries the code it needs, in final form.

**Type consistency:** `stripConstraints` is defined once and used once. `clientPath`/`clientPaths`/`registeredPaths` are used only within `route_contract_test.go`. `InitForTest`'s signature is unchanged across Tasks 1 and 2.
