# API Test Harness Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/apitest`, which serves RocketVault's real router, middleware chain and handlers in-process so CLI adapter tests decode JSON marshalled by production code instead of by the test author.

**Architecture:** `api.Init` builds the production router against `cmd/testutils.MockServiceContainer`; `httptest.NewServer` serves it; the harness hands back a `*vaultapi.Client` seeded with a static bearer token. Services are stubbed, so this closes response-shape drift and status handling — not business logic.

**Tech Stack:** Go 1.24, gorilla/mux, testify (mock + require), `net/http/httptest`.

**Spec:** `docs/superpowers/specs/2026-09-05-in-process-api-test-harness-design.md`

**Followed by:** `2026-09-05-api-test-harness-02-migrate-vault-access.md`, which converts the three existing `cmd/vault-access` remote tests onto this harness. A harness with no consumer proves nothing, so run both.

## Global Constraints

- The harness is test-only. Nothing in `internal/apitest` may be imported by non-test production code.
- No import cycle: `internal/apitest` imports `rocketvault/api` and `rocketvault/cmd/testutils`. Neither imports `cmd/vault-access`, and `api` does not import `cmd/testutils`. Do not add an import that breaks this.
- The response JSON must be produced by the production handler. Never hand-write a response body in the harness — that reintroduces the exact gap this exists to close.
- All commits are GPG-signed (`git commit -S`). The repo requires it.
- Run `go build ./...` and `golangci-lint run ./internal/apitest/` before every commit.

---

### Task 1: Serve the real router in-process

**Files:**
- Create: `internal/apitest/apitest.go`
- Test: `internal/apitest/apitest_test.go`

**Interfaces:**
- Produces: `apitest.New(t *testing.T, opts Options) *Server`, `apitest.Options{RoleAssignments authzServices.RoleAssignmentService; DenyDataAction model.DataAction}`, and `(*Server).URL() string`. Tasks 2 and 3 extend `Server`; plan 02 consumes all of it.

- [ ] **Step 1: Write the failing test**

Create `internal/apitest/apitest_test.go`. This is the shape-guard test from
spec §6: it asserts a field that only `model.ListRoleAssignmentsResponse`
supplies, so renaming that JSON tag breaks it.

```go
package apitest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/assert"

	"rocketvault/cmd/testutils"
	"rocketvault/model"
)

// TestNew_ServesTheRealHandler proves the response body is marshalled by the
// production handler, not by this test. listRoleAssignments enriches each row
// with VaultName and ExpandedPolicyCount -- fields the service layer never
// returns -- so their presence is only explicable by the real handler running.
func TestNew_ServesTheRealHandler(t *testing.T) {
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Secrets User",
	}

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{assignment}, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := New(t, Options{RoleAssignments: roleSvc})

	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/api/v1/vaults/payments/role-assignments", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var decoded model.ListRoleAssignmentsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	require.Len(t, decoded.RoleAssignments, 1)
	assert.Equal(t, assignment.ID.String(), decoded.RoleAssignments[0].ID)
	assert.Equal(t, "payments", decoded.RoleAssignments[0].VaultName,
		"VaultName is set by the handler, not the service -- if this is empty the real handler did not run")
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/apitest/ -run TestNew_ServesTheRealHandler`
Expected: FAIL — the package does not exist yet (`no Go files` or `undefined: New`).

- [ ] **Step 3: Implement the harness**

Create `internal/apitest/apitest.go`:

```go
// Package apitest serves RocketVault's real HTTP API in-process, so CLI
// adapter tests decode JSON that the production handler marshalled from the
// production response struct.
//
// The alternative -- an httptest.Server with a hand-written handler -- proves
// nothing: a mock that agrees with the client stays green when the real API
// renames a field. Everything below the service layer is stubbed, so this
// harness catches response-shape drift, status codes, route existence and
// auth-header plumbing, and nothing else. Business logic, persistence and
// real authorization decisions are out of scope by design; see the spec.
package apitest

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	"rocketvault/api"
	"rocketvault/app"
	"rocketvault/cmd/testutils"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// testToken is the bearer token the harness's client sends. The stubbed
// authentication service accepts any token; this constant exists so tests
// driving raw HTTP can send the same one.
const testToken = "apitest-token"

// Options configures the stubbed services behind the real router. Fields are
// added one per command group as that group's adapter lands -- the first real
// consumer should shape each one rather than guessing groups ahead.
type Options struct {
	// RoleAssignments stubs the role-assignment service. Nil leaves the
	// MockServiceContainer default in place, which allows every data action.
	RoleAssignments authzServices.RoleAssignmentService

	// DenyDataAction, when non-empty, makes the authorization stub deny that
	// one action so a test can assert the CLI's 403 mapping. Empty allows
	// everything. Wired in Task 3.
	DenyDataAction model.DataAction
}

// Server is a running in-process API. It is closed via t.Cleanup; callers do
// not close it themselves.
type Server struct {
	tc   *testutils.TestContext
	http *httptest.Server
}

// URL returns the server root, e.g. "http://127.0.0.1:38123".
func (s *Server) URL() string { return s.http.URL }

// New starts an in-process server backed by the real route table and
// middleware chain. It fails the test outright on any construction error: a
// harness that returns an error invites tests that ignore it.
func New(t *testing.T, opts Options) *Server {
	t.Helper()
	relaxRateLimits(t)

	tc := testutils.NewTestContext(t)

	// AuthenticationMiddleware calls ValidateSession on every non-exempt
	// route. Accept any token as a fixed admin: this harness tests wire
	// shape, not authentication.
	tc.MockAuthService.On("ValidateSession", mock.Anything, mock.Anything).
		Return(&authServices.JWTClaims{
			UserID:   tc.TestUserID,
			Username: "testuser",
			Roles:    []string{model.RoleAdmin},
		}, nil).Maybe()

	// VaultResolutionMiddleware resolves {vault_name} for every vault-scoped
	// route. NewTestContext registers GetVault only for "default", and an
	// unregistered testify call panics -- so a request to /vaults/payments/...
	// would blow up inside the middleware. Accept any name. The earlier,
	// more specific "default" expectation still matches first.
	tc.MockVaultService.On("GetVault", mock.Anything, mock.Anything).
		Return(&model.Vault{ID: tc.TestVaultID, Name: "test", Enabled: true}, nil).Maybe()

	if opts.RoleAssignments != nil {
		tc.MockContainer.RoleAssignmentService = opts.RoleAssignments
	}

	router := mux.NewRouter()
	// WithMetricsEnabled(false) is required, not cosmetic: enabling it
	// registers a Prometheus collector, and a second New() in the same test
	// binary would panic on duplicate registration.
	api.Init(
		api.WithAPP(&app.App{ServiceContainer: tc.MockContainer, Logger: tc.Logger}),
		api.WithRouter(router),
		api.WithBasePath("/api/v1"),
		api.WithLogger(tc.Logger),
		api.WithMetricsEnabled(false),
	)

	httpSrv := httptest.NewServer(router)
	t.Cleanup(httpSrv.Close)

	return &Server{tc: tc, http: httpSrv}
}

// relaxRateLimits raises the per-IP and per-vault budgets for the duration of
// the test. Every test in a package shares 127.0.0.1, so as more command
// groups add harness-backed tests the shared budget would eventually be the
// thing that fails -- a slow-building landmine rather than an honest failure.
// The limiter itself is exercised by internal/middleware's own tests.
func relaxRateLimits(t *testing.T) {
	t.Helper()
	for _, key := range []string{"rate_limit.default", "rate_limit.auth", "rate_limit.per_vault"} {
		previous := viper.Get(key)
		viper.Set(key, 1_000_000)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
}

// unused keeps the context import honest until Task 2 adds the token source.
var _ = context.Background
```

Delete the `var _ = context.Background` line and the `context` import if the
package compiles without them; Task 2 adds a real use.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/apitest/ -run TestNew_ServesTheRealHandler -v`
Expected: PASS.

If it fails with a testify panic naming an unregistered call, a middleware
needs a stub the list above is missing — add it in `New` with `.Maybe()` and
a comment saying which middleware forced it. Do not work around it in the
test.

- [ ] **Step 5: Prove the shape guard bites**

Temporarily rename the `vault_name` JSON tag on
`model.RoleAssignmentResponse.VaultName` (`model/role_assignment.go:43`) to
`vault_name_x`, then run the test again.

Expected: FAIL on the `VaultName` assertion — which is the whole point of the
harness. Revert the tag and confirm the test passes again before committing.

- [ ] **Step 6: Commit**

```bash
go build ./... && golangci-lint run ./internal/apitest/
git add internal/apitest/apitest.go internal/apitest/apitest_test.go
git commit -S -m "test(apitest): serve the real API in-process

Remote-adapter tests stand up httptest servers whose handlers return JSON
the test author typed, so renaming a field on the real response struct
leaves every test green while production breaks.

This serves the production router, middleware chain and handlers against
stubbed services, so the response body is marshalled by real code."
```

---

### Task 2: Hand back a vaultapi client and target

**Files:**
- Modify: `internal/apitest/apitest.go`
- Test: `internal/apitest/apitest_test.go`

**Interfaces:**
- Consumes: `New`/`Server` from Task 1.
- Produces: `(*Server).Client() *vaultapi.Client` and `(*Server).Target() *cliclient.Target`. Plan 02 passes both straight into `runGrantRemote`/`runListRemote`/`runRevokeRemote`.

- [ ] **Step 1: Write the failing test**

Add to `internal/apitest/apitest_test.go`. This is spec §6's auth-header
test: it proves the real `Authorization` header travels the real middleware,
rather than assuming it.

```go
// TestServer_ClientSendsBearerToken proves the harness client's token reaches
// AuthenticationMiddleware -- the auth-header plumbing is covered, not assumed.
func TestServer_ClientSendsBearerToken(t *testing.T) {
	var gotToken string

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{}, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := New(t, Options{RoleAssignments: roleSvc})

	// Re-register ValidateSession to capture what the middleware received.
	srv.tc.MockAuthService.ExpectedCalls = nil
	srv.tc.MockAuthService.On("ValidateSession", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { gotToken = args.String(1) }).
		Return(&authServices.JWTClaims{
			UserID: srv.tc.TestUserID, Username: "testuser", Roles: []string{model.RoleAdmin},
		}, nil)

	_, _, err := srv.Client().ListRoleAssignments(context.Background(), "payments", 0)
	require.NoError(t, err)
	assert.Equal(t, testToken, gotToken, "the client's bearer token must reach the auth middleware")

	assert.Equal(t, srv.URL(), srv.Target().Server)
}
```

Add `"context"` and `authServices "rocketvault/internal/services/auth"` to the
test file's imports.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/apitest/ -run TestServer_ClientSendsBearerToken`
Expected: FAIL — `srv.Client undefined` and `srv.Target undefined`.

- [ ] **Step 3: Add the client and target**

In `internal/apitest/apitest.go`, add the token source and both accessors,
and store the client on `Server` so repeated calls return the same one:

```go
// staticToken is the harness's token source. The stubbed authentication
// service accepts any token, so this only has to be non-empty and stable.
type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }
```

Add a `client *vaultapi.Client` field to `Server`, build it at the end of
`New` (after `httpSrv` exists, since it needs the URL), and store it:

```go
	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    httpSrv.URL,
		HTTPClient: httpSrv.Client(),
		Tokens:     staticToken(testToken),
		// DisableRetry keeps a deliberate 4xx from being retried, so a test
		// asserting an error path does not wait on backoff.
		DisableRetry: true,
	})
	if err != nil {
		t.Fatalf("apitest: build vaultapi client: %v", err)
	}

	return &Server{tc: tc, http: httpSrv, client: client}
```

And the accessors:

```go
// Client returns a vaultapi client pointed at this server, authenticated with
// a token the stubbed auth service accepts.
func (s *Server) Client() *vaultapi.Client { return s.client }

// Target returns the cliclient.Target a remote adapter resolves its vault
// against.
func (s *Server) Target() *cliclient.Target {
	return &cliclient.Target{Server: s.http.URL}
}
```

Add `"rocketvault/internal/cliclient"` and `"rocketvault/internal/vaultapi"`
to the package imports, and drop the `var _ = context.Background` placeholder
from Task 1 — `staticToken` now uses `context`.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/apitest/ -v`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
go build ./... && golangci-lint run ./internal/apitest/
git add internal/apitest/apitest.go internal/apitest/apitest_test.go
git commit -S -m "test(apitest): hand back a vaultapi client and target

The client is seeded with a static bearer token and the server's own
transport, so a remote adapter can be called against the harness exactly
as it is called against a real server -- including the Authorization
header travelling the real middleware."
```

---

### Task 3: Let a test opt into a genuine 403

**Files:**
- Modify: `internal/apitest/apitest.go`
- Test: `internal/apitest/apitest_test.go`

**Interfaces:**
- Consumes: `Options`, `New`, `(*Server).Client()` from Tasks 1 and 2.
- Produces: working `Options.DenyDataAction`. Plan 02 Task 1 uses it to replace a hand-written `w.WriteHeader(403)`.

- [ ] **Step 1: Write the failing test**

```go
// TestOptions_DenyDataAction_Produces403 proves a test can opt into a real
// authorization denial travelling the real error path, rather than asserting
// against a hand-written 403.
func TestOptions_DenyDataAction_Produces403(t *testing.T) {
	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{}, nil).Maybe()

	srv := New(t, Options{
		RoleAssignments: roleSvc,
		DenyDataAction:  model.ActionRoleAssignmentsWrite,
	})

	_, err := srv.Client().CreateRoleAssignment(context.Background(), "payments",
		vaultapi.GrantRoleRequest{Principal: "alice", Role: "Key Vault Secrets User", PrincipalType: "user"})

	require.Error(t, err)
	var apiErr *vaultapi.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, vaultapi.KindForbidden, apiErr.Kind)
}
```

Add `"rocketvault/internal/vaultapi"` to the test file's imports.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/apitest/ -run TestOptions_DenyDataAction_Produces403`
Expected: FAIL — `DenyDataAction` is declared but nothing reads it, so the
request succeeds and no error is returned.

- [ ] **Step 3: Wire DenyDataAction**

In `New`, after the `opts.RoleAssignments` assignment, install a
`HasDataAction` expectation that denies the named action and allows the rest.
Register the specific denial **first**, because testify matches expectations
in registration order:

```go
	if opts.DenyDataAction != "" {
		svc, ok := tc.MockContainer.RoleAssignmentService.(*testutils.MockRoleAssignmentService)
		if !ok {
			t.Fatalf("apitest: DenyDataAction needs a *testutils.MockRoleAssignmentService, got %T",
				tc.MockContainer.RoleAssignmentService)
		}
		// Clear the allow-everything default from NewTestContext, then deny
		// the named action and allow every other.
		svc.ExpectedCalls = nil
		svc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, opts.DenyDataAction).
			Return(false, nil).Maybe()
		svc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(true, nil).Maybe()
	}
```

Clearing `ExpectedCalls` drops any `ListAssignments`/`AssignRole`
expectations the test registered before calling `New`, so tests using
`DenyDataAction` must register those **after** `New` returns, or rely on the
request never reaching the handler — which is the point of a 403.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/apitest/ -v`
Expected: PASS, all three tests.

- [ ] **Step 5: Commit**

```bash
go build ./... && golangci-lint run ./internal/apitest/
git add internal/apitest/apitest.go internal/apitest/apitest_test.go
git commit -S -m "test(apitest): let a test opt into a real 403

DenyDataAction denies one data action at the authorization stub, so a
test asserting the CLI's forbidden-path copy exercises a genuine denial
travelling the real error path instead of a hand-written status code."
```

---

## Self-Review

**Spec coverage:** §2 (architecture, package, no-cycle) and §3.1–3.2 land in
Task 1; §3.3 in Task 3; the `Client()`/`Target()` surface from §2 in Task 2.
§3.4 (rate limiting) lands in Task 1 — see the deviation note below. §6's
three harness tests map one-to-one onto the three tasks. §7's migration steps
1 and 2 are this plan and plan 02 respectively.

**Deliberate deviation from spec §3.4:** the spec says to verify whether the
rate limiter actually bites before adding a knob. This plan raises the limits
unconditionally instead. Rationale: the limiter is per-IP and every test in a
package shares `127.0.0.1`, so the budget is a shared resource that five more
command groups will draw down in plan 04 — a test suite that passes at 300
requests and fails at 301 fails slowly and confusingly, long after the change
that caused it. The limiter has its own coverage in
`internal/middleware/vault_rate_limit_test.go`, so nothing is lost by relaxing
it here.

**Placeholder scan:** no TBDs. Task 1 Step 3 carries one explicitly temporary
line (`var _ = context.Background`) whose removal is specified in Task 2 Step
3. Task 1 Step 4 tells the implementer what to do if an unregistered mock call
panics, rather than leaving it to be discovered.

**Type consistency:** `Options.RoleAssignments` is
`authzServices.RoleAssignmentService` in Task 1 and satisfied by
`*testutils.MockRoleAssignmentService` in every test. `DenyDataAction` is
`model.DataAction`, matching `HasDataAction`'s fourth parameter
(`internal/services/authorization/role_assignment_service.go:99`).
`(*Server).Client()` returns `*vaultapi.Client`, which is what
`runGrantRemote` takes in plan 02.

**Verified against source before writing:** `api.With*` option names
(`api/options.go`), `MockServiceContainer.RoleAssignmentService` and its
allow-all default (`cmd/testutils/test_utils.go:83,101,151-155`),
`ValidateSession`'s signature (`test_utils.go:806`), `GetVault` being
registered only for `"default"` (`test_utils.go:75`), and `model.Vault`'s
`ID`/`Name`/`Enabled` fields (`model/vault.go:25-28`).

**Known risk:** `New` reaches into `tc.MockAuthService` and
`tc.MockVaultService` to register expectations, so it is coupled to
`NewTestContext`'s internals. If `cmd/testutils` changes which calls it
pre-registers, the harness breaks loudly at the first unregistered call rather
than silently — acceptable, but worth a comment on `New` if that file churns.
