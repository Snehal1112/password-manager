// Package apitest serves RocketVault's real HTTP API in-process, so CLI
// adapter tests decode JSON that the production handler marshalled from the
// production response struct.
//
// The alternative -- an httptest.Server with a hand-written handler -- proves
// nothing: a mock that agrees with the client stays green when the real API
// renames a field. Everything below the service layer is stubbed, so this
// harness catches status codes, route existence and auth-header plumbing
// outright. Response-shape drift is only caught once a caller decodes
// through its own independently-declared struct -- e.g. (*Server).Client(),
// whose vaultapi wire types are declared independently of the model package
// -- rather than a model type, since decoding into the same model type the
// handler marshals from round-trips regardless of tag renames.
// TestServer_ClientSendsBearerToken exercises this: it decodes through
// vaultapi's own roleAssignmentWire, then maps into the exported
// vaultapi.RoleAssignment, and fails if a model-side JSON tag drifts.
// Business logic, persistence and real authorization decisions are out of
// scope by design; see the spec.
//
// # Extending this harness
//
// Add one Options field per newly-stubbed service, register its container
// getter with .Maybe() so an unexercised route doesn't panic on an
// unregistered call, and check the corresponding cmd/testutils getter is not
// a hardcoded nil before relying on it. Certificates are the known case:
// MockServiceContainer.GetCertificateService() (cmd/testutils/test_utils.go)
// returns nil unconditionally, so Context.certSvc() returns nil without
// setting an error and certificate handlers silently no-op into an empty
// 200 -- no panic, no log, just a bare client-side EOF. The fix is to
// convert that getter to a settable field the way VaultService already is;
// this pass only documents the gap, it does not close it.
package apitest

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	"rocketvault/api"
	"rocketvault/app"
	"rocketvault/cmd/testutils"
	"rocketvault/internal/cliclient"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

// testToken is the bearer token the harness's client sends. The stubbed
// authentication service accepts any token; this constant exists so tests
// driving raw HTTP can send the same one.
const testToken = "apitest-token"

// staticToken is the harness's token source. The stubbed authentication
// service accepts any token, so this only has to be non-empty and stable.
type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// Options configures the stubbed services behind the real router. Fields are
// added one per command group as that group's adapter lands -- the first real
// consumer should shape each one rather than guessing groups ahead.
type Options struct {
	// RoleAssignments stubs the role-assignment service. Nil leaves the
	// MockServiceContainer default in place, which allows every data action.
	// A non-nil value REPLACES that allow-all default outright, not merges
	// with it: it must itself stub HasDataAction (and any other method the
	// exercised route calls) for every action the test's route needs, or an
	// unregistered call panics. This has teeth on a data-plane route -- e.g.
	// a keys test that supplies RoleAssignments and hits ListKeys will panic
	// on an unregistered HasDataAction unless its stub covers that action.
	RoleAssignments authzServices.RoleAssignmentService

	// DenyDataAction, when non-empty, makes the authorization stub deny that
	// one action so a test can assert the CLI's 403 mapping. Empty allows
	// everything.
	//
	// This only has an observable effect on RouteVaultData routes, as
	// classified by MapRouteToDataAction -- vault data-plane routes (secrets,
	// keys, certificates), which PolicyMiddleware gates unconditionally via
	// HasDataAction with no admin bypass. It does nothing on vault-management
	// or role-assignment routes: the harness's stubbed caller is a global
	// admin (see New's ValidateSession stub), and both CanManageVault and
	// CanManageRoleAssignments (internal/services/authorization/vault_authz.go)
	// short-circuit to true for a global admin before HasDataAction is ever
	// consulted. Use DenyAccessPolicy for those routes instead.
	DenyDataAction model.DataAction

	// DenyAccessPolicy, when true, makes the access-policy stub return an
	// explicit deny on (vaults, manage) so a test can assert a real 403 on
	// vault-management and role-assignment routes -- the routes
	// DenyDataAction cannot reach. resolvePolicy
	// (internal/middleware/middleware.go) maps every "/vaults/..." path,
	// including "/vaults/{name}/role-assignments", to (PolicyResourceVaults,
	// OpManage) regardless of method, and PolicyMiddleware checks that
	// access-policy decision before the request ever reaches a handler
	// (middleware.go's explicit-deny-override step), so this denial travels
	// the real error path rather than asserting against a hand-written 403.
	// It has no effect on RouteVaultData routes; use DenyDataAction for those.
	DenyAccessPolicy bool
}

// Server is a running in-process API. It is closed via t.Cleanup; callers do
// not close it themselves.
type Server struct {
	tc     *testutils.TestContext
	http   *httptest.Server
	client *vaultapi.Client
}

// URL returns the server root, e.g. "http://127.0.0.1:38123".
func (s *Server) URL() string { return s.http.URL }

// Client returns a vaultapi client pointed at this server, authenticated with
// a token the stubbed auth service accepts.
func (s *Server) Client() *vaultapi.Client { return s.client }

// Target returns the cliclient.Target a remote adapter resolves its vault
// against.
func (s *Server) Target() *cliclient.Target {
	return &cliclient.Target{Server: s.http.URL}
}

// TestContext returns the stubbed service context backing this server, so a
// consumer outside this package can override a stub New already registered
// (ValidateSession, GetVault, ValidateEndpointAccess, ...) -- testify
// returns the first matching expectation, and New's own stubs are
// registered before this returns, so an override must either clear
// ExpectedCalls on the relevant mock first or otherwise ensure it matches
// before New's default. This exists to stub services only: never use it to
// hand-write an HTTP response or otherwise bypass the real router and
// middleware chain -- doing so defeats the entire purpose of this package,
// which is to serve production handlers over the real route table.
func (s *Server) TestContext() *testutils.TestContext { return s.tc }

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
	//
	// This catch-all always returns Name: "test", regardless of the name
	// requested, and its registration-order precedence over a test-specific
	// expectation on the SAME name means the vault-not-found 404 and
	// vault-disabled 403 paths are unreachable through this stub as-is -- a
	// cmd/vaults test asserting an echoed vault name back from the API would
	// see "test", not the name it requested.
	tc.MockVaultService.On("GetVault", mock.Anything, mock.Anything).
		Return(&model.Vault{ID: tc.TestVaultID, Name: "test", Enabled: true}, nil).Maybe()

	// AuthenticationMiddleware calls GetAuditService() after a successful
	// ValidateSession, to record an audit event. NewTestContext does not
	// register this call, so it panics as an unexpected mock invocation.
	// MockServiceContainer.GetAuditService returning nil here is safe on its
	// own (cmd/testutils/test_utils.go): AuthenticationMiddleware
	// (internal/middleware/middleware.go) checks for a nil audit service and
	// falls back to logger-based audit logging instead of calling into it.
	tc.MockContainer.On("GetAuditService").Return(nil).Maybe()

	// AuthorizationMiddleware calls ValidateEndpointAccess for every route to
	// check the caller's global role against the endpoint. NewTestContext
	// does not register this call. Allow every route: this harness tests
	// wire shape, not RBAC decisions.
	tc.MockRBACService.On("ValidateEndpointAccess", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()

	// buildRoleAssignmentResponse (api/role_assignments.go) calls GetUser to
	// resolve PrincipalUsername for every row in the response. Failure there
	// is non-fatal in production (the field is omitempty), but an
	// unregistered testify call still panics the request. Return a
	// not-found error so the handler takes its existing non-fatal path.
	tc.MockUserService.On("GetUser", mock.Anything, mock.Anything).
		Return(nil, errors.New("user not found")).Maybe()

	if opts.RoleAssignments != nil {
		tc.MockContainer.RoleAssignmentService = opts.RoleAssignments
	}

	if opts.DenyDataAction != "" {
		svc, ok := tc.MockContainer.RoleAssignmentService.(*testutils.MockRoleAssignmentService)
		if !ok {
			t.Fatalf("apitest: DenyDataAction needs a *testutils.MockRoleAssignmentService, got %T",
				tc.MockContainer.RoleAssignmentService)
		}
		// Clear the allow-everything default from NewTestContext, then deny
		// the named action and allow every other. This also drops any
		// expectations the test registered on this same mock instance before
		// calling New -- such a test must register those after New returns.
		svc.ExpectedCalls = nil
		svc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, opts.DenyDataAction).
			Return(false, nil).Maybe()
		svc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(true, nil).Maybe()
	}

	if opts.DenyAccessPolicy {
		svc, ok := tc.MockContainer.AccessPolicyService.(*testutils.MockAccessPolicyService)
		if !ok {
			t.Fatalf("apitest: DenyAccessPolicy needs a *testutils.MockAccessPolicyService, got %T",
				tc.MockContainer.AccessPolicyService)
		}
		// Clear the allow-everything default from NewTestContext, then deny
		// (vaults, manage) -- the resource/operation pair resolvePolicy
		// (internal/middleware/middleware.go) maps every vault-management and
		// role-assignment route to -- and allow every other resource/op pair.
		// This also drops any expectations the test registered on this same
		// mock instance before calling New -- such a test must register
		// those after New returns.
		svc.ExpectedCalls = nil
		svc.On("CheckAccess", mock.Anything, mock.Anything, model.PolicyResourceVaults, model.OpManage, mock.Anything).
			Return(authzServices.AccessDenied, nil).Maybe()
		svc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(authzServices.AccessAllowed, nil).Maybe()
	}

	router := mux.NewRouter()
	// WithMetricsEnabled(false) keeps this a minimal harness by default.
	// It is not required for safety: internal/metrics registers the
	// Prometheus collector idempotently, tolerating duplicate registration
	// across repeated New() calls in the same binary, so a future test that
	// needs metrics can pass true here.
	api.Init(
		api.WithAPP(&app.App{ServiceContainer: tc.MockContainer, Logger: tc.Logger}),
		api.WithRouter(router),
		api.WithBasePath("/api/v1"),
		api.WithLogger(tc.Logger),
		api.WithMetricsEnabled(false),
	)

	httpSrv := httptest.NewServer(router)
	t.Cleanup(httpSrv.Close)

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
}

// relaxRateLimits raises the per-IP and per-vault budgets for the duration of
// the test. Every test in a package shares 127.0.0.1, so as more command
// groups add harness-backed tests the shared budget would eventually be the
// thing that fails -- a slow-building landmine rather than an honest failure.
// The limiter itself is exercised by internal/middleware's own tests.
//
// This mutates process-global viper state and restores it via t.Cleanup, not
// a lock. A test calling t.Parallel() alongside another New()-backed test in
// the same package (or process) races on these same keys: one test's
// Cleanup can reset a key while the other still expects it relaxed. Do not
// combine this harness with t.Parallel() until that's addressed.
func relaxRateLimits(t *testing.T) {
	t.Helper()
	for _, key := range []string{"rate_limit.default", "rate_limit.auth", "rate_limit.per_vault"} {
		previous := viper.Get(key)
		viper.Set(key, 1_000_000)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
}
