// Package apitest serves RocketVault's real HTTP API in-process, so CLI
// adapter tests decode JSON that the production handler marshalled from the
// production response struct.
//
// The alternative -- an httptest.Server with a hand-written handler -- proves
// nothing: a mock that agrees with the client stays green when the real API
// renames a field. Everything below the service layer is stubbed, so this
// harness catches status codes, route existence and auth-header plumbing
// outright. Response-shape drift is only caught once a caller decodes
// through its own independently-declared struct -- e.g. the vaultapi client
// -- rather than a model type, since decoding into the same model type the
// handler marshals from round-trips regardless of tag renames; see Task 2.
// Business logic, persistence and real authorization decisions are out of
// scope by design; see the spec.
package apitest

import (
	"errors"
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

	// AuthenticationMiddleware calls GetAuditService() after a successful
	// ValidateSession, to record an audit event. NewTestContext does not
	// register this call, so it panics as an unexpected mock invocation.
	// Returning nil is handled explicitly by MockServiceContainer.GetAuditService,
	// which falls back to logger-based audit logging.
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
