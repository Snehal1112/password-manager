// Package api — proves the route-to-data-action mapper agrees with the real router.
package api

import (
	"database/sql"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/logging"
	authzServices "rocketvault/internal/services/authorization"
)

// routerWalkContainer wraps policyContainer (defined in access_policies_test.go,
// same package) and overrides the two methods Init/InitHealth call directly
// during route REGISTRATION rather than from inside a request handler:
// middleware.NewMiddleware reads GetLogger() eagerly, and InitHealth reads
// GetDatabase() eagerly. Every other method keeps policyContainer's
// "panic if called" behavior — this test never sends a request through the
// router, only walks its route table, so no handler body ever runs and no
// other container method is ever touched.
type routerWalkContainer struct {
	*policyContainer
	logger *logging.Logger
}

func (c *routerWalkContainer) GetLogger() *logging.Logger { return c.logger }
func (c *routerWalkContainer) GetDatabase() *sql.DB       { return nil }

// TestAuthorizationMatrixOpsAreRealRoutes walks the REAL router built by
// api.Init — the same construction api.go uses in production, with the full
// middleware chain and every Init* call — and, for every registered route
// that MapRouteToDataAction classifies as RouteVaultData, asserts it maps to
// a non-empty data action.
//
// internal/services/authorization/authorization_matrix_test.go's matrixOps
// proves the mapper is self-consistent against a hand-maintained path list;
// it structurally cannot prove the mapper and the real router agree — a path
// hardcoded there could be unreachable (not actually registered), or a real
// route could be reachable but unmapped, and that test would still pass
// either way. This test closes that gap by asking the router itself, not a
// hand-maintained list, which routes exist.
func TestAuthorizationMatrixOpsAreRealRoutes(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
	)
	require.NotNil(t, built)

	checked := 0
	err := router.Walk(func(route *mux.Route, r *mux.Router, ancestors []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			// Routes with no path template (e.g. the catch-all NotFoundHandler)
			// carry no method/path pair to classify.
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			// Public subrouters (OAuth2 token endpoint, Config, JWKS) register via
			// HandleFunc without .Methods(...); none are vault data-plane routes.
			return nil
		}
		for _, method := range methods {
			action, kind := authzServices.MapRouteToDataAction(method, tmpl)
			if kind != authzServices.RouteVaultData {
				continue
			}
			checked++
			assert.NotEmpty(t, action,
				"route %s %s classifies as RouteVaultData but MapRouteToDataAction returns no action", method, tmpl)
		}
		return nil
	})
	require.NoError(t, err)
	// Sanity: the walk actually found and classified a substantial number of
	// vault data-plane routes, so an empty walk (e.g. from a basePath
	// mismatch between Init and MapRouteToDataAction's DataPlaneBasePath)
	// can't pass this test by finding nothing to check.
	assert.Greater(t, checked, 30,
		"expected the router walk to classify a substantial number of vault data-plane routes")
}
