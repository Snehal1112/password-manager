package api

import (
	"os"
	"sort"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
)

// TestGenerateRouteInventory walks the real router -- the same construction
// api.Init uses in production -- and writes every registered method+path
// pair to docs/api-routes.generated.txt, sorted for a stable diff. Run this
// whenever routes change, to regenerate the ground truth Task 3's OpenAPI
// rewrite (and Task 4's drift-check test) are built against:
//
//	go test ./api/... -run TestGenerateRouteInventory -v
func TestGenerateRouteInventory(t *testing.T) {
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

	routes, err := WalkRoutes(router)
	require.NoError(t, err)
	require.Greater(t, len(routes), 30, "expected a substantial number of real routes")

	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})

	var out string
	for _, r := range routes {
		out += r.Method + "\t" + r.Path + "\n"
	}
	require.NoError(t, os.WriteFile("../docs/api-routes.generated.txt", []byte(out), 0o644))
}
