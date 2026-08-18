package api

import (
	"flag"
	"os"
	"sort"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
)

// updateInventory rewrites docs/api-routes.generated.txt with the current
// route walk instead of comparing against it. Off by default so a plain
// `go test ./...` can never silently dirty a tracked file -- pass the flag
// explicitly when routes have genuinely changed:
//
//	go test ./api/... -run TestGenerateRouteInventory -update-route-inventory
var updateInventory = flag.Bool("update-route-inventory", false, "rewrite docs/api-routes.generated.txt instead of comparing against it")

// TestGenerateRouteInventory walks the real router -- the same construction
// api.Init uses in production -- and compares every registered method+path
// pair, sorted for a stable diff, against the golden file
// docs/api-routes.generated.txt. Run with -update-route-inventory whenever
// routes genuinely change, to regenerate the ground truth Task 3's OpenAPI
// rewrite (and Task 4's drift-check test) are built against:
//
//	go test ./api/... -run TestGenerateRouteInventory -update-route-inventory
func TestGenerateRouteInventory(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
		WithMetricsEnabled(true),
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

	const path = "../docs/api-routes.generated.txt"
	if *updateInventory {
		require.NoError(t, os.WriteFile(path, []byte(out), 0o644))
		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), out, "route inventory is stale; re-run with -update-route-inventory")
}
