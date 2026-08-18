package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"rocketvault/app"
)

// openAPISpec is the minimal shape this test needs from
// docs/api-specification.yaml -- just enough to know which method+path pairs
// the spec documents, not full schema validation.
type openAPISpec struct {
	Paths map[string]map[string]any `yaml:"paths"`
}

// httpMethods is the set of YAML keys under a path item that represent real
// HTTP operations, per the OpenAPI 3.0.3 Path Item Object. A path item map
// can also carry non-method keys like "parameters", "summary", or
// "description" alongside these -- those must not be misread as orphaned
// routes when walking spec.Paths in the reverse direction below.
var httpMethods = map[string]bool{
	"get":     true,
	"post":    true,
	"put":     true,
	"delete":  true,
	"patch":   true,
	"head":    true,
	"options": true,
	"trace":   true,
}

// muxParamPattern strips a mux path-parameter's regex constraint down to
// bare OpenAPI parameter syntax, e.g. "{secret_id:[A-Fa-f0-9-]+}" becomes
// "{secret_id}". docs/api-specification.yaml deliberately omits mux regex
// constraints (raw mux syntax isn't valid OpenAPI -- see Task 3), so the raw
// path template WalkRoutes returns must be normalized the same way before
// comparing against the spec's path keys, or every parameterized route would
// spuriously fail to match.
//
// The pattern is anchored to a "{name:" opening, not a bare ":", so a
// literal ":" in a static path segment (however unlikely in practice) is
// left untouched instead of being misread as the start of a constraint.
var muxParamPattern = regexp.MustCompile(`\{(\w+):[^}]*\}`)

// normalizeMuxPath strips mux regex constraints from every parameterized
// segment in path, e.g.
// "/api/v1/secrets/{secret_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}"
// becomes "/api/v1/secrets/{secret_id}/versions/{version}".
func normalizeMuxPath(path string) string {
	return muxParamPattern.ReplaceAllString(path, "{$1}")
}

// TestOpenAPISpecCoversAllRoutes walks the REAL router -- the same
// construction api.Init uses in production -- and fails if any registered
// route has no corresponding entry in docs/api-specification.yaml. This is
// the permanent guard against the spec drifting the way it did before this
// test existed (Critical Finding #11): it runs on every `go test ./...`,
// not just when someone remembers to check.
func TestOpenAPISpecCoversAllRoutes(t *testing.T) {
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

	raw, err := os.ReadFile("../docs/api-specification.yaml")
	require.NoError(t, err)
	var spec openAPISpec
	require.NoError(t, yaml.Unmarshal(raw, &spec))

	var missing []string
	for _, r := range routes {
		path := normalizeMuxPath(r.Path)
		methods, ok := spec.Paths[path]
		if !ok {
			missing = append(missing, r.Method+" "+path+" (path missing entirely)")
			continue
		}
		if _, ok := methods[strings.ToLower(r.Method)]; !ok {
			missing = append(missing, r.Method+" "+path+" (path documented, method missing)")
		}
	}
	require.Empty(t, missing, "docs/api-specification.yaml is missing %d route(s):\n%s", len(missing), joinLines(missing))

	// Reverse direction: every method the spec documents must correspond to
	// a route the real router actually registers. This is the guard against
	// a fictional/orphaned spec entry -- e.g. a stray documented path that
	// no longer (or never did) exist in the router -- which the
	// forward-only loop above cannot catch.
	real := make(map[string]map[string]bool, len(routes))
	for _, r := range routes {
		p := normalizeMuxPath(r.Path)
		if real[p] == nil {
			real[p] = map[string]bool{}
		}
		real[p][strings.ToLower(r.Method)] = true
	}
	var orphaned []string
	for p, ops := range spec.Paths {
		for m := range ops {
			if !httpMethods[m] {
				continue // skip non-method YAML keys like "parameters", "summary"
			}
			if !real[p][m] {
				orphaned = append(orphaned, strings.ToUpper(m)+" "+p)
			}
		}
	}
	require.Empty(t, orphaned, "docs/api-specification.yaml documents %d route(s) the router does not register:\n%s", len(orphaned), strings.Join(orphaned, "\n"))
}

// TestNormalizeMuxPath exercises normalizeMuxPath directly, including the
// adversarial case a review of the original unanchored regex (`:[^}]*}`)
// found: a literal ":" in a static path segment, before any "{...}" group,
// must survive untouched rather than being misread as the start of a
// parameter constraint and swallowing everything up to the next "}".
func TestNormalizeMuxPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "single parameterized segment",
			in:   "/api/v1/secrets/{secret_id:[A-Fa-f0-9-]+}",
			want: "/api/v1/secrets/{secret_id}",
		},
		{
			name: "multiple parameterized segments",
			in:   "/api/v1/secrets/{secret_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}",
			want: "/api/v1/secrets/{secret_id}/versions/{version}",
		},
		{
			name: "three parameterized segments",
			in:   "/api/v1/vaults/{vault_name:[a-z0-9-]+}/secrets/{secret_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}",
			want: "/api/v1/vaults/{vault_name}/secrets/{secret_id}/versions/{version}",
		},
		{
			name: "no parameters",
			in:   "/api/v1/secrets",
			want: "/api/v1/secrets",
		},
		{
			name: "adversarial: literal colon in a static segment before a real parameter",
			in:   "/api/v1/foo:bar/{id:[0-9]+}",
			want: "/api/v1/foo:bar/{id}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, normalizeMuxPath(tc.in))
		})
	}
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += "  " + l + "\n"
	}
	return out
}
