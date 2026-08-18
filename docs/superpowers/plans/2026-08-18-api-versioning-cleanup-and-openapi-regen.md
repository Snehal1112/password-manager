# API Versioning Cleanup and OpenAPI Spec Regeneration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove RocketVault's dead, never-wired API-versioning subsystem (Critical Finding #10) and regenerate `docs/api-specification.yaml` from the real router so it stops documenting a fictional API surface (Critical Finding #11), with a CI-enforceable test that fails the moment the spec next drifts from the real routes.

**Architecture:** `api/versioning.go` is deleted outright rather than wired in — the real router already hardcodes `/api/v1` everywhere (confirmed via `authzServices.DataPlaneBasePath`, `cmd/serve.go`'s `basePath`, and every existing route registration), and the dead subsystem's own `v2` has no designed routes at all, so "wiring it in" would mean inventing a whole new API version with no product requirement driving it — out of scope for a bug fix. A new route-inventory test walks the real `mux.Router` (reusing this repo's existing `router.Walk` pattern from `api/router_authorization_matrix_test.go`) to produce the ground truth for the spec rewrite, and a second, permanent test re-walks the router on every `go test` run and fails if any real route lacks a matching OpenAPI path entry.

**Tech Stack:** Go 1.24, `github.com/gorilla/mux`, `gopkg.in/yaml.v3` (already a direct dependency), `github.com/stretchr/testify`.

**Spec:** `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Critical Findings #10 and #11 — see the "Critical findings" table and the "API compatibility" section for full detail)

## Global Constraints

- `api/versioning.go` and `api/versioning_test.go` are deleted in full — do not attempt to preserve or repurpose any part of them; the whole subsystem (path/header/Accept-header version negotiation, `Deprecated`/`Sunset` headers, `v1`/`v2` registration) is unused dead code with no live caller anywhere in the repo (grep-confirmed in the audit and re-confirmed while writing this plan).
- The real API has no version concept today and this plan does not add one — every route stays under the existing hardcoded `/api/v1` prefix. This plan's job is removing the fiction, not building a real versioning story.
- The route-inventory mechanism must walk the REAL router built by `api.Init(...)` — the same construction `api.go` uses in production — not a hand-maintained list. This is what makes the drift-check test (Task 4) actually catch future drift instead of just re-encoding today's snapshot.
- Verification gate for every task: `go build ./... && go test ./...` (this codebase's standing rule — `go vet` alone misses interface/mock signature mismatches).

---

### Task 1: Remove the dead API-versioning subsystem

**Files:**
- Delete: `api/versioning.go`
- Delete: `api/versioning_test.go`
- Modify: `api/coverage_boost_test.go` (remove the versioning-specific test functions and their now-unused imports)
- Modify: `common/common_test.go` (remove the `APIVersionKey` row from its context-key registry test, if that test enumerates every key)
- Modify: `common/context.go` (remove the now-unused `APIVersionKey` declaration)

**Interfaces:**
- Consumes: nothing — this task only removes code.
- Produces: nothing new. Confirms a clean build/test with the subsystem gone, which every later task in this plan (and the rest of the repo) can assume.

- [ ] **Step 1: Confirm the full blast radius before deleting anything**

Run:
```bash
grep -rln "NewVersionManager\|VersionManager\|GetVersionFromContext\|CreateVersionedRouter\|InitializeVersions\|CompatibilityMiddleware\|VersionMiddleware\|api\.Version\b" --include="*.go" .
grep -rn "APIVersionKey" --include="*.go" .
```
Expected: only `api/versioning.go`, `api/versioning_test.go`, and `api/coverage_boost_test.go` reference the versioning symbols; `APIVersionKey` additionally appears in `common/context.go` (the declaration) and `common/common_test.go` (a context-key registry test). If this grep turns up any OTHER file, stop and re-scope this task — do not delete code something else still depends on.

- [ ] **Step 2: Delete the two versioning files**

```bash
rm api/versioning.go api/versioning_test.go
```

- [ ] **Step 3: Remove the versioning-specific tests from `api/coverage_boost_test.go`**

Open `api/coverage_boost_test.go` and find the test functions that exercise `common.APIVersionKey`/`GetVersionFromContext` (per Step 1's grep, around lines 71-110 as of this plan's writing — confirm the exact function names and line ranges by reading the file, since line numbers drift). Delete those test functions in full. If any import in that file becomes unused as a result (e.g. `"context"` if nothing else in the file needs it), remove the unused import too — `go build` will tell you.

- [ ] **Step 4: Remove `APIVersionKey` from `common/context.go`**

Read `common/context.go` around line 30 and delete the `APIVersionKey = &contextKey{"api_version"}` line (or equivalent — confirm exact current syntax by reading the file).

- [ ] **Step 5: Remove the corresponding row from `common/common_test.go`**

Read `common/common_test.go` around line 511 and remove the `{"rocketvault/api_version", APIVersionKey}` entry (or equivalent — confirm exact current syntax and surrounding table structure by reading the file) from whatever table/slice enumerates context keys.

- [ ] **Step 6: Build and test**

```bash
go build ./...
go test ./api/... ./common/... -v
```
Expected: clean build, all tests pass. If `go build` reports an unused import anywhere touched in Steps 3-5, remove it.

- [ ] **Step 7: Full repo verification**

```bash
go build ./... && go test ./...
```
Expected: clean across the entire repository — this confirms Step 1's blast-radius grep was accurate and nothing else silently depended on the removed subsystem.

- [ ] **Step 8: Commit**

```bash
git add api/coverage_boost_test.go common/context.go common/common_test.go
git rm api/versioning.go api/versioning_test.go
git commit -m "$(cat <<'EOF'
fix(api): remove dead API-versioning subsystem

api/versioning.go implemented full Azure-style API-version negotiation
(path/header/Accept-header parsing, Deprecated/Sunset headers, v1/v2
registration) but NewVersionManager was never called from api.Init(),
bootstrap, or main.go -- the real API has always hardcoded /api/v1
everywhere. The registered v1's SunsetDate (2025-12-31) was already in
the past. Delete the subsystem rather than wire it in: v2 has no
designed routes, and inventing a real versioning story is a product
decision, not a bug fix.

Critical Finding #10, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```

---

### Task 2: Route-inventory test — walk the real router, write the ground truth

**Files:**
- Create: `api/route_inventory.go`
- Create: `api/route_inventory_test.go`
- Create: `docs/api-routes.generated.txt`

**Interfaces:**
- Consumes: `mux.Router` (from `github.com/gorilla/mux`), and `api.Init(...)`'s existing construction (via the test-only `policyContainer`/stub pattern already proven in `api/router_authorization_matrix_test.go`).
- Produces: `api.RouteInfo{Method, Path string}` and `api.WalkRoutes(router *mux.Router) []RouteInfo`, an exported, non-test helper both this task's generator test and Task 4's drift-check test call. `docs/api-routes.generated.txt`, a checked-in, sorted `METHOD\tPATH` reference file — the literal ground truth Task 3 uses to rewrite the OpenAPI spec.

- [ ] **Step 1: Write `RouteInfo` and `WalkRoutes` as a plain, reusable, non-test function**

Create `api/route_inventory.go`:

```go
package api

import "github.com/gorilla/mux"

// RouteInfo is one registered route: an HTTP method and its path template,
// exactly as gorilla/mux would match it (e.g. "/api/v1/vaults/{vault_name}/secrets").
type RouteInfo struct {
	Method string
	Path   string
}

// WalkRoutes enumerates every method+path pair registered on router. A route
// with no path template (e.g. a catch-all NotFoundHandler) or no explicit
// .Methods(...) call (some public subrouters register via bare HandleFunc)
// is skipped -- neither carries a meaningful method+path pair to document.
func WalkRoutes(router *mux.Router) ([]RouteInfo, error) {
	var routes []RouteInfo
	err := router.Walk(func(route *mux.Route, r *mux.Router, ancestors []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			return nil
		}
		for _, method := range methods {
			routes = append(routes, RouteInfo{Method: method, Path: tmpl})
		}
		return nil
	})
	return routes, err
}
```

- [ ] **Step 2: Write the generator test**

Read `api/router_authorization_matrix_test.go` first (in full) — it already defines `routerWalkContainer` (wrapping `policyContainer` from `api/access_policies_test.go`, same package) with the exact minimal stub needed to build the real router via `api.Init(...)` without a live database. Reuse that same construction pattern; do not redefine a second stub container.

Create `api/route_inventory_test.go`:

```go
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
```

- [ ] **Step 3: Run the generator to produce the real ground truth**

```bash
go test ./api/... -run TestGenerateRouteInventory -v
```
Expected: PASS, and `docs/api-routes.generated.txt` now exists with a real, sorted `METHOD\tPATH` line per registered route. Read the file after running this — it is the exact input Task 3 works from.

- [ ] **Step 4: Build and test**

```bash
go build ./... && go test ./api/... -v
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add api/route_inventory.go api/route_inventory_test.go docs/api-routes.generated.txt
git commit -m "$(cat <<'EOF'
feat(api): add route-inventory generator walking the real router

WalkRoutes enumerates every registered method+path pair from the real
mux.Router api.Init builds in production, reusing the router.Walk
pattern already proven in router_authorization_matrix_test.go.
TestGenerateRouteInventory runs it and writes a sorted, checked-in
docs/api-routes.generated.txt -- the ground truth the OpenAPI spec
rewrite (next commit) and its drift-check test are built against,
rather than a hand-maintained guess at what routes exist.

Critical Finding #11, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```

---

### Task 3: Regenerate `docs/api-specification.yaml` from the real route inventory

**Files:**
- Modify: `docs/api-specification.yaml`

**Interfaces:**
- Consumes: `docs/api-routes.generated.txt` (Task 2's output — the authoritative route list for this task).
- Produces: an OpenAPI document whose `paths:` section has an entry for every line in `docs/api-routes.generated.txt`. Task 4's drift-check test enforces this mechanically — this task is done when that test passes.

- [ ] **Step 1: Read the current spec and the generated inventory side by side**

```bash
cat docs/api-routes.generated.txt
```

Read `docs/api-specification.yaml` in full. It currently has exactly 10 paths (`/health`, `/health/ready`, `/health/live`, `/vault/tenant`, `/vault/tenant/{id}`, `/secrets/export`, `/secrets/import`, `/secrets/{id}/versions`, `/secrets/{id}/versions/{version}`, `/secrets/{id}/versions/latest`). Keep the ones that correspond to real routes in the generated inventory (health, secrets/export, secrets/import, secrets versions) as-is — they're already correctly documented and are your style reference for the rest of this task. Delete `/vault/tenant` and `/vault/tenant/{id}` entirely — grep `docs/api-routes.generated.txt` to confirm neither exists as a real route (the real routes are under `/vaults`, not `/vault/tenant`).

- [ ] **Step 2: Fix the document-level metadata**

Update the `info:` block:
```yaml
info:
  title: RocketVault API
  description: |
    A self-hosted, open-source alternative to Azure Key Vault: secrets
    management, cryptographic key operations, X.509 certificate lifecycle
    management, and multi-vault RBAC.
  version: 4.0.0
  contact:
    name: RocketVault
    url: https://github.com/Snehal1112/rocketvault
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT
```
(Confirm the exact current key names/nesting in the file before editing — match the existing YAML structure, only change the values.)

- [ ] **Step 3: Add a path entry for every remaining line in the generated inventory**

Work through `docs/api-routes.generated.txt` domain by domain, grouping by URL prefix (e.g. every `/secrets*` line together, every `/keys*` line together). For each method+path pair not already covered by an existing entry from Step 1, add a `paths:` entry following the exact structure the existing correct entries already use (`summary`, `operationId`, `tags`, `parameters` for path/query params, `requestBody` for POST/PUT/PATCH, `responses` with at least the success status and a `4xx`), reusing the real request/response field names from the actual Go types (read the relevant `model/*.go` struct and the handler in `api/*.go` the route dispatches to — do not invent field names). Every route appears in **both** its legacy flat form (e.g. `/secrets/{id}`) and its vault-scoped form (e.g. `/vaults/{vault_name}/secrets/{id}`) per this codebase's documented flat-vs-vault-scoped duplication (see `CLAUDE.md`'s Multi-Vault Architecture note) — document both; do not assume one implies the other in the spec.

Cover at minimum, in this order (the highest-value, most-used domains first): `/secrets` CRUD + soft-delete routes, `/keys` CRUD + crypto-ops + rotation-policy routes, `/certificates` CRUD + policy routes, `/vaults` lifecycle routes, `/vault-access` role-assignment routes (or whatever the real registered path prefix is per the inventory — confirm exact spelling from the file, don't guess), `/access-policies` routes, `/users` auth routes, `/service-accounts` and `/oauth2` routes, `/oidc` routes, `/jwks.json`, `/backup`/`/restore` routes, `/audit` routes, `/config`, `/metrics`.

- [ ] **Step 2 (repeat as needed): Re-run the drift check locally as you go**

Once Task 4's test exists (it's written next, but you may write and run it early against your in-progress spec to check coverage incrementally rather than only at the very end):
```bash
go test ./api/... -run TestOpenAPISpecCoversAllRoutes -v
```
Use its failure output (which routes are still missing) as your checklist — do not consider this task done until it passes.

- [ ] **Step 4: Commit**

```bash
git add docs/api-specification.yaml
git commit -m "$(cat <<'EOF'
docs(api): regenerate OpenAPI spec from the real route table

The spec documented only 10 paths -- zero for /keys or /certificates,
missing core /secrets CRUD, a fictional /vault/tenant pair that
doesn't exist in the router (real routes are under /vaults), and a
stale "Password Manager API" title. Rewritten from
docs/api-routes.generated.txt, the real router's own route inventory,
covering both the legacy flat and vault-scoped route forms this
codebase registers for every resource.

Critical Finding #11, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```

---

### Task 4: CI-enforceable drift-check test

**Files:**
- Create: `api/openapi_drift_test.go`

**Interfaces:**
- Consumes: `api.WalkRoutes` (Task 2), `docs/api-specification.yaml` (Task 3's output).
- Produces: `TestOpenAPISpecCoversAllRoutes`, a normal (untagged, always-runs) test — this is what makes the drift check "CI-enforceable" per the finding's own recommendation, not an opt-in tool someone has to remember to run.

- [ ] **Step 1: Write the failing test**

Create `api/openapi_drift_test.go`:

```go
package api

import (
	"os"
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
		methods, ok := spec.Paths[r.Path]
		if !ok {
			missing = append(missing, r.Method+" "+r.Path+" (path missing entirely)")
			continue
		}
		if _, ok := methods[strings_ToLowerMethod(r.Method)]; !ok {
			missing = append(missing, r.Method+" "+r.Path+" (path documented, method missing)")
		}
	}
	require.Empty(t, missing, "docs/api-specification.yaml is missing %d route(s):\n%s", len(missing), joinLines(missing))
}
```

You will need two small unexported helpers this snippet references — `strings_ToLowerMethod` (OpenAPI documents HTTP methods lowercase as YAML map keys, e.g. `get`/`post`, while `mux.Route.GetMethods()` returns them uppercase) and `joinLines` (for a readable multi-line failure message). Write them directly in the same file:

```go
func strings_ToLowerMethod(method string) string {
	out := make([]byte, len(method))
	for i := 0; i < len(method); i++ {
		c := method[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += "  " + l + "\n"
	}
	return out
}
```

(If this file's package already imports `strings` elsewhere for something unrelated, prefer `strings.ToLower(method)` directly instead of the hand-rolled `strings_ToLowerMethod` helper above — check `api/*.go` for whether `"strings"` is already commonly imported in this package before introducing a manual byte-loop purely to avoid one import; the manual version above exists only as a fallback if there's a reason to avoid the import, which there almost certainly isn't.)

- [ ] **Step 2: Run test to verify it currently passes**

Because Task 3 already brought the spec into full coverage before this task started, this test should PASS on first run, not fail — unlike the plan's usual RED/GREEN pattern. Run it to confirm:
```bash
go test ./api/... -run TestOpenAPISpecCoversAllRoutes -v
```
Expected: PASS. If it fails, Task 3 is incomplete — go back and add whatever `docs/api-specification.yaml` entries the failure output lists as missing, then re-run this step.

- [ ] **Step 3: Prove the test actually catches drift**

Temporarily comment out or rename one path entry in `docs/api-specification.yaml` (pick any real one, e.g. `/secrets`), re-run the test, confirm it FAILS with that path named in the output, then revert the change:
```bash
go test ./api/... -run TestOpenAPISpecCoversAllRoutes -v
# Expected: FAIL, listing the path you removed
git checkout -- docs/api-specification.yaml
go test ./api/... -run TestOpenAPISpecCoversAllRoutes -v
# Expected: PASS again
```
This step is verification, not a permanent code change — do not commit the temporary breakage.

- [ ] **Step 4: Full repo verification**

```bash
go build ./... && go test ./...
```
Expected: clean across the entire repository.

- [ ] **Step 5: Commit**

```bash
git add api/openapi_drift_test.go
git commit -m "$(cat <<'EOF'
test(api): guard OpenAPI spec against future route drift

TestOpenAPISpecCoversAllRoutes walks the real router on every test run
and fails if any registered route lacks a docs/api-specification.yaml
entry -- the permanent version of the one-time regeneration in the
previous commit, so this exact drift (Critical Finding #11) can't
silently recur.

Critical Finding #11, docs/plans/2026-08-18-azure-keyvault-parity-audit.md
EOF
)"
```
