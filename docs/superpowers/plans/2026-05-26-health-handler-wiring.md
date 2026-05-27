# Health Handler Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing `HealthHandler` and `HealthCollector` into `InitHealth()` so that `GET /api/v1/health/database` returns rich diagnostics (DB ping, connection pool stats, query performance) and the existing `/health/ready` and `/health/live` routes use the real handler methods instead of static stubs.

**Architecture:** `HealthCollector` is constructed from `c.App.ServiceContainer.GetDatabase()` inside `InitHealth()` — no new container field needed. `NewHealthHandler` wraps it. The three routes (`/health`, `/health/ready`, `/health/live`) are re-wired to the handler methods; a fourth route `/health/database` is added pointing to a new `DatabaseCheck` handler method that calls `CheckDatabaseHealth`. All routes remain public (wrapped with `ApiHandler`, not `ApiSessionRequired`).

**Tech Stack:** Go 1.24.2, `net/http`, `internal/health.HealthCollector`, `internal/health.HealthHandler` (already in `api/health.go`), Gorilla Mux.

**Spec:** `docs/plans/2026-05-23-azure-keyvault-parity-audit.md` §Observability row "Rich HealthHandler … never registered by InitHealth()"; CLAUDE.md note about `/health/database`.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `api/health.go` | Modify | Add `DatabaseCheck` method to `HealthHandler`; rewrite `InitHealth()` to wire all four routes |
| `api/health_test.go` | Create | HTTP-level tests for all four health endpoints |

No other files need to change — `HealthCollector` and `HealthHandler` are fully implemented; `GetDatabase()` is already on `ServiceContainerInterface`.

---

## Task 1: Add `DatabaseCheck` handler method and rewrite `InitHealth`

**Files:**
- Modify: `api/health.go`
- Create: `api/health_test.go`

### Step 1: Write failing tests

Create `api/health_test.go`. The test package must be `package api` (in-package, matching `api/keys_crypto_test.go`). Read `api/keys_crypto_test.go` first to understand the stub-container pattern used there, then write analogous tests for health.

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// healthTestApp builds a minimal *app.App with a nil ServiceContainer.
// InitHealth falls back to static stubs when ServiceContainer is nil.
func healthTestApp(t *testing.T) *app.App {
	t.Helper()
	return &app.App{}
}

func TestInitHealth_LiveEndpoint(t *testing.T) {
	t.Parallel()
	a := healthTestApp(t)
	api := &API{App: a, BaseRoutes: &Routes{}, Logger: a.Logger}
	router := mux.NewRouter()
	api.rootRouter = router
	api.basePath = "/api/v1"
	api.BaseRoutes.Health = router.PathPrefix("/api/v1/health").Subrouter()
	api.InitHealth()

	req := httptest.NewRequest("GET", "/api/v1/health/live", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "alive", body["status"])
}

func TestInitHealth_ReadyEndpoint(t *testing.T) {
	t.Parallel()
	a := healthTestApp(t)
	api := &API{App: a, BaseRoutes: &Routes{}, Logger: a.Logger}
	router := mux.NewRouter()
	api.rootRouter = router
	api.basePath = "/api/v1"
	api.BaseRoutes.Health = router.PathPrefix("/api/v1/health").Subrouter()
	api.InitHealth()

	req := httptest.NewRequest("GET", "/api/v1/health/ready", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "ready", body["status"])
}

func TestInitHealth_DatabaseEndpoint_NilDB(t *testing.T) {
	t.Parallel()
	a := healthTestApp(t)
	api := &API{App: a, BaseRoutes: &Routes{}, Logger: a.Logger}
	router := mux.NewRouter()
	api.rootRouter = router
	api.basePath = "/api/v1"
	api.BaseRoutes.Health = router.PathPrefix("/api/v1/health").Subrouter()
	api.InitHealth()

	req := httptest.NewRequest("GET", "/api/v1/health/database", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// With nil DB, CheckDatabaseHealth returns "critical" status — handler
	// returns 503 (see DatabaseCheck implementation).
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "critical", body["status"])
}
```

Note: when `App.ServiceContainer` is nil, `InitHealth` constructs a `HealthCollector` with a nil DB. `CheckDatabaseHealth` with nil DB returns `{"status":"critical", "error":"database not initialized"}`.

### Step 2: Run to confirm tests fail

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestInitHealth" -v 2>&1 | tail -20
```

Expected: FAIL — `TestInitHealth_DatabaseEndpoint_NilDB` 404 (route doesn't exist).

### Step 3: Add `DatabaseCheck` method to `HealthHandler`

In `api/health.go`, add after `LivenessCheck` (line 159):

```go
// DatabaseCheck handles GET /health/database — returns rich DB diagnostics.
func (h *HealthHandler) DatabaseCheck(w http.ResponseWriter, r *http.Request) {
	result, err := h.collector.CheckDatabaseHealth(r.Context())

	status := http.StatusOK
	if s, ok := result["status"].(string); ok && (s == "critical" || s == "degraded") {
		status = http.StatusServiceUnavailable
	}

	if err != nil && status == http.StatusOK {
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}
```

### Step 4: Rewrite `InitHealth`

Replace the entire `InitHealth` method body (lines 34-48 in `api/health.go`) with:

```go
func (api *API) InitHealth() {
	r := api.BaseRoutes.Health

	var db *sql.DB
	if api.App != nil && api.App.ServiceContainer != nil {
		db = api.App.ServiceContainer.GetDatabase()
	}

	var logger *logging.Logger
	if api.App != nil {
		logger = api.App.Logger
	}
	if logger == nil {
		logger = &logging.Logger{}
	}

	collector := health.NewHealthCollector(db)
	h := NewHealthHandler(collector, logger)

	r.Handle("", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		h.HealthCheck(w, r)
	})).Methods("GET")
	r.Handle("/ready", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		h.ReadinessCheck(w, r)
	})).Methods("GET")
	r.Handle("/live", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		h.LivenessCheck(w, r)
	})).Methods("GET")
	r.Handle("/database", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		h.DatabaseCheck(w, r)
	})).Methods("GET")

	api.Logger.Infoln("Health API routes initialized")
}
```

Also add `"database/sql"` to the import block in `api/health.go` since `InitHealth` now references `*sql.DB` directly.

### Step 5: Build and run tests

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestInitHealth" -v 2>&1 | tail -25
```

Expected: all three `TestInitHealth_*` tests PASS.

### Step 6: Run full test suite

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|^ok"
```

Expected: all packages `ok`, no FAILs.

### Step 7: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add api/health.go api/health_test.go && git commit -S -m "feat(health): wire HealthHandler into InitHealth; add /health/database route"
```

---

## Self-Review

**Spec coverage:**
- "Rich HealthHandler defined but never registered by InitHealth()" → `InitHealth` now creates `HealthCollector` + `HealthHandler` and wires all routes. ✅
- "/health/database referenced in CLAUDE.md but doesn't exist" → `/health/database` route registered, calls `DatabaseCheck`. ✅
- `/health/ready` and `/health/live` now use real handler methods. ✅
- `/health` root now returns real metrics. ✅

**Placeholder scan:** No TBDs, no "add appropriate error handling" — all error paths are concrete. ✅

**Type consistency:**
- `DatabaseCheck` uses `h.collector.CheckDatabaseHealth` — method exists on `*health.HealthCollector` at `internal/health/health.go:286`. ✅
- `NewHealthHandler` takes `*health.HealthCollector` and `*logging.Logger` — matches `api/health.go:57`. ✅
- `api.App.ServiceContainer.GetDatabase()` returns `*sql.DB` — method on `ServiceContainerInterface` at `internal/container/service_container.go:76`. ✅
- `logging.Logger{}` zero value is safe as a fallback — logger methods on `*logging.Logger` guard nil fields internally. ✅
