# Repository Hardening — Plan 05: Shared `withMetrics` Helper

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse five copy-pasted `executeWithMetrics` methods into one package-level helper that honors the configured `monitoring.slow_query_threshold`, so the slow-query log warnings and the `SlowQueryCount` metric stop disagreeing.

**Architecture:** `executeWithMetrics` is defined five times — `key_repository.go:280`, `certificate_repository.go:330`, `secret_repository.go:125`, `user_repository.go:43`, `session_repository.go:434` — with identical bodies differing only in the `"table"` log field (which two of the five omit entirely). Each hardcodes `100 * time.Millisecond`. Meanwhile `db.RecordQueryExecution`, which all five call, applies `getSlowQueryThreshold()` — the value `bootstrap.go:296` sets from config. So once an operator tunes that setting, the metric counts one set of queries as slow and the logs warn about a different set. The fix exports the threshold accessor and replaces the five copies with one function.

**Tech Stack:** Go 1.24, `github.com/sirupsen/logrus`, `testify`.

**Spec:** `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md` (finding F4)

## Global Constraints

- **No exported repository interface, signature, or error-message change.** `internal/repositories/mocks/` must not be regenerated. The one new export is `db.SlowQueryThreshold()`, in `internal/db`.
- **The helper must be a package-level function, not a struct field or constructor parameter.** Repository structs are built via struct literals in tests (this is why `itemLifecycleConfig` is supplied by a `crud()` *method* rather than a stored field — a zero-valued `wrap` would panic on first call). A per-repository threshold field would reintroduce exactly that hazard.
- **Do not change what is instrumented in this plan** beyond the two sites named in Task 2, and note that change explicitly in its commit message.
- Branch: `refactor/repo-hardening`. One signed commit per task (GPG key `61D246B30285ED35`).
- Per task, before committing: `go build ./...`, `go vet ./...`, `go test ./internal/repositories/... ./internal/services/...`

---

### Task 1: Export the threshold and add the shared helper

**Files:**
- Modify: `internal/db/db.go:1454-1457` (add an exported accessor beside `getSlowQueryThreshold`)
- Create: `internal/repositories/metrics.go`
- Test: `internal/repositories/metrics_test.go` (create)

**Interfaces:**
- Produces:
  - `func SlowQueryThreshold() time.Duration` in package `internal/db` — exported wrapper over the existing unexported, mutex-guarded `getSlowQueryThreshold()`.
  - `func withMetrics(table, operation string, fn func() error) error` in package `internal/repositories` — unexported, used by every repository in Task 2.

- [ ] **Step 1: Write the failing test**

```go
// internal/repositories/metrics_test.go
package repositories_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
)

// TestSlowQueryThresholdIsConfigurable pins the F4 fix: the repository layer
// must read the same threshold db.RecordQueryExecution applies, not a
// hardcoded 100ms. Before this, tuning monitoring.slow_query_threshold moved
// the SlowQueryCount metric but left every repository's log warning at 100ms,
// so the metric and the logs disagreed about which queries were slow.
func TestSlowQueryThresholdIsConfigurable(t *testing.T) {
	original := rvdb.SlowQueryThreshold()
	t.Cleanup(func() { rvdb.SetSlowQueryThreshold(original) })

	require.Equal(t, 100*time.Millisecond, original,
		"the package default matches config.LoadMonitoringConfig's default")

	rvdb.SetSlowQueryThreshold(2 * time.Second)
	require.Equal(t, 2*time.Second, rvdb.SlowQueryThreshold(),
		"the exported accessor must observe SetSlowQueryThreshold")
}

// TestNoRepositoryHardcodesTheThreshold guards against a sixth copy of the
// wrapper reappearing with its own literal cutoff.
func TestNoRepositoryHardcodesTheThreshold(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(name)
		require.NoError(t, readErr, "read %s", name)
		require.NotContains(t, string(src), "100*time.Millisecond",
			"%s must take its slow-query cutoff from db.SlowQueryThreshold()", name)
		require.NotContains(t, string(src), "100 * time.Millisecond",
			"%s must take its slow-query cutoff from db.SlowQueryThreshold()", name)
	}
}

// TestWithMetricsPropagatesTheError confirms the wrapper is transparent: it
// times and records the call but never swallows or rewrites its result.
func TestWithMetricsPropagatesTheError(t *testing.T) {
	sentinel := errors.New("boom")
	err := repositories.WithMetricsForTest("keys", "test_op", func() error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}
```

The import block is `errors`, `os`, `strings`, `testing`, `time`, `github.com/stretchr/testify/require`, `rvdb "rocketvault/internal/db"`, `rocketvault/internal/repositories`.

`withMetrics` is unexported, so the external test package reaches it through the standard `export_test.go` hook — a file in the *internal* package `repositories`, whose `_test.go` suffix keeps it out of the production build:

```go
// internal/repositories/export_test.go
package repositories

// WithMetricsForTest exposes the unexported withMetrics helper to the external
// repositories_test package. Test-only: the _test.go suffix keeps this out of
// the production build, so nothing ships an exported alias.
var WithMetricsForTest = withMetrics
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `go test ./internal/repositories/ -run 'TestSlowQueryThreshold|TestNoRepositoryHardcodes|TestWithMetrics' -v`
Expected:
- `TestSlowQueryThresholdIsConfigurable` FAILS to compile — `rvdb.SlowQueryThreshold` is undefined.
- The other two fail to compile for the same reason (`withMetrics` does not exist yet).

A compile failure is the correct red here; do not work around it.

- [ ] **Step 3: Export the threshold accessor**

In `internal/db/db.go`, immediately after `getSlowQueryThreshold` (line 1454-1457), add:

```go
// SlowQueryThreshold returns the duration above which a query counts as slow,
// as configured by monitoring.slow_query_threshold. Exported so the repository
// layer logs slow-query warnings at the same cutoff RecordQueryExecution uses
// for the SlowQueryCount metric -- they previously disagreed, because every
// repository hardcoded 100ms while this value was configurable.
// Safe for concurrent use.
func SlowQueryThreshold() time.Duration {
	return getSlowQueryThreshold()
}
```

- [ ] **Step 4: Add the shared helper**

Create `internal/repositories/metrics.go`:

```go
package repositories

import (
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
)

// withMetrics times fn, records it against the package-wide query metrics, and
// warns when it exceeds the configured slow-query threshold. It is transparent:
// fn's error is returned unchanged.
//
// A package-level function rather than a method or a struct field, deliberately.
// Repository structs are built via struct literals in tests, where a
// constructor-set field would zero-value -- the same hazard that keeps
// itemLifecycleConfig behind a crud() method instead of a stored field.
//
// table names the SQL table for the log field; pass "" to omit it, which
// preserves the shape of the two repositories whose copy of this wrapper never
// logged one.
func withMetrics(table, operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	db.RecordQueryExecution(duration)

	// The same threshold RecordQueryExecution just applied to SlowQueryCount,
	// so the metric and this warning can never disagree.
	if duration > db.SlowQueryThreshold() {
		fields := logrus.Fields{
			"operation": operation,
			"duration":  duration.Milliseconds(),
		}
		if table != "" {
			fields["table"] = table
		}
		logrus.WithFields(fields).Warn("Slow database query detected")
	}

	return err
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `go test ./internal/repositories/ -run 'TestSlowQueryThreshold|TestWithMetrics' -v`
Expected: PASS

`TestNoRepositoryHardcodesTheThreshold` still FAILS — the five old copies are still in place. Task 2 removes them.

- [ ] **Step 6: Run the build**

Run: `go build ./... && go vet ./...`
Expected: PASS. `withMetrics` is unused so far, which `go vet` does not flag for functions.

- [ ] **Step 7: Commit** (use the `1-git-commit` skill)

```bash
git add internal/db/db.go internal/repositories/metrics.go internal/repositories/metrics_test.go internal/repositories/export_test.go
```

---

### Task 2: Delete the five copies

**Files:**
- Modify: `internal/repositories/key_repository.go:279-298`, `certificate_repository.go:314-348`, `secret_repository.go:124-142`, `user_repository.go:42-60`, `session_repository.go:433-451`
- Test: `internal/repositories/metrics_test.go` (already written in Task 1)

**Interfaces:**
- Consumes: `withMetrics` from Task 1.
- Produces: five `executeWithMetrics` methods are deleted; all their call sites move to `withMetrics`.

Each repository keeps its `r.executeWithMetrics(op, fn)` call sites intact by converting the method into a thin delegation, rather than editing dozens of call sites. This also preserves `itemLifecycleConfig.wrap`, which is assigned `r.executeWithMetrics` by `crud()` and expects that exact `func(string, func() error) error` shape.

- [ ] **Step 1: Convert `KeyRepository.executeWithMetrics` to a delegation**

In `internal/repositories/key_repository.go`, replace the whole method (lines 279-298) with:

```go
// executeWithMetrics wraps database operations with performance monitoring.
// Delegates to the shared withMetrics helper; kept as a method because
// crud() assigns it to itemLifecycleConfig.wrap, which needs this exact
// func(string, func() error) error shape.
func (r *KeyRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("keys", operation, fn)
}
```

- [ ] **Step 2: Convert `CertificateRepository.executeWithMetrics`**

In `internal/repositories/certificate_repository.go`, replace lines 330-348 with:

```go
// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *CertificateRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("certificates", operation, fn)
}
```

Note lines 314-315 carry a stray doc comment (`// executeWithMetrics wraps database operations with performance monitoring.`) sitting above `crud()`, where it does not belong. Delete that stray line while you are here; `crud()`'s own comment on line 315 stays.

- [ ] **Step 3: Convert `SecretRepository.executeWithMetrics`**

In `internal/repositories/secret_repository.go`, replace lines 124-142 with:

```go
// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *SecretRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("secrets", operation, fn)
}
```

**This adds a `"table"` log field that secret's copy did not emit.** That is an intentional consistency fix, not an accident — say so in the commit message.

- [ ] **Step 4: Convert `UserRepository.executeWithMetrics`**

In `internal/repositories/user_repository.go`, replace lines 42-60 with:

```go
// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *UserRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("users", operation, fn)
}
```

- [ ] **Step 5: Convert `SessionRepository.executeWithMetrics`**

In `internal/repositories/session_repository.go`, replace lines 433-451 with:

```go
// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *SessionRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("user_sessions", operation, fn)
}
```

- [ ] **Step 6: Drop now-unused imports**

Removing the bodies may leave `time` or `logrus` unused in some of these files. Run `go build ./...` and delete whichever imports the compiler reports as unused. Do not remove any import the compiler still needs — several of these files use `time` and `logrus` extensively elsewhere.

- [ ] **Step 7: Run the tests and verify they pass**

Run: `go test ./internal/repositories/ -run TestNoRepositoryHardcodesTheThreshold -v`
Expected: PASS — this test was red at the end of Task 1 and goes green here.

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 8: Confirm the duplication is gone**

Run: `grep -c "start := time.Now()" internal/repositories/*.go | grep -v ':0' | grep -v _test`
Expected: only `internal/repositories/metrics.go:1`.

- [ ] **Step 9: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/key_repository.go internal/repositories/certificate_repository.go \
        internal/repositories/secret_repository.go internal/repositories/user_repository.go \
        internal/repositories/session_repository.go
```

---

### Task 3: Instrument `SecretRepository.Update`

**Files:**
- Modify: `internal/repositories/secret_repository.go:277-312` (`Update`)

**Interfaces:**
- Consumes: `withMetrics` via `r.executeWithMetrics` from Task 2.
- Produces: nothing new; one method body gains a wrapper.

`SecretRepository.Update` runs no metrics wrapper at all, while `KeyRepository.Update` and `CertificateRepository.Update` both do. So scoped secret updates are invisible to `QueryCount`, `TotalQueryTime`, and slow-query warnings.

**This is a real behavior change**, not a refactor: one operation starts being counted that was not counted before, which will shift `rocketvault_db_*` gauge values slightly on deployment. Say so in the commit message.

**`SecretRepository.Delete` is deliberately left alone here.** It is also uninstrumented, but Plan 06 Task 2 replaces its entire body with the shared `deleteItemWithTags`, which calls `cfg.wrap` — and secret's `crud()` supplies `passthroughWrap`, so a wrapper added here would be silently discarded two plans later. Leave `Delete` uninstrumented; if secret deletes should be measured, that is a change to secret's `crud()` config, not to this method.

- [ ] **Step 1: Wrap `Update`**

In `internal/repositories/secret_repository.go`, wrap the entire existing body of `Update` in `return r.executeWithMetrics("update_secret_scoped", func() error { ... })`, matching how `KeyRepository.Update` (`key_repository.go:149-182`) is structured. The body itself is unchanged — every statement, log line, and return stays exactly as it is, only re-indented one level and with the outer `return` added.

The operation name `"update_secret_scoped"` mirrors key's `"update_key_scoped"` and certificate's `"update_certificate_scoped"`.

- [ ] **Step 2: Confirm the error paths are unchanged**

Run: `git diff internal/repositories/secret_repository.go`

Read the diff. Every removed line must reappear, identical apart from one extra level of indentation. If any `fmt.Errorf` string, audit-log call, or return value differs, redo the change — the point of this task is instrumentation, nothing else.

- [ ] **Step 3: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 4: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/secret_repository.go
```

---

## On completion

Finding F4 is closed. One metrics wrapper exists, it reads the configured threshold, and no repository hardcodes a cutoff — guarded by `TestNoRepositoryHardcodesTheThreshold`.

**Next plan — execute this immediately, without asking:**
`docs/superpowers/plans/2026-09-07-repo-hardening-06-tag-orphans.md`
