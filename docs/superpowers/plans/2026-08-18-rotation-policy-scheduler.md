# Rotation-Policy Scheduler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make key rotation policies actually execute (they are CRUD-only today), by adding a generic scheduler core (`internal/schedulerkit`) and a key-rotation executor, then migrating the existing secrets and certificate schedulers onto that same core, and introducing one unified `rotation:` YAML config section for all three.

**Architecture:** `internal/schedulerkit.Runner` is a generic ticker/lifecycle wrapper around a `func(ctx) error` callback (mirrors `internal/cachekit`'s generic-core pattern). `key_rotation_policies` gains `last_rotated_at`/`next_rotation_at` columns (materialized due-dates, mirroring `secret_policies`' existing pattern) so due-lookup stays a trivial `<= ?` comparison. A new `RotationExecutor` in `internal/services/keys` sweeps due policies (admin-scoped, global) and calls the existing `KeyService.RotateKey`. The existing secrets scheduler (`internal/services/secrets/scheduler_service.go`) and certificate scheduler (`internal/services/certificates/renewal_scheduler.go`) keep their public APIs unchanged but delegate their ticker plumbing to `schedulerkit.Runner` internally. `bootstrap.go` wires all three from one new `config.RotationConfig`.

**Tech Stack:** Go 1.24, SQLite (dev) / PostgreSQL (prod), `github.com/mattn/go-sqlite3` for tests, `testify` (`require`/`assert`/`mock`), `github.com/spf13/viper` for config.

**Spec:** `docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md`

## Global Constraints

- `model.DefaultVaultID = "00000000-0000-0000-0000-00000000efa1"` — reused verbatim wherever a hardcoded default-vault literal already appears (no new literal needed by this plan).
- The key-rotation sweep is deliberately vault-agnostic: every call the executor makes uses `model.NewAdminScope(uuid.Nil)`. This is intentional (see spec §10), not a bug to "fix" during review.
- The migration backfill for `key_rotation_policies.next_rotation_at` anchors on the migration's own run time (`now`), **not** `key.created_at` — see spec §4 for why (retroactive mass-rotation risk). Only the ongoing runtime path (`KeyService.UpsertKeyRotationPolicy`) anchors on `key.created_at`, and only when the policy has never been rotated before.
- `CertificateRenewalScheduler` and `schedulerService` (secrets) keep their existing exported type names, constructor signatures, and public methods (`Start`/`Stop`/`IsRunning` etc.) — `bootstrap.go`, `bootstrap_test.go`, and any other caller must not need changes beyond what each task explicitly lists. Only their internal ticker/goroutine plumbing is replaced.
- `schedulerkit.Runner.Stop()` must be safe to call on a `Runner` that was never `Start`ed (returns nil, does not panic or block) — `bootstrap_test.go`'s `TestShutdown_WithRenewalScheduler_StopsCleanly` constructs a scheduler and calls `Stop()` directly without ever calling `Start()`, and must keep passing unmodified.
- A `checkFn`/`Check` error passed to `schedulerkit.Runner` is logged generically by the Runner itself (`"%s scheduler tick failed"`) — a domain's own `checkFn` must not *also* log that same error before returning it (would double-log). Per-item errors inside a sweep (e.g. one bad key) are logged domain-specifically and swallowed — only a sweep-level failure (e.g. the due-policy query itself failing) should propagate out of `checkFn`.
- Verification gate for every task: `go build ./... && go test ./...` (this codebase's standing rule — `go vet` alone misses interface/mock signature mismatches).
- `KeyRotationPolicyRepositoryInterface` has no mockery-generated mock (not listed in `.mockery.yaml`) — it is hand-mocked per test file. There are exactly two existing hand-rolled implementations that must be extended wherever the interface gains a method: `mockKeyPolicyRepo` in `internal/services/keys/key_service_test.go`, and `mockKeyRotationPolicyRepo` in `api/key_rotation_policy_test.go`. Do not add a mockery entry for this interface as part of this plan — out of scope, keep the diff minimal.

---

### Task 1: `internal/schedulerkit` — generic scheduler core

**Files:**
- Create: `internal/schedulerkit/runner.go`
- Test: `internal/schedulerkit/runner_test.go`

**Interfaces:**
- Consumes: nothing — this is a new, standalone package with no dependency on any domain package.
- Produces: `schedulerkit.CheckFunc` (`type CheckFunc func(ctx context.Context) error`) and `schedulerkit.Runner` with `NewRunner(name string, checkFn CheckFunc, log *logging.Logger) *Runner`, `(*Runner) Start(ctx context.Context, interval time.Duration) error`, `(*Runner) Stop() error`, `(*Runner) IsRunning() bool`. Every later task that touches a scheduler depends on this exact signature set.

- [ ] **Step 1: Write the failing tests**

Create `internal/schedulerkit/runner_test.go`:

```go
package schedulerkit_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/schedulerkit"
)

func newTestLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func TestRunner_StartRunsCheckImmediately(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), time.Hour))
	defer r.Stop() //nolint:errcheck

	require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) >= 1 }, time.Second, 5*time.Millisecond)
}

func TestRunner_TicksTriggerCheck(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), 10*time.Millisecond))
	defer r.Stop() //nolint:errcheck

	require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) >= 3 }, time.Second, 5*time.Millisecond)
}

func TestRunner_DoubleStartErrors(t *testing.T) {
	check := func(ctx context.Context) error { return nil }
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), time.Hour))
	defer r.Stop() //nolint:errcheck

	require.Error(t, r.Start(context.Background(), time.Hour))
}

func TestRunner_StopWithoutStart_NoPanic(t *testing.T) {
	check := func(ctx context.Context) error { return nil }
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Stop())
}

func TestRunner_StopWaitsForInFlightCheck(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	check := func(ctx context.Context) error {
		close(started)
		<-release
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), time.Hour))

	<-started // The immediate first check is now blocked inside check().
	stopped := make(chan struct{})
	go func() {
		r.Stop() //nolint:errcheck
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Stop returned before the in-flight check finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after the in-flight check finished")
	}
}

func TestRunner_CheckErrorIsLoggedNotFatal(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			return errors.New("boom")
		}
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), 10*time.Millisecond))
	defer r.Stop() //nolint:errcheck

	// The loop must keep ticking after a checkFn error, not stop.
	require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) >= 2 }, time.Second, 5*time.Millisecond)
}

func TestRunner_IsRunning(t *testing.T) {
	check := func(ctx context.Context) error { return nil }
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.False(t, r.IsRunning())
	require.NoError(t, r.Start(context.Background(), time.Hour))
	require.True(t, r.IsRunning())
	require.NoError(t, r.Stop())
	require.False(t, r.IsRunning())
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/schedulerkit/... -v`
Expected: FAIL — package `internal/schedulerkit` does not exist yet.

- [ ] **Step 3: Implement the Runner**

Create `internal/schedulerkit/runner.go`:

```go
// Package schedulerkit provides a generic ticker-based scheduler core,
// shared by every domain that runs a periodic background check (secret
// rotation, certificate renewal, key rotation). It has no knowledge of what
// any check function does.
package schedulerkit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"rocketvault/internal/logging"
)

// CheckFunc is one scheduled unit of work. A returned error is logged by the
// Runner and does not stop the loop — the next tick still runs. Domain-level
// per-item error handling (e.g. "one bad item must not abort the sweep")
// belongs inside CheckFunc; only a failure of the sweep itself (e.g. the
// due-item query failing) should be returned here.
type CheckFunc func(ctx context.Context) error

// Runner runs a CheckFunc once immediately on Start, then once per interval,
// until Stop is called.
type Runner struct {
	name     string
	checkFn  CheckFunc
	log      *logging.Logger
	ctx      context.Context
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	running  bool
}

// NewRunner creates a Runner. name identifies this runner in log lines
// (e.g. "secret rotation", "key rotation", "certificate renewal").
func NewRunner(name string, checkFn CheckFunc, log *logging.Logger) *Runner {
	return &Runner{name: name, checkFn: checkFn, log: log}
}

// Start launches the ticker loop in the background and returns immediately
// -- it does not block on the first check. Returns an error if already running.
func (r *Runner) Start(ctx context.Context, interval time.Duration) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("%s scheduler is already running", r.name)
	}
	r.ctx = ctx
	r.running = true
	r.stopChan = make(chan struct{})
	r.ticker = time.NewTicker(interval)
	r.wg.Add(1)
	r.mu.Unlock()

	go r.run()

	r.log.WithField("interval", interval).Infof("%s scheduler started", r.name)
	return nil
}

// Stop signals the loop to exit and waits for any in-flight check to finish.
// Safe to call on a Runner that was never started.
func (r *Runner) Stop() error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = false
	close(r.stopChan)
	r.ticker.Stop()
	r.mu.Unlock()

	r.wg.Wait()
	r.log.Infof("%s scheduler stopped", r.name)
	return nil
}

// IsRunning returns whether the scheduler is currently running.
func (r *Runner) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

func (r *Runner) run() {
	defer r.wg.Done()

	r.runOnce() // Run once immediately, then on each subsequent tick.
	for {
		select {
		case <-r.ticker.C:
			r.runOnce()
		case <-r.stopChan:
			return
		}
	}
}

func (r *Runner) runOnce() {
	if err := r.checkFn(r.ctx); err != nil {
		r.log.WithError(err).Errorf("%s scheduler tick failed", r.name)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/schedulerkit/... -v -race`
Expected: PASS (all 7 tests). `-race` matters here: this package's whole job is concurrency.

- [ ] **Step 5: Commit**

```bash
git add internal/schedulerkit/
git commit -m "feat(schedulerkit): add generic ticker-based scheduler core"
```

---

### Task 2: DB migration — `key_rotation_policies` due-tracking columns

**Files:**
- Modify: `internal/db/db.go` (`createOptimizedSchema` ~line 486-502; `migrateSchema`'s own `CREATE TABLE IF NOT EXISTS key_rotation_policies` ~line 789-802, its `migrations` slice ~line 860, and the post-loop block ~line 878)
- Test: `internal/db/key_rotation_due_tracking_migration_test.go` (new)

**Interfaces:**
- Consumes: nothing new.
- Produces: `key_rotation_policies.last_rotated_at` (nullable `TIMESTAMP`) and `key_rotation_policies.next_rotation_at` (`TIMESTAMP`, always populated in practice). Task 3's repository layer assumes both columns exist and that no row has a NULL `next_rotation_at` by the time application code runs.

- [ ] **Step 1: Write the failing migration test**

Create `internal/db/key_rotation_due_tracking_migration_test.go`:

```go
// Regression test for the key_rotation_policies.last_rotated_at /
// next_rotation_at migration. Proves migrateSchema adds both columns to an
// old-shape database, that next_rotation_at is backfilled anchored on the
// migration's own run time (not the key's created_at -- a mass-rotation
// hazard, see docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md
// section 4), and that a second run is idempotent.
package db

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestMigrateSchema_KeyRotationPoliciesDueTracking(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, err = conn.Exec(`
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL);
		CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE certificates (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE audit_logs (id TEXT PRIMARY KEY);
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE, retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL, scheduled_purge_at TIMESTAMP NULL
		);
		CREATE TABLE keys (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			created_at TIMESTAMP NOT NULL
		);
		-- Old-shape rotation_policies (already vault_id-scoped from an earlier
		-- migration in real installs; irrelevant to this test, minimal shape).
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL, description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		-- Old-shape key_rotation_policies: already has vault_id (a later
		-- migration than this one in real installs) but no due-tracking columns.
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO keys (id, name, vault_id, created_at) VALUES
			('11111111-1111-1111-1111-111111111111', 'old-key', '00000000-0000-0000-0000-00000000efa1', '2020-01-01 00:00:00');
		INSERT INTO key_rotation_policies (id, key_id, user_id, rotate_after_days, enabled) VALUES
			('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333', 45, TRUE);
	`)
	require.NoError(t, err)

	repo := &DBRepository{dialect: SQLite}
	logger := &logging.Logger{Logger: newSilentLogrus()}
	repo.log = logger

	beforeMigration := time.Now().UTC()
	require.NoError(t, repo.migrateSchema(conn))
	afterMigration := time.Now().UTC()

	var lastRotatedAt sql.NullTime
	var nextRotationAt time.Time
	err = conn.QueryRow(`SELECT last_rotated_at, next_rotation_at FROM key_rotation_policies WHERE id = ?`,
		"22222222-2222-2222-2222-222222222222").Scan(&lastRotatedAt, &nextRotationAt)
	require.NoError(t, err)

	require.False(t, lastRotatedAt.Valid, "a never-rotated policy must not get a fabricated last_rotated_at")

	// next_rotation_at must be anchored on the migration's own run time (not
	// the key's 2020-01-01 created_at, which would make this policy
	// instantly overdue) plus its own rotate_after_days (45).
	wantEarliest := beforeMigration.AddDate(0, 0, 45).Add(-time.Minute)
	wantLatest := afterMigration.AddDate(0, 0, 45).Add(time.Minute)
	require.True(t, nextRotationAt.After(wantEarliest) && nextRotationAt.Before(wantLatest),
		"next_rotation_at = %v, want between %v and %v", nextRotationAt, wantEarliest, wantLatest)

	// Second run must be idempotent: no error, and next_rotation_at must not
	// be recomputed a second time now that it's already populated.
	require.NoError(t, repo.migrateSchema(conn))
	var nextRotationAtAfterSecondRun time.Time
	err = conn.QueryRow(`SELECT next_rotation_at FROM key_rotation_policies WHERE id = ?`,
		"22222222-2222-2222-2222-222222222222").Scan(&nextRotationAtAfterSecondRun)
	require.NoError(t, err)
	require.True(t, nextRotationAt.Equal(nextRotationAtAfterSecondRun),
		"a second migration run must not recompute an already-populated next_rotation_at")
}
```

Check whether a `newSilentLogrus()` test helper already exists in package `db` (grep `internal/db/*_test.go` for `newSilentLogrus` or similar); if one already exists under a different name, use that name instead of introducing a duplicate. If none exists, add:

```go
func newSilentLogrus() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}
```
(with `"io"` and `"github.com/sirupsen/logrus"` imports) in the new test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/... -run TestMigrateSchema_KeyRotationPoliciesDueTracking -v`
Expected: FAIL (no such columns).

- [ ] **Step 3: Add the columns to `createOptimizedSchema`**

In `internal/db/db.go`, in the `CREATE TABLE IF NOT EXISTS key_rotation_policies` block inside `createOptimizedSchema` (~line 486), insert two new lines between `enabled` and `created_at`:

```sql
			enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
			last_rotated_at            TIMESTAMP NULL,
			next_rotation_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
```

- [ ] **Step 4: Add the same columns to `migrateSchema`'s own `CREATE TABLE`**

In the same file's `migrateSchema` method, the `CREATE TABLE IF NOT EXISTS key_rotation_policies` literal inside the `migrations` slice (~line 789, for installs old enough to be missing the table entirely) gets the identical two-line insertion in the identical position.

- [ ] **Step 5: Add the `ALTER TABLE` pair for existing installs**

In the `migrations` slice, immediately after the existing line
`"ALTER TABLE key_rotation_policies ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",` (~line 860), add:

```go
		"ALTER TABLE key_rotation_policies ADD COLUMN last_rotated_at TIMESTAMP",
		"ALTER TABLE key_rotation_policies ADD COLUMN next_rotation_at TIMESTAMP",
```

(No `NOT NULL DEFAULT <literal>` here — unlike `vault_id`, there is no single default value that's correct for every row; `next_rotation_at` is backfilled per-row in Step 6.)

- [ ] **Step 6: Add the parameterized backfill, after the migrations loop**

Immediately after the existing `for _, stmt := range migrations { ... }` loop (the loop ends ~line 878, right before the `// Feature: vault-scoped role assignments table` comment), add:

```go
	// Backfill key_rotation_policies.next_rotation_at for rows that predate
	// this column. Anchored on this migration's own run time, not the key's
	// created_at: using created_at would retroactively mark every existing
	// enabled policy whose key predates its own rotation window as
	// simultaneously overdue the moment this feature ships -- a mass
	// rotation nobody asked for at that moment. See
	// docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md
	// section 4. Only rows already migrated by the ALTER TABLE statements
	// above (next_rotation_at IS NULL) are touched, so re-running this is a
	// no-op once every row has a value.
	now := time.Now().UTC()
	backfillSQL := "UPDATE key_rotation_policies SET next_rotation_at = datetime(?, '+' || rotate_after_days || ' days') WHERE next_rotation_at IS NULL"
	if d.dialect == Postgres {
		backfillSQL = "UPDATE key_rotation_policies SET next_rotation_at = ?::timestamp + (rotate_after_days || ' days')::interval WHERE next_rotation_at IS NULL"
	}
	if _, err := db.Exec(d.dialect.Rebind(backfillSQL), now); err != nil {
		return fmt.Errorf("backfill key_rotation_policies.next_rotation_at: %w", err)
	}
```

Confirm `"time"` is already imported in `internal/db/db.go` (it almost certainly is, given `time.Time` fields elsewhere in this file); add the import if not.

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/db/... -run TestMigrateSchema_KeyRotationPoliciesDueTracking -v`
Expected: PASS.

- [ ] **Step 8: Run the full DB package test suite**

Run: `go test ./internal/db/... -v`
Expected: PASS — confirms this change did not break the existing `rotation_vault_scope_migration_test.go` or any other migration test.

- [ ] **Step 9: Commit**

```bash
git add internal/db/db.go internal/db/key_rotation_due_tracking_migration_test.go
git commit -m "feat(db): add key_rotation_policies due-tracking columns"
```

---

### Task 3: Repository, model, and service layer — due-date read/write path

**Files:**
- Modify: `model/key_rotation_policy.go`
- Modify: `internal/repositories/key_rotation_policy_repository.go`
- Modify: `internal/repositories/key_rotation_policy_repository_test.go` (extend `setupKeyRotationPolicyTestDB`; add new tests)
- Modify: `internal/services/keys/key_service.go` (`UpsertKeyRotationPolicy`)
- Modify: `internal/services/keys/key_service_test.go` (extend `mockKeyPolicyRepo` with the two new interface methods)
- Modify: `api/key_rotation_policy_test.go` (extend `mockKeyRotationPolicyRepo` with the two new interface methods)

**Interfaces:**
- Consumes: nothing from Task 1; consumes Task 2's two new DB columns.
- Produces: `model.KeyRotationPolicy.LastRotatedAt *time.Time` / `.NextRotationAt time.Time`; `KeyRotationPolicyRepositoryInterface.GetDuePolicies(ctx, scope) ([]model.KeyRotationPolicy, error)` and `.MarkRotated(ctx, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error`. Task 4's executor calls both of these by exact name and signature.

- [ ] **Step 1: Add the two fields to the model**

In `model/key_rotation_policy.go`, add to the `KeyRotationPolicy` struct, after `Enabled`:

```go
	Enabled                bool       `json:"enabled" db:"enabled"`
	LastRotatedAt          *time.Time `json:"last_rotated_at,omitempty" db:"last_rotated_at"`
	NextRotationAt         time.Time  `json:"next_rotation_at" db:"next_rotation_at"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
```

- [ ] **Step 2: Write the failing repository tests**

Append to `internal/repositories/key_rotation_policy_repository_test.go`:

```go
func TestKeyRotationPolicy_GetDuePolicies_ReturnsOnlyEnabledDueRows(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))
	ctx := context.Background()
	now := time.Now()

	due := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: uuid.New(), UserID: uuid.New(), VaultID: uuid.New(),
		RotateAfterDays: 90, Enabled: true, NextRotationAt: now.Add(-time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
	notYetDue := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: uuid.New(), UserID: uuid.New(), VaultID: uuid.New(),
		RotateAfterDays: 90, Enabled: true, NextRotationAt: now.Add(time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
	disabledButDue := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: uuid.New(), UserID: uuid.New(), VaultID: uuid.New(),
		RotateAfterDays: 90, Enabled: false, NextRotationAt: now.Add(-time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
	noActionConfigured := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: uuid.New(), UserID: uuid.New(), VaultID: uuid.New(),
		RotateAfterDays: 0, Enabled: true, NextRotationAt: now.Add(-time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
	for _, p := range []*model.KeyRotationPolicy{due, notYetDue, disabledButDue, noActionConfigured} {
		require.NoError(t, repo.Upsert(ctx, p))
	}

	got, err := repo.GetDuePolicies(ctx, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, due.ID, got[0].ID)
}

func TestKeyRotationPolicy_MarkRotated_UpdatesBothTimestamps(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	now := time.Now()
	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: uuid.New(), VaultID: vaultID,
		RotateAfterDays: 30, Enabled: true, NextRotationAt: now.Add(-time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	rotatedAt := now.Truncate(time.Second)
	require.NoError(t, repo.MarkRotated(ctx, keyID, model.NewAdminScope(uuid.Nil), rotatedAt, 30))

	scope := model.NewVaultScope(vaultID, uuid.New())
	loaded, err := repo.GetByKeyID(ctx, keyID, scope)
	require.NoError(t, err)
	require.NotNil(t, loaded.LastRotatedAt)
	require.WithinDuration(t, rotatedAt, *loaded.LastRotatedAt, time.Second)
	require.WithinDuration(t, rotatedAt.AddDate(0, 0, 30), loaded.NextRotationAt, time.Second)
}

func TestKeyRotationPolicy_MarkRotated_UnknownKeyReturnsNoRows(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))

	err := repo.MarkRotated(context.Background(), uuid.New(), model.NewAdminScope(uuid.Nil), time.Now(), 30)
	require.ErrorIs(t, err, sql.ErrNoRows)
}
```

Also update `setupKeyRotationPolicyTestDB` in the same file to add the two new columns to its `CREATE TABLE key_rotation_policies` statement (between `enabled` and `created_at`, same as Task 2 Step 3):

```go
		enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
		last_rotated_at            TIMESTAMP NULL,
		next_rotation_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/repositories/... -run TestKeyRotationPolicy -v`
Expected: FAIL — `GetDuePolicies`/`MarkRotated` don't exist yet.

- [ ] **Step 4: Extend the repository interface and implementation**

In `internal/repositories/key_rotation_policy_repository.go`, add `"fmt"` and `"time"` to the imports, then extend the interface:

```go
type KeyRotationPolicyRepositoryInterface interface {
	// Upsert inserts or replaces the policy for a key. policy.VaultID must be
	// the parent key's own vault — callers derive it from the key, never
	// supply it independently.
	Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error
	// GetByKeyID retrieves the policy for a key, scoped to a vault.
	GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error)
	// DeleteByKeyID removes the policy for a key, scoped to a vault.
	DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// GetDuePolicies returns enabled policies (with a configured rotation
	// action) whose next_rotation_at has passed, authorized by scope. The
	// scheduler sweep always passes model.NewAdminScope.
	GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error)
	// MarkRotated stamps last_rotated_at = at and recomputes
	// next_rotation_at = at + rotateAfterDays, after a successful automatic
	// rotation. rotateAfterDays is supplied by the caller (already available
	// from the GetDuePolicies row) so this stays a plain parameterized
	// UPDATE with no per-row SQL date arithmetic.
	MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error
}
```

Update `Upsert` to persist the two new columns:

```go
func (r *KeyRotationPolicyRepository) Upsert(ctx context.Context, p *model.KeyRotationPolicy) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO key_rotation_policies
			(id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
			 expiry_days, enabled, last_rotated_at, next_rotation_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key_id) DO UPDATE SET
			rotate_after_days         = excluded.rotate_after_days,
			notify_before_expiry_days = excluded.notify_before_expiry_days,
			expiry_days               = excluded.expiry_days,
			enabled                   = excluded.enabled,
			last_rotated_at           = excluded.last_rotated_at,
			next_rotation_at          = excluded.next_rotation_at,
			updated_at                = excluded.updated_at`,
		p.ID.String(), p.KeyID.String(), p.UserID.String(), p.VaultID.String(),
		p.RotateAfterDays, p.NotifyBeforeExpiryDays, p.ExpiryDays, p.Enabled,
		p.LastRotatedAt, p.NextRotationAt, p.CreatedAt, p.UpdatedAt,
	)
	return err
}
```

Update `GetByKeyID`'s SELECT column list and `scanKeyRotationPolicyRow`:

```go
func (r *KeyRotationPolicyRepository) GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	query := `
		SELECT id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, last_rotated_at, next_rotation_at, created_at, updated_at
		FROM key_rotation_policies WHERE key_id = ?
	`
	return ScopedGet(ctx, r.db, query, []any{keyID.String()}, scope, scanKeyRotationPolicyRow)
}

// scanKeyRotationPolicyRow scans one key_rotation_policies row.
func scanKeyRotationPolicyRow(row *sql.Row) (*model.KeyRotationPolicy, error) {
	var p model.KeyRotationPolicy
	var idStr, keyIDStr, userIDStr, vaultIDStr string
	var lastRotatedAt sql.NullTime
	if err := row.Scan(&idStr, &keyIDStr, &userIDStr, &vaultIDStr,
		&p.RotateAfterDays, &p.NotifyBeforeExpiryDays, &p.ExpiryDays, &p.Enabled,
		&lastRotatedAt, &p.NextRotationAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if p.ID, err = uuid.Parse(idStr); err != nil {
		return nil, err
	}
	if p.KeyID, err = uuid.Parse(keyIDStr); err != nil {
		return nil, err
	}
	if p.UserID, err = uuid.Parse(userIDStr); err != nil {
		return nil, err
	}
	if p.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return nil, err
	}
	if lastRotatedAt.Valid {
		p.LastRotatedAt = &lastRotatedAt.Time
	}
	return &p, nil
}
```

Add `GetDuePolicies`, its row-scan helper, and `MarkRotated`:

```go
// GetDuePolicies returns enabled policies with a configured rotation action
// (rotate_after_days > 0) whose next_rotation_at has passed, authorized by
// scope. The scheduler sweep always passes an admin scope (see spec section 10).
func (r *KeyRotationPolicyRepository) GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	query := `
		SELECT id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, last_rotated_at, next_rotation_at, created_at, updated_at
		FROM key_rotation_policies
		WHERE enabled = TRUE AND rotate_after_days > 0 AND next_rotation_at <= ?
	`
	due, err := ScopedList(ctx, r.db, query, []any{time.Now()}, scope, scanKeyRotationPolicyRows)
	if err != nil {
		r.log.WithError(err).Error("Failed to get due key rotation policies")
		return nil, fmt.Errorf("failed to get due key rotation policies: %w", err)
	}
	return due, nil
}

// scanKeyRotationPolicyRows scans one key_rotation_policies row from a
// *sql.Rows cursor (ScopedList's shape), mirroring scanKeyRotationPolicyRow.
func scanKeyRotationPolicyRows(rows *sql.Rows) (model.KeyRotationPolicy, error) {
	var p model.KeyRotationPolicy
	var idStr, keyIDStr, userIDStr, vaultIDStr string
	var lastRotatedAt sql.NullTime
	if err := rows.Scan(&idStr, &keyIDStr, &userIDStr, &vaultIDStr,
		&p.RotateAfterDays, &p.NotifyBeforeExpiryDays, &p.ExpiryDays, &p.Enabled,
		&lastRotatedAt, &p.NextRotationAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	var err error
	if p.ID, err = uuid.Parse(idStr); err != nil {
		return p, err
	}
	if p.KeyID, err = uuid.Parse(keyIDStr); err != nil {
		return p, err
	}
	if p.UserID, err = uuid.Parse(userIDStr); err != nil {
		return p, err
	}
	if p.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return p, err
	}
	if lastRotatedAt.Valid {
		p.LastRotatedAt = &lastRotatedAt.Time
	}
	return p, nil
}

// MarkRotated stamps last_rotated_at = at and recomputes
// next_rotation_at = at + rotateAfterDays, after a successful automatic
// rotation. Returns sql.ErrNoRows if keyID has no policy within scope.
func (r *KeyRotationPolicyRepository) MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error {
	next := at.AddDate(0, 0, rotateAfterDays)
	result, err := ScopedExec(ctx, r.db,
		"UPDATE key_rotation_policies SET last_rotated_at = ?, next_rotation_at = ? WHERE key_id = ?",
		[]any{at, next, keyID.String()}, scope)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
```

- [ ] **Step 5: Extend `mockKeyPolicyRepo` in `internal/services/keys/key_service_test.go`**

Add these two methods so `mockKeyPolicyRepo` keeps satisfying `KeyRotationPolicyRepositoryInterface`:

```go
func (m *mockKeyPolicyRepo) GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	args := m.Called(ctx, scope)
	if v := args.Get(0); v != nil {
		return v.([]model.KeyRotationPolicy), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyPolicyRepo) MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error {
	return m.Called(ctx, keyID, scope, at, rotateAfterDays).Error(0)
}
```

Add `"time"` to that file's imports if not already present.

- [ ] **Step 6: Extend `mockKeyRotationPolicyRepo` in `api/key_rotation_policy_test.go`**

Read the existing `mockKeyRotationPolicyRepo` definition in that file first to match its exact receiver/style, then add the same two methods (same bodies as Step 5, adjusted to that file's receiver name). Add `"time"` to that file's imports if not already present.

- [ ] **Step 7: Update `KeyService.UpsertKeyRotationPolicy` to compute `NextRotationAt`**

In `internal/services/keys/key_service.go`, replace the body of `UpsertKeyRotationPolicy`:

```go
// UpsertKeyRotationPolicy creates or replaces the rotation policy for keyID,
// authorized by scope against the parent key.
func (s *keyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	// Preserve an existing policy's rotation history: an Upsert that only
	// changes e.g. notify_before_expiry_days must not reset the due-date
	// clock an earlier automatic rotation already advanced.
	var lastRotatedAt *time.Time
	baseline := key.CreatedAt
	if existing, err := s.policyRepo.GetByKeyID(ctx, keyID, scope); err == nil && existing != nil {
		lastRotatedAt = existing.LastRotatedAt
		if lastRotatedAt != nil {
			baseline = *lastRotatedAt
		}
	}

	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 scope.ActorID(),
		VaultID:                key.VaultID, // derived from the parent key, never from the caller
		RotateAfterDays:        req.RotateAfterDays,
		NotifyBeforeExpiryDays: req.NotifyBeforeExpiryDays,
		ExpiryDays:             req.ExpiryDays,
		Enabled:                req.Enabled,
		LastRotatedAt:          lastRotatedAt,
		NextRotationAt:         baseline.AddDate(0, 0, req.RotateAfterDays),
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	// Read-after-write so the caller gets the canonical stored row.
	return s.policyRepo.GetByKeyID(ctx, keyID, scope)
}
```

- [ ] **Step 8: Update the existing `TestUpsertKeyRotationPolicy...` tests' mock expectations**

Grep `internal/services/keys/key_service_test.go` for existing tests calling `UpsertKeyRotationPolicy` (e.g. a test named similarly to `TestGetKeyRotationPolicy_VerifiesKeyAccessFirst`). Each one that sets up `policyRepo.On("Upsert", ...)` expectations now also needs a `policyRepo.On("GetByKeyID", ...)` expectation for the new pre-read (return `(nil, sql.ErrNoRows)` for a "no existing policy" case, or an existing `*model.KeyRotationPolicy` for an "update an existing policy" case) *before* the `Upsert` call's own expectation, plus the existing read-after-write `GetByKeyID` call already expected after `Upsert`. Use `mock.Anything` liberally rather than exact-matching the now-more-complex `*model.KeyRotationPolicy` argument to `Upsert`, unless a test specifically asserts on `NextRotationAt`/`LastRotatedAt`.

- [ ] **Step 9: Run all affected tests**

Run: `go test ./model/... ./internal/repositories/... ./internal/services/keys/... ./api/... -v`
Expected: PASS.

- [ ] **Step 10: Run the full build and test suite**

Run: `go build ./... && go test ./...`
Expected: PASS — confirms no other implementer of `KeyRotationPolicyRepositoryInterface` was missed.

- [ ] **Step 11: Commit**

```bash
git add model/key_rotation_policy.go internal/repositories/key_rotation_policy_repository.go internal/repositories/key_rotation_policy_repository_test.go internal/services/keys/key_service.go internal/services/keys/key_service_test.go api/key_rotation_policy_test.go
git commit -m "feat(keys): track rotation due-dates in key_rotation_policies"
```

---

### Task 4: Key rotation executor + scheduler wrapper

**Files:**
- Create: `internal/services/keys/rotation_executor.go`
- Create: `internal/services/keys/rotation_executor_test.go`
- Create: `internal/services/keys/rotation_scheduler.go`

**Interfaces:**
- Consumes: `schedulerkit.NewRunner`/`Runner` (Task 1); `KeyRotationPolicyRepositoryInterface.GetDuePolicies`/`.MarkRotated` (Task 3); `KeyService.RotateKey` (pre-existing, unchanged).
- Produces: `keys.NewRotationExecutor(keyService, policyRepo, log) *RotationExecutor` with method `Check(ctx) error` (a `schedulerkit.CheckFunc`); `keys.NewRotationScheduler(executor *RotationExecutor, log *logging.Logger, interval time.Duration) *RotationScheduler` with `Start(ctx)`/`Stop()`. Task 8 (bootstrap wiring) constructs both by these exact names.

- [ ] **Step 1: Write the failing executor tests**

Create `internal/services/keys/rotation_executor_test.go`:

```go
package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	keysmocks "rocketvault/internal/services/keys/mocks"
	"rocketvault/model"
)

func TestRotationExecutor_Check_RotatesDuePolicies(t *testing.T) {
	keySvc := keysmocks.NewMockKeyService(t)
	policyRepo := new(mockKeyPolicyRepo)

	keyID := uuid.New()
	due := []model.KeyRotationPolicy{{ID: uuid.New(), KeyID: keyID, Enabled: true, RotateAfterDays: 90}}

	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(due, nil)
	keySvc.EXPECT().RotateKey(mock.Anything, keyID, mock.Anything).Return(&CreateKeyResult{KeyID: keyID}, nil)
	policyRepo.On("MarkRotated", mock.Anything, keyID, mock.Anything, mock.AnythingOfType("time.Time"), 90).Return(nil)

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.NoError(t, exec.Check(context.Background()))

	policyRepo.AssertExpectations(t)
}

func TestRotationExecutor_Check_OneFailureDoesNotStopSweep(t *testing.T) {
	keySvc := keysmocks.NewMockKeyService(t)
	policyRepo := new(mockKeyPolicyRepo)

	badKey, goodKey := uuid.New(), uuid.New()
	due := []model.KeyRotationPolicy{
		{ID: uuid.New(), KeyID: badKey, Enabled: true, RotateAfterDays: 90},
		{ID: uuid.New(), KeyID: goodKey, Enabled: true, RotateAfterDays: 30},
	}
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(due, nil)
	keySvc.EXPECT().RotateKey(mock.Anything, badKey, mock.Anything).Return(nil, errors.New("rotation failed"))
	keySvc.EXPECT().RotateKey(mock.Anything, goodKey, mock.Anything).Return(&CreateKeyResult{KeyID: goodKey}, nil)
	policyRepo.On("MarkRotated", mock.Anything, goodKey, mock.Anything, mock.AnythingOfType("time.Time"), 30).Return(nil)

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.NoError(t, exec.Check(context.Background()))

	policyRepo.AssertExpectations(t)
	policyRepo.AssertNotCalled(t, "MarkRotated", mock.Anything, badKey, mock.Anything, mock.Anything, mock.Anything)
}

func TestRotationExecutor_Check_MarkRotatedFailureIsLoggedNotFatal(t *testing.T) {
	keySvc := keysmocks.NewMockKeyService(t)
	policyRepo := new(mockKeyPolicyRepo)

	keyID := uuid.New()
	due := []model.KeyRotationPolicy{{ID: uuid.New(), KeyID: keyID, Enabled: true, RotateAfterDays: 90}}
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(due, nil)
	keySvc.EXPECT().RotateKey(mock.Anything, keyID, mock.Anything).Return(&CreateKeyResult{KeyID: keyID}, nil)
	policyRepo.On("MarkRotated", mock.Anything, keyID, mock.Anything, mock.AnythingOfType("time.Time"), 90).
		Return(errors.New("db write failed"))

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	// The rotation itself succeeded; a bookkeeping failure must not surface
	// as a sweep-level error (that would risk a double-rotation retry).
	require.NoError(t, exec.Check(context.Background()))
}

func TestRotationExecutor_Check_GetDuePoliciesErrorPropagates(t *testing.T) {
	keySvc := keysmocks.NewMockKeyService(t)
	policyRepo := new(mockKeyPolicyRepo)
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(nil, errors.New("db unavailable"))

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.Error(t, exec.Check(context.Background()))
}

func TestRotationExecutor_Check_NoDuePolicies_NoOp(t *testing.T) {
	keySvc := keysmocks.NewMockKeyService(t)
	policyRepo := new(mockKeyPolicyRepo)
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return([]model.KeyRotationPolicy{}, nil)

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.NoError(t, exec.Check(context.Background()))
	// keySvc has no RotateKey expectations set -- an unexpected call would
	// fail the mock automatically.
}
```

This test file lives in package `keys` (not `keys_test`), so it reuses `mockKeyPolicyRepo` (defined in `key_service_test.go`, same package, extended in Task 3) and `newTestKeyLogger` (existing helper in this package's tests) directly with no new imports for either.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/keys/... -run TestRotationExecutor -v`
Expected: FAIL — `NewRotationExecutor` doesn't exist yet.

- [ ] **Step 3: Implement the executor**

Create `internal/services/keys/rotation_executor.go`:

```go
package keys

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// RotationExecutor sweeps for due KeyRotationPolicy rows and rotates their keys.
type RotationExecutor struct {
	keyService KeyService
	policyRepo repositories.KeyRotationPolicyRepositoryInterface
	log        *logging.Logger
}

// NewRotationExecutor constructs a RotationExecutor.
func NewRotationExecutor(keyService KeyService, policyRepo repositories.KeyRotationPolicyRepositoryInterface, log *logging.Logger) *RotationExecutor {
	return &RotationExecutor{keyService: keyService, policyRepo: policyRepo, log: log}
}

// Check is a schedulerkit.CheckFunc: sweep due policies and rotate their
// keys. The sweep is deliberately vault-agnostic (model.NewAdminScope) --
// this is a trusted background process, not a per-vault user request; see
// docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md
// section 10. A returned error here means the sweep itself could not run
// (e.g. the due-policy query failed); a single key's rotation failing is
// logged and does not abort the rest of the sweep.
func (e *RotationExecutor) Check(ctx context.Context) error {
	due, err := e.policyRepo.GetDuePolicies(ctx, model.NewAdminScope(uuid.Nil))
	if err != nil {
		return fmt.Errorf("get due key rotation policies: %w", err)
	}
	for _, policy := range due {
		if _, err := e.keyService.RotateKey(ctx, policy.KeyID, model.NewAdminScope(uuid.Nil)); err != nil {
			e.log.WithError(err).WithField("key_id", policy.KeyID).Error("automatic key rotation failed")
			continue
		}
		if err := e.policyRepo.MarkRotated(ctx, policy.KeyID, model.NewAdminScope(uuid.Nil), time.Now(), policy.RotateAfterDays); err != nil {
			// Rotation already succeeded -- do not retry the rotation itself
			// next tick just because this bookkeeping write failed, or the
			// key would be double-rotated.
			e.log.WithError(err).WithField("key_id", policy.KeyID).Error("failed to record key rotation timestamp")
		}
	}
	return nil
}
```

- [ ] **Step 4: Implement the scheduler wrapper**

Create `internal/services/keys/rotation_scheduler.go`:

```go
package keys

import (
	"context"
	"time"

	"rocketvault/internal/logging"
	"rocketvault/internal/schedulerkit"
)

// RotationScheduler runs a RotationExecutor on a configurable interval.
type RotationScheduler struct {
	runner   *schedulerkit.Runner
	interval time.Duration
}

// NewRotationScheduler creates a scheduler with the given interval. If
// interval is <= 0 it defaults to 1 hour.
func NewRotationScheduler(executor *RotationExecutor, log *logging.Logger, interval time.Duration) *RotationScheduler {
	if interval <= 0 {
		interval = time.Hour
	}
	return &RotationScheduler{
		runner:   schedulerkit.NewRunner("key rotation", executor.Check, log),
		interval: interval,
	}
}

// Start launches the scheduler in a background goroutine.
func (s *RotationScheduler) Start(ctx context.Context) {
	_ = s.runner.Start(ctx, s.interval) // Runner logs its own start/error lines.
}

// Stop signals the scheduler to stop.
func (s *RotationScheduler) Stop() {
	_ = s.runner.Stop()
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/services/keys/... -v`
Expected: PASS (all key-package tests, including the pre-existing ones from Task 3).

- [ ] **Step 6: Commit**

```bash
git add internal/services/keys/rotation_executor.go internal/services/keys/rotation_executor_test.go internal/services/keys/rotation_scheduler.go
git commit -m "feat(keys): add automatic key rotation executor and scheduler"
```

---

### Task 5: Migrate the secrets scheduler onto `schedulerkit`

**Files:**
- Modify: `internal/services/secrets/scheduler_service.go`

**Interfaces:**
- Consumes: `schedulerkit.NewRunner`/`Runner` (Task 1).
- Produces: nothing new — `SchedulerServiceInterface` and every existing public method keep their exact signatures. This task is a pure internal refactor.

- [ ] **Step 1: Confirm there is no existing scheduler_service_test.go to break**

Run: `find internal/services/secrets -iname '*scheduler*test*'`. As of this plan being written, no such file exists — this task's only regression surface is the API/CLI tests that exercise `SchedulerServiceInterface` indirectly through `MockServiceContainer` (they mock the interface, so an internal refactor cannot break them). If a `scheduler_service_test.go` has since been added, read it before proceeding and make sure this task's changes keep it passing.

- [ ] **Step 2: Replace the ticker/lifecycle fields and methods with a Runner**

In `internal/services/secrets/scheduler_service.go`:

Replace the `schedulerService` struct:

```go
// schedulerService implements SchedulerServiceInterface with service dependencies.
type schedulerService struct {
	rotationSvc   RotationServiceInterface
	versioningSvc VersioningServiceInterface
	userRepo      repositories.UserRepositoryInterface
	secretRepo    repositories.SecretRepositoryInterface
	rotationRepo  repositories.RotationPolicyRepositoryInterface
	log           *logging.Logger
	runner        *schedulerkit.Runner
}
```

Replace `NewSchedulerService`:

```go
// NewSchedulerService creates a new scheduler service with proper service dependencies.
func NewSchedulerService(
	rotationSvc RotationServiceInterface,
	versioningSvc VersioningServiceInterface,
	userRepo repositories.UserRepositoryInterface,
	secretRepo repositories.SecretRepositoryInterface,
	rotationRepo repositories.RotationPolicyRepositoryInterface,
	log *logging.Logger,
) SchedulerServiceInterface {
	s := &schedulerService{
		rotationSvc:   rotationSvc,
		versioningSvc: versioningSvc,
		userRepo:      userRepo,
		secretRepo:    secretRepo,
		rotationRepo:  rotationRepo,
		log:           log,
	}
	s.runner = schedulerkit.NewRunner("secret rotation", func(ctx context.Context) error {
		s.processAllUserOperations(ctx)
		return nil
	}, log)
	return s
}
```

Replace `Start`/`Stop`/`IsRunning`/`run` (delete `run` entirely):

```go
// Start begins the rotation scheduler with business logic orchestration.
func (s *schedulerService) Start(ctx context.Context, interval time.Duration) error {
	return s.runner.Start(ctx, interval)
}

// Stop stops the rotation scheduler gracefully.
func (s *schedulerService) Stop() error {
	return s.runner.Stop()
}

// IsRunning returns whether the scheduler is currently running.
func (s *schedulerService) IsRunning() bool {
	return s.runner.IsRunning()
}
```

Update `processAllUserOperations` to take `ctx` as a parameter instead of reading it from a removed `s.ctx` field:

```go
// processAllUserOperations processes rotations and reminders for all users.
func (s *schedulerService) processAllUserOperations(ctx context.Context) {
	users, err := s.getAllUsers(ctx)
	if err != nil {
		s.log.WithError(err).Error("Failed to get users for rotation processing")
		return
	}

	for _, userID := range users {
		err := s.ProcessUserRotations(ctx, userID)
		if err != nil {
			s.log.WithError(err).WithField("user_id", userID).Error("Failed to process user rotations")
		}

		err = s.ProcessUserReminders(ctx, userID)
		if err != nil {
			s.log.WithError(err).WithField("user_id", userID).Error("Failed to process user reminders")
		}
	}
}
```

Update the import block: remove `"sync"` (no longer used — `Runner` owns its own `sync.WaitGroup`/`sync.RWMutex`), add `"rocketvault/internal/schedulerkit"`. Leave every other method (`ProcessUserRotations`, `ProcessUserReminders`, `PerformManualRotation`, `performAutomaticRotation`, `sendReminder`, `getAllUsers`) untouched.

- [ ] **Step 3: Build and test**

Run: `go build ./internal/services/secrets/... && go test ./internal/services/secrets/... ./api/... ./cmd/... -v`
Expected: PASS. `go build` first catches the removed `sync` import / removed `s.ctx` field cleanly before running the broader test sweep.

- [ ] **Step 4: Commit**

```bash
git add internal/services/secrets/scheduler_service.go
git commit -m "refactor(secrets): move scheduler onto schedulerkit.Runner"
```

---

### Task 6: Migrate the certificate scheduler onto `schedulerkit`

**Files:**
- Modify: `internal/services/certificates/renewal_scheduler.go`

**Interfaces:**
- Consumes: `schedulerkit.NewRunner`/`Runner` (Task 1).
- Produces: nothing new — `CertificateRenewalScheduler`'s exported type name, `NewCertificateRenewalScheduler` constructor signature, and `Start(ctx)`/`Stop()` methods are unchanged. `bootstrap.go` and `bootstrap_test.go` (`TestShutdown_WithRenewalScheduler_StopsCleanly`) must keep compiling and passing with no changes.

- [ ] **Step 1: Replace the implementation**

Replace the full contents of `internal/services/certificates/renewal_scheduler.go`:

```go
package certificates

import (
	"context"
	"time"

	"rocketvault/internal/logging"
	"rocketvault/internal/schedulerkit"
)

// CertificateRenewalScheduler runs CertificateRenewalService on a configurable interval.
type CertificateRenewalScheduler struct {
	runner   *schedulerkit.Runner
	interval time.Duration
}

// NewCertificateRenewalScheduler creates a scheduler with the given interval.
// If interval is <= 0 it defaults to 24 hours.
func NewCertificateRenewalScheduler(svc CertificateRenewalService, log *logging.Logger, interval time.Duration) *CertificateRenewalScheduler {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	check := func(ctx context.Context) error {
		renewed, warned, err := svc.CheckAndRenewCertificates(ctx)
		if err != nil {
			log.WithError(err).Error("certificate renewal check failed")
			return nil // handled here; nothing further for the Runner to log
		}
		if renewed > 0 || warned > 0 {
			log.Infof("certificate renewal check: %d renewed, %d warned", renewed, warned)
		}
		return nil
	}
	return &CertificateRenewalScheduler{
		runner:   schedulerkit.NewRunner("certificate renewal", check, log),
		interval: interval,
	}
}

// Start launches the scheduler in a background goroutine.
func (s *CertificateRenewalScheduler) Start(ctx context.Context) {
	_ = s.runner.Start(ctx, s.interval)
}

// Stop signals the scheduler to stop.
func (s *CertificateRenewalScheduler) Stop() {
	_ = s.runner.Stop()
}
```

Note this preserves the original's exact log semantics: a `CheckAndRenewCertificates` error is still logged as `"certificate renewal check failed"` (not the Runner's generic `"%s scheduler tick failed"` line) by returning `nil` from `check` after logging — `svc` is `nil`-safe here in the sense that `bootstrap_test.go`'s `TestShutdown_WithRenewalScheduler_StopsCleanly` constructs this scheduler with `svc = nil` but never calls `Start()`, so `check` (which would nil-deref on `svc.CheckAndRenewCertificates`) is never invoked by that test.

- [ ] **Step 2: Build and test**

Run: `go build ./internal/services/certificates/... ./bootstrap/... && go test ./internal/services/certificates/... ./bootstrap/... -v`
Expected: PASS, including the existing `TestShutdown_WithRenewalScheduler_StopsCleanly`.

- [ ] **Step 3: Commit**

```bash
git add internal/services/certificates/renewal_scheduler.go
git commit -m "refactor(certificates): move renewal scheduler onto schedulerkit.Runner"
```

---

### Task 7: Unified `rotation:` config

**Files:**
- Modify: `config/config.go`
- Modify: `config/config_test.go`
- Modify: `.rocketvault.yaml.example`

**Interfaces:**
- Consumes: nothing.
- Produces: `config.RotationConfig` (with `Secrets`, `Certificates`, `Keys` fields, each a `config.ResourceRotationConfig{Enabled bool; Interval time.Duration}`) and `config.LoadRotationConfig() RotationConfig`. Task 8 (bootstrap wiring) calls this by exact name.

- [ ] **Step 1: Write the failing config tests**

Read `config/config_test.go` first to match its existing style for `LoadMonitoringConfig`/`LoadSoftDeleteConfig` tests (setup/teardown of `viper` state between tests), then add, following that same style:

```go
func TestLoadRotationConfig_Defaults(t *testing.T) {
	viper.Reset()
	cfg := LoadRotationConfig()
	require.True(t, cfg.Secrets.Enabled)
	require.Equal(t, time.Hour, cfg.Secrets.Interval)
	require.True(t, cfg.Certificates.Enabled)
	require.Equal(t, 24*time.Hour, cfg.Certificates.Interval)
	require.True(t, cfg.Keys.Enabled)
	require.Equal(t, time.Hour, cfg.Keys.Interval)
}

func TestLoadRotationConfig_OverridesFromViper(t *testing.T) {
	viper.Reset()
	viper.Set("rotation.secrets.enabled", false)
	viper.Set("rotation.keys.interval", "30m")
	viper.Set("rotation.certificates.enabled", false)
	cfg := LoadRotationConfig()

	require.False(t, cfg.Secrets.Enabled)
	require.Equal(t, time.Hour, cfg.Secrets.Interval) // untouched key keeps its default
	require.Equal(t, 30*time.Minute, cfg.Keys.Interval)
	require.False(t, cfg.Certificates.Enabled)
}
```

Match whatever assertion library (`require` vs `assert`) and `viper.Reset()`-vs-manual-unset convention the existing tests in this file already use; adjust the snippets above to match rather than introducing a second style.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/... -run TestLoadRotationConfig -v`
Expected: FAIL — `LoadRotationConfig` doesn't exist yet.

- [ ] **Step 3: Implement `RotationConfig`**

In `config/config.go`, add after `LoadMonitoringConfig` (and before the `CacheConfig` block):

```go
// ResourceRotationConfig controls one resource type's rotation scheduler.
type ResourceRotationConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

// RotationConfig holds ResourceRotationConfig for every resource type with a
// rotation scheduler: secrets, certificates, and keys.
type RotationConfig struct {
	Secrets      ResourceRotationConfig `mapstructure:"secrets"`
	Certificates ResourceRotationConfig `mapstructure:"certificates"`
	Keys         ResourceRotationConfig `mapstructure:"keys"`
}

// loadResourceRotationConfig reads one resource type's rotation.<prefix>.*
// keys from Viper, overriding def field-by-field for whichever keys are
// explicitly set.
func loadResourceRotationConfig(prefix string, def ResourceRotationConfig) ResourceRotationConfig {
	cfg := def
	if viper.IsSet(prefix + ".enabled") {
		cfg.Enabled = viper.GetBool(prefix + ".enabled")
	}
	if viper.IsSet(prefix + ".interval") {
		cfg.Interval = viper.GetDuration(prefix + ".interval")
	}
	return cfg
}

// LoadRotationConfig reads rotation.<resource>.* settings from Viper for
// secrets, certificates, and keys, falling back to defaults that exactly
// match this codebase's previous hardcoded values (1h for secrets and keys,
// 24h for certificates) so a config with no rotation: section behaves
// identically to before this config section existed.
func LoadRotationConfig() RotationConfig {
	return RotationConfig{
		Secrets:      loadResourceRotationConfig("rotation.secrets", ResourceRotationConfig{Enabled: true, Interval: time.Hour}),
		Certificates: loadResourceRotationConfig("rotation.certificates", ResourceRotationConfig{Enabled: true, Interval: 24 * time.Hour}),
		Keys:         loadResourceRotationConfig("rotation.keys", ResourceRotationConfig{Enabled: true, Interval: time.Hour}),
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/... -v`
Expected: PASS.

- [ ] **Step 5: Document the new section in `.rocketvault.yaml.example`**

In `.rocketvault.yaml.example`, insert after the existing `monitoring:` block (before `# Health Check Configuration`):

```yaml

# Rotation scheduler intervals for secrets, certificates, and keys. Defaults
# shown below match this file's previous hardcoded behavior; this section is
# optional -- omitting it entirely is equivalent to these defaults.
rotation:
  secrets:
    enabled: true
    interval: "1h"
  certificates:
    enabled: true
    interval: "24h"
  keys:
    enabled: true
    interval: "1h"
```

- [ ] **Step 6: Commit**

```bash
git add config/config.go config/config_test.go .rocketvault.yaml.example
git commit -m "feat(config): add unified rotation: YAML section"
```

---

### Task 8: Bootstrap wiring

**Files:**
- Modify: `bootstrap/bootstrap.go`
- Modify: `bootstrap/bootstrap_test.go`

**Interfaces:**
- Consumes: `config.LoadRotationConfig` (Task 7); `keys.NewRotationExecutor`/`NewRotationScheduler` (Task 4); `app.WithSchedulerEnabled` (pre-existing, unchanged).
- Produces: nothing new for later tasks — this is the final integration point.

- [ ] **Step 1: Load rotation config and store it on `bootstrap`**

In `bootstrap/bootstrap.go`, add `keysServices "rocketvault/internal/services/keys"` to the imports (alongside the existing `certServices "rocketvault/internal/services/certificates"`).

Add a field to the `bootstrap` struct, alongside the existing scheduler fields:

```go
type bootstrap struct {
	dbInitializer      *DatabaseInitializer
	serverStarter      *ServerStarter
	configValidator    *ConfigurationValidator
	serviceContainer   *container.ServiceContainer
	cfg                *config.Config
	purgeScheduler     *softdelete.PurgeScheduler
	renewalScheduler   *certServices.CertificateRenewalScheduler
	keyRotationScheduler *keysServices.RotationScheduler
	metricsScheduler   *metrics.MetricsScheduler
	monitoringCfg      config.MonitoringConfig
	rotationCfg        config.RotationConfig
}
```

In `setup`, right after the existing `b.monitoringCfg = config.LoadMonitoringConfig()` line (Step 2a), add:

```go
	// Step 2a-1: Load rotation scheduler config for secrets, certs, and keys.
	b.rotationCfg = config.LoadRotationConfig()
```

- [ ] **Step 2: Make the certificate scheduler config-driven**

Replace the existing unconditional block:

```go
	// Step 2c: Start certificate renewal scheduler.
	if sc := b.serviceContainer.GetCertificateRenewalService(); sc != nil {
		b.renewalScheduler = certServices.NewCertificateRenewalScheduler(sc, b.cfg.Logger, 24*time.Hour)
		b.renewalScheduler.Start(ctx)
		b.cfg.Logger.Info("Certificate renewal scheduler started")
	}
```

with:

```go
	// Step 2c: Start certificate renewal scheduler, if enabled.
	if sc := b.serviceContainer.GetCertificateRenewalService(); sc != nil && b.rotationCfg.Certificates.Enabled {
		b.renewalScheduler = certServices.NewCertificateRenewalScheduler(sc, b.cfg.Logger, b.rotationCfg.Certificates.Interval)
		b.renewalScheduler.Start(ctx)
		b.cfg.Logger.Info("Certificate renewal scheduler started")
	}
```

- [ ] **Step 3: Wire the new key rotation scheduler**

Immediately after that block, add:

```go
	// Step 2d: Start key rotation scheduler, if enabled.
	if b.rotationCfg.Keys.Enabled {
		executor := keysServices.NewRotationExecutor(
			b.serviceContainer.GetKeyService(),
			b.serviceContainer.GetKeyRotationPolicyRepository(),
			b.cfg.Logger,
		)
		b.keyRotationScheduler = keysServices.NewRotationScheduler(executor, b.cfg.Logger, b.rotationCfg.Keys.Interval)
		b.keyRotationScheduler.Start(ctx)
		b.cfg.Logger.Info("Key rotation scheduler started")
	}
```

This block must come after `serviceContainer` is assigned (Step 3 of `setup`, ~line 316-323) — the certificate scheduler block it's placed after already runs after that point, so no reordering is needed as long as this is inserted directly after Step 2's edit.

- [ ] **Step 4: Make the secrets scheduler config-driven**

In `createApplication`, replace:

```go
		app.WithSchedulerEnabled(true, 1*time.Hour), // Enable scheduler with 1-hour interval.
```

with:

```go
		app.WithSchedulerEnabled(b.rotationCfg.Secrets.Enabled, b.rotationCfg.Secrets.Interval),
```

- [ ] **Step 5: Stop the key rotation scheduler on shutdown**

In `Shutdown`, add alongside the existing `renewalScheduler` block:

```go
	if b.keyRotationScheduler != nil {
		b.keyRotationScheduler.Stop()
		logrus.Info("Key rotation scheduler stopped")
	}
```

- [ ] **Step 6: Write the failing shutdown test**

In `bootstrap/bootstrap_test.go`, add, following the exact pattern of `TestShutdown_WithRenewalScheduler_StopsCleanly` immediately above it:

```go
// TestShutdown_WithKeyRotationScheduler covers the keyRotationScheduler != nil
// branch. We create the scheduler but do NOT Start() it, mirroring
// TestShutdown_WithRenewalScheduler_StopsCleanly -- Stop() must be safe on a
// never-started scheduler.
func TestShutdown_WithKeyRotationScheduler_StopsCleanly(t *testing.T) {
	t.Parallel()

	logger := newTestLogger()
	executor := keysServices.NewRotationExecutor(nil, nil, logger)
	sched := keysServices.NewRotationScheduler(executor, logger, time.Hour)

	bs := &bootstrap{keyRotationScheduler: sched}
	err := bs.Shutdown(context.Background())
	assert.NoError(t, err)
}
```

Add `keysServices "rocketvault/internal/services/keys"` to this test file's imports if not already present (it likely is not, since the key package wasn't previously referenced from `bootstrap_test.go`).

- [ ] **Step 7: Run tests to verify the new one fails, then passes**

Run: `go test ./bootstrap/... -run TestShutdown -v`
Expected: first FAIL (before Steps 1-5's edits are in place, if run out of order) — but since Steps 1-5 are applied first in this task, expect PASS directly once this step's test is added. If genuinely following strict red-green, temporarily revert Step 5's edit, confirm the new test fails without it, then reapply.

- [ ] **Step 8: Full build and test**

Run: `go build ./... && go test ./...`
Expected: PASS across the entire repository — this is the final integration task for the whole plan.

- [ ] **Step 9: Commit**

```bash
git add bootstrap/bootstrap.go bootstrap/bootstrap_test.go
git commit -m "feat(bootstrap): wire config-driven rotation schedulers, add key rotation"
```

---

## Post-plan follow-up (not part of this plan's tasks)

Once this plan is merged, `README.md`'s roadmap checklist item `- [ ] Rotation-policy scheduler — actually execute the rotation policies that already exist...` should move from `Planned` to the `Completed`/dated section above it (same pattern as the other dated roadmap entries in that file). This plan deliberately does not include that edit as a task — precedent (Spec A) handled README updates separately, outside the implementation plan itself.
