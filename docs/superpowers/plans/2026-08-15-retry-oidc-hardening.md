# Retry/OIDC Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four confirmed, adversarially-verified code-review findings in RocketVault's retry/circuit-breaker infrastructure and OIDC login callback, without regressing any existing behavior or crossing DDD layer boundaries.

**Architecture:** All four fixes stay inside `internal/retry` (the pure, dependency-free retry/circuit-breaker package) and the service layer (`internal/services/retry`, `internal/services/auth`) that consumes it. No repository, API handler, or middleware code changes — these bugs are entirely below the service layer's public contract, so the fix surface naturally respects the existing `api/` → `internal/services/` → `internal/repositories/` layering (see the service-layer-conventions skill). One fix (Bug D) adds a fourth named retry policy tier (`interactive`) alongside the existing `database`/`external_services`/`service_operations` tiers, following the exact pattern those three already establish across `retry.go`, `config.go`, `config_loader.go`, and `internal/services/retry/retry_service.go`.

**Tech Stack:** Go 1.24.2, `github.com/spf13/viper` (already a dependency), stdlib `sync`/`time`/`testing`. No new third-party dependencies.

**Spec:** No standalone spec document — this plan implements four findings from an automated adversarial code-review pass (`/code-review`), each independently re-verified by direct code research in this session. The full finding text and supporting research are reproduced in the "Background" section immediately below so an engineer with zero conversation context has everything needed.

## Global Constraints

- Go 1.24.2; no new third-party dependencies — everything is achievable with stdlib + the already-vendored `github.com/spf13/viper`.
- All interface changes are additive (new methods/fields), never breaking removals — `RetryService`, `RetryExecutor`, and `Config` gain members; nothing existing is deleted from their public surface.
- No repository or API-handler files are touched by this plan. If any task appears to require touching `api/` or `internal/repositories/`, stop and re-scope — that would mean the task has drifted outside the confirmed findings.
- Every task must leave `go build ./...`, `go vet ./...`, and the full existing test suite green before it is considered done — no task may leave the tree in a broken intermediate state for a later task to fix.
- Preserve existing behavior exactly except for the specific defect each task targets. Where a fix could plausibly also "improve" adjacent behavior (e.g. the circuit breaker's failure-reopen semantics), leave that adjacent behavior untouched unless a task explicitly says otherwise — minimizing surface area minimizes regression risk.

---

## Background: the four confirmed findings

Quoted verbatim from the code-review pass that triggered this plan:

1. **`internal/services/auth/oidc_service.go:218`** — the OAuth2 authorization-code exchange in `HandleCallback` is wrapped in a retry policy meant for idempotent calls; a lost response on a successful exchange causes a retry with an already-consumed code, failing login even though the first attempt succeeded.
2. **`internal/retry/config_loader.go:168`** — `SetRetryDefaults()`'s viper default for `retry.external_services.retryable_errors` wasn't updated to match the newer `ExternalServicePolicy()` retryable-error list, so deployments without an explicit override silently lose 5xx-retry behavior. (This repo's own `.rocketvault.yaml` masks it by setting the value explicitly.)
3. **`internal/retry/retry.go:133`** — `CircuitBreaker`'s Open→HalfOpen transition has a check-then-act race allowing multiple concurrent callers into the half-open trial at once instead of capping at `HalfOpenRequests`; newly reachable in production via this branch's retry-service wiring into concurrent HTTP paths like OIDC login.
4. **`internal/services/retry/retry_service.go:79`** — applying the generic external-services retry policy (up to 5 attempts / 30s max delay under default config) to the synchronous `/oidc/callback` request risks exceeding typical browser/reverse-proxy timeouts.

### Follow-up research (this session, direct code reads — not re-summarized, cited exactly)

**Finding 2 (stale defaults) — exact drift**, `internal/retry/retry.go:61-87` vs `internal/retry/config_loader.go:145-194`:

`ExternalServicePolicy()`'s `RetryableErrors` (8 entries): `"connection refused"`, `"no such host"`, `"timeout"`, `"temporary failure"`, `"service unavailable"`, `"too many requests"`, `"internal server error"`, `"bad gateway"`.

`SetRetryDefaults()`'s `retry.external_services.retryable_errors` (6 entries, missing the last two): `"connection refused"`, `"no such host"`, `"timeout"`, `"temporary failure"`, `"service unavailable"`, `"too many requests"`.

The same drift class exists for `retry.database.retryable_errors`: `DatabasePolicy()` (`retry.go:49-56`) has 6 entries including `"connection reset by peer"` and `"broken pipe"`; `SetRetryDefaults()`'s database block (`config_loader.go:154-159`) has only the first 4. This plan fixes both tiers with the same one-line-per-tier change, since leaving the database tier's identical bug in place while fixing external_services would just leave a known-duplicate defect for the next reviewer to re-find.

Confirmed shadowing mechanism: `viper.IsSet(key)` returns `true` purely from a `SetDefault`-registered value (viper v1.20.1 `viper.go:1356-1360`, `find()` falls through to `v.defaults`). `SetRetryDefaults()` runs at startup (`cmd/root.go`'s `initConfig()`), so `retry.external_services.retryable_errors` always has a default registered before `LoadConfig()` runs, making `loadPolicyConfig`'s `l.viper.IsSet(key + ".retryable_errors")` (`config_loader.go:85`) true even with no YAML override — so `GetStringSlice` returns the stale 6-entry list, and `mergePolicyWithDefaults` (`config_loader.go:229-230`) overwrites the correct 8-entry `ExternalServicePolicy()` default with it. Any deployment whose YAML omits `retry.external_services.retryable_errors` (this repo's own `.rocketvault.yaml:120-128` sets it explicitly, masking the bug locally) silently loses 5xx-phrase retry.

**Finding 3 (circuit breaker race) — exact mechanism**, `internal/retry/retry.go:106-212` (current, pre-fix):

```go
type CircuitBreaker struct {
	config        CircuitBreakerConfig
	failures      int
	lastFailure   time.Time
	state         CircuitState
	halfOpenCount int
	mu            sync.RWMutex
}

func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.RLock()
	state := cb.state
	cb.mu.RUnlock()

	switch state {
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.config.Timeout {
			cb.transitionToHalfOpen()
			return cb.executeHalfOpen(fn)
		}
		return ErrCircuitBreakerOpen
	case StateHalfOpen:
		return cb.executeHalfOpen(fn)
	case StateClosed:
		return cb.executeClosed(fn)
	default:
		return errors.New("unknown circuit breaker state")
	}
}

func (cb *CircuitBreaker) executeHalfOpen(fn func() error) error {
	cb.mu.Lock()
	cb.halfOpenCount++
	currentCount := cb.halfOpenCount
	cb.mu.Unlock()

	err := fn()
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.mu.Lock()
	if currentCount >= cb.config.HalfOpenRequests {
		cb.state = StateClosed
		cb.failures = 0
		cb.halfOpenCount = 0
	}
	cb.mu.Unlock()

	return nil
}

func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateHalfOpen
	cb.halfOpenCount = 0
}
```

`state` is read once under `RLock`, then the lock is released before `time.Since(cb.lastFailure) > cb.config.Timeout` is evaluated (that read is entirely unlocked — a second, independent race). Any number of concurrent goroutines can observe `StateOpen` with an elapsed timeout simultaneously, each call `transitionToHalfOpen()` (which unconditionally resets `halfOpenCount = 0`, even if another goroutine already reserved a slot), and each proceed into `executeHalfOpen`, which increments `halfOpenCount` unconditionally with **no check against `config.HalfOpenRequests` before calling `fn()`**. `HalfOpenRequests` is only consulted *after* a successful call, to decide whether to fully close — never as an admission cap. Confirmed sole production instantiation site: `internal/services/retry/retry_service.go:65-67`, one singleton per policy tier, shared across every concurrent HTTP request goroutine via the DI container (`internal/container/service_container.go:317`). No existing test in `internal/retry/*_test.go` spawns goroutines against a shared `*CircuitBreaker` — concurrent half-open admission is entirely untested today.

**Finding 1 (non-idempotent Exchange retried) — exact code**, `internal/services/auth/oidc_service.go:209-289` (current, pre-fix; full function already read directly for this plan):

All three of `HandleCallback`'s network calls — `Exchange` (218-222), `Verify` (233-237), `UserInfo` (265-269) — are wrapped identically in `withRetry(ctx, s.retryExecutor, func() error {...})`, which routes to `RetryExecutor.ExecuteExternalServiceOperation`. None distinguishes idempotency. `Exchange` redeems a single-use authorization code (RFC 6749 §4.1.3) — a lost response on a request the IdP already processed means retrying resends the same code, which the IdP correctly rejects as `invalid_grant`, turning a successful exchange into a failed login. Verify and UserInfo are naturally idempotent (re-verifying/re-fetching has no side effect) — retrying those is safe and desirable.

**Finding 4 (timeout budget) — exact numbers**, `internal/retry/config.go:80-99` (`ProductionConfig().ExternalServices`) and `retry.go:62-87` (`ExternalServicePolicy()`, used by `DefaultConfig()`): both are `MaxAttempts: 5, InitialDelay: 1s, MaxDelay: 30s, BackoffMultiplier: 2.0, JitterEnabled: true`. Worst-case backoff-sleep sum across 4 inter-attempt delays (with up to 30% jitter): `1.3 + 2.6 + 5.2 + 10.4 ≈ 19.5s` for a *single* `ExecuteExternalServiceOperation` call — before this plan's Finding-1 fix, `HandleCallback` made three such calls sequentially (Exchange, Verify, UserInfo), so a worst case could sum to ~58.5s of backoff sleep alone, well past the server's 30s `WriteTimeout` (`.rocketvault.yaml:69`) and typical browser/reverse-proxy timeouts. After this plan's Finding-1 fix, Exchange is no longer retried at all, leaving Verify and UserInfo — still up to ~39s combined under `ExternalServicePolicy()`, still too long for a request-path call. `ExecuteExternalServiceOperation` has exactly one production call site in the whole repo (`oidc_service.go`), used both for OIDC discovery (a one-time startup call, background, no timeout concern) and for `HandleCallback`'s per-request calls — there is no existing distinction between "background call" and "request-path call" policy budgets.

---

## File Structure

| File | Change |
|---|---|
| `internal/retry/config_loader.go` | Task 1: derive `SetRetryDefaults()`'s `retryable_errors` lists from the `*Policy()` functions instead of hand-duplicated literals |
| `internal/retry/config_loader_test.go` | Task 1: pin the derived-defaults fix with a new assertion |
| `internal/retry/retry.go` | Task 2: fix `CircuitBreaker`'s Open→HalfOpen admission race; Task 4: add `InteractivePolicy()` |
| `internal/retry/retry_test.go` | Task 2: new concurrent half-open admission test; Task 4: `InteractivePolicy()` sanity test |
| `internal/services/auth/oidc_service.go` | Task 3: stop retrying `Exchange`; Task 5: route `Verify`/`UserInfo` through the new interactive tier |
| `internal/services/auth/oidc_service_test.go` | Task 3: regression test proving `Exchange` is never retried; Task 5: regression test proving `Verify`/`UserInfo` use the interactive tier |
| `internal/retry/config.go` | Task 4: add `Config.Interactive` field, wire into `DefaultConfig`/`DevelopmentConfig`/`ProductionConfig`/`TestingConfig`/`Validate`/`Merge`/example docs |
| `internal/services/retry/retry_service.go` | Task 4: add `interactivePolicy`/`interactiveBreaker`, `ExecuteInteractiveOperation`, `GetInteractivePolicy` |
| `internal/services/retry/retry_wrappers_test.go` | Task 4: tests for the new tier's mechanical Execute/Get behavior |
| `.rocketvault.yaml` | Task 4: document the new `retry.interactive` block explicitly (same style as the other three tiers) |
| `.claude/known-bugs.md` | Task 6: record all four fixes with their commit hashes, following this file's existing `### B<N> — title` / `**Status**: Fixed in commit ...` convention |

---

## Task 1: Derive `SetRetryDefaults()`'s retryable-error lists from the policy functions

**Files:**
- Modify: `internal/retry/config_loader.go:154-159,168-174`
- Test: `internal/retry/config_loader_test.go` (extend `TestSetRetryDefaults`, lines 380-403)

**Interfaces:**
- Consumes: `DatabasePolicy()`, `ExternalServicePolicy()` (both already exported from `internal/retry/retry.go`, unchanged signatures: `func() Policy`).
- Produces: no new exported symbols — this task only changes what `SetRetryDefaults(v *viper.Viper)` sets as the default value for two viper keys.

- [ ] **Step 1: Write the failing test**

Add this to the end of `TestSetRetryDefaults` in `internal/retry/config_loader_test.go` (the function currently ends at line 403 with the circuit-breaker assertion; insert before its closing `}`):

```go
	// Check retryable_errors lists match their source-of-truth Policy
	// functions exactly — pins the fix for the defaults drifting apart
	// (SetRetryDefaults previously hand-duplicated these lists and fell out
	// of sync with DatabasePolicy()/ExternalServicePolicy() when the latter
	// gained new entries).
	dbErrors := v.GetStringSlice("retry.database.retryable_errors")
	if !reflect.DeepEqual(dbErrors, DatabasePolicy().RetryableErrors) {
		t.Errorf("retry.database.retryable_errors default = %v, want %v (DatabasePolicy().RetryableErrors)",
			dbErrors, DatabasePolicy().RetryableErrors)
	}
	extErrors := v.GetStringSlice("retry.external_services.retryable_errors")
	if !reflect.DeepEqual(extErrors, ExternalServicePolicy().RetryableErrors) {
		t.Errorf("retry.external_services.retryable_errors default = %v, want %v (ExternalServicePolicy().RetryableErrors)",
			extErrors, ExternalServicePolicy().RetryableErrors)
	}
```

Add `"reflect"` to the import block at the top of `internal/retry/config_loader_test.go` (currently `"strings"`, `"testing"`, `"time"`, `"github.com/spf13/viper"` — add `"reflect"` alongside them, alphabetically before `"strings"`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/retry/... -run TestSetRetryDefaults -v`
Expected: FAIL — `retry.external_services.retryable_errors default = [connection refused no such host timeout temporary failure service unavailable too many requests], want [connection refused no such host timeout temporary failure service unavailable too many requests internal server error bad gateway]` (and the equivalent database mismatch).

- [ ] **Step 3: Write minimal implementation**

In `internal/retry/config_loader.go`, replace the two hand-written literals in `SetRetryDefaults` (lines 154-159 and 168-174):

```go
	v.SetDefault("retry.database.retryable_errors", []string{
		"connection refused",
		"database is locked",
		"busy",
		"timeout",
	})
```
becomes:
```go
	v.SetDefault("retry.database.retryable_errors", DatabasePolicy().RetryableErrors)
```

and:
```go
	v.SetDefault("retry.external_services.retryable_errors", []string{
		"connection refused",
		"no such host",
		"timeout",
		"temporary failure",
		"service unavailable",
		"too many requests",
	})
```
becomes:
```go
	v.SetDefault("retry.external_services.retryable_errors", ExternalServicePolicy().RetryableErrors)
```

Both functions (`DatabasePolicy`, `ExternalServicePolicy`) are defined in `internal/retry/retry.go` and already in the same package as `config_loader.go` — no import changes needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/retry/... -run TestSetRetryDefaults -v`
Expected: PASS

- [ ] **Step 5: Run the full package test suite to check for regressions**

Run: `go test ./internal/retry/... -v`
Expected: PASS — in particular `TestConfigLoader_LoadConfig` and `TestBindRetryConfig` must still pass unchanged, since this task only changes the *value* two `SetDefault` calls register, not any loading/binding logic.

- [ ] **Step 6: Commit**

```bash
git add internal/retry/config_loader.go internal/retry/config_loader_test.go
git commit -m "fix(retry): derive SetRetryDefaults retryable_errors from policy functions

SetRetryDefaults hand-duplicated the database and external_services
retryable_errors lists instead of referencing DatabasePolicy()/
ExternalServicePolicy(). The external_services list had fallen out of
sync (missing the 5xx-reason-phrase entries added to
ExternalServicePolicy()), silently disabling 5xx retry for any
deployment that doesn't explicitly override the key in its own config."
```

---

## Task 2: Fix `CircuitBreaker`'s Open→HalfOpen admission race

**Files:**
- Modify: `internal/retry/retry.go:132-212` (the `Execute`, `executeClosed`, `executeHalfOpen`, `recordFailure`, `recordSuccess`, `transitionToHalfOpen` methods)
- Test: `internal/retry/retry_test.go` (new test, place after the existing `TestCircuitBreaker` at line ~309)

**Interfaces:**
- Consumes: nothing new — `CircuitBreaker`, `CircuitBreakerConfig`, `NewCircuitBreaker`, `GetState`, `ErrCircuitBreakerOpen` all keep their exact existing signatures.
- Produces: `CircuitBreaker.Execute(fn func() error) error` keeps its exact existing signature and exact existing external behavior (state transitions, close/reopen semantics) — only the *internal* admission race is fixed. No other file in the repo needs to change because of this task.

- [ ] **Step 1: Write the failing test**

Add to `internal/retry/retry_test.go`, immediately after the existing `TestCircuitBreaker` function (which ends at line 309):

```go
func TestCircuitBreaker_HalfOpenAdmissionIsCapped(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 1,
		Timeout:          20 * time.Millisecond,
		HalfOpenRequests: 2,
	}
	cb := NewCircuitBreaker(config)

	// Trip the breaker open.
	_ = cb.Execute(func() error { return errors.New("failure") })
	if cb.GetState() != StateOpen {
		t.Fatalf("expected state to be open after 1 failure, got %v", cb.GetState())
	}

	// Wait for the timeout to elapse, then fire far more concurrent callers
	// than HalfOpenRequests allows right as the breaker becomes eligible to
	// transition. Every fn() invocation blocks on admitted until the test
	// has counted how many callers got through, so admission (not
	// completion order) is what's under test.
	time.Sleep(config.Timeout + 10*time.Millisecond)

	const concurrentCallers = 20
	var admittedCount int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(concurrentCallers)
	for i := 0; i < concurrentCallers; i++ {
		go func() {
			defer wg.Done()
			<-start
			_ = cb.Execute(func() error {
				atomic.AddInt32(&admittedCount, 1)
				// Hold "in flight" briefly so concurrent admission attempts
				// genuinely overlap instead of serializing through fast
				// sequential calls.
				time.Sleep(5 * time.Millisecond)
				return nil
			})
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&admittedCount); got > int32(config.HalfOpenRequests) {
		t.Errorf("expected at most %d calls admitted into the half-open trial, got %d",
			config.HalfOpenRequests, got)
	}
}
```

Add `"sync"` and `"sync/atomic"` to the import block at the top of `internal/retry/retry_test.go` (currently `"context"`, `"errors"`, `"strings"`, `"testing"`, `"time"` — add both alongside them, alphabetically: `"context"`, `"errors"`, `"strings"`, `"sync"`, `"sync/atomic"`, `"testing"`, `"time"`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/retry/... -run TestCircuitBreaker_HalfOpenAdmissionIsCapped -race -v`
Expected: FAIL — `expected at most 2 calls admitted into the half-open trial, got 20` (or some number greater than 2; exact count may vary run to run since it's a genuine race, but should reliably exceed `HalfOpenRequests`).

- [ ] **Step 3: Write minimal implementation**

Replace `internal/retry/retry.go` lines 132-212 (from `// Execute runs the given function...` through the end of `transitionToHalfOpen`) with:

```go
// Execute runs fn through the circuit breaker. It returns
// ErrCircuitBreakerOpen without calling fn if the breaker denies admission:
// always denied while open (until config.Timeout has elapsed since the last
// failure), and capped at config.HalfOpenRequests concurrent/total trial
// calls while half-open.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	admitted, halfOpen := cb.admit()
	if !admitted {
		return ErrCircuitBreakerOpen
	}
	if halfOpen {
		return cb.finishHalfOpen(fn)
	}
	return cb.executeClosed(fn)
}

// admit atomically decides whether to let a call through, performing the
// Open→HalfOpen transition and reserving a half-open trial slot in the same
// critical section as the state check. This closes the race where multiple
// concurrent callers each observe a stale Open state (or a stale
// lastFailure) and each independently transition and admit themselves —
// the previous two-step "read state under RLock, then act unlocked"
// version allowed unbounded concurrent callers into the half-open trial
// regardless of config.HalfOpenRequests.
func (cb *CircuitBreaker) admit() (admitted bool, halfOpen bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true, false
	case StateOpen:
		if time.Since(cb.lastFailure) < cb.config.Timeout {
			return false, false
		}
		cb.state = StateHalfOpen
		cb.halfOpenCount = 1
		return true, true
	case StateHalfOpen:
		if cb.halfOpenCount >= cb.config.HalfOpenRequests {
			return false, false
		}
		cb.halfOpenCount++
		return true, true
	default:
		return false, false
	}
}

func (cb *CircuitBreaker) executeClosed(fn func() error) error {
	err := fn()
	if err != nil {
		cb.recordFailure()
	} else {
		cb.recordSuccess()
	}
	return err
}

// finishHalfOpen runs fn for an already-admitted half-open trial (slot
// reserved by admit) and applies its outcome, preserving the pre-existing
// semantics exactly: any failure reopens the breaker via recordFailure; the
// trial whose reservation brought halfOpenCount up to config.HalfOpenRequests
// closes the breaker on success.
func (cb *CircuitBreaker) finishHalfOpen(fn func() error) error {
	err := fn()
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.mu.Lock()
	if cb.halfOpenCount >= cb.config.HalfOpenRequests {
		cb.state = StateClosed
		cb.failures = 0
		cb.halfOpenCount = 0
	}
	cb.mu.Unlock()

	return nil
}

func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.config.FailureThreshold {
		cb.state = StateOpen
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
}
```

Note what changed vs. the original: `transitionToHalfOpen` is removed (its one call site is now inlined into `admit`'s locked `StateOpen` case); `executeHalfOpen` is renamed `finishHalfOpen` and no longer performs the admission increment itself (that moved into `admit`, gated by the `cb.halfOpenCount >= cb.config.HalfOpenRequests` check that was previously entirely absent before `fn()` was called); `recordFailure` and `recordSuccess` are byte-for-byte unchanged. `lastFailure` is now only ever read inside `admit`'s single `cb.mu.Lock()`/`defer cb.mu.Unlock()` critical section, fixing the second, independent unlocked read the original `Execute` had at `time.Since(cb.lastFailure)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/retry/... -run TestCircuitBreaker -race -v`
Expected: PASS for both `TestCircuitBreaker` (the pre-existing sequential test — confirms behavior preservation) and the new `TestCircuitBreaker_HalfOpenAdmissionIsCapped`.

- [ ] **Step 5: Run the full package test suite and the retry-consuming service package, with the race detector, to check for regressions**

Run: `go test ./internal/retry/... ./internal/services/retry/... -race -v`
Expected: PASS. Pay particular attention to `TestRetryService_CircuitBreaker_TripsAndShortCircuits`, `TestRetryService_CircuitBreaker_HalfOpensAfterTimeout`, and `TestRetryService_CircuitBreaker_IndependentPerPolicy` in `internal/services/retry/retry_circuit_breaker_test.go` — these exercise `CircuitBreaker` through `RetryService` and must still pass unchanged, since this task preserves `Execute`'s external contract exactly.

- [ ] **Step 6: Commit**

```bash
git add internal/retry/retry.go internal/retry/retry_test.go
git commit -m "fix(retry): close CircuitBreaker's Open->HalfOpen admission race

Execute previously read state under RLock, released the lock, then
acted on it unlocked (including an entirely-unlocked read of
lastFailure) — so concurrent callers could all observe a stale Open
state, each independently transition to HalfOpen, and each be
admitted into the half-open trial with no cap. HalfOpenRequests was
only ever checked after a successful call, never as an admission
gate before fn() ran.

admit() now performs the state check, Open->HalfOpen transition, and
half-open slot reservation as one locked critical section, capping
concurrent/total half-open trial admission at HalfOpenRequests while
preserving every other existing state-transition semantic exactly."
```

---

## Task 3: Stop retrying the non-idempotent OAuth2 authorization-code exchange

**Files:**
- Modify: `internal/services/auth/oidc_service.go:217-225`
- Test: `internal/services/auth/oidc_service_test.go` (extend `callbackFakeIdP`, add a new test after `TestHandleCallback_RetriesExchangeAndVerifyIndependently`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `HandleCallback`'s exported behavior is unchanged on the success path; on a failing `Exchange`, it now fails after exactly one attempt instead of retrying. No other file depends on the old retry-Exchange behavior (confirmed: `HandleCallback` has exactly one caller, `api/oidc.go`'s callback handler, which only checks for a non-nil error — it has no dependency on how many attempts were made).

- [ ] **Step 1: Write the failing test**

Add a failure-injection knob to `callbackFakeIdP` in `internal/services/auth/oidc_service_test.go`. First, add a field to the struct (after `jwksFailUntil int32`, before `userInfoAlwaysFail bool`, in the struct defined at lines 51-70):

```go
	// tokenFailUntil: token requests numbered <= this value return 500.
	tokenFailUntil int32
```

Then change the `/token` handler (lines 108-117) from:

```go
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.tokenCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.idToken,
		})
	})
```

to:

```go
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&f.tokenCalls, 1)
		if n <= atomic.LoadInt32(&f.tokenFailUntil) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.idToken,
		})
	})
```

Then add a new test after `TestHandleCallback_RetriesExchangeAndVerifyIndependently` (which ends at line 389):

```go
func TestHandleCallback_ExchangeIsNeverRetried(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.idToken = f.signIDToken(t, "client-1", "user-123", "nonce-abc")
	// The token endpoint fails on its first call. If Exchange were retried,
	// a second call would succeed and the login would too — proving the bug
	// this test guards against.
	atomic.StoreInt32(&f.tokenFailUntil, 1)

	executor := &countingRetryExecutor{maxAttempts: 3}
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: f.issuer, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		RetryExecutor: executor,
	})
	require.NoError(t, err)

	_, err = svc.HandleCallback(context.Background(), "auth-code-xyz", "nonce-abc")
	require.Error(t, err, "Exchange failing once must fail the login outright, not be silently retried")

	require.Equal(t, int32(1), atomic.LoadInt32(&f.tokenCalls),
		"Exchange must be attempted exactly once even on failure — replaying a single-use authorization code is unsafe")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/auth/... -run TestHandleCallback_ExchangeIsNeverRetried -v`
Expected: FAIL — `Exchange failing once must fail the login outright, not be silently retried: An error is expected but got nil` (because today's retry wrapper retries once more and the second `/token` call succeeds).

- [ ] **Step 3: Write minimal implementation**

In `internal/services/auth/oidc_service.go`, replace lines 217-225:

```go
	var token *oauth2.Token
	err := withRetry(ctx, s.retryExecutor, func() error {
		var err error
		token, err = s.oauth2Config.Exchange(ctx, code)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange failed: %w", err)
	}
```

with:

```go
	// Exchange redeems a single-use authorization code — it is not safe to
	// retry. If the response is lost after the IdP has already processed
	// the request (e.g. a timeout), replaying it sends the same code again
	// and the IdP correctly rejects it as invalid_grant, turning what was
	// actually a successful exchange into a failed login. Call it exactly
	// once; on failure the user can simply retry the login from the start,
	// which obtains a fresh code.
	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange failed: %w", err)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/auth/... -run TestHandleCallback -v`
Expected: PASS for `TestHandleCallback_ExchangeIsNeverRetried`, `TestHandleCallback_RetriesExchangeAndVerifyIndependently`, and `TestHandleCallback_UserInfoFailureIsSwallowed`.

- [ ] **Step 5: Run the full package test suite to check for regressions**

Run: `go test ./internal/services/auth/... -v`
Expected: PASS — all `TestOIDCService_*` and `TestNewOIDCService_*` tests unaffected (none of them exercise `Exchange` failing).

- [ ] **Step 6: Commit**

```bash
git add internal/services/auth/oidc_service.go internal/services/auth/oidc_service_test.go
git commit -m "fix(oidc): never retry the OAuth2 authorization-code exchange

Exchange redeems a single-use code. Wrapping it in the same retry
policy used for idempotent calls (Verify, UserInfo) meant a lost
response on a successful exchange caused a retry that replayed an
already-consumed code, which the IdP correctly rejects as
invalid_grant — turning a successful login attempt into a failure.
Exchange now runs exactly once; a failure surfaces immediately and
the user can restart the login flow for a fresh code."
```

---

## Task 4: Add a bounded `interactive` retry policy tier (plumbing only, not yet consumed)

This task adds the fourth policy tier end-to-end — `internal/retry` core, config loading, and `RetryService` — following the exact existing pattern of `database`/`external_services`/`service_operations`. It intentionally does not change `oidc_service.go` yet (that's Task 5) so this task's diff is reviewable purely as "does the new tier plumb through correctly," independent of "is it wired to the right caller."

**Files:**
- Modify: `internal/retry/retry.go` (add `InteractivePolicy()`)
- Modify: `internal/retry/config.go` (add `Config.Interactive`, wire into all four `*Config()` functions, `Validate`, `Merge`, `ExampleYAML`, `ExampleJSON`)
- Modify: `internal/retry/config_loader.go` (load `retry.interactive`, add its `SetRetryDefaults`/`BindRetryConfig` entries)
- Modify: `internal/services/retry/retry_service.go` (add `interactivePolicy`/`interactiveBreaker`, `ExecuteInteractiveOperation`, `GetInteractivePolicy`)
- Modify: `.rocketvault.yaml` (document the new block, matching the other three tiers' style)
- Test: `internal/retry/retry_test.go`, `internal/retry/config_loader_test.go`, `internal/services/retry/retry_wrappers_test.go`

**Interfaces:**
- Consumes: `Policy` (existing struct, unchanged), `CircuitBreakerConfig` (existing, unchanged).
- Produces: `retry.InteractivePolicy() Policy`; `Config.Interactive Policy` field; `RetryService.ExecuteInteractiveOperation(ctx context.Context, operation func() error) error`; `RetryService.GetInteractivePolicy() retry.Policy`. Task 5 consumes exactly these three new symbols.

- [ ] **Step 1: Write the failing test for `InteractivePolicy()`**

Add to `internal/retry/retry_test.go`, after `TestCircuitBreaker_HalfOpenAdmissionIsCapped` (added in Task 2):

```go
func TestInteractivePolicy_BoundedForRequestPath(t *testing.T) {
	policy := InteractivePolicy()

	if !policy.Enabled {
		t.Error("expected InteractivePolicy to be enabled by default")
	}
	if policy.MaxAttempts != 2 {
		t.Errorf("expected MaxAttempts 2, got %d", policy.MaxAttempts)
	}
	if policy.MaxDelay > 5*time.Second {
		t.Errorf("expected MaxDelay bounded well under a typical 30s proxy timeout, got %v", policy.MaxDelay)
	}

	// Worst-case single-call backoff sleep (jitter included) must leave
	// generous headroom under a 30s reverse-proxy/browser timeout even when
	// stacked twice (HandleCallback's Verify + UserInfo calls, post the
	// Task-3 fix that stopped retrying Exchange).
	var worst time.Duration
	for attempt := 0; attempt < policy.MaxAttempts-1; attempt++ {
		d := calculateDelay(attempt, policy)
		worst += d
	}
	if twoCalls := worst * 2; twoCalls > 10*time.Second {
		t.Errorf("worst-case combined backoff sleep for two sequential interactive calls = %v, want <= 10s", twoCalls)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/retry/... -run TestInteractivePolicy_BoundedForRequestPath -v`
Expected: FAIL with a compile error — `undefined: InteractivePolicy`.

- [ ] **Step 3: Write minimal implementation — `InteractivePolicy()`**

Add to `internal/retry/retry.go`, immediately after `ExternalServicePolicy()` (which ends at line 87, before the `CircuitBreakerConfig` type at line 90):

```go
// InteractivePolicy returns a retry policy for external calls made on a
// synchronous, user-facing request path (e.g. an OAuth2/OIDC callback
// holding a browser redirect's HTTP response open). Deliberately short
// compared to ExternalServicePolicy's up-to-~19.5s-per-call worst-case
// backoff budget (5 attempts, 1s-30s): a caller here can't let several
// stacked retried calls risk exceeding a typical 30s reverse-proxy or
// browser timeout.
func InteractivePolicy() Policy {
	return Policy{
		Enabled:           true,
		MaxAttempts:       2,
		InitialDelay:      250 * time.Millisecond,
		MaxDelay:          2 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableErrors:   ExternalServicePolicy().RetryableErrors,
		JitterEnabled:     true,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/retry/... -run TestInteractivePolicy_BoundedForRequestPath -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for `Config.Interactive` loading and defaults**

Add to `internal/retry/config_loader_test.go`, inside `TestSetRetryDefaults` (extended in Task 1), immediately after the `extErrors` assertion added in Task 1:

```go
	// Check interactive tier defaults exist and are bounded (new tier — see
	// InteractivePolicy).
	if v.GetInt("retry.interactive.max_attempts") != 2 {
		t.Errorf("expected interactive max attempts 2, got %d", v.GetInt("retry.interactive.max_attempts"))
	}
	interactiveErrors := v.GetStringSlice("retry.interactive.retryable_errors")
	if !reflect.DeepEqual(interactiveErrors, ExternalServicePolicy().RetryableErrors) {
		t.Errorf("retry.interactive.retryable_errors default = %v, want %v", interactiveErrors, ExternalServicePolicy().RetryableErrors)
	}
```

Also add a new standalone test to `internal/retry/config_loader_test.go`, after `TestConfigLoader_LoadConfig`:

```go
func TestConfigLoader_LoadConfig_Interactive(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	yamlConfig := `
retry:
  interactive:
    enabled: true
    max_attempts: 3
    initial_delay: "300ms"
    max_delay: "3s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "timeout"
    jitter_enabled: false
`
	if err := v.ReadConfig(strings.NewReader(yamlConfig)); err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	loader := NewConfigLoader(v)
	config, err := loader.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Interactive.MaxAttempts != 3 {
		t.Errorf("expected interactive max_attempts 3, got %d", config.Interactive.MaxAttempts)
	}
	if config.Interactive.InitialDelay != 300*time.Millisecond {
		t.Errorf("expected interactive initial_delay 300ms, got %v", config.Interactive.InitialDelay)
	}
	if len(config.Interactive.RetryableErrors) != 1 || config.Interactive.RetryableErrors[0] != "timeout" {
		t.Errorf("expected interactive retryable_errors [timeout], got %v", config.Interactive.RetryableErrors)
	}
}
```

`strings` and `viper` are already imported in this test file (confirmed at the top of `internal/retry/config_loader_test.go`); no import changes needed for this step.

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/retry/... -run 'TestSetRetryDefaults|TestConfigLoader_LoadConfig_Interactive' -v`
Expected: FAIL — `TestConfigLoader_LoadConfig_Interactive` fails to compile (`config.Interactive undefined`); `TestSetRetryDefaults` fails on the new assertions (`retry.interactive.max_attempts` reads 0, not 2).

- [ ] **Step 7: Write minimal implementation — `Config.Interactive` and its loading**

In `internal/retry/config.go`:

1. Add the field to the `Config` struct (currently lines 12-17):
```go
type Config struct {
	Database          Policy               `yaml:"database" json:"database"`
	ExternalServices  Policy               `yaml:"external_services" json:"external_services"`
	ServiceOperations Policy               `yaml:"service_operations" json:"service_operations"`
	Interactive       Policy               `yaml:"interactive" json:"interactive"`
	CircuitBreaker    CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
}
```

2. In `DefaultConfig()` (lines 20-39), add `Interactive: InteractivePolicy(),` after the `ServiceOperations: Policy{...},` block:
```go
func DefaultConfig() Config {
	return Config{
		Database:         DatabasePolicy(),
		ExternalServices: ExternalServicePolicy(),
		ServiceOperations: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      500 * time.Millisecond,
			MaxDelay:          2 * time.Second,
			BackoffMultiplier: 1.5,
			RetryableErrors: []string{
				"connection refused",
				"timeout",
				"temporary failure",
			},
			JitterEnabled: true,
		},
		Interactive:    InteractivePolicy(),
		CircuitBreaker: DefaultCircuitBreaker(),
	}
}
```

3. In `DevelopmentConfig()` (lines 42-77), add after the `ServiceOperations:` block and before `CircuitBreaker:`:
```go
		Interactive: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      100 * time.Millisecond,
			MaxDelay:          1 * time.Second,
			BackoffMultiplier: 2.0,
			RetryableErrors:   InteractivePolicy().RetryableErrors,
			JitterEnabled:     true,
		},
```

4. In `ProductionConfig()` (lines 80-115), add after the `ServiceOperations:` block and before `CircuitBreaker:`:
```go
		Interactive: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      250 * time.Millisecond,
			MaxDelay:          2 * time.Second,
			BackoffMultiplier: 2.0,
			RetryableErrors:   InteractivePolicy().RetryableErrors,
			JitterEnabled:     true,
		},
```

5. In `TestingConfig()` (lines 118-153), add after the `ServiceOperations:` block and before `CircuitBreaker:`:
```go
		Interactive: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      1 * time.Millisecond,
			MaxDelay:          10 * time.Millisecond,
			BackoffMultiplier: 2.0,
			RetryableErrors:   InteractivePolicy().RetryableErrors,
			JitterEnabled:     false,
		},
```

6. In `Validate()` (lines 156-170), add after the `ServiceOperations` check and before the `CircuitBreaker` check:
```go
	if err := validatePolicy(c.Interactive, "interactive"); err != nil {
		return err
	}
```

7. In `Merge()` (lines 213-232), add after the `ServiceOperations` block and before the `CircuitBreaker config is always merged` comment:
```go
	if other.Interactive.Enabled {
		result.Interactive = other.Interactive
	}
```

8. In `ExampleYAML()` (lines 325-373), add a new block after the `service_operations:` block and before `circuit_breaker:`:
```yaml

  interactive:
    enabled: true
    max_attempts: 2
    initial_delay: "250ms"
    max_delay: "2s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "no such host"
      - "timeout"
      - "temporary failure"
      - "service unavailable"
      - "too many requests"
      - "internal server error"
      - "bad gateway"
    jitter_enabled: true
```

9. In `ExampleJSON()` (lines 376-427), add a new `"interactive"` block after `"service_operations"` and before `"circuit_breaker"`, following the exact same structure as the `"service_operations"` entry (with a trailing comma added after `"service_operations"`'s closing `}`):
```json
  "interactive": {
    "enabled": true,
    "max_attempts": 2,
    "initial_delay": "250ms",
    "max_delay": "2s",
    "backoff_multiplier": 2.0,
    "retryable_errors": [
      "connection refused",
      "no such host",
      "timeout",
      "temporary failure",
      "service unavailable",
      "too many requests",
      "internal server error",
      "bad gateway"
    ],
    "jitter_enabled": true
  },
```

Now in `internal/retry/config_loader.go`:

10. In `LoadConfig()` (lines 20-67), add after the `service_operations` block (ends line 51) and before the `circuit_breaker` block:
```go
	// Load interactive retry configuration
	if l.viper.IsSet("retry.interactive") {
		interactiveConfig := l.loadPolicyConfig("retry.interactive")
		if interactiveConfig != nil {
			config.Interactive = mergePolicyWithDefaults(*interactiveConfig, InteractivePolicy())
		}
	}
```

11. In `BindRetryConfig()` (lines 114-143), add after the `service_operations` block (ends line 137) and before the `circuit_breaker` block:
```go
	// Bind interactive retry configuration
	v.BindEnv("retry.interactive.enabled", "RETRY_INTERACTIVE_ENABLED")                       //nolint:errcheck,gosec
	v.BindEnv("retry.interactive.max_attempts", "RETRY_INTERACTIVE_MAX_ATTEMPTS")             //nolint:errcheck,gosec
	v.BindEnv("retry.interactive.initial_delay", "RETRY_INTERACTIVE_INITIAL_DELAY")           //nolint:errcheck,gosec
	v.BindEnv("retry.interactive.max_delay", "RETRY_INTERACTIVE_MAX_DELAY")                   //nolint:errcheck,gosec
	v.BindEnv("retry.interactive.backoff_multiplier", "RETRY_INTERACTIVE_BACKOFF_MULTIPLIER") //nolint:errcheck,gosec
	v.BindEnv("retry.interactive.jitter_enabled", "RETRY_INTERACTIVE_JITTER_ENABLED")         //nolint:errcheck,gosec
```

12. In `SetRetryDefaults()` (lines 146-194), add after the `service_operations` block (ends line 188) and before the `circuit_breaker` block:
```go
	// Interactive (request-path) retry defaults
	v.SetDefault("retry.interactive.enabled", true)
	v.SetDefault("retry.interactive.max_attempts", 2)
	v.SetDefault("retry.interactive.initial_delay", "250ms")
	v.SetDefault("retry.interactive.max_delay", "2s")
	v.SetDefault("retry.interactive.backoff_multiplier", 2.0)
	v.SetDefault("retry.interactive.jitter_enabled", true)
	v.SetDefault("retry.interactive.retryable_errors", InteractivePolicy().RetryableErrors)
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./internal/retry/... -v`
Expected: PASS across the whole package, including `TestSetRetryDefaults`, `TestConfigLoader_LoadConfig_Interactive`, `TestInteractivePolicy_BoundedForRequestPath`, and every pre-existing test (in particular `TestConfigLoader_LoadConfig` itself, which constructs its own expected `Config{}` literals — confirm none of those need updating; since Go struct literals with named fields don't require every field to be listed, and `Config.Interactive`'s zero value is only ever compared implicitly via `reflect.DeepEqual`-style checks if the test uses one — inspect `TestConfigLoader_LoadConfig`'s assertion style during this step and adjust only if it fails).

- [ ] **Step 9: Add the `RetryService` wiring — write the failing test**

Add to `internal/services/retry/retry_wrappers_test.go` (after the existing `TestRetryService_ExecuteServiceOperation_Success`/`_Error` tests — locate them via `grep -n "TestRetryService_ExecuteServiceOperation" internal/services/retry/retry_wrappers_test.go` and insert immediately after):

```go
func TestRetryService_ExecuteInteractiveOperation_Success(t *testing.T) {
	v := viper.New()
	v.Set("retry.interactive.max_attempts", 1)
	v.Set("retry.interactive.initial_delay", "1ms")
	v.Set("retry.interactive.max_delay", "1ms")
	v.Set("retry.interactive.backoff_multiplier", 2.0)
	v.Set("retry.interactive.enabled", true)

	svc, err := NewRetryService(v)
	if err != nil {
		t.Fatalf("NewRetryService failed: %v", err)
	}

	calls := 0
	err = svc.ExecuteInteractiveOperation(context.Background(), func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryService_ExecuteInteractiveOperation_Error(t *testing.T) {
	v := viper.New()
	v.Set("retry.interactive.max_attempts", 1)
	v.Set("retry.interactive.initial_delay", "1ms")
	v.Set("retry.interactive.max_delay", "1ms")
	v.Set("retry.interactive.backoff_multiplier", 2.0)
	v.Set("retry.interactive.enabled", true)
	v.Set("retry.interactive.retryable_errors", []string{"boom"})

	svc, err := NewRetryService(v)
	if err != nil {
		t.Fatalf("NewRetryService failed: %v", err)
	}

	err = svc.ExecuteInteractiveOperation(context.Background(), func() error {
		return errors.New("boom")
	})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestRetryService_GetInteractivePolicy(t *testing.T) {
	svc, err := NewRetryService(viper.New())
	if err != nil {
		t.Fatalf("NewRetryService failed: %v", err)
	}

	policy := svc.GetInteractivePolicy()
	if policy.MaxAttempts <= 0 && policy.Enabled {
		t.Error("expected interactive policy to be initialized")
	}
}
```

Check the existing imports at the top of `internal/services/retry/retry_wrappers_test.go` first (via `head -20 internal/services/retry/retry_wrappers_test.go`) — this file already tests `ExecuteExternalServiceOperation_Error` with a similar shape, so `"context"`, `"errors"`, `"testing"`, and `"github.com/spf13/viper"` should already be imported; add any that are missing.

- [ ] **Step 10: Run test to verify it fails**

Run: `go test ./internal/services/retry/... -run 'TestRetryService_ExecuteInteractiveOperation|TestRetryService_GetInteractivePolicy' -v`
Expected: FAIL with compile errors — `svc.ExecuteInteractiveOperation undefined` and `svc.GetInteractivePolicy undefined`.

- [ ] **Step 11: Write minimal implementation — `RetryService.ExecuteInteractiveOperation`/`GetInteractivePolicy`**

In `internal/services/retry/retry_service.go`:

1. Add two methods to the `RetryService` interface (lines 15-33), after `ExecuteServiceOperation` and before `GetDatabasePolicy`:
```go
	// ExecuteInteractiveOperation executes an external call on a
	// synchronous, user-facing request path with a bounded retry budget
	// (see retry.InteractivePolicy)
	ExecuteInteractiveOperation(ctx context.Context, operation func() error) error
```
and after `GetServiceOperationsPolicy`:
```go
	// GetInteractivePolicy returns the interactive (request-path) retry policy
	GetInteractivePolicy() retry.Policy
```

2. Add two fields to the `retryService` struct (lines 36-47):
```go
type retryService struct {
	databasePolicy          retry.Policy
	externalServicesPolicy  retry.Policy
	serviceOperationsPolicy retry.Policy
	interactivePolicy       retry.Policy

	// One circuit breaker per policy type. Each protects an independent
	// failure domain, so e.g. a database outage does not trip the breaker
	// guarding unrelated external service calls.
	databaseBreaker          *retry.CircuitBreaker
	externalServicesBreaker  *retry.CircuitBreaker
	serviceOperationsBreaker *retry.CircuitBreaker
	interactiveBreaker       *retry.CircuitBreaker
}
```

3. In `NewRetryService` (lines 50-69), add to both the struct-literal field assignments:
```go
	return &retryService{
		databasePolicy:          config.Database,
		externalServicesPolicy:  config.ExternalServices,
		serviceOperationsPolicy: config.ServiceOperations,
		interactivePolicy:       config.Interactive,

		databaseBreaker:          retry.NewCircuitBreaker(config.CircuitBreaker),
		externalServicesBreaker:  retry.NewCircuitBreaker(config.CircuitBreaker),
		serviceOperationsBreaker: retry.NewCircuitBreaker(config.CircuitBreaker),
		interactiveBreaker:       retry.NewCircuitBreaker(config.CircuitBreaker),
	}, nil
```

4. Add the method implementation after `ExecuteServiceOperation` (ends line 90) and before `GetDatabasePolicy`:
```go
// ExecuteInteractiveOperation executes an external call on a synchronous,
// user-facing request path with a bounded retry budget
func (s *retryService) ExecuteInteractiveOperation(ctx context.Context, operation func() error) error {
	return s.interactiveBreaker.Execute(func() error {
		return retry.WithExponentialBackoff(ctx, s.interactivePolicy, operation)
	})
}
```

5. Add the accessor after `GetServiceOperationsPolicy` (ends line 105, end of file):
```go

// GetInteractivePolicy returns the interactive (request-path) retry policy
func (s *retryService) GetInteractivePolicy() retry.Policy {
	return s.interactivePolicy
}
```

- [ ] **Step 12: Run test to verify it passes**

Run: `go test ./internal/services/retry/... -v`
Expected: PASS across the whole package.

- [ ] **Step 13: Document the new tier in `.rocketvault.yaml`**

Read the current `retry:` block first (`sed -n '95,130p' .rocketvault.yaml`) to confirm exact indentation, then add a new `interactive:` block after `external_services:` and before `service_operations:`, matching the file's existing style exactly:

```yaml
  interactive:
    enabled: true
    max_attempts: 2
    initial_delay: "250ms"
    max_delay: "2s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "no such host"
      - "timeout"
      - "temporary failure"
      - "service unavailable"
      - "too many requests"
      - "internal server error"
      - "bad gateway"
    jitter_enabled: true
```

- [ ] **Step 14: Run the full repo build and test suite to check for regressions**

Run: `go build ./... && go vet ./... && go test ./internal/retry/... ./internal/services/retry/... -v`
Expected: BUILD OK, VET OK, all tests PASS. Also run `go test ./...` for the whole repo once, since `Config` gained a field and any code constructing a `retry.Config{}` literal elsewhere in the repo (grep to confirm — expected: none outside `internal/retry` itself, since all other callers go through `LoadConfigFromViper`/`NewRetryService`) must still compile.

- [ ] **Step 15: Commit**

```bash
git add internal/retry/retry.go internal/retry/retry_test.go internal/retry/config.go \
        internal/retry/config_loader.go internal/retry/config_loader_test.go \
        internal/services/retry/retry_service.go internal/services/retry/retry_wrappers_test.go \
        .rocketvault.yaml
git commit -m "feat(retry): add a bounded interactive retry tier

Adds retry.InteractivePolicy() and a fourth Config/RetryService tier
(retry.interactive.*, ExecuteInteractiveOperation), following the
exact pattern the existing database/external_services/
service_operations tiers already establish. Not yet consumed by any
caller — this is plumbing only, so it can be reviewed independently
of which caller needs it.

Deliberately short defaults (2 attempts, 250ms-2s backoff) versus
ExternalServicePolicy's up-to-~19.5s-per-call budget: intended for
synchronous, user-facing request paths that can't risk exceeding a
typical reverse-proxy/browser timeout when a retried call is on the
critical path of an HTTP response."
```

---

## Task 5: Route OIDC `Verify`/`UserInfo` through the interactive retry tier

**Files:**
- Modify: `internal/services/auth/oidc_service.go:61-74,232-269`
- Test: `internal/services/auth/oidc_service_test.go` (extend `countingRetryExecutor`, add a new regression test)

**Interfaces:**
- Consumes: `RetryService.ExecuteInteractiveOperation` (from Task 4, already satisfied structurally by `*retryService` — no change needed in `internal/container/service_container.go`, since `OIDCConfig.RetryExecutor: c.retryService` (`service_container.go:408`) passes the whole `*retryService`, which will now also satisfy the widened local `RetryExecutor` interface automatically via Go's structural typing).
- Produces: `HandleCallback`'s `Verify` and `UserInfo` calls now retry under `retry.InteractivePolicy()`'s bounded budget instead of `retry.ExternalServicePolicy()`'s. `NewOIDCService`'s one-time discovery call is deliberately left on `ExecuteExternalServiceOperation` (background call, no request-path timeout concern).

- [ ] **Step 1: Write the failing test**

First, extend `countingRetryExecutor` in `internal/services/auth/oidc_service_test.go` (lines 30-45) to track interactive calls separately, so a test can distinguish which policy tier `HandleCallback` actually routed through:

```go
type countingRetryExecutor struct {
	maxAttempts       int
	calls             int
	interactiveCalls  int
}

func (e *countingRetryExecutor) ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error {
	var lastErr error
	for i := 0; i < e.maxAttempts; i++ {
		e.calls++
		lastErr = operation()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func (e *countingRetryExecutor) ExecuteInteractiveOperation(ctx context.Context, operation func() error) error {
	var lastErr error
	for i := 0; i < e.maxAttempts; i++ {
		e.interactiveCalls++
		lastErr = operation()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}
```

Then add a new test after `TestHandleCallback_ExchangeIsNeverRetried` (added in Task 3):

```go
func TestHandleCallback_VerifyAndUserInfoUseInteractivePolicy(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.idToken = f.signIDToken(t, "client-1", "user-123", "nonce-abc")

	executor := &countingRetryExecutor{maxAttempts: 3}
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: f.issuer, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		RetryExecutor: executor,
	})
	require.NoError(t, err)
	// NewOIDCService's discovery call already used one
	// ExecuteExternalServiceOperation attempt above; reset so this test
	// only observes calls made by HandleCallback itself.
	executor.calls = 0

	identity, err := svc.HandleCallback(context.Background(), "auth-code-xyz", "nonce-abc")
	require.NoError(t, err)
	require.Equal(t, "user-123", identity.Subject)

	require.Equal(t, 0, executor.calls,
		"HandleCallback must not use ExecuteExternalServiceOperation: Exchange is never retried (Task 3) and Verify/UserInfo must use the interactive policy instead")
	require.Equal(t, 2, executor.interactiveCalls,
		"Verify and UserInfo should each make exactly one successful call through the interactive policy")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/auth/... -run TestHandleCallback_VerifyAndUserInfoUseInteractivePolicy -v`
Expected: FAIL to compile — `countingRetryExecutor does not implement RetryExecutor (missing method ExecuteInteractiveOperation)` once the interface is widened in the next step, or (before that step) the test itself fails with `executor.calls` still `2` (Verify + UserInfo both still routed through `ExecuteExternalServiceOperation`) rather than `0`.

Run the two steps in this order: apply the `countingRetryExecutor` extension and new test first (compiles fine against the *current*, unwidened `RetryExecutor` interface, since Go doesn't require a struct to implement extra methods beyond what an interface needs — the extra `ExecuteInteractiveOperation` method is simply unused until the interface or a caller references it), confirm it fails on the assertion values, then proceed to Step 3.

- [ ] **Step 3: Write minimal implementation**

In `internal/services/auth/oidc_service.go`:

1. Widen the `RetryExecutor` interface (lines 61-63):
```go
type RetryExecutor interface {
	ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error
	ExecuteInteractiveOperation(ctx context.Context, operation func() error) error
}
```

2. Add a second free function alongside `withRetry` (lines 65-74), after it:
```go
// withInteractiveRetry is withRetry's counterpart for calls on a
// synchronous, user-facing request path (see
// RetryExecutor.ExecuteInteractiveOperation) — used by HandleCallback's
// Verify and UserInfo calls, which hold an HTTP response open while they
// run and so cannot use ExecuteExternalServiceOperation's much longer
// worst-case backoff budget.
func withInteractiveRetry(ctx context.Context, executor RetryExecutor, fn func() error) error {
	if executor == nil {
		return fn()
	}
	return executor.ExecuteInteractiveOperation(ctx, fn)
}
```

3. In `HandleCallback`, change the `Verify` call (lines 232-237 in the pre-Task-3 numbering; after Task 3's edit, this block is unchanged in content, just shifted a few lines up since the `Exchange` block shrank) from `withRetry` to `withInteractiveRetry`:
```go
	var idToken *oidc.IDToken
	err = withInteractiveRetry(ctx, s.retryExecutor, func() error {
		var err error
		idToken, err = s.verifier.Verify(ctx, rawIDToken)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}
```

4. And the `UserInfo` call similarly:
```go
	var userInfo *oidc.UserInfo
	if uiErr := withInteractiveRetry(ctx, s.retryExecutor, func() error {
		var err error
		userInfo, err = s.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		return err
	}); uiErr == nil {
```

`NewOIDCService`'s discovery call (lines 143-147) is deliberately left calling `withRetry` unchanged — it runs once at container-construction time, not on a request path, so `ExternalServicePolicy`'s longer budget remains appropriate there.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/auth/... -run TestHandleCallback -v`
Expected: PASS for all `TestHandleCallback_*` tests, including the new `TestHandleCallback_VerifyAndUserInfoUseInteractivePolicy`.

- [ ] **Step 5: Run the full package test suite to check for regressions**

Run: `go test ./internal/services/auth/... -v`
Expected: PASS — in particular confirm `TestHandleCallback_RetriesExchangeAndVerifyIndependently` and `TestHandleCallback_UserInfoFailureIsSwallowed` still pass (they assert on the fake IdP's own per-endpoint call counters, which are unaffected by which `RetryExecutor` method drives the retry loop) and `TestNewOIDCService_RetriesDiscoveryOnFailure` still passes (discovery is untouched by this task).

- [ ] **Step 6: Run the full repo build, vet, and test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: BUILD OK, VET OK, all tests PASS repo-wide.

- [ ] **Step 7: Commit**

```bash
git add internal/services/auth/oidc_service.go internal/services/auth/oidc_service_test.go
git commit -m "fix(oidc): bound HandleCallback's Verify/UserInfo retry budget

Verify and UserInfo were retried under ExternalServicePolicy, whose
worst-case backoff (5 attempts, 1s-30s) can sum to ~19.5s per call —
stacked across HandleCallback's synchronous, user-facing request
path, this risked exceeding a typical 30s reverse-proxy/browser
timeout well before the retries were exhausted.

Both now route through the new retry.InteractivePolicy tier (2
attempts, 250ms-2s), added in the prior commit. Discovery, which
runs once at startup rather than on a request path, is unchanged."
```

---

## Task 6: Full regression sweep and bug-tracking documentation

**Files:**
- Modify: `.claude/known-bugs.md`
- No code changes — this task is verification and documentation only.

**Interfaces:** None — this task consumes nothing new and produces nothing new in code.

- [ ] **Step 1: Full build, vet, and race-enabled test sweep**

Run, in order, stopping to investigate any failure before continuing:
```bash
go build ./...
go vet ./...
gofmt -l internal/retry internal/services/retry internal/services/auth
go test ./... -race
```
Expected: every command exits 0 with no output from `gofmt -l` (no unformatted files) and `PASS`/`ok` for every package in `go test ./... -race`. The `-race` flag matters specifically for Task 2's `CircuitBreaker` fix and Task 4/5's new concurrent-safe tier — a race in either would only reliably surface here.

- [ ] **Step 2: Confirm no other caller depended on the old behavior**

Run: `grep -rn "ExecuteExternalServiceOperation\|ExecuteInteractiveOperation" --include="*.go" internal/ api/ cmd/ | grep -v _test.go`
Expected: `ExecuteExternalServiceOperation` still appears only in `internal/services/retry/retry_service.go` (definition) and `internal/services/auth/oidc_service.go` (the one remaining caller, `NewOIDCService`'s discovery call). `ExecuteInteractiveOperation` appears in `internal/services/retry/retry_service.go` (definition) and `internal/services/auth/oidc_service.go` (the two `HandleCallback` callers added in Task 5). If anything else turns up, stop and investigate before proceeding — it would mean a caller this plan didn't account for exists.

- [ ] **Step 3: Confirm DDD layering wasn't crossed**

Run: `grep -rln "internal/repositories" internal/retry internal/services/retry internal/services/auth`
Expected: no output (or only pre-existing, unrelated references if any existed before this plan — compare against `git diff main --stat` for this branch to confirm none of the files this plan touched import `internal/repositories`). This plan's fixes are entirely within `internal/retry` (pure package, no dependencies on this codebase's other internal packages) and the service layer's existing retry/OIDC wiring — no repository or API-handler code should appear in the diff at all:
```bash
git diff --stat HEAD~6
```
Expected: only files listed in this plan's "File Structure" table above appear.

- [ ] **Step 4: Record the fixes in `.claude/known-bugs.md`**

Get the four commit hashes from Tasks 1-3 and 5 (the ones with `fix(...)` subjects — Task 4 is plumbing, not itself a bug fix, so it doesn't get its own entry; fold its commit reference into the Finding-4 entry since that's the fix it enables):
```bash
git log --oneline -6
```

Read `.claude/known-bugs.md`'s existing `## Open Bugs` section structure first (it uses `### B<N> — title` headers with `**Status**`/`**Severity**`/`**File**` fields, e.g. entries `B1` and `B2`). Add four new entries following that exact convention, using the next available `B<N>` numbers (check the file's highest existing `B<N>`/other-prefix number first via `grep -n '^### ' .claude/known-bugs.md` and continue from there). Example shape for one entry (repeat for all four, substituting the real commit hashes from Step 4's `git log` output and adjusting file/description per finding):

```markdown
### B<N> — CircuitBreaker Open→HalfOpen admission race

**Status**: Fixed in commit `<hash>`
**Severity**: Resolved
**File**: `internal/retry/retry.go`

**What was fixed**: `Execute` previously read state under `RLock`, released
the lock, then acted on it unlocked — including an entirely unlocked read
of `lastFailure` — so concurrent callers could all observe a stale `Open`
state, each independently transition to `HalfOpen`, and each be admitted
into the half-open trial with no cap; `HalfOpenRequests` was only ever
checked after a successful call, never as an admission gate before `fn()`
ran. `admit()` now performs the state check, transition, and half-open slot
reservation as one locked critical section, capping concurrent/total
half-open admission at `HalfOpenRequests`.
```

- [ ] **Step 5: Commit the documentation update**

```bash
git add .claude/known-bugs.md
git commit -m "docs(known-bugs): record the retry/OIDC hardening fixes"
```

---

## Self-Review

**Spec coverage:** All four findings from the Background section have a dedicated task — Finding 2 → Task 1, Finding 3 → Task 2, Finding 1 → Task 3, Finding 4 → Tasks 4+5 (split because adding the policy tier and wiring a caller to it are independently reviewable deliverables). Task 6 is the regression/documentation closer the user explicitly asked for ("make sure new change does not create any regression").

**Placeholder scan:** Every step has real, complete code — no "TBD"/"add error handling"/"similar to Task N" placeholders. Every test asserts concrete values derived from the actual current source (verified by directly reading `retry.go`, `config.go`, `config_loader.go`, `retry_service.go`, `oidc_service.go`, and both test files in full before writing this plan, not from summary).

**Type consistency:** `InteractivePolicy() Policy` (Task 4) is referenced identically in Task 4's own tests, `Config.Interactive` field type (`Policy`), `RetryService.ExecuteInteractiveOperation(ctx context.Context, operation func() error) error` and `GetInteractivePolicy() retry.Policy` (Task 4), and `RetryExecutor.ExecuteInteractiveOperation(ctx context.Context, operation func() error) error` (Task 5, the widened local interface in `oidc_service.go`) — same method name and signature throughout, satisfied structurally without any explicit `var _ RetryExecutor = (*retryService)(nil)` assertion needed (none exists for the current `ExecuteExternalServiceOperation` either, so this doesn't introduce a new convention).

**DDD compliance:** Confirmed via Task 6 Step 3 — every touched file lives in `internal/retry` (pure, dependency-free package) or the service layer (`internal/services/retry`, `internal/services/auth`), matching the service-layer-conventions skill's `api/` → `internal/services/` → `internal/repositories/` layering. No repository or API-handler files are touched by any task.

**Regression safety:** Every task's final steps re-run the full test suite for its touched packages before committing (Tasks 1, 2, 3, 5), Task 4 additionally re-runs `go build ./...`/`go vet ./...` repo-wide since it changes a widely-referenced struct (`retry.Config`), and Task 6 closes with a repo-wide `-race` sweep plus a grep-based check that no unaccounted-for caller exists. Task 2 and Task 4/5 specifically add the concurrency-focused and interface-widening tests needed to pin down exactly the classes of bug this plan fixes, so a future regression in either area fails loudly rather than silently reintroducing the same defect.
