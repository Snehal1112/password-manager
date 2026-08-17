# CLI Exit Code Fix (`cmd/root.go` Execute) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `cmd/root.go`'s `Execute()` so every RocketVault CLI command exits with a non-zero status on failure, instead of the current `os.Exit(0)` regardless of error.

**Architecture:** Extract the exit-code decision out of `Execute()` into a small, pure, unit-testable `run(cmd *cobra.Command) int` helper. `Execute()` becomes a one-line wrapper (`os.Exit(run(rootCmd))`). This is the standard Go pattern for testing exit-code logic without terminating the test binary via a real `os.Exit` call.

**Tech Stack:** Go 1.25, Cobra (`github.com/spf13/cobra`), testify (`assert`).

**Spec:** No separate design doc — this is a fully diagnosed, single-root-cause bug fix, not a new feature. The diagnosis lives in `~/data/rocket/Nl-knowledge-base/rocketvault/known-issues-gotchas.md`'s "CRITICAL, CLI-wide: every command exits `0` on error" entry (added 2026-08-17) and in `.claude/manual-testing-plan.md` §0 gotcha #4 / §2 gotcha #8, both of which this plan's Task 3 and the sibling docs-sync plan will update once this lands.

## Global Constraints

- Go 1.25 toolchain, no `Makefile` — `go build ./...`, `go vet ./...`, `go test ./...` are the canonical verification commands for this repo.
- `Execute()` has exactly one caller in the entire codebase: `main.go:35`. No other code path is affected by this change.
- Do not change the exit code for a Go **panic** (already correctly non-zero, `2`, via the Go runtime) — this plan only touches the clean-`error`-return path.

---

### Task 1: Extract a testable `run()` helper and write failing regression tests

**Files:**
- Modify: `cmd/root.go:71-79`
- Modify: `cmd/root_test.go` (append; add `"errors"` to the import block)

**Interfaces:**
- Produces: `run(cmd *cobra.Command) int` — unexported function in package `cmd`, returns `0` on success, `1` on any error from `cmd.ExecuteContext`. `Execute()` (unchanged signature, still the sole public entry point called from `main.go`) becomes `os.Exit(run(rootCmd))`.

- [ ] **Step 1: Write the failing tests in `cmd/root_test.go`**

Add `"errors"` to the existing import block (currently `context`, `testing`, `time`, then the third-party/internal groups — insert `"errors"` alphabetically after `"context"`):

```go
import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/retry"
	authServices "rocketvault/internal/services/auth"
)
```

Append these two tests at the end of the file (after the existing `TestInitConfig_RetryConfigEnvOverride`, which currently ends at line 209):

```go
// TestRun_ReturnsNonZeroOnError is the regression test for the bug where
// Execute() called os.Exit(0) even when rootCmd.ExecuteContext returned a
// non-nil error, making every CLI failure indistinguishable from success
// at the shell level ("&&"/"set -e" never caught it).
func TestRun_ReturnsNonZeroOnError(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("boom")
		},
	}
	cmd.SetArgs([]string{})

	exitCode := run(cmd)

	assert.NotEqual(t, 0, exitCode, "run() must return a non-zero exit code when the command errors")
}

// TestRun_ReturnsZeroOnSuccess pins the success path so a future change to
// run() can't flip both cases to the same wrong value.
func TestRun_ReturnsZeroOnSuccess(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	cmd.SetArgs([]string{})

	exitCode := run(cmd)

	assert.Equal(t, 0, exitCode, "run() must return 0 when the command succeeds")
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile (the `run` function doesn't exist yet)**

Run: `go test ./cmd/... -run 'TestRun_ReturnsNonZeroOnError|TestRun_ReturnsZeroOnSuccess' -v`
Expected: `FAIL` — compile error, `undefined: run`

- [ ] **Step 3: Commit the test-only change (red)**

```bash
git add cmd/root_test.go
git commit -m "$(cat <<'EOF'
test(cmd): add failing regression test for Execute() exit code

rootCmd.Execute() currently calls os.Exit(0) even when
ExecuteContext returns an error, so every CLI failure exits 0 and
&&/set -e never catch it. These tests pin the correct behavior
against a not-yet-existing run() helper (next commit).
EOF
)"
```

---

### Task 2: Fix the bug — implement `run()`, exit non-zero on error

**Files:**
- Modify: `cmd/root.go:71-79`

**Interfaces:**
- Consumes: nothing new (uses the existing package-level `rootCmd *cobra.Command`, already defined at `cmd/root.go:51`).
- Produces: `run(cmd *cobra.Command) int` (matches Task 1's test signature exactly).

- [ ] **Step 1: Replace the buggy `Execute()` with `Execute()` + `run()`**

Current code (`cmd/root.go:71-79`):

```go
// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ctx := context.Background()
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		os.Exit(0)
	}
}
```

Replace with:

```go
// Execute adds all child commands to the root command, sets flags
// appropriately, and exits the process with the resulting status code.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	os.Exit(run(rootCmd))
}

// run executes cmd and returns the process exit code: 0 on success, 1 on
// any error. Separated from Execute so the exit-code decision is
// unit-testable without terminating the test binary via a real os.Exit
// call — see TestRun_ReturnsNonZeroOnError / TestRun_ReturnsZeroOnSuccess.
func run(cmd *cobra.Command) int {
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		return 1
	}
	return 0
}
```

- [ ] **Step 2: Run the regression tests to verify they pass**

Run: `go test ./cmd/... -run 'TestRun_ReturnsNonZeroOnError|TestRun_ReturnsZeroOnSuccess' -v`
Expected: `PASS` for both.

- [ ] **Step 3: Run the full `cmd` package test suite to confirm nothing else broke**

Run: `go test ./cmd/... -v 2>&1 | tail -50`
Expected: all `PASS`, no `FAIL`. (The companion audit plan, `2026-08-17-cli-exit-code-audit.md`, already confirmed via full-repo investigation that no existing test calls the package-level `Execute()`/`run()` or asserts exit-code-0 for a failure case — this step is confirming that finding empirically, not expecting surprises.)

- [ ] **Step 4: Commit (green)**

```bash
git add cmd/root.go
git commit -m "$(cat <<'EOF'
fix(cmd): exit non-zero on CLI command failure

Execute() called os.Exit(0) unconditionally, even when
rootCmd.ExecuteContext returned an error — every CLI failure was
indistinguishable from success at the shell level, silently
breaking &&/set -e-based scripts and CI steps.

Extracted the exit-code decision into a small run(cmd) helper so
it's unit-testable without terminating the test binary. Execute()
now exits 1 on any command error, 0 on success.
EOF
)"
```

---

### Task 3: Full-repo verification

**Files:** None (verification only).

**Interfaces:** None.

- [ ] **Step 1: Full build, vet, and test suite**

Run:
```bash
go build ./...
go vet ./...
go test ./...
```
Expected: `build`/`vet` produce no output (silence = success); `test` prints `ok` for every package with test files, no `FAIL`.

- [ ] **Step 2: Empirical manual verification against the built binary** (mirrors the verification standard already used throughout `.claude/manual-testing-plan.md` §0/§2 — don't just trust the unit tests, prove the shell-visible behavior changed)

```bash
go build -o /tmp/rocketvault-bin .
/tmp/rocketvault-bin users admin --admin-username admin
echo "exit: $?"
```
Expected: `Error: admin-username, bootstrap-token, and admin-password are required` on stderr, followed by `exit: 1` (previously `exit: 0` — this is the exact negative case documented as `exit=0` in `.claude/manual-testing-plan.md` §2 step 9, before this fix).

- [ ] **Step 3: Confirm a successful command still exits 0**

```bash
/tmp/rocketvault-bin --help >/dev/null
echo "exit: $?"
```
Expected: `exit: 0`.

- [ ] **Step 4: Clean up the scratch binary**

```bash
rm -f /tmp/rocketvault-bin
```

No commit for this task — it's verification only, no file changes.
