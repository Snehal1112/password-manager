# `secrets generate-password` Exit Code Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `cmd/secrets/generate.go`'s `generateCmd`, which independently has the exact same bug class as `cmd/root.go`'s `Execute()` — it calls `os.Exit(0)` when `generatePassword` returns an error, instead of a non-zero code.

**Architecture:** Convert `Run: func(cmd *cobra.Command, args []string) { ... }` to `RunE: func(cmd *cobra.Command, args []string) error { ...; return err }`. This removes the manual `os.Exit(0)` call entirely — Cobra propagates the returned error up to `rootCmd.ExecuteContext`, which (once `2026-08-17-cli-exit-code-fix.md` lands) correctly exits 1 via the fixed `run()` helper. This is the idiomatic Cobra pattern already used by essentially every other command in this codebase (`Run:` with a manual `os.Exit` is the outlier here, not the norm).

**Tech Stack:** Go 1.25, Cobra, testify.

**Spec:** No separate design doc — same class of bug as `2026-08-17-cli-exit-code-fix.md`, found as a side effect of that plan's investigation (`cmd/secrets/generate.go:57`). See that plan's Task/investigation notes and `~/data/rocket/Nl-knowledge-base/rocketvault/known-issues-gotchas.md`.

## Global Constraints

- **Depends on `2026-08-17-cli-exit-code-fix.md` landing first (or in the same session before this is verified).** This plan's fix relies on `cmd/root.go`'s `run()` helper correctly exiting 1 on a returned error — without that fix, converting this command to `RunE` would just trade one silent-exit-0 bug for the *other* still-open one, and Task 2's verification step would fail.
- Go 1.25, no `Makefile` — `go build ./...`, `go vet ./...`, `go test ./...` are canonical.

---

### Task 1: Convert `Run` to `RunE`, remove the manual `os.Exit(0)`, write a regression test

**Files:**
- Modify: `cmd/secrets/generate.go:36-65` (the `generateCmd` var block and its import list)
- Modify: `cmd/secrets/generate_test.go` (append)

**Interfaces:**
- Produces: `generateCmd.RunE` (was `.Run`) — same cobra command, same flags, same `generatePassword` call; only the error-handling shape changes.

- [ ] **Step 1: Remove the now-unused `"os"` import**

Current import block (`cmd/secrets/generate.go:23-30`):

```go
import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)
```

Replace with (drop `"os"` — after this task's Step 2, nothing in this file calls `os.Exit` or anything else from `os`):

```go
import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)
```

- [ ] **Step 2: Convert `Run` to `RunE`**

Current (`cmd/secrets/generate.go:47-65`):

```go
	Run: func(cmd *cobra.Command, args []string) {
		length, _ := cmd.Flags().GetInt("length")
		useUpper, _ := cmd.Flags().GetBool("uppercase")
		useLower, _ := cmd.Flags().GetBool("lowercase")
		useNumbers, _ := cmd.Flags().GetBool("numbers")
		useSpecial, _ := cmd.Flags().GetBool("special")

		password, err := generatePassword(length, useUpper, useLower, useNumbers, useSpecial)
		if err != nil {
			logrus.Error("Failed to generate password: ", err)
			os.Exit(0)
			return
		}

		logrus.WithFields(logrus.Fields{
			"length": length,
		}).Info("Password generated successfully")
		fmt.Println("Generated password:", password)
	},
```

Replace with:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		length, _ := cmd.Flags().GetInt("length")
		useUpper, _ := cmd.Flags().GetBool("uppercase")
		useLower, _ := cmd.Flags().GetBool("lowercase")
		useNumbers, _ := cmd.Flags().GetBool("numbers")
		useSpecial, _ := cmd.Flags().GetBool("special")

		password, err := generatePassword(length, useUpper, useLower, useNumbers, useSpecial)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}

		logrus.WithFields(logrus.Fields{
			"length": length,
		}).Info("Password generated successfully")
		fmt.Println("Generated password:", password)
		return nil
	},
```

- [ ] **Step 3: Write a regression test in `cmd/secrets/generate_test.go`**

Append (existing imports — `strings`, `testing`, `unicode`, `assert`, `require` — already cover what this needs):

```go
// TestGenerateCmd_InvalidLength_ReturnsError is the regression test for the
// bug where generateCmd's Run handler called os.Exit(0) on a
// generatePassword error, making the failure indistinguishable from
// success at the shell level. RunE must return a non-nil error instead,
// letting Cobra (and, ultimately, cmd.Execute()) surface it as a non-zero
// exit code.
func TestGenerateCmd_InvalidLength_ReturnsError(t *testing.T) {
	cmd := generateCmd
	cmd.Flags().Set("length", "0") //nolint:errcheck
	cmd.SetArgs([]string{})

	err := cmd.RunE(cmd, []string{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate password")
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./cmd/secrets/... -run TestGenerateCmd_InvalidLength_ReturnsError -v`
Expected: `PASS`

- [ ] **Step 5: Run the full `cmd/secrets` package test suite**

Run: `go test ./cmd/secrets/... -v 2>&1 | tail -40`
Expected: all `PASS`, no `FAIL` (in particular, `TestGeneratePasswordRejectsZeroLength` and the other existing `generatePassword`-level tests are unaffected — this change is purely in the cobra command wrapper, not `generatePassword` itself).

- [ ] **Step 6: Commit**

```bash
git add cmd/secrets/generate.go cmd/secrets/generate_test.go
git commit -m "$(cat <<'EOF'
fix(secrets): return error instead of os.Exit(0) in generate-password

generateCmd called os.Exit(0) when generatePassword failed (e.g.
length < 1), the same silent-exit-0 bug class as cmd/root.go's
Execute(). Converted Run to RunE so Cobra propagates the error
normally, letting the (now-fixed) root Execute()/run() exit 1.
EOF
)"
```

---

### Task 2: Empirical verification against the built binary

**Files:** None (verification only).

**Interfaces:** None.

- [ ] **Step 1: Build and confirm exit code with an invalid `--length`**

```bash
go build -o /tmp/rocketvault-bin .
/tmp/rocketvault-bin secrets generate-password --length 0 \
  --username admin --password admin123 --totp-code 000000
echo "exit: $?"
```
Expected: `Error: failed to generate password: password length must be at least 1` on stderr, and `exit: 1` — this requires `2026-08-17-cli-exit-code-fix.md`'s `run()` fix to already be built into this binary (Global Constraints dependency).

- [ ] **Step 2: Confirm a valid invocation still succeeds and prints a password**

```bash
/tmp/rocketvault-bin secrets generate-password --length 16 \
  --username admin --password admin123 --totp-code 000000 2>&1 | tail -5
echo "exit: $?"
```
Expected: either a `Generated password: ...` line with `exit: 0` (if auth succeeds against whatever instance is running), or an auth-failure error unrelated to this fix — either way, confirm the exit code matches whether the command actually errored, not a hardcoded value.

- [ ] **Step 3: Clean up**

```bash
rm -f /tmp/rocketvault-bin
```

No commit for this task — verification only.
