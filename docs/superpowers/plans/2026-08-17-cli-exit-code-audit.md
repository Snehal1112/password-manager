# CLI Exit Code Fix — Downstream Audit & Verification Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confirm nothing in this repo silently depended on the buggy `os.Exit(0)`-on-error behavior, and verify the one script that's a known **bonus fix** (`scripts/create_admin.sh`) now actually works correctly.

**Architecture:** Pure verification — no new production code. An investigation already ran (2026-08-17, as part of scoping `2026-08-17-cli-exit-code-fix.md`) across `cmd/**/*_test.go`, `.github/workflows/*.yml`, and `scripts/*.sh` and found **zero** files that need updating because of the exit-code fix. This plan's job is to (a) re-confirm that with a fresh full-suite run after the fix actually lands, and (b) manually exercise the one script whose failure-detection logic was silently dead code due to this exact bug and is now expected to work.

**Tech Stack:** Go 1.25, bash.

**Spec:** No separate design doc. Findings this plan verifies are recorded in `~/data/rocket/Nl-knowledge-base/rocketvault/known-issues-gotchas.md`'s "CRITICAL, CLI-wide" entry and in the investigation notes referenced from `2026-08-17-cli-exit-code-fix.md`.

## Global Constraints

- **Depends on `2026-08-17-cli-exit-code-fix.md` and `2026-08-17-secrets-generate-exit-code-fix.md` both having landed.** This plan verifies their combined effect; running it before either lands will show the pre-fix (broken) behavior and is not a useful signal.
- No `Makefile` — `go build ./...`, `go vet ./...`, `go test ./...` are canonical.

---

### Task 1: Full-repo regression run

**Files:** None (verification only).

**Interfaces:** None.

- [ ] **Step 1: Full build, vet, and test suite**

Run:
```bash
go build ./...
go vet ./...
go test ./...
```
Expected: `build`/`vet` silent (success), `test` all `ok`, no `FAIL`. This is the same baseline command sequence used throughout `.claude/manual-testing-plan.md` §1 — confirming the two exit-code fixes didn't regress anything else in the ~600+ test files across the repo.

- [ ] **Step 2: Confirm no test in the repo currently asserts an exit code of exactly 0 for a command expected to fail**

Run:
```bash
grep -rn "ExitCode() == 0\|ExitCode(), 0\|exit.*== *0" --include="*_test.go" . || echo "no matches — confirms the 2026-08-17 investigation finding"
```
Expected: `no matches` (or, if something matches, read it and confirm it's asserting `0` for a genuinely *successful* case, not a failure case — if it's the latter, that test was silently encoding the bug and needs updating; stop and fix it before proceeding, since that would mean the original investigation missed something).

- [ ] **Step 3: golangci-lint / govulncheck, matching CI**

Run (same tools `.github/workflows/go.yml` runs):
```bash
golangci-lint run ./...
govulncheck ./...
```
Expected: both clean (no new findings introduced by either fix — the changes are small and localized, but confirm rather than assume, since this is what CI will actually gate on).

No commit for this task — verification only.

---

### Task 2: Verify `scripts/create_admin.sh`'s bootstrap-failure branch (bonus fix)

**Files:** None (verification only — this script itself needs no code change; its failure-detection logic at lines 371-388 was already correct, just unreachable due to the bug).

**Interfaces:** None.

- [ ] **Step 1: Trigger the bootstrap-mode failure path deliberately**

Using a scratch config per `.claude/manual-testing-plan.md` §0, bootstrap successfully once, then run the script again against the same (now-bootstrapped) database so `scripts/create_admin.sh`'s `CMD` — `./rocketvault --config="$CONFIG_FILE" users admin --admin-username=... --bootstrap-token=...` — fails with `Bootstrap not allowed: users exist`:

```bash
cd /path/to/rocketvault
go build -o rocketvault .
cp .rocketvault.yaml /tmp/rv-test.yaml
# edit /tmp/rv-test.yaml: database.connection -> /tmp/rv-test.db
TOKEN=$(grep '^bootstrap_token:' /tmp/rv-test.yaml | cut -d'"' -f2)
./rocketvault --config=/tmp/rv-test.yaml users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token "$TOKEN"
# second run — this database already has an admin, so this must fail.
# create_admin.sh's real flags (verified against its own --help, not
# guessed): -c/--config, -m/--mode, -u/--username, -p/--password,
# --bootstrap-token.
bash scripts/create_admin.sh --config /tmp/rv-test.yaml --mode bootstrap \
  --username admin2 --password admin123 --bootstrap-token "$TOKEN"
```

- [ ] **Step 2: Confirm the failure branch now actually triggers**

Expected, **before** this session's two fixes: the script's `if OUTPUT=$(eval "$CMD" 2>&1); then` treats the failed `rocketvault` invocation as *success* (because `$CMD` exited `0` even though it printed `Bootstrap not allowed: users exist` to stdout) — `print_success "Admin user created successfully using bootstrap method!"` prints despite nothing having been created.

Expected, **after** both fixes: `eval "$CMD"` now returns non-zero, the script's `else` branch runs instead — `print_error "Bootstrap admin creation failed:"` followed by the specific `print_warning "Bootstrap mode failed because users already exist"` guidance (triggered by the script's own `grep -q "Bootstrap not allowed"` check against `$OUTPUT`, `scripts/create_admin.sh` lines ~380-384).

- [ ] **Step 3: Clean up**

```bash
rm -f /tmp/rv-test.yaml /tmp/rv-test.db rocketvault
```

No commit for this task — verification only; `scripts/create_admin.sh` itself is unmodified.
