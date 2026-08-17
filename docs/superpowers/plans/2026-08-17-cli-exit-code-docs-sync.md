# CLI Exit Code Fix — Docs & KB Sync Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Once the exit-code fix lands, update every place that documents the old (buggy) behavior as current/expected — `.claude/manual-testing-plan.md` and the developer KB — so they describe the fixed behavior instead of the bug.

**Architecture:** Docs-only. No production code touched. Both target files were written *by this same investigation* earlier tonight (2026-08-17), so every location needing an update is already known precisely — this plan is a mechanical sync, not a fresh audit.

**Tech Stack:** Markdown.

**Spec:** No separate design doc. Source of the "before" text is the actual current content of `.claude/manual-testing-plan.md` and `~/data/rocket/Nl-knowledge-base/rocketvault/known-issues-gotchas.md` as of 2026-08-17.

## Global Constraints

- **Depends on `2026-08-17-cli-exit-code-fix.md` and `2026-08-17-secrets-generate-exit-code-fix.md` both having landed and been committed.** This plan's edits reference the actual commit hashes from those two — get them first: `git log --oneline -5` after both are merged, find the `fix(cmd): exit non-zero on CLI command failure` and `fix(secrets): return error instead of os.Exit(0) in generate-password` commits, and substitute their short hashes everywhere this plan says `<root-fix-commit>` / `<generate-fix-commit>`.
- `.claude/` is gitignored in this repo (`.gitignore:111`) — `.claude/manual-testing-plan.md` changes are local-only and will never show up in `git status`/`git diff` for this repo. That's expected, not a mistake.
- `~/data/rocket/Nl-knowledge-base/rocketvault/known-issues-gotchas.md` lives in a **separate** repo/directory (`~/data/rocket/Nl-knowledge-base/`), not this one — edits there are independent of anything in `/home/numericlabs/data/rocket/rocketvault`.

---

### Task 1: Update `.claude/manual-testing-plan.md`

**Files:**
- Modify: `.claude/manual-testing-plan.md` (four locations: §0's gotcha #4, §0 step 5's expected output, §0 step 6's expected output, §2's gotcha #8, §2 step 9's expected output — five edits total, listed below)

**Interfaces:** None (prose-only document).

- [ ] **Step 1: Update §0's gotcha #4 (currently describes the bug as present-tense fact)**

Find this exact block (currently around line 102-108):

```
4. **CLI command failures — including a `serve` that never manages to
   start — commonly exit `0`, indistinguishable from success at the shell
   level.** This is the same `os.Exit(0)`-on-error behavior documented in
   §2's worked example gotcha #8, confirmed here again independently: a
   `serve` that fails cleanly with a PKCS#11 "token not found" error still
   exits `0`. This is distinct from gotcha #3's panic case — a panic
   bypasses `Execute()`'s return path entirely and does exit non-zero (`2`).
```

Replace with:

```
4. **CLI command failures used to exit `0` unconditionally — FIXED
   `<root-fix-commit>` (2026-08-17).** `Execute()` (`cmd/root.go`) called
   `os.Exit(0)` even when `rootCmd.ExecuteContext` returned an error,
   making every CLI failure indistinguishable from success at the shell
   level — confirmed live at the time: a `serve` that failed cleanly with
   a PKCS#11 "token not found" error still exited `0`. Now exits `1` on
   any command error via the `run()` helper extracted in the fix; this is
   still distinct from gotcha #3's panic case — a panic bypasses
   `Execute()`'s return path entirely and exits non-zero (`2`) regardless.
   If you're on a checkout older than `<root-fix-commit>`, the old
   behavior still applies — check `git log -1 --format=%H -- cmd/root.go`
   against that hash before trusting `$?` from this CLI.
```

- [ ] **Step 2: Update §0 step 5's expected output (currently shows `exit: 0` as the expected/current result)**

Find this exact block (currently around lines 234-250):

````
**5. Confirm HSM's *other* failure mode — library file present, but the
configured token label doesn't exist — returns a clean `error` instead of
panicking, and confirm this failure still exits `0`:**
```bash
# edit /tmp/rv-test.yaml: hsm.enabled -> true, hsm.lib_path -> the real path
# (e.g. /usr/lib/softhsm/libsofthsm2.so), hsm.token_label -> nonexistent-token-label
go run main.go --config /tmp/rv-test.yaml serve
echo "exit: $?"
```
Expect:
```
Error: service container initialization failed: failed to initialize services: failed to initialise PKCS#11 key provider: pkcs11: token with label "nonexistent-token-label" not found
Usage:
  rocketvault serve [flags]
...
exit: 0
```
Don't trust `$?` alone to detect this class of failure in a script
(gotcha #4).
````

Replace with:

````
**5. Confirm HSM's *other* failure mode — library file present, but the
configured token label doesn't exist — returns a clean `error` instead of
panicking, and confirm the exit code correctly reflects the failure:**
```bash
# edit /tmp/rv-test.yaml: hsm.enabled -> true, hsm.lib_path -> the real path
# (e.g. /usr/lib/softhsm/libsofthsm2.so), hsm.token_label -> nonexistent-token-label
go run main.go --config /tmp/rv-test.yaml serve
echo "exit: $?"
```
Expect:
```
Error: service container initialization failed: failed to initialize services: failed to initialise PKCS#11 key provider: pkcs11: token with label "nonexistent-token-label" not found
Usage:
  rocketvault serve [flags]
...
exit: 1
```
(Before `<root-fix-commit>`, this printed `exit: 0` — see gotcha #4.)
````

- [ ] **Step 3: Update §0 step 6's expected output (bind-conflict case — this one is a SEPARATE bug, not fixed by this plan; only update it if it's also been fixed, otherwise leave as-is and say so explicitly)**

This step documents `bootstrap/bootstrap.go:77-82` discarding `StartServer`'s error — a **different** bug from the `Execute()` exit-code bug, not addressed by `2026-08-17-cli-exit-code-fix.md` or `2026-08-17-secrets-generate-exit-code-fix.md`. Do **not** change this step's expected `exit: 0` — it is still accurate after both sibling plans land. Instead, add one clarifying sentence immediately after the existing gotcha #5 paragraph (the one starting "A bind failure on `server.listen_addr` is swallowed the same way") making the distinction explicit:

```
   (This remains `0` even after the `<root-fix-commit>` fix to `Execute()`'s
   exit code — the bind failure here never reaches `Execute()`'s error path
   at all, since `ServerStarter.Start` discards `StartServer`'s return
   value before `Execute()` ever sees it. A separate fix, not covered by
   this session's plans.)
```

- [ ] **Step 4: Update §2's gotcha #8**

Find this exact block (currently around lines 733-741):

```
8. **Every failure below still exits `0`.** `Execute()` (`cmd/root.go:73-78`)
   calls `os.Exit(0)` inside its `if err != nil` branch. Combined with the
   fact that no `SilenceUsage`/`SilenceErrors` is set anywhere under
   `cmd/`, a failed bootstrap prints `Error: ...` followed by the full
   usage block and returns `$? == 0`. **This is not specific to bootstrap
   — every CLI command in this codebase exits 0 on failure.** Do not wrap
   any CLI negative-test-case anywhere in this plan in `set -e` or `&&` and
   expect failure to be caught — grep the output instead. Step 9 measures
   this directly.
```

Replace with:

```
8. **Every failure below used to still exit `0` — FIXED `<root-fix-commit>`
   (2026-08-17).** `Execute()` (`cmd/root.go:73-78`) called `os.Exit(0)`
   inside its `if err != nil` branch. Combined with the fact that no
   `SilenceUsage`/`SilenceErrors` is set anywhere under `cmd/`, a failed
   bootstrap printed `Error: ...` followed by the full usage block and
   returned `$? == 0` regardless. **This was not specific to bootstrap —
   every CLI command in this codebase exited 0 on failure**, until the fix.
   Step 9 now demonstrates the corrected `exit=1` behavior. If you're
   testing against a checkout older than `<root-fix-commit>`, the old
   behavior still applies.
```

- [ ] **Step 5: Update §2 step 9's expected output**

Find this exact block (currently around lines 873-879):

````
**9. Confirm the exit code is `0` even for every failure above** (gotcha
#8) — worth doing once so you never trust `&&` here:
```bash
go run main.go --config "$CFG" users admin --admin-username admin >/dev/null 2>&1
echo "exit=$?"
```
Expect `exit=0`.
````

Replace with:

````
**9. Confirm the exit code correctly reflects failure** (gotcha #8 — fixed
`<root-fix-commit>`; kept as a regression check rather than removed):
```bash
go run main.go --config "$CFG" users admin --admin-username admin >/dev/null 2>&1
echo "exit=$?"
```
Expect `exit=1`. (Before `<root-fix-commit>`, this printed `exit=0` despite
the command genuinely failing on missing required flags — see gotcha #8.)
````

- [ ] **Step 6: No commit needed** — `.claude/` is gitignored in this repo; there is nothing to `git add`/`git commit` for this task. Just save the file.

---

### Task 2: Update the developer KB (`known-issues-gotchas.md` and `security-auth.md`)

**Files:**
- Modify: `~/data/rocket/Nl-knowledge-base/rocketvault/known-issues-gotchas.md` (the top-of-file "CRITICAL, CLI-wide" section, plus the `secrets/generate.go` follow-on)

**Interfaces:** None (prose-only document, separate repo from RocketVault itself).

- [ ] **Step 1: Flip the top-of-file entry's status**

In `known-issues-gotchas.md`, find the `## CRITICAL, CLI-wide: every command exits \`0\` on error` section's status line:

```
- **Status**: Not fixed, not yet filed as a numbered bug as of 2026-08-17 — found during manual-test-plan drafting (an agent ran `rocketvault serve --config <bad-hsm-config>` and multiple bootstrap-failure cases live, checked `$?` each time, and got `0` every time).
```

Replace with:

```
- **Status**: FIXED (commit `<root-fix-commit>`, 2026-08-17). `Execute()` now delegates to a `run(cmd *cobra.Command) int` helper (`cmd/root.go`) that returns 1 on error, 0 on success — unit-tested directly (`TestRun_ReturnsNonZeroOnError`/`TestRun_ReturnsZeroOnSuccess`, `cmd/root_test.go`) rather than only relied on empirically. A companion audit (`docs/superpowers/plans/2026-08-17-cli-exit-code-audit.md` in the rocketvault repo) confirmed zero tests or CI steps depended on the old exit-0 behavior; `scripts/create_admin.sh`'s bootstrap-failure detection, previously dead code because of this bug, is now reachable and correct.
```

- [ ] **Step 2: Add a short new entry for the second, independently-discovered instance of the same bug class**

Immediately after the section from Step 1 (still inside the same `## CRITICAL, CLI-wide` heading — this is the same root-cause pattern, not a new top-level section), add:

```
### A second, independent instance of the same bug: `cmd/secrets/generate.go`
- **What it was**: `generateCmd`'s `Run` handler called `os.Exit(0)` when `generatePassword` returned an error (e.g. `--length 0`), the identical bug pattern to the `cmd/root.go` case above, but a separate manual `os.Exit` call, not routed through `Execute()`/`run()` at all.
- **Fix**: converted `Run` to `RunE`, removed the manual `os.Exit(0)` entirely, and let the error propagate through Cobra to the (now-fixed) `run()` helper. Regression test: `TestGenerateCmd_InvalidLength_ReturnsError` (`cmd/secrets/generate_test.go`).
- **Status**: FIXED (commit `<generate-fix-commit>`, 2026-08-17).
- **Source**: `cmd/secrets/generate.go`; `docs/superpowers/plans/2026-08-17-secrets-generate-exit-code-fix.md` in the rocketvault repo.
```

- [ ] **Step 3: No production-code commit needed** — this is a separate KB repo (`~/data/rocket/Nl-knowledge-base/`). If that directory is itself a git repo, commit there per its own conventions; if it's not version-controlled, just save the file. Check with `git -C ~/data/rocket/Nl-knowledge-base status` before assuming either way.

---

### Task 3: Confirm no manual changelog needs updating

**Files:** None expected — this task is a check, not an edit.

**Interfaces:** None.

- [ ] **Step 1: Confirm this repo has no manually-maintained `CHANGELOG.md`**

```bash
ls CHANGELOG.md 2>&1
cat cliff.toml | head -20
```
Expected: `CHANGELOG.md` does not exist; `cliff.toml` exists — this repo generates its changelog from conventional-commit messages at release time via `git-cliff` (see `docs/superpowers/plans/*.md`'s existing conventions and this repo's `release.sh`/`release.yml`, per `[[project-release-infra]]`), not a hand-edited file.

- [ ] **Step 2: Confirm both fix commits use conventional-commit prefixes that `git-cliff` will pick up correctly**

```bash
git log --oneline -5 | grep -E "^\w+ fix\(cmd\)|^\w+ fix\(secrets\)"
```
Expected: both `fix(cmd): exit non-zero on CLI command failure` and `fix(secrets): return error instead of os.Exit(0) in generate-password` appear — confirming no further action is needed here; the next release's auto-generated changelog will include both under its "Fixed" section without any manual step.

No commit for this task — verification only.
