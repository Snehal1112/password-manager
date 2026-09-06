# API Refactor 01 — Baseline & Verification Gate

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Commit the design spec and the plan chain onto the refactor branch, then build the one verification script every later plan reuses as its gate.

**Architecture:** No production code changes. This plan exists so that plans 02-11 can each end with a single command that proves nothing regressed, rather than each re-deriving what "green" means.

**Tech Stack:** Go 1.25, gorilla/mux, testify. Bash for the gate script.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0 (`go.mod`). Generics, `slices` and `maps` are all available.
- Worktree: `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`, based on `v-4.0.0` @ `4dc0285`.
- Baseline to preserve: `go build ./...` exit 0, `go vet ./api/...` exit 0, `go test ./api/...` ok at **86.0%** statement coverage.
- **Plans 02-08 must not modify any `_test.go` file.** A test that needs editing in those plans proves behavior changed — stop and report instead of adjusting the test.
- All commits are GPG-signed (key `61D246B30285ED35`). Use the `1-git-commit` skill for commit messages rather than freeform `git commit -m`.
- Comments use short, plain full sentences ending in a punctuation mark. No emojis.

---

### Task 1: Land the spec and plan chain on the branch

**Files:**
- Modify (already written, needs committing): `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`
- Modify (already written, needs committing): `docs/superpowers/plans/2026-09-06-api-refactor-01-baseline.md` through `...-11-cleanup-and-close.md`

**Interfaces:**
- Consumes: nothing.
- Produces: the committed spec path that every later plan cites in its header.

- [ ] **Step 1: Confirm you are in the worktree on the right branch**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
git branch --show-current
```
Expected: `refactor/api-generics`

If this prints anything else, stop. Do not proceed on the main checkout.

- [ ] **Step 2: Confirm the docs are present and nothing else is staged**

Run:
```bash
git status --porcelain
```
Expected: only untracked entries under `docs/superpowers/specs/` and `docs/superpowers/plans/`. If any `api/*.go` file appears, stop and investigate — this plan changes no production code.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md \
        docs/superpowers/plans/
git commit -S -m "docs(api): add generic-primitive refactor spec and plan chain"
```

---

### Task 2: Build the shared verification gate

**Files:**
- Create: `scripts/verify-api-refactor.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: `scripts/verify-api-refactor.sh`, invoked by every later plan as its final gate. It exits non-zero on any failure and prints the coverage percentage it measured.

- [ ] **Step 1: Write the script**

Create `scripts/verify-api-refactor.sh`:

```bash
#!/usr/bin/env bash
# Verification gate for the api/ generic-primitive refactor.
# Every plan in the chain runs this before committing. It fails loudly rather
# than reporting partial success, because a refactor that only mostly works is
# a regression that has not been found yet.
set -euo pipefail

BASELINE_COVERAGE=86.0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> go build ./..."
go build ./...

echo "==> go vet ./api/..."
go vet ./api/...

echo "==> go test ./... -count=1"
go test ./... -count=1

echo "==> go test ./api/... -count=1 -cover"
coverage_line="$(go test ./api/... -count=1 -cover | tee /dev/stderr | grep -o 'coverage: [0-9.]*%')"
coverage="${coverage_line#coverage: }"
coverage="${coverage%\%}"

# awk rather than bash arithmetic: these are decimals, and bash only does
# integers, so a plain [ ] comparison would silently accept a drop.
if awk -v c="$coverage" -v b="$BASELINE_COVERAGE" 'BEGIN { exit !(c < b) }'; then
    echo "FAIL: api/ coverage ${coverage}% is below the ${BASELINE_COVERAGE}% baseline."
    exit 1
fi

echo "PASS: build, vet, full test suite green; api/ coverage ${coverage}% (baseline ${BASELINE_COVERAGE}%)."
```

- [ ] **Step 2: Make it executable**

Run:
```bash
chmod +x scripts/verify-api-refactor.sh
```

- [ ] **Step 3: Verify it detects a coverage drop**

The gate is worthless if it cannot fail. Prove it can:

```bash
sed -i 's/^BASELINE_COVERAGE=86.0/BASELINE_COVERAGE=99.9/' scripts/verify-api-refactor.sh
./scripts/verify-api-refactor.sh; echo "exit=$?"
```
Expected: the script prints `FAIL: api/ coverage 86.0% is below the 99.9% baseline.` and `exit=1`.

Now restore it:
```bash
sed -i 's/^BASELINE_COVERAGE=99.9/BASELINE_COVERAGE=86.0/' scripts/verify-api-refactor.sh
grep '^BASELINE_COVERAGE=' scripts/verify-api-refactor.sh
```
Expected: `BASELINE_COVERAGE=86.0`

---

### Task 3: Record the green baseline and commit

**Files:**
- Modify: `scripts/verify-api-refactor.sh` (committing it)

**Interfaces:**
- Consumes: `scripts/verify-api-refactor.sh` from Task 2.
- Produces: a committed, proven-green gate. Every later plan's final step is `./scripts/verify-api-refactor.sh`.

- [ ] **Step 1: Run the gate for real**

Run:
```bash
./scripts/verify-api-refactor.sh
```
Expected final line: `PASS: build, vet, full test suite green; api/ coverage 86.0% (baseline 86.0%).`

If this does not pass on an unmodified tree, stop. The baseline is wrong and every later plan's gate would be meaningless.

- [ ] **Step 2: Confirm no production code drifted**

Run:
```bash
git status --porcelain
```
Expected: only `scripts/verify-api-refactor.sh` as untracked. No `api/*.go` changes.

- [ ] **Step 3: Commit**

```bash
git add scripts/verify-api-refactor.sh
git commit -S -m "chore(api): add verification gate for the refactor chain"
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-02-respond.md` next.**
