# API Refactor 11 — Cleanup, Final Verification, Close

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove dead code the refactor exposed, run the full verification one last time, and write up what actually changed — including what was found and deliberately not fixed.

**Architecture:** No new abstractions. This plan closes the chain and produces the report the work is ultimately for.

**Tech Stack:** Go 1.25.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Delete nothing without proving it is unreferenced across the whole repo**, not just `api/`. An exported symbol may have a caller in `cmd/`, `internal/`, or a test.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Remove proven-dead code

**Files:**
- Modify: `api/context.go` (the `SessionRequired` alias), plus anything else the sweep proves dead

**Interfaces:**
- Consumes: the whole repository, for reference checking.
- Produces: a smaller package. No new symbols.

- [ ] **Step 1: Prove `SessionRequired` is unreferenced**

`api/context.go` declares `var SessionRequired = ApiSessionRequired`, described
as a backward-compatibility alias. It is exported, so a caller could live
anywhere.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
grep -rn '\bSessionRequired\b' --include='*.go' . | grep -v 'ApiSessionRequired'
```
Expected, if it is dead: only the declaration in `api/context.go`.

Note the `grep -v` is doing real work — `ApiSessionRequired` contains
`SessionRequired` as a substring, so a naive grep reports hundreds of false hits.

If any real caller exists, **keep the alias** and record it in Task 3's report
as intentionally retained rather than deleting it.

- [ ] **Step 2: Sweep for anything else the refactor orphaned**

The plans replaced helpers with generics; some old helpers may now be unused.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go vet ./... 2>&1 | tail -20
gofmt -l api/ internal/ cmd/
```

Go does not report unused package-level functions, so check the specific
symbols the chain was meant to retire:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
for sym in secretSvc keySvc cryptoSvc userSvc certSvc authSvc; do
    printf "%-12s %s\n" "$sym" "$(grep -rn "\b$sym\b" --include='*.go' . | wc -l)"
done
```
Expected: 0 for each, or a small number confined to `api/context.go` if plan 04
Task 3 kept one as a test-facing delegation. Any other hit is a site plan 04 missed.

- [ ] **Step 3: Delete, gate, commit**

Delete only what Steps 1 and 2 proved dead.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
./scripts/verify-api-refactor.sh
```
Expected: `PASS`.

```bash
git add api/
git commit -S -m "refactor(api): drop the dead SessionRequired alias"
```

Adjust the message if the sweep removed more, or skip this commit entirely if it
turned out nothing was dead — an empty cleanup is a legitimate result and better
than inventing a deletion.

---

### Task 2: Full verification against the original baseline

**Files:**
- Modify: none (verification only)

**Interfaces:**
- Consumes: the whole chain, plans 01-11.
- Produces: the measured numbers Task 3 reports.

- [ ] **Step 1: Run the complete suite from clean**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go clean -testcache
go build ./...
go vet ./...
go test ./... -count=1 2>&1 | tail -40
```
Expected: every package `ok` or `no test files`. **Note this is `go vet ./...`,
the whole repo, not just `api/`** — plan 09 changed `internal/`, so the wider
vet matters here.

- [ ] **Step 2: Confirm the route surface never moved**

The refactor promised to change no route. Prove it, rather than trusting that
the contract tests would have caught it:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./api/... -count=1 -run 'Route|Contract|OpenAPI|Inventory|Authorization' -v 2>&1 | tail -30
```
Expected: all pass, including `TestClientPathsAreRegistered`,
`TestOpenAPISpecCoversAllRoutes` and `TestAuthorizationMatrixOpsAreRealRoutes`.

- [ ] **Step 3: Measure the outcome**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
echo "=== non-test lines ==="
echo "baseline (4dc0285): 7214"
echo "now:                $(wc -l $(ls *.go | grep -v _test) | tail -1 | awk '{print $1}')"
echo
echo "=== files over 600 lines ==="
wc -l $(ls *.go | grep -v _test) | sort -rn | awk '$1 > 600 && $2 != "total"'
echo
echo "=== coverage ==="
cd .. && go test ./api/... -count=1 -cover 2>&1 | tail -2
echo
echo "=== idiom counts, baseline -> now ==="
cd api
printf "encode      78 -> %s\n" "$(grep -c 'json.NewEncoder(w).Encode' $(ls *.go|grep -v _test) | awk -F: '{s+=$2} END {print s}')"
printf "decode      20 -> %s\n" "$(grep -c 'json.NewDecoder(r.Body).Decode' $(ls *.go|grep -v _test) | awk -F: '{s+=$2} END {print s}')"
printf "uuid.Parse  51 -> %s\n" "$(grep -c 'uuid.Parse(c.Params' $(ls *.go|grep -v _test) | awk -F: '{s+=$2} END {print s}')"
printf "map bodies  21 -> %s\n" "$(grep -c 'map\[string\]any{' $(ls *.go|grep -v _test) | awk -F: '{s+=$2} END {print s}')"
```

Record every number. Task 3 reports them.

---

### Task 3: Write the report and hand off

**Files:**
- Create: `docs/superpowers/specs/2026-09-06-api-refactor-outcome.md`
- Modify: `.claude/known-bugs.md` (any finding not fixed)

**Interfaces:**
- Consumes: the measurements from Task 2.
- Produces: the outcome document, and a branch ready to merge.

- [ ] **Step 1: Write the outcome report**

Create `docs/superpowers/specs/2026-09-06-api-refactor-outcome.md`:

```markdown
# `api/` Generic-Primitive Refactor — Outcome

**Branch:** `refactor/api-generics`, based on `v-4.0.0` @ `4dc0285`
**Spec:** `2026-09-06-api-generic-primitives-design.md`

## What changed

[The measured numbers from Task 2 Step 3: line count before and after, the
four idiom counts, final coverage, largest remaining file.]

## Primitives added

[One line each for the seven, naming the file each lives in.]

## Behavior changes

Plans 02-08 changed no behavior and modified no test file. Plans 09-11 changed
behavior deliberately:

[Each behavioral change, one line, with the commit that made it.]

## Found but not fixed

[Every defect noticed during the review that was not addressed, with a pointer
to its `.claude/known-bugs.md` entry. If this section is empty, say so
explicitly rather than deleting the heading — "nothing outstanding" is
information.]

## Remaining work

[Anything the chain deliberately left, e.g. any file still over 600 lines, the
`ApiHandler`/`ApiSessionRequired` consolidation the spec listed as a non-goal,
any response body still a map and why.]
```

Fill in every bracketed section from the actual measurements. A bracketed
placeholder left in the committed file is a plan failure.

- [ ] **Step 2: File anything found but unfixed**

If the review surfaced defects that no plan fixed, add each to
`.claude/known-bugs.md` in that file's existing format — symptom, root cause,
fix recipe. Candidates carried through this chain:

- The unscoped `KeyRepository.ReadDeleted`, if plan 09 did not audit its
  existing callers. It takes no `model.Scope`, so any caller on an
  authorization-relevant path would read across vault boundaries. Worth an
  explicit audit even though plan 09 avoided using it.
- Anything plan 10's triage moved to its "defer" bucket.

- [ ] **Step 3: Final gate and hand off**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
./scripts/verify-api-refactor.sh
git add docs/superpowers/specs/2026-09-06-api-refactor-outcome.md .claude/known-bugs.md
git commit -S -m "docs(api): record the generic-primitive refactor outcome"
git log --oneline 4dc0285..HEAD
```

Then report to the user:

- The measured before/after numbers.
- The commit list.
- That the branch is `refactor/api-generics` in the worktree at
  `/home/numericlabs/data/rocket/rocketvault-api-refactor`, ready for review.
- **Do not merge and do not delete the worktree.** Merging is the user's call.
  Offer `superpowers:finishing-a-development-branch` as the next step and stop.

---

## Next plan

**None — this is the final plan in the chain.** Report to the user and stop.
