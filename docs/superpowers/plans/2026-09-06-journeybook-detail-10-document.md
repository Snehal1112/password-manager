# Journeybook Detail — Document the Contract — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write the five fields and the five gates into `.claude/authoring-cases.md`, so the next person to edit a case knows that a `why` without a `source` is not acceptable — then update the surrounding docs and close the chain.

**Architecture:** The enrichment brief was scaffolding for seven agents; the rules inside it are permanent. Fold the durable half into the file that already governs case authoring, delete the scaffolding, and correct the two docs that describe what the page contains.

**Tech Stack:** Markdown.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Prerequisite:** Plan 09 complete and committed.

**Followed by:** nothing. This is the last plan in the chain.

## Global Constraints

- `journeybook/.claude/authoring-cases.md` is the governing document for case data. Its seven existing rules stay; the new ones are added, not substituted.
- `journeybook/CLAUDE.md` must stay small and point at `.claude/` rather than absorbing it.
- Do not restate bug status or case counts that live elsewhere and will drift.
- All commits are GPG-signed.

---

### Task 1: Fold the gates into the authoring rules

**Files:**
- Modify: `journeybook/.claude/authoring-cases.md`
- Delete: `journeybook/.claude/enrichment-brief.md`

**Interfaces:**
- Consumes: the durable half of the brief written in plan 04 Task 1.
- Produces: the standing contract for anyone adding detail to a case.

- [x] **Step 1: Extend the field table and the rules**

In `journeybook/.claude/authoring-cases.md`, in the **The rules** section,
after existing rule 7 (`notes` explains why the case exists), add:

```markdown
**8. A claim needs a citation or it does not ship.** `why`, `verify` and
`after` each require `source` — a document section
(`VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap`) or a code
location (`internal/services/vaults/vault_service.go:214`). `scripts/check-links.mjs`
fails the build if one is missing.

**Omission is a correct outcome.** A case with no `why` is honest. A case
with a plausible-sounding invented one is the failure this rule exists to
prevent, and it is worse than the thin case it replaced — a thin check sends
a tester to the document, a confidently wrong one sends them to file a defect
against working software.

**9. `verify.command` is transcribed or confirmed, never inferred.** Copy it
from the journeys document, or build it only from flags you have read in the
cobra registration in `cmd/`. Never from a flag name, a help string, or the
shape of a neighbouring command. A verification command carrying a flag that
does not exist teaches a tester to distrust the whole page.

**10. When the document and the code disagree, say so — do not choose.**
`VAULT_USER_ACCESS_JOURNEYS_v3.md` is dated and the CLI has drifted before. A
case quietly corrected from the code contradicts the document a tester is
reading beside it, and hides what may be a real defect. Raise it.

**11. No hedging.** No "should", "presumably", "likely", "appears to". A claim
you cannot state flatly from a source is not written. Hedged text reads as
information while carrying none, and a tester cannot act on it.

**12. `why` and `notes` do not overlap.** `why` is the system's mechanism;
`notes` is what a tester should do or watch out for. Where a note already
carries mechanism, move that half to `why` and leave the actionable half.
Never duplicate, and never drop the actionable half. See `J6` for the worked
split.
```

- [x] **Step 2: Extend the "Where things live" table and add the field reference**

In the same file, in the table under **Where things live**, add a row:

```markdown
| `scripts/apply-enrichment.mjs` | Merges enrichment JSON into the case data. Agents never edit `src/data/` directly |
| `scripts/check-links.mjs` | Fails on a dangling `related` id or a claim with no `source` |
```

Then, immediately after the rules, add:

```markdown
## The detail fields

Beyond `command`, `expected` and `assert`, a case can carry five optional
fields. They render in one fixed order — Why, Before, Run, Expected, Verify,
After, Note, Related, Source — as a definition list with labels right-aligned
in a 3.5rem gutter.

| Field | Holds | Required with it |
| --- | --- | --- |
| `why` | The mechanism. Why the system behaves this way, not what the command does | `source` |
| `verify` | `{ command?, look }` — how to settle pass from fail when `expected` leaves a margin | `source` |
| `after` | What the check leaves behind, and what to undo first | `source` |
| `related` | `{ id, rel }[]` — `depends`, `diverges` or `contrasts` | ids must resolve |
| `source` | Provenance. Document section or `file.go:line`, several joined by `; ` | — |

`Suite.context` holds the journey-level prose as one string per paragraph.

Most cases carry none of these. `verify` earns its place only where the
expected line genuinely leaves room for doubt; `after` only where the check
leaves state behind. Journey J is the reference for all of them.
```

- [x] **Step 3: Remove the scaffolding**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git rm journeybook/.claude/enrichment-brief.md
```

The brief was written for seven agents doing one backfill. Its durable half is
now in `authoring-cases.md`, and leaving both means two documents stating the
same rules, which is how one of them goes stale without anyone noticing.

- [x] **Step 4: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/.claude/authoring-cases.md
git commit -m "docs(journeybook): make the detail gates standing rules

Rules 8-12 and a field reference, so the next person editing a case
knows a why without a source does not ship, a verify command is never
inferred from a flag name, and a doc/code disagreement is raised rather
than resolved into the case.

Removes the enrichment brief. It was scaffolding for one backfill and
its durable half is here now; keeping both would leave two copies of
the same rules to drift apart."
```

---

### Task 2: Correct what the surrounding docs claim

**Files:**
- Modify: `journeybook/README.md`
- Modify: `journeybook/CLAUDE.md`
- Modify: `CLAUDE.md` (repository root)

**Interfaces:**
- Consumes: the actual built artifact size from plan 09 Task 3 Step 1.
- Produces: docs that describe the page as it now is.

- [x] **Step 1: Update the journeybook README**

In `journeybook/README.md`:

- The opening paragraph says the page "walks a QA engineer through every
  RocketVault vault, user and access journey ... and records a pass or fail
  against each one." Extend it to say each check now also carries why the
  system behaves that way, how to settle an ambiguous result, and what it
  leaves behind.
- The **Building it** section states the output is "roughly 553 kB, 215 kB
  gzipped". Replace both figures with the real ones from plan 09's build. Do
  not estimate — run `ls -la dist/` and `gzip -c dist/journeybook.html | wc -c`
  and use what they say.
- The **Keeping it true** section already points at `authoring-cases.md`. Add
  that a claim in a case carries a citation, and that `bun run check:links`
  fails the build if one is missing.

- [x] **Step 2: Update `journeybook/CLAUDE.md`**

Add to the **Things that will bite** list:

```markdown
- **A `why`, `verify` or `after` with no `source` fails `bun run check:links`.**
  That is deliberate, not a lint annoyance: a claim a reader cannot trace is
  the one failure mode this page cannot survive. If you cannot cite it, delete
  it — an absent field is honest.
- **Enrichment is applied by `scripts/apply-enrichment.mjs`, not by hand.** It
  brace-matches the case object and refuses to apply twice. Hand-editing 245
  cases is how transcription errors get back in.
```

- [x] **Step 3: Update the repository CLAUDE.md**

In the root `CLAUDE.md`, the **QA Journeybook** bullet under Developer
Resources describes the page as "23 suites, 245 checks, each carrying its
command, its verbatim expected output, and which of the three gates it
exercises."

Extend that list to include the mechanism, the verification and the
cross-references, and note that each claim carries its provenance. Keep the
existing sentence about the cases going stale the moment the CLI changes — it
is more true now, not less.

Do not add a count that will drift. The bullet already says 245; leave the
number where it is rather than adding a second one.

- [x] **Step 4: Rebuild and commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run build && ls -la dist/ && gzip -c dist/journeybook.html | wc -c
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/README.md journeybook/CLAUDE.md CLAUDE.md
git commit -m "docs: describe what the journeybook now carries

Each check carries the mechanism, the verification and its
cross-references, not only a command and an expected line. Corrects the
build-size figures in the README to the measured values rather than the
pre-enrichment ones."
```

---

## When this plan is complete

The chain is finished. Confirm the whole thing still holds:

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run typecheck && bun run lint && bun run check:links \
  && bun scripts/check-contrast.mjs && bun run build
cd /home/numericlabs/data/rocket/rocketvault
git log --oneline -12
git status --short
```

Expected: five clean exits, the ten-plus commits of this chain in order, and a
clean working tree.

**Next plan:** none. Report to the human: what shipped, what was cut and why,
and any contradiction from plans 06 or 08 that needs a follow-up — a code
defect found during the backfill belongs in `.claude/known-bugs.md`, which is
this repository's living source of truth for bug status, not in a commit
message where it will be lost.

---

## Self-Review

**Spec coverage:** the spec's final consequence — "`authoring-cases.md` needs a
new section documenting the five fields and the five gates" — is Task 1. Task 2
covers the doc drift the change causes.

**Placeholder scan:** none. Task 2 deliberately refuses to write a build size,
because the real number is only known after plan 09's build and a guessed one
would be exactly the stale figure it is replacing.

**Type consistency:** the field table in Task 1 Step 2 matches `Case` from plan
01 Task 1 exactly — `why`, `verify: { command?, look }`, `after`,
`related: { id, rel }[]`, `source`, and `Suite.context`. The three `rel` values
match `Relation`.

**Known risk:** rules 8–12 are only as strong as the next author's willingness
to read them, and only rule 8 has a mechanical check behind it
(`check-links.mjs`). Rules 9 through 12 rely on review. That asymmetry is worth
knowing rather than papering over — the honest position is that provenance is
enforced and judgment is not.
