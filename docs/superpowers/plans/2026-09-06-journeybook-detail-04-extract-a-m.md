# Journeybook Detail — Extract A–M — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write the shared extraction brief, then produce doc-sourced enrichment for journeys A–F (64 cases) and G–M (50 cases, minus Journey J which the pilot already did).

**Architecture:** One brief, written once and handed verbatim to all five extraction agents, so the rules do not drift between groups. Each agent reads its slice of `VAULT_USER_ACCESS_JOURNEYS_v3.md` and its slice of the case data, and emits one JSON file. No agent opens `src/data/*.ts` for writing.

**Tech Stack:** Agent tool with Sonnet — transcription and structured extraction, not architectural reasoning. The Opus pass comes in plan 06, where Go authorization paths have to be understood rather than copied.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Prerequisite:** Plan 03 Task 3's human approval. Do not start otherwise.

**Followed by:** `2026-09-06-journeybook-detail-05-extract-n-w.md`, which covers the remaining three groups.

## Global Constraints

- The five gates bind every agent. They are stated in full in the brief written by Task 1 and must be passed to every dispatch verbatim.
- **No subagent writes to `journeybook/src/data/`.** Output is JSON in the scratchpad. An agent that edits a data file has broken the plan; discard its work and re-dispatch.
- Journey J is already done. The G–M agent must skip it entirely — re-enriching it would trip the merge script's double-application guard in plan 09.
- Scratchpad root for this work: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/`

---

### Task 1: Write the shared extraction brief

**Files:**
- Create: `journeybook/.claude/enrichment-brief.md`

**Interfaces:**
- Produces: the file every dispatch in plans 04, 05 and 06 points its agent at. Plan 10 folds its durable half into `.claude/authoring-cases.md` and deletes it.

- [ ] **Step 1: Write the brief**

Create `journeybook/.claude/enrichment-brief.md`:

````markdown
# Enrichment brief

You are adding detail to RocketVault's QA journeybook. A QA engineer opens
this page offline and records a pass or fail against each check. Today a check
carries a title, one assertion, a command and an expected line. You are adding
the reasoning the source document has and the page dropped.

**The thing that matters more than coverage: a check that misleads a tester is
worse than a thin one.** A thin check sends them to the document. A confidently
wrong one sends them to file a defect against working software, or to pass a
broken build. Every rule below exists for that reason.

## What you produce

One JSON file, keyed by case id. Nothing else. **Do not edit any file under
`journeybook/src/data/`** — five agents writing four files concurrently
corrupts them.

```json
{
  "B3": {
    "why":    { "text": "...", "source": "..." },
    "verify": { "command": "...", "look": "...", "source": "..." },
    "after":  { "text": "...", "source": "..." },
    "related": [{ "id": "B2", "rel": "depends" }],
    "needs-code": ["why: <the precise open question>"]
  }
}
```

Every key is optional. A case with nothing worth adding gets no entry at all.

## The fields

**`why`** — the mechanism. Why the system behaves this way, not what the
command does. "`HasDataAction` has no admin short-circuit, so creating a vault
grants nothing inside it" is a why. "This command lists keys" is not.

**`verify`** — how to settle pass from fail when `expected` leaves a margin.
`look` is required; `command` is optional. Add it only where the expected line
genuinely leaves room for doubt, not on every case.

**`after`** — what the check leaves behind, and what to undo before the next
one. Most checks leave nothing; most cases get no `after`.

**`related`** — cross-references. `depends` (this check is meaningless unless
that one passed first), `diverges` (the same authority gives a different answer
there), `contrasts` (the neighbouring case with the opposite outcome). Only
real, useful links. Two or three across a journey beats one on every case.

**`needs-code`** — open questions you could not settle from the documents.
Phrase each as `field: the precise question`. These do not block the fields
beside them: a case can carry a finished `why` and an open `verify` question at
once.

## The five gates

**1. Provenance or nothing.** Every `why`, `verify` and `after` carries a
`source`: a document section (`VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J —
the purge trap`) or a code location (`internal/services/vaults/vault_service.go:214`).
If you cannot cite it, do not write it. **Omission is a correct outcome.** An
absent `why` is honest; a plausible-sounding invented one is the failure this
brief exists to prevent.

**2. No invented commands.** A `verify.command` is transcribed verbatim from
the document, or built only from flags you have confirmed exist by reading the
cobra registration in `cmd/`. Never inferred from a flag name, never guessed
from a pattern in a neighbouring command. If you cannot confirm it, ship `look`
prose with no command and raise a `needs-code` question.

**3. You will be checked.** A different agent re-opens every citation you write
and reports whether it supports your claim, overstates it, contradicts it, or
does not exist. Only supported claims ship. Write accordingly.

**4. Doc/code disagreement is surfaced, never resolved.** The journeys document
is dated and the CLI has drifted before. If the document says one thing and the
code says another, **do not pick a winner and do not write the code's answer
into the case.** Record both in a `needs-code` entry prefixed `DISAGREEMENT:`
and move on. A case quietly corrected from source contradicts the document the
tester has open beside it, and it hides what may be a real bug or real doc rot.

**5. No hedging.** No "should", "presumably", "likely", "appears to", "is
expected to". A claim you cannot state flatly from a source is not written.
Hedged text reads as information while carrying none, and a tester cannot act
on it.

## Style

- The audience is a QA engineer mid-run, not a developer reading a design doc.
  Plain sentences. No filler.
- Two inline markers render, and nothing else: `` `code` `` and `**bold**`.
  Anything else appears literally, deliberately, so a real error message
  containing an asterisk is not silently eaten.
- Keep `why` to one to four sentences. If it needs more, you are explaining the
  subsystem rather than the check.
- Where an existing `notes` already carries the mechanism, put that half in
  `why` and add a `needs-code` entry saying which `notes` needs its mechanism
  half removed. **Do not duplicate**, and never propose dropping the actionable
  half of a note.

## The worked example

`journeybook/src/data/journeys-g-m.ts`, Journey J, is the reference. Read all
seven cases before you start. Three things in it are precedent:

- **J2 carries no `why`.** The document shows its command and does not explain
  it. Inferring a reason from the flag name would be a Gate 1 violation. This
  is the single most important line in the example.
- **J1 and J4 carry `needs-code` beside finished fields.**
- **J5's `why` cites Journey K**, because that is where the fact actually is.
  Cite where the claim lives, not where the case sits.
````

- [ ] **Step 2: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/.claude/enrichment-brief.md
git commit -m "docs(journeybook): add the enrichment extraction brief

One brief handed verbatim to all five extraction agents so the rules do
not drift between groups. Carries the five gates from the 2026-09-06
spec and points at Journey J as the worked example.

Plan 10 folds the durable half into authoring-cases.md and removes this."
```

---

### Task 2: Extract journeys A–F

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/a-f.json`

**Interfaces:**
- Consumes: the brief from Task 1.
- Produces: enrichment for 64 cases across suites A, B, C, D, E, F.

- [ ] **Step 1: Dispatch**

Use the Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Extract A-F case detail"`, with this prompt:

```
You are enriching QA test cases for RocketVault's journeybook.

Read these three things in full before writing anything:

1. /home/numericlabs/data/rocket/rocketvault/journeybook/.claude/enrichment-brief.md
   -- the rules. They are binding. Follow them exactly.
2. /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
   lines 1-505. That is the two v3 corrections, the global setup, the cast,
   and Journeys A through F. Read the corrections and the cast too, not only
   the journey sections -- a great deal of the "why" for A-F lives in
   Correction 8, which explains the CLI-only global role gate.
3. /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/journeys-a-f.ts
   -- the 64 cases you are enriching, ids A1-A12, B1-B12, C1-C23, D1-D6,
   E1-E6, F1-F5.

Also read Journey J in journeys-g-m.ts as the worked example. It is already
enriched and is the standard you are matching.

Write your output to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/a-f.json

Do not edit any other file. Do not touch journeybook/src/data/.

Scope notes for this group specifically:

- Correction 8 is the mechanism behind a large share of A-F's denials. Where
  a case fails because the CLI checks a global role that HTTP does not, say
  so and cite the Correction 8 section.
- Journey C is 23 cases covering the whole key lifecycle. Correction 9 lists
  which key capabilities have no CLI command at all. Cases asserting the
  absence of a capability should cite Correction 9.
- Journey F is about a Crypto User hitting the rotation-policy wall. The
  document explains the boundary; make sure the why says which permission is
  missing, not just that one is.

Report back: how many cases you enriched, how many you deliberately left
without a why and why you judged that right, and every needs-code question in
full. Quote any DISAGREEMENT entries verbatim -- those go to a human.
```

- [ ] **Step 2: Sanity-check the output before accepting it**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun scripts/apply-enrichment.mjs --dry-run \
  /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/a-f.json
```

Expected: it parses, every id resolves, and `git diff --stat` is empty.

Then read the JSON yourself and check three things, because these are the
failure modes the dry run cannot catch:

- **Every `why` has a `source`.** Grep for `"why"` and confirm each object has
  a sibling `"source"`.
- **No hedging.** `grep -iE '"(text|look)": "[^"]*(should|presumably|likely|appears to|probably)' a-f.json` must return nothing.
- **Some cases have no `why`.** If all 64 are enriched, the agent has been
  inventing. Journey J's ratio — six of seven, with one deliberate omission —
  is the shape to expect, but a group with no omissions at all is a red flag
  worth challenging.

If any check fails, send the agent back with the specific problem rather than
fixing it yourself. It has the document loaded; you do not.

---

### Task 3: Extract journeys G–M, skipping J

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/g-m.json`

**Interfaces:**
- Consumes: the brief from Task 1.
- Produces: enrichment for 43 cases across G, H, I, K, L, M. Journey J's 7 are excluded.

- [ ] **Step 1: Dispatch**

Use the Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Extract G-M case detail"`, with this prompt:

```
You are enriching QA test cases for RocketVault's journeybook.

Read these three things in full before writing anything:

1. /home/numericlabs/data/rocket/rocketvault/journeybook/.claude/enrichment-brief.md
   -- the rules. They are binding. Follow them exactly.
2. /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
   lines 1-100 (the two v3 corrections and the cast) and lines 505-810
   (Journeys G through M).
3. /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/journeys-g-m.ts
   -- your cases are G1-G11, H1-H6, I1-I6, K1-K4, L1-L11, M1-M5.

CRITICAL: Journey J (J1-J7) is ALREADY ENRICHED and is your worked example.
Read all seven of its cases as the standard you are matching, but do NOT
include any J case in your output. Including one breaks the merge in a later
step.

Write your output to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/g-m.json

Do not edit any other file. Do not touch journeybook/src/data/.

Scope notes for this group specifically:

- Journey H is explicit deny. The important mechanism is ordering: an access
  policy deny is evaluated BEFORE any role grant, so it overrides a role the
  principal genuinely holds. Make that ordering explicit in the why.
- Journey K is the CLI/HTTP purge divergence, and Journey J's J5 already
  points at K3 with rel "diverges". Add the reciprocal links from K's side.
- Journey L's auditor cases turn on audit logs being admin-only and
  instance-wide, so vault-scoped Reader grants are irrelevant to them. The
  document flags this as a friction point for compliance process design.
- Journey M is offboarding. Where a step has no CLI equivalent, the case
  should already assert the absence; your why explains why the absence
  matters operationally.

Report back: how many cases you enriched, how many you deliberately left
without a why and why you judged that right, and every needs-code question in
full. Quote any DISAGREEMENT entries verbatim.
```

- [ ] **Step 2: Check the output, and check J is absent**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
grep -oE '"J[0-9]+"' /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/g-m.json
```

Expected: matches only inside `related` arrays (a K case pointing back at a J
case is correct and wanted), never as a top-level key. Confirm by eye which
context each match sits in.

```bash
bun scripts/apply-enrichment.mjs --dry-run \
  /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/g-m.json
```

Expected: parses, all ids resolve, `git diff --stat` empty. If it reports a J
case would be updated, the agent included one as a key — send it back.

Then run the same three eyeball checks from Task 2 Step 2: every `why` has a
`source`, no hedging words, and some cases deliberately left bare.

---

## When this plan is complete

Tick every checkbox above, then confirm:

```bash
ls -la /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/
cd /home/numericlabs/data/rocket/rocketvault && git status --short journeybook/src/data/
```

Expected: `j.json`, `a-f.json` and `g-m.json` present, and **no modification to
any data file** — nothing is applied until plan 09. One new commit, for the
brief.

Keep every agent's DISAGREEMENT report. Plan 06 Task 3 takes them to the human.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-05-extract-n-w.md`

---

## Self-Review

**Spec coverage:** this is the first half of the spec's phase 1. Groups 1 and 2
of the five-group split table. The brief operationalises all five gates.

**Placeholder scan:** none. Both dispatch prompts are final text to be passed
verbatim, not summaries of a prompt to compose.

**Type consistency:** the JSON shape in the brief matches `properties()` in
plan 01 Task 2 exactly — `why.text`, `verify.command`/`verify.look`,
`after.text`, `related[].id`/`related[].rel`, per-field `source`, and
`needs-code` as an array of strings.

**Known risk:** Sonnet extraction agents reliably over-produce — the pull
toward filling every field is strong, and an invented `why` looks exactly like
a real one until its citation is opened. That is precisely what plans 07 and 08
exist for, and it is why Task 2 Step 2 treats "no omissions at all" as a signal
to challenge rather than a sign of thoroughness.
