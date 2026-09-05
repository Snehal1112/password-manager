# Journeybook Detail — Extract N–W — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce doc-sourced enrichment for the remaining three groups — N–Q (47 cases), R–U (52 cases) and V–W (32 cases) — completing phase 1.

**Architecture:** Same shape as plan 04. Three more Sonnet agents against the same brief, each writing one JSON file, none touching `src/data/`.

**Tech Stack:** Agent tool with Sonnet.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Prerequisite:** Plan 04 complete. `journeybook/.claude/enrichment-brief.md` must exist — every dispatch here depends on it.

**Followed by:** `2026-09-06-journeybook-detail-06-code-pass.md`, which resolves every `needs-code` question the five extraction agents raised.

## Global Constraints

- The five gates bind every agent, via the brief. Do not restate or paraphrase them in a dispatch prompt — point at the file, so there is one copy that cannot drift.
- **No subagent writes to `journeybook/src/data/`.**
- Groups 3 and 4 both cover cases living in `journeys-n-u.ts`. They still write separate JSON files; nothing is applied until plan 09, so there is no conflict.
- Scratchpad root: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/`

---

### Task 1: Extract journeys N–Q

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/n-q.json`

**Interfaces:**
- Consumes: `journeybook/.claude/enrichment-brief.md` from plan 04 Task 1.
- Produces: enrichment for 47 cases — N1–N5, O1–O11, P1–P15, Q1–Q16.

- [ ] **Step 1: Dispatch**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Extract N-Q case detail"`:

```
You are enriching QA test cases for RocketVault's journeybook.

Read these in full before writing anything:

1. /home/numericlabs/data/rocket/rocketvault/journeybook/.claude/enrichment-brief.md
   -- the rules. Binding. Follow them exactly.
2. /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
   lines 1-100 (the two v3 corrections and the cast) and lines 811-1230
   (Journeys N through Q).
3. /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/journeys-n-u.ts
   -- your cases are N1-N5, O1-O11, P1-P15, Q1-Q16. That file also holds
   R through U; ignore those entirely, another agent has them.

Read Journey J in journeys-g-m.ts as the worked example. It is already
enriched and is the standard you are matching.

Write your output to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/n-q.json

Do not edit any other file. Do not touch journeybook/src/data/.

Scope notes for this group specifically:

- Journey N is multi-vault isolation. The mechanism is that a grant in one
  vault confers nothing in another, and the cases prove it in both
  directions. Say which check produced each denial -- the brief's rules on
  precision apply hardest here, because three different 403s mean three
  different things in RocketVault.
- Journey O is a secret migration between vaults with the original retired
  afterwards. Its "after" fields matter more than most: a half-finished
  migration leaves the instance in a state later journeys run against.
- Journey P is the one where a global-role `user` runs the whole secret
  rotation lifecycle, because secrets rotation checks no global role at all.
  That absence IS the mechanism. The document also flags that re-running
  `assign` for the same pair bubbles a raw triple-wrapped driver error
  rather than a clean "already assigned" -- that is a real trap and the
  case for it should carry the exact behaviour.
- Journey Q is the certificate lifecycle. Note where certificate commands
  need the certificate_manager global role per Correction 8.

Report back: how many cases you enriched, how many you deliberately left
without a why and why that was right, and every needs-code question in full.
Quote any DISAGREEMENT entries verbatim.
```

- [ ] **Step 2: Check the output**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun scripts/apply-enrichment.mjs --dry-run \
  /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/n-q.json
grep -oE '"[R-U][0-9]+":' /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/n-q.json
```

Expected: the dry run parses and resolves every id with `git diff --stat`
empty; the grep returns nothing, confirming the agent stayed inside its half
of the shared file.

Then the three eyeball checks: every `why` has a `source`; no hedging
(`grep -iE '"(text|look)": "[^"]*(should|presumably|likely|appears to|probably)'`
returns nothing); and some cases are deliberately bare.

---

### Task 2: Extract journeys R–U

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/r-u.json`

**Interfaces:**
- Consumes: the same brief.
- Produces: enrichment for 52 cases — R1–R11, S1–S12, T1–T20, U1–U9.

- [ ] **Step 1: Dispatch**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Extract R-U case detail"`:

```
You are enriching QA test cases for RocketVault's journeybook.

Read these in full before writing anything:

1. /home/numericlabs/data/rocket/rocketvault/journeybook/.claude/enrichment-brief.md
   -- the rules. Binding. Follow them exactly.
2. /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
   lines 1-100 (the two v3 corrections and the cast) and lines 1231-1820
   (Journeys R through U).
3. /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/journeys-n-u.ts
   -- your cases are R1-R11, S1-S12, T1-T20, U1-U9. That file also holds
   N through Q; ignore those entirely, another agent has them.

Read Journey J in journeys-g-m.ts as the worked example. It is already
enriched and is the standard you are matching.

Write your output to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/r-u.json

Do not edit any other file. Do not touch journeybook/src/data/.

This group carries the four most dangerous traps in the whole document.
Treat their why and after fields as the highest-value work here:

- Journey R, the post-rotation restore. Losing the pre-rotation master key
  is unrecoverable: every secret value, key PEM and certificate private key
  in that backup is column-level ciphertext sealed under the lost key,
  independent of the file wrapper. There is no recovery path. Say that
  flatly.
- Journey S, master key rotation. Two separate traps: nothing in the code
  stops the rotation running against a live server, and typing anything
  other than the exact string "yes" -- including a blank line -- prints
  "Aborted." and EXITS 0. A maintenance script checking only the exit code
  reads an aborted no-op rotation as a success. The fix is --yes for
  unattended runs. Both belong in why fields, stated flatly.
- Journey T, working across three environments from one laptop. The
  mechanism is a stale `context use` having real blast radius on secrets
  create/update/delete/import, and no blast radius elsewhere because every
  other group is still behind a loud "remote mode is not yet supported"
  guard. Also covers the ROCKETVAULT_VAULT divergence: vault-access reads
  it, secrets does not. That divergence is a real one -- flag it as such.
- Journey U, the vault webhook. The document is explicit that configuring
  it today buys nothing operationally because no sender ships yet, and
  that no operational process should depend on it firing. A case here
  asserts a gap, not a behaviour. Do not soften that.

Report back: how many cases you enriched, how many you deliberately left
without a why and why that was right, and every needs-code question in full.
Quote any DISAGREEMENT entries verbatim.
```

- [ ] **Step 2: Check the output**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun scripts/apply-enrichment.mjs --dry-run \
  /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/r-u.json
grep -oE '"[N-Q][0-9]+":' /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/r-u.json
```

Expected: dry run clean, grep silent.

Then, beyond the three standard checks, read Journey S's entries specifically.
The "exits 0 on abort" trap is the single most consequential sentence this
whole effort adds to the book — a tester who misses it signs off a rotation
that never happened. If its `why` is vague, send it back.

---

### Task 3: Extract journeys V–W

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/v-w.json`

**Interfaces:**
- Consumes: the same brief.
- Produces: enrichment for 32 cases — V1–V20, W1–W12.

- [ ] **Step 1: Dispatch**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Extract V-W case detail"`:

```
You are enriching QA test cases for RocketVault's journeybook.

Read these in full before writing anything:

1. /home/numericlabs/data/rocket/rocketvault/journeybook/.claude/enrichment-brief.md
   -- the rules. Binding. Follow them exactly.
2. /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
   lines 1-100 (the two v3 corrections and the cast) and lines 1821-2176.
   That last range is Journeys V and W, the CLI Quick Reference, and the
   corrections retained from v2. Read all of it -- the quick reference's
   "flag gotchas" and "which gate produced your error" sections explain
   mechanisms that several V and W cases turn on.
3. /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/journeys-v-w.ts
   -- your cases are V1-V20 and W1-W12.

Read Journey J in journeys-g-m.ts as the worked example. It is already
enriched and is the standard you are matching.

Write your output to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/v-w.json

Do not edit any other file. Do not touch journeybook/src/data/.

Scope notes for this group specifically:

- Journey V is delegated vault CREATION without delegating the instance.
  The load-bearing mechanism is that this tier is deliberately
  non-delegable: a principal able to amend its own provisioning grant
  could raise its own quota, which would make the bound the grant exists
  to impose decorative. That reasoning belongs in the why of the
  non-delegability cases.
- Journey W is a behaviour CHANGE, not a static behaviour: a global
  vault_id-NULL (vaults, manage) allow used to confer management over
  every vault and no longer does. The asymmetry is the point -- a
  NULL-scoped DENY still matches every vault, a NULL-scoped ALLOW matches
  none. Get that direction right; reversing it would mislead a tester
  about an access-control boundary, which is the worst possible error in
  this document.
- W also has an upgrade dimension: a global-policy holder who created a
  vault under the old behaviour got no creator-grant row and loses
  management of it on upgrade. Cases about upgrading rather than testing
  fresh should say so in a precondition-shaped why.

Report back: how many cases you enriched, how many you deliberately left
without a why and why that was right, and every needs-code question in full.
Quote any DISAGREEMENT entries verbatim.
```

- [ ] **Step 2: Check the output, and check the deny/allow direction by hand**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun scripts/apply-enrichment.mjs --dry-run \
  /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/v-w.json
```

Then run the three standard checks, and one extra that is specific to this
group. Read every W entry mentioning `NULL` scope and confirm it says: a
NULL-scoped **deny** matches every vault, a NULL-scoped **allow** matches
none. Reversed, that sentence tells a tester an access-control boundary works
the opposite of how it does. Check it by eye against
`docs/release-notes/v4.6.0-narrow-global-vault-manage.md`, not only against
the journeys document.

---

## When this plan is complete

```bash
ls /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/
cd /home/numericlabs/data/rocket/rocketvault && git status --short journeybook/src/data/
```

Expected: six JSON files — `j`, `a-f`, `g-m`, `n-q`, `r-u`, `v-w` — and no
modified data file. Phase 1 is complete; nothing is applied yet.

Collect every agent's `needs-code` and `DISAGREEMENT` report into one place.
Plan 06 consumes them.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-06-code-pass.md`

---

## Self-Review

**Spec coverage:** groups 3, 4 and 5 of the spec's five-group split, completing
phase 1.

**Placeholder scan:** none. All three prompts are final text passed verbatim.

**Type consistency:** all three agents write the JSON shape defined in the
brief, which matches `properties()` in plan 01 Task 2.

**Known risk:** Journey W's allow/deny asymmetry is the highest-consequence
sentence in this group, and it is the kind of fact an extraction agent
mirror-images without noticing, because the symmetric version reads more
naturally. Task 3 Step 2 checks it against the release note rather than the
journeys document alone, so a single upstream error cannot propagate unchecked.
