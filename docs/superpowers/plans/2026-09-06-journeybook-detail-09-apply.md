# Journeybook Detail — Apply and Ship — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge every verified claim into the four data files, split the notes that now duplicate their own mechanism, and put the whole diff in front of a human before it lands.

**Architecture:** One merge pass over eight JSON files, one hand-editing pass for the notes splits the script cannot do, then the full mechanical check suite and a read of the complete diff. Nothing is delegated here — this is the point where 245 cases change at once, and the value of a fresh reviewer is lower than the value of one person seeing all of it.

**Tech Stack:** `scripts/apply-enrichment.mjs`, Prettier, Biome, `tsc -b`, `scripts/check-links.mjs`, `scripts/check-contrast.mjs`, Vite.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Prerequisite:** Plan 08 complete. Every enrichment file carries only `supported` claims, `needs-code` arrays are gone, and every contradiction has a human decision recorded in `questions.md`.

**Followed by:** `2026-09-06-journeybook-detail-10-document.md`.

## Global Constraints

- Journey J is already applied. Its file `j.json` must **not** be re-applied — the merge script's double-application guard will stop it, which is the intended behaviour, not a bug to work around.
- The merge script refuses two inputs claiming the same case id. If it complains, an answer file is restating a field an extraction agent already wrote. Fix the input; do not pass a flag to silence it.
- Run the full check suite before the commit, not after.
- All commits are GPG-signed.

---

### Task 1: Merge everything

**Files:**
- Modify: `journeybook/src/data/journeys-a-f.ts`, `journeys-g-m.ts`, `journeys-n-u.ts`, `journeys-v-w.ts`

**Interfaces:**
- Consumes: the seven remaining enrichment files (`j.json` is already applied).
- Produces: 245 cases carrying their verified detail.

- [x] **Step 1: Dry run the whole set first**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
E=/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
bun scripts/apply-enrichment.mjs --dry-run \
  $E/a-f.json $E/g-m.json $E/n-q.json $E/r-u.json $E/v-w.json \
  $E/answers-cli.json $E/answers-authz.json
```

Expected: a per-file count, a total, and **no unresolved lines** — every
`needs-code` was removed in plan 08 Task 3 Step 2. If the script reports a
duplicate id across two inputs, an answer file is restating an extraction
field; remove it from the answer file, which is the one that should carry only
what it newly resolved.

`git diff --stat` must be empty after a dry run. Confirm it.

- [x] **Step 2: Apply**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
E=/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
bun scripts/apply-enrichment.mjs \
  $E/a-f.json $E/g-m.json $E/n-q.json $E/r-u.json $E/v-w.json \
  $E/answers-cli.json $E/answers-authz.json
bun run format
```

- [x] **Step 3: Confirm it typechecks before going further**

```bash
bun run typecheck && bun run lint && bun run check:links
```

Expected: three clean exits. `check-links` now reports a much larger "carrying
detail" count — note the number, it goes in the commit message.

If `check-links` fails on a missing `source`, a field was written without one
and slipped both the verifier and plan 08's cut. Find it, cut it, and note it
in `cuts.md`: it is a Gate 1 escape and worth knowing about.

---

### Task 2: Split the notes that now repeat themselves

**Files:**
- Modify: whichever of the four data files the collected notes-split list names

**Interfaces:**
- Consumes: every `needs-code` entry from plans 04–05 that said a `notes` needs its mechanism half removed, collected in `questions.md`.
- Produces: no case where `why` and `notes` say the same thing twice.

**The rule, from the pilot:** where an existing `notes` carries mechanism that
is now in `why`, remove the mechanism half and leave the actionable half.
Never duplicate. **Never drop the actionable half** — it is the part a tester
acts on, and it was authored deliberately.

- [x] **Step 1: Work the list**

For each case named, open it, read `why` and `notes` together, and edit
`notes` down to what `why` does not already say. Journey J's J6 is the worked
example: its mechanism moved to `why` and its note became one sentence — the
rule "purge contents item-by-item first, or accept orphaned rows."

If a note has nothing left once the mechanism is removed, delete the `notes`
field rather than leaving an empty string.

- [x] **Step 2: Sweep for duplicates the list missed**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun -e "
  const { allCases } = await import('./src/data/index.ts')
  for (const c of allCases) {
    if (!c.why || !c.notes) continue
    const norm = s => s.toLowerCase().replace(/[^a-z0-9 ]/g,'').split(/\s+/)
    const w = new Set(norm(c.why)), n = norm(c.notes)
    const shared = n.filter(t => t.length > 4 && w.has(t)).length
    if (shared / n.length > 0.5) console.log(c.id + '  ' + Math.round(100*shared/n.length) + '% overlap')
  }
"
```

This is a blunt lexical overlap check, not a judgment. Read each case it
names and decide for yourself — a high score can be two different points that
share vocabulary, which is fine.

- [x] **Step 3: Re-verify**

```bash
bun run format && bun run typecheck && bun run lint && bun run check:links
```

---

### Task 3: Read the whole diff, then ship it

**Files:** none created; this is the review gate.

- [x] **Step 1: Run the complete check suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run format \
  && bun run typecheck \
  && bun run lint \
  && bun run check:links \
  && bun scripts/check-contrast.mjs \
  && bun run build
ls -la dist/
```

Expected: six clean exits, and `dist/journeybook.html` plus `dist/index.html`
written. Note the file size — the spec estimated ~900 KB, and a wild
divergence from that is worth understanding before shipping.

- [x] **Step 2: Read the rendered page, not just the diff**

```bash
bun run dev
```

Walk at least one journey from each of the five groups — A, G, N, R, V —
expanding every case. You are looking for four things:

1. A panel that reads as a wall of text. If one journey's `why` fields are
   consistently four sentences where two would do, that is a group-level
   authoring problem, not a case-level one.
2. A `why` that restates the `assert` instead of explaining the mechanism.
3. Sections appearing in an order other than Why → Before → Run → Expected →
   Verify → After → Note → Related → Source.
4. Anything that reads as hedged. Gate 5 was checked mechanically by grep and
   by the verifiers, but a sentence can hedge without using a hedging word.

- [x] **Step 3: Read the full diff**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git diff --stat journeybook/src/data/
git diff journeybook/src/data/ | less
```

All of it. This is 245 cases written by seven agents, and the mechanical
checks confirm shape and provenance, not judgment. The spec says this out
loud: the gates make bad output detectable, they do not make it impossible.

- [x] **Step 4: Present the summary to the human before committing**

Report, from `cuts.md` and the verdict files:

- cases enriched, and how many carry each field
- claims cut, by verdict, and the two or three most notable
- every contradiction and its recorded decision
- anything you found reading the diff that the gates did not catch

- [x] **Step 5: Commit**

Fill the counts in from the actual run rather than copying these:

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/src/data/
git commit -m "feat(journeybook): backfill case detail across all 23 journeys

Every check now carries the mechanism behind the behaviour, the
verification that settles an ambiguous result, what it leaves behind,
and its cross-references -- the reasoning
docs/VAULT_USER_ACCESS_JOURNEYS_v3.md has and the page dropped. A
tester whose run does not match now has something to reason with.

<N> of 245 cases enriched. <M> claims were cut before shipping: <breakdown
by verdict>. Every surviving claim cites the document section or the
file:line it came from, and a different agent than wrote it re-opened
that citation and confirmed it says what the claim says.

Cases the sources do not explain carry no why. That is the intended
outcome rather than a gap -- an absent field is honest, and a
plausible-sounding invented one is what this process exists to prevent."
```

---

## When this plan is complete

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run check:links && bun run build
git -C .. log --oneline -1
```

Expected: the link check passes, the build writes both files, and one new
commit holds the whole backfill.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-10-document.md`

---

## Self-Review

**Spec coverage:** the spec's phase 4 and its three mechanical checks, plus its
requirement that the full diff is read by hand with the journeys document
open.

**Placeholder scan:** the commit message carries `<N>` and `<M>` markers, which
are deliberate — they are filled from the run's actual output, and inventing
numbers here would be worse than marking them. Task 3 Step 5 says so
explicitly. Nothing else is a placeholder.

**Type consistency:** the merge consumes the same JSON shape all seven agents
produced, through the same `properties()` from plan 01 Task 2.

**Known risk:** Task 3 Step 3 asks one reader to review a diff of several
thousand lines, and attention degrades across it. The mitigation is that the
mechanical checks have already settled shape, provenance and links, so the
read is only looking for judgment failures — but a reviewer who treats it as a
formality gets no value from it. If the diff is genuinely too large to read
attentively in one sitting, split the commit by data file and read them on
separate passes rather than skimming one.
