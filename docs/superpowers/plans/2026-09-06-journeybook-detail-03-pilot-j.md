# Journeybook Detail — Pilot: Journey J — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Backfill Journey J's seven cases by hand as the reference exemplar every later subagent copies, and stop for human approval before any fan-out.

**Architecture:** Journey J is the pilot because the document's purge-trap section is the densest material in the file — it carries a mechanism, a SQL-level explanation, an inverted assertion where finding rows is the pass, a cross-journey divergence, and a guardrail. If the schema and panel survive J, they survive the other 22 journeys.

**Tech Stack:** JSON enrichment applied by `scripts/apply-enrichment.mjs` from plan 01.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Followed by:** `2026-09-06-journeybook-detail-04-extract-a-m.md`, but **only after a human has approved the output of this plan**. Task 3 is a hard stop. The whole point of a pilot is that a misread of the intended shape costs seven cases instead of 245.

## Global Constraints

- The five gates from the spec bind this plan as they bind every later one:
  provenance or nothing, no invented commands, independent verification,
  doc/code disagreement is surfaced rather than resolved, and no hedging.
- Journey J's material is **entirely doc-sourced**. Every citation in this plan
  is `VAULT_USER_ACCESS_JOURNEYS_v3.md`. If you find yourself wanting to read
  Go to justify a sentence here, that sentence belongs in `needs-code` instead.
- `command`, `expected`, `assert`, `id`, `surface` and `gate` are **not
  touched**. This plan adds fields and rewrites exactly one `notes` string.
- All commits are GPG-signed.

---

### Task 1: Author the Journey J enrichment

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/j.json`

**Interfaces:**
- Consumes: the JSON shape read by `scripts/apply-enrichment.mjs` (plan 01 Task 2) — per-case `why`/`verify`/`after` objects each carrying `text` (or `command`/`look`) and `source`, plus a flat `related` array and an optional `needs-code` array of open questions.
- Produces: the exemplar. Plans 04–08 quote this file to their subagents as the standard to match.

**Read first:** `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` lines 644–693, which is
the whole of Journey J. Everything below is transcribed from it.

- [ ] **Step 1: Write the enrichment file**

```bash
mkdir -p /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
```

Create `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/j.json`:

```json
{
  "J1": {
    "why": {
      "text": "The cascade stamps every contained secret, key and certificate with the vault's own `deleted_at`, not with a timestamp of its own. That shared value is what makes J3's recovery possible, and it is the same fact that makes J4's earlier-deleted secret unrecoverable.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J"
    },
    "verify": {
      "look": "Every item the cascade touched carries the same `deleted_at` as the vault row itself, not the time each one was created or last changed.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J"
    },
    "needs-code": [
      "verify.command: is there a CLI flag that lists soft-deleted secrets for one vault and shows deleted_at, or is the sqlite3 query in J6 the only way to read that column?"
    ]
  },

  "J2": {
    "related": [{ "id": "J1", "rel": "depends" }]
  },

  "J3": {
    "why": {
      "text": "Recovery cascades, but the restore is scoped by `WHERE vault_id = ? AND deleted_at = ?`. Only children carrying the vault's exact deletion timestamp come back — which is every item the J1 cascade stamped, and nothing else.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J"
    },
    "related": [{ "id": "J1", "rel": "depends" }]
  },

  "J4": {
    "why": {
      "text": "A secret soft-deleted individually, earlier, carries its own `deleted_at`, and that value does not equal the vault's. The `WHERE vault_id = ? AND deleted_at = ?` clause driving the cascade therefore never matches it, so vault recovery steps straight past it.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J"
    },
    "after": {
      "text": "The secret is still soft-deleted and still recoverable on its own. Restore it explicitly before continuing, or the rest of this journey runs against a smaller secret set than it expects.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J"
    },
    "related": [{ "id": "J3", "rel": "depends" }],
    "needs-code": [
      "after: what is the exact CLI command that restores one soft-deleted secret? CLAUDE.md names the service method RecoverSecret but not the cobra command."
    ]
  },

  "J5": {
    "why": {
      "text": "Purge is deliberately a second pair of hands. The CLI path also carries an admin bypass in `CanPurgeVault` that the HTTP route does not have, so a global admin succeeds here and takes a 403 for the same purge over REST.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey K"
    },
    "related": [{ "id": "K3", "rel": "diverges" }]
  },

  "J6": {
    "why": {
      "text": "`PurgeVault` deletes the vault row and its `access_policies` rows and stops. There is no cascade call, and no foreign key forcing one — `secrets`, `keys` and `certificates` carry a plain `vault_id TEXT NOT NULL` with no `REFERENCES vaults(id)`, unlike `role_assignments.vault_id`, which does have `ON DELETE CASCADE`.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap"
    },
    "verify": {
      "look": "Rows come back. They are still soft-deleted, and their `vault_id` names a vault that is no longer in the `vaults` table. **Rows coming back is the pass here, not the failure** — an empty result means the orphaning did not happen and something about this build differs from the document.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap"
    },
    "after": {
      "text": "Nothing to undo; the rows cannot be reached to be undone. Vault-scoped routes 404 because the name no longer resolves, flat routes only ever reach `default`, and the purge scheduler never sweeps them because it purges individually-deleted items only.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap"
    },
    "related": [{ "id": "J5", "rel": "depends" }]
  },

  "J7": {
    "why": {
      "text": "The one guardrail that does exist in the other direction, and it fails closed: a vault holding any purge-protected item refuses the bulk purge outright rather than purging everything it is allowed to and leaving the rest.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J"
    },
    "related": [{ "id": "J5", "rel": "contrasts" }]
  }
}
```

- [ ] **Step 2: Check it against the three judgment calls it encodes**

These are the calls a later subagent will have to make hundreds of times, so
confirm each is right here before it becomes precedent:

1. **J2 gets no `why`.** The document shows the command and says nothing about
   why deleted vaults are hidden by default. Inferring it from the flag name
   would be exactly the plausible-sounding invention Gate 1 forbids. An absent
   field is the honest output — **this is the most important line in the
   exemplar.**
2. **J1 and J4 carry `needs-code` alongside finished fields.** An open question
   does not block the fields beside it. Phase 2 resolves the question; the
   prose ships now.
3. **J5's `why` cites Journey K, not Journey J.** The admin-bypass fact lives
   in K's section. Cite where the claim actually is, not where the case sits.

- [ ] **Step 3: Validate the JSON parses and every id exists**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun scripts/apply-enrichment.mjs --dry-run \
  /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/j.json
```

Expected: `would update journeys-g-m.ts: 7 case(s)`, then `dry run: 7 case(s)
across 1 file(s).`, then the two unresolved questions listed under `2
unresolved, for the phase 2 code pass:`. `git diff --stat` must be empty.

---

### Task 2: Apply it, and split J6's overloaded note

**Files:**
- Modify: `journeybook/src/data/journeys-g-m.ts` (Journey J only)

**Interfaces:**
- Consumes: `j.json` from Task 1.
- Produces: seven enriched cases and one rewritten `notes`, which plan 04's subagents read as the worked example.

- [ ] **Step 1: Apply**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun scripts/apply-enrichment.mjs \
  /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/j.json
bun run format
```

- [ ] **Step 2: Split J6's `notes`**

J6's existing `notes` carries both the mechanism and the actionable rule. The
mechanism half is now in `why`, so leaving it in `notes` prints the same
paragraph twice in one panel.

**The rule this establishes, and every later plan inherits it:** where an
existing `notes` already contains mechanism, move that half into `why` and
leave only the actionable half in `notes`. Never duplicate, and never delete
the actionable half.

In `journeybook/src/data/journeys-g-m.ts`, find the `J6` case and replace its
`notes` value in full. The current value begins ``"`PurgeVault` deletes the
vault row"``. Replace the entire string with:

```ts
        notes:
          "**Purge a vault's contents item-by-item before purging the vault**, or accept permanently orphaned rows.",
```

- [ ] **Step 3: Add the journey context**

In the same file, in the `J` suite object, after the `premise` field and
before `cases:`, add:

```ts
    context: [
      "Three operations, three different cascade behaviours. Soft-delete cascades to everything in the vault. Recovery cascades too, but only to children stamped with the vault's exact `deleted_at`. Purge does not cascade at all.",
      "The last of those is the trap this journey exists for, and it is silent — nothing errors and nothing warns. The API cannot show you the rows that are left behind, which is why J6 goes to the database directly.",
    ],
```

- [ ] **Step 4: Verify the whole toolchain**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run format && bun run typecheck && bun run lint && bun run check:links && bun scripts/check-contrast.mjs && bun run build
```

Expected: all six exit 0. `check-links` reports `245 cases, 6 carrying
detail, 0 problems.` — six, not seven, because J2 has only a `related` and
carries no claim of its own.

- [ ] **Step 5: Read the rendered result**

```bash
bun run dev
```

Open `http://localhost:5174`, jump to Journey J, and expand all seven cases.
Check specifically:

- J6 shows Why, Run, Expected, Verify, After, Note, Related and Source — eight
  sections — and reads top to bottom without repeating itself. This is the
  densest panel in the book; if it holds, the layout holds.
- J6's Verify makes the inverted assertion unmissable. A tester who sees rows
  must not file a defect.
- J2 shows only Run, Expected and Related, and looks deliberate rather than
  unfinished.
- The `K3` link in J5 jumps to Journey K. Press `j` afterwards and confirm
  keyboard navigation still works with an anchor focused.
- Both themes. Then re-run `bun scripts/check-contrast.mjs`.

- [ ] **Step 6: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/src/data/journeys-g-m.ts
git commit -m "feat(journeybook): backfill Journey J as the detail exemplar

Seven cases carrying the mechanism, the verification, the teardown and
the cross-references the journeys document has and the page did not.
J is the pilot because the purge-trap section is the densest material
in that document: a SQL-level mechanism, an inverted assertion where
finding rows is the pass, a cross-journey divergence and a guardrail.

Three precedents set here for the remaining 22 journeys:

- J2 gets no why. The document does not explain it, and inferring one
  from a flag name is the invention the spec's first gate forbids.
- J1 and J4 carry open needs-code questions beside finished fields. An
  unresolved question does not block the prose next to it.
- J6's notes is split: the mechanism moved to why, the actionable rule
  stayed. Never duplicate, never drop the actionable half."
```

---

### Task 3: Human approval gate — stop here

**Files:** none.

- [ ] **Step 1: Present the pilot**

Show the human the rendered Journey J and state plainly:

- Seven cases enriched, six carrying claims, all seven citations pointing at
  `VAULT_USER_ACCESS_JOURNEYS_v3.md`.
- Two `needs-code` questions deferred to phase 2, quoted in full.
- The three precedents from Task 2 Step 6's commit message, since each one
  multiplies by 22 journeys if it is wrong.

- [ ] **Step 2: Stop**

**Do not start plan 04.** Fanning out to five subagents before a human has
confirmed the shape is how a misread turns into 245 cases of rework. Wait for
an explicit yes.

If the human asks for changes, apply them to Journey J, re-run Task 2 Step 4,
and present again. The exemplar has to be right before it is copied.

---

## When this plan is complete

Tick every checkbox above. The state to hand over:

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run check:links
git -C .. log --oneline -1
```

Expected: `245 cases, 6 carrying detail, 0 problems.` and one new commit.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-04-extract-a-m.md`
— **gated on human approval from Task 3.**

---

## Self-Review

**Spec coverage:** this plan is the spec's phase 0 data half (phase 0's code
half is plans 01 and 02). It exercises all five gates on real content: Gate 1
in J2's deliberate omission, Gate 2 in J1's missing `verify.command`, Gate 5 in
the absence of any hedged sentence, and Gates 3 and 4 by having nothing to
report — Journey J's material is entirely doc-sourced and does not disagree
with itself.

**Placeholder scan:** none. Every JSON value is final text, not a description
of text to write.

**Type consistency:** the JSON uses `why.text`, `verify.look`,
`verify.command`, `after.text`, `related[].id`, `related[].rel` and
`*.source`, which is exactly what `properties()` in plan 01 Task 2 reads. The
`rel` values `depends`, `diverges` and `contrasts` are the three members of
`Relation` from plan 01 Task 1. `context` is `string[]`, matching `Suite`.

**Known risk:** J5's `why` asserts a CLI admin bypass in `CanPurgeVault`. That
is doc-sourced from Journey K and is corroborated by the project CLAUDE.md,
but it is the one claim in this pilot that a code check could contradict. If
plan 06's code pass finds otherwise, it is a Gate 4 disagreement — surface it,
do not quietly rewrite J5.
