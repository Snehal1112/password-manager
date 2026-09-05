# Journeybook case detail — design

**Date**: 2026-09-06
**Branch**: v-4.0.0
**Status**: approved, not yet implemented

## The problem

`journeybook/` renders 245 checks across 23 suites. Each check carries a title,
one `assert` line, a `command`, an `expected` line, and sometimes two sentences
of `notes`. The document it is transcribed from,
`docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`, carries far more: the mechanism behind
each behaviour, the verification that settles an ambiguous result, the state a
step leaves behind, and the cross-references between journeys that contradict
each other.

Journey J is the clearest example. The document explains that `PurgeVault`
deletes the vault row and its `access_policies` rows and stops, that no foreign
key forces a cascade because `secrets`/`keys`/`certificates` carry a plain
`vault_id TEXT NOT NULL` with no `REFERENCES vaults(id)`, and it gives the
`sqlite3` query that shows the orphaned rows. The journeybook case for it says
the vault is purged.

A tester whose run does not match has nothing to reason with. That is the gap
this closes.

## What this is not

This does not change which checks exist, their ids, their `command`, their
`expected`, or their verdicts. Case ids stay permanent —
`journeybook/.claude/authoring-cases.md` rule 2 — and the `localStorage` key
`journeybook-run-v1` is not bumped, because the shape of a stored run does not
change. A tester mid-run loses nothing.

## Schema

### `Case`, five new optional fields

```ts
/** The mechanism. Why the system behaves this way, not what the command does. */
why?: string

/** How to settle pass from fail when `expected` leaves a margin. */
verify?: {
  /** Transcribed from the doc, or built only from flags verified in cmd/. */
  command?: string
  /** What in the result settles it. Required whenever `verify` is present. */
  look: string
}

/** What this leaves behind, and what to undo before the next check. */
after?: string

/** Other checks this one leans on or contradicts. */
related?: { id: string; rel: "depends" | "diverges" | "contrasts" }[]

/** Provenance for `why`, `verify` and `after`. See Gate 1. */
source?: string
```

`verify` is one object, not an array. Rule 3 of `authoring-cases.md` is one
assertion per case; a check that needs two independent verifications is two
checks.

`related.rel` is deliberately three values, not a free string:

- `depends` — this check is meaningless unless that one passed first.
- `diverges` — the same authority produces a different answer there. Journey K's
  CLI/HTTP purge split is the archetype.
- `contrasts` — the neighbouring case that shows the opposite outcome, usually
  the allow next to a deny.

Every `related.id` must resolve to a real case. A dangling id is a build-time
error, not a broken link at runtime — see Verification below.

### `Suite`, one new field

```ts
/** The journey-level prose the doc carries between its command blocks. */
context?: string[]
```

One string per paragraph. `premise` stays as the one-sentence summary shown
collapsed; `context` is what a tester reads before starting the journey.

### `buildReport`

A failed check currently pastes id, surface, assert, first command line, and
three lines of expected. It gains `why` and `verify.command` when present.

The reasoning is that a defect report saying "J4 failed, expected the vault
purged" is not triageable, and one that adds "PurgeVault deletes the vault row
and its access_policies rows and stops — no cascade, no FK" tells whoever picks
it up where to look. This is the highest-value placement of the new text and it
costs nothing at read time.

## The panel

Sections render in one fixed order, all visible on expand, none behind a second
click:

Why → Before → Run → Expected → Verify → After → Related

Labels sit in a left gutter as a definition list rather than as headings above
each block. The expanded panel is already indented `sm:pl-[4.4rem]`; the label
occupies that indent and the content runs beside it, giving the eye one fixed
left edge to scan instead of seven headings interrupting the prose.

Labels are **sentence case** in the existing `.label` treatment.
`authoring-cases.md` forbids tracked-out caps eyebrows, and seven of them per
row across 245 rows is precisely the pattern that rule exists to prevent.

Below 640px the label column collapses and labels stack above their content.

Existing constraints that continue to apply, all from `journeybook/CLAUDE.md`:

- Shell content goes through `.transcript` / `.transcript-line`. `verify.command`
  is shell, so it uses `Terminal`, not hand-rolled `font-mono`.
- `.transcript-line` must never share an element with a `px-*` utility.
- Prose keeps `letter-spacing: -0.011em`; anything compared against a terminal
  resets to `normal`.
- `why`, `after` and `look` render through `Prose`, which supports `` `code` ``
  and `**bold**` and nothing else. Any other markup appears literally, by
  design.

## Anti-misleading gates

A check that misleads a QA engineer is worse than a thin one. A thin check sends
them to the document; a confidently wrong one sends them to file a defect
against working software, or to pass a broken build. These five gates are
binding on every agent doing the backfill, and each is independently checkable
after the fact.

### Gate 1 — Provenance or nothing

Every `why`, `verify` and `after` requires a `source`. Two forms are legal:

- `VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap`
- `internal/services/vaults/vault_service.go:214`

A field whose claim cannot be traced to one of those does not ship. **Omission
is a correct outcome.** A case with no `why` is honest. A case with a
plausible-sounding invented `why` is the failure this whole document exists to
prevent.

### Gate 2 — No invented commands

`verify.command` is either transcribed verbatim from the journeys document, or
constructed only from flags confirmed to exist by reading the cobra
registration in `cmd/`. If neither holds, `verify` ships with `look` prose and
no command.

This is rule 1 of `authoring-cases.md` applied to the new field. A verification
command with a flag that does not exist wastes a tester's time and teaches them
to distrust the page.

### Gate 3 — Independent adversarial verification

The agent that verifies a suite must not be the agent that wrote it. The
verifier re-opens every `source` citation and returns one verdict per field:

| Verdict | Meaning | Action |
|---|---|---|
| `supported` | The cited text or code says this | ship |
| `overstated` | The citation is related but weaker than the claim | rewrite to what the citation supports |
| `contradicted` | The citation says something else | cut, and report |
| `not-found` | The cited section or line does not exist or does not discuss this | cut, and report |

Only `supported` ships. `contradicted` and `not-found` are reported upward, not
silently dropped, because either can indicate a real defect in the document
rather than a bad citation.

### Gate 4 — Doc/code disagreement is surfaced, never resolved

`VAULT_USER_ACCESS_JOURNEYS_v3.md` is dated and the CLI has drifted before. When
the document and the code disagree, an agent does **not** pick a winner and does
not quietly write the code's answer into a case.

It records both, flags the case, and stops. The disagreement comes back to the
human. Silently "correcting" a case from source produces a check that
contradicts the document a tester is holding open beside it, which is the exact
misleading outcome being guarded against — and it also hides what may be a real
bug or a real doc rot.

### Gate 5 — Hedging is banned; uncertainty means omission

No "should", "presumably", "likely", "appears to", "is expected to". A `why`
that cannot be stated flatly from its source is not written at all.

Hedged text reads as information while carrying none, and a tester cannot act on
it. The honest signal for "we do not know" is an absent field.

## Execution

Five phases. Phase 0 is a pilot the human approves before any fan-out, so a
misread of the intended shape costs seven cases rather than 245.

| Phase | Who | Output |
|---|---|---|
| 0 | me | Schema, panel, report change, Journey J backfilled as the reference (7 cases) |
| 1 | 5 subagents | Doc-sourced enrichment; every unresolved claim marked `needs-code` |
| 2 | 2 subagents | `needs-code` claims resolved against `cmd/` and `internal/`, cited to file:line |
| 3 | 5 subagents, none reviewing its own work | Gate 3 verdict per field |
| 4 | me | Merge, `typecheck`, `lint`, `build`, `check-contrast.mjs`, read the diff |

The suite split for phases 1 and 3 follows the existing files, except that
`journeys-n-u.ts` carries 99 cases and splits in two at the N–Q / R–U boundary:

| Group | File | Suites | Cases |
|---|---|---|---|
| 1 | `journeys-a-f.ts` | A–F | 64 |
| 2 | `journeys-g-m.ts` | G–M | 50 |
| 3 | `journeys-n-u.ts` | N–Q | 47 |
| 4 | `journeys-n-u.ts` | R–U | 52 |
| 5 | `journeys-v-w.ts` | V, W | 32 |

### Agents do not edit the data files

No subagent writes to `src/data/*.ts`. Five agents editing four files
concurrently corrupts them, and it also makes phase 3 impossible — a verifier
needs the claim and its citation side by side, not a diff.

Instead each agent writes one JSON file to the scratchpad, keyed by case id:

```json
{
  "J4": {
    "why":    { "text": "PurgeVault deletes …", "source": "…§ the purge trap" },
    "verify": { "command": "sqlite3 …", "look": "Rows still present …",
                "source": "…§ the purge trap" },
    "after":  { "text": "Nothing to undo …", "source": "…§ the purge trap" },
    "related": [{ "id": "J3", "rel": "depends" }]
  },
  "J5": { "needs-code": ["why: does vaults purge check contained items first?"] }
}
```

Phase 4 applies them with a merge script rather than by hand. Hand-editing 245
cases invites exactly the transcription errors this design is trying to remove,
and the escaping of backticks and backslashes inside TypeScript template
literals is mechanical work a script does correctly every time. Prettier
normalises formatting afterwards.

The `source` lives per-field in the JSON but collapses to one `Case.source`
string when merged, listing each distinct citation once. Per-field provenance is
what the verifier needs; a tester needs to know where the case came from, not
which sentence came from where.

Model tiering follows the project convention: extraction and verification on
Sonnet, the code-reading gap-fill in phase 2 on Opus, since it is the phase that
has to reason about Go authorization paths rather than transcribe prose.

## Verification

Beyond the five gates, three mechanical checks run in phase 4:

1. `bun run typecheck` — the new fields are optional, so this catches shape
   errors only, but a malformed `related` entry fails here.
2. Every `related.id` resolves to a case in `allCases`. This is a new assertion;
   there is no test runner in `journeybook/`, so it goes in the same script
   style as `scripts/check-contrast.mjs` rather than assuming one exists.
3. `bun run lint`, `bun run build`, and `bun scripts/check-contrast.mjs` — the
   last because the panel adds a label treatment, and `journeybook/CLAUDE.md`
   requires it after touching anything colour-adjacent.

Spot-checking is not optional on my side: I read the full diff of every suite
before it lands, with the journeys document open. The gates make bad output
detectable; they do not make it impossible.

## Consequences

- Data files grow roughly threefold, ~140 KB to ~450 KB of source.
- `dist/journeybook.html` goes from 553 KB to an estimated ~900 KB, ~300 KB
  gzipped. It remains one self-contained offline file, which is the constraint
  that matters.
- `authoring-cases.md` needs a new section documenting the five fields and the
  five gates, because the next person to edit a case has to know that `why`
  without `source` is not acceptable.
