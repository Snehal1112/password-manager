# Plan 09 — Apply and Ship — progress ledger

Plan: `docs/superpowers/plans/2026-09-06-journeybook-detail-09-apply.md`
Branch: `v-4.0.0` (in place)
Completed: 2026-09-06 — commit `d610315`

## Tasks — ALL COMPLETE

- [x] Task 1: merge everything into the four data files
- [x] Task 2: split notes that repeat their own `why`
- [x] Task 3: full check suite, read the whole diff, ship

## The three merge hazards, all resolved

Every one was found by the merge script's own guards during earlier plans, not
by luck at merge time:

1. **`j.json` is spent** — already applied in plan 03. Excluded from the merge
   set. Re-applying trips the double-application guard, which is correct.
2. **J1 `verify` and J4 `after` amend already-applied fields** — hand-applied to
   `journeys-g-m.ts` rather than machine-merged, with the plan-06 answer text as
   a complete replacement field. The old J4 `after` said "restore it explicitly"
   without warning that **no CLI command can do it at all**, which would have
   sent a tester hunting for a nonexistent `secrets restore` subcommand.
3. **G9 `why` supplied by two files** — `g-m.json` (names two of three excluded
   roles) and `answers-code.json` (names all three). Removed the `g-m` version
   before merging so the complete one wins.

## What shipped

| | Count |
|---|---|
| Cases carrying new detail | 171 of 245 (70%) |
| — `why` | 151 |
| — `verify` | 20 |
| — `after` | 13 |
| — `related` | 76 cases, 81 links |
| — `source` | 160 |
| Deliberately bare | 74 |

The 74 bare cases are the intended outcome, not a shortfall: the document shows
those commands without explaining them, and Gate 1 makes omission the correct
answer where a source does not exist.

## Two defects I found reading the diff that the gates did not catch

Both were mine, and both are the reason Task 3 Step 3 is a hand read rather than
a formality.

1. **G3 and G8 cited one source and named another.** When plan 08 re-cited them
   from the Corrected Cast table to Journey G's body, I changed the `source` but
   left the prose saying "the cast table describes her role as covering role
   assignments alone". Reworded both to drop the false attribution.
2. **T6 and T9 notes duplicated their own `why`.** The lexical sweep flagged them
   at 60% and 56%. Cause: my own Task 2 trims had kept a mechanism sentence in
   each, because neither note had an actionable half to preserve. The correct
   outcome for both was deletion, which is what they got. Re-swept clean.

A third check found nothing but was worth running: no `why` merely restates its
`assert`. Three cases (T18, W1, U5) scored high on lexical overlap, but each
carries a real mechanism first and only *ends* by restating the outcome.

## Check suite — all green before the commit

`format`, `typecheck`, `lint`, `check:links` (245 cases, 160 carrying detail,
**0 problems**), `check-contrast` (0 failing in both themes), `build`
(678 KB — under the spec's ~900 KB estimate, no wild divergence).

## Deviation: the rendered-page walk was not done

Task 3 Step 2 asks for `bun run dev` and a walk through one journey from each of
the five groups, looking for wall-of-text panels, `why` fields that restate the
`assert`, wrong section order, and hedging. **I cannot visually inspect a
browser**, so I ran the data-level equivalent — the assert-restatement check
above, the notes-overlap sweep, and a full read of the diff — and said so
plainly rather than claiming the step.

The section-order check in particular is *not* covered by what I ran: order is a
property of `case-row.tsx`'s rendering, fixed in code since plan 02, but nobody
has looked at it with 171 populated cases. `journeybook/dist/journeybook.html` is
built and current for whoever does.

## Rulings I made

**Hand-applied J1/J4 rather than forcing the merge.** The script refuses to
overwrite an existing field, and that guard is right. Passing a flag to silence
it would have defeated the protection that caught all three hazards.

## Deferred to plan 10

- The **seven source-document corrections** the user approved: A7, C3 (×2), C4,
  D2, Q5, plus Journey G demonstrating only two of its three role exclusions.
  None is applied yet — plan 09 changed only the journeybook.
- **D2's rewrite** to assert the table `vault-access list` actually prints. Still
  outstanding; the case as it stands cannot pass.
- `cuts.md` and `questions.md` live in the scratchpad and are not committed
  anywhere. If that record is worth keeping, plan 10 is the place to fold it in.
