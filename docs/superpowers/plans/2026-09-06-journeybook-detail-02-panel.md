# Journeybook Detail — The Panel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render the five new `Case` fields and `Suite.context` as one sectioned panel in a fixed reading order, and carry the mechanism text into the pasteable defect report.

**Architecture:** The expanded row becomes a definition list with labels right-aligned in a 3.5rem gutter and content starting at 5.5rem, so nine possible sections share one hard vertical rule instead of nine headings interrupting the prose. `Terminal` gains an optional label so a shell block can sit in that layout without printing a second label of its own.

**Tech Stack:** React 19, Tailwind v4 CSS-first (tokens in `src/index.css`, no config file), shadcn `base-luma` on `@base-ui/react`.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Followed by:** `2026-09-06-journeybook-detail-03-pilot-j.md`, which backfills Journey J by hand as the reference exemplar every later subagent copies. Do not start the fan-out before that pilot is approved.

## Global Constraints

- Section labels are **sentence case**. `journeybook/.claude/authoring-cases.md` forbids tracked-out caps eyebrows, and nine of them per row across 245 rows is exactly the pattern that rule exists to stop.
- Shell content goes through `Terminal`, which owns `.transcript` / `.transcript-line`. Never hand-roll a code block with `font-mono text-[12px]`.
- `.transcript-line` must never share an element with a `px-*` utility — Tailwind's later cascade layer wins the padding half of its hanging indent and drags the first line out of the box.
- Prose inherits `letter-spacing: -0.011em` from `body`; anything compared against a terminal resets to `normal`. `Terminal` already does this. Do not set tracking by hand.
- Hand-rolled `<button>`s need `.focus-ring`. Registry components in `src/components/ui/` ship their own.
- `src/components/ui/` is byte-identical to the registry and in `.prettierignore`. Wrap or compose; never edit one.
- Every keyboard shortcut is a bare letter. Anything focusable added here must not swallow them — `src/App.tsx`'s handler already skips inputs, textareas and contenteditable, and anchors are safe.
- Run `bun run typecheck`, `bun run lint`, and `bun scripts/check-contrast.mjs` before every commit. The last is required by `journeybook/CLAUDE.md` after touching anything colour-adjacent.

---

### Task 1: Let `Terminal` omit its label

**Files:**
- Modify: `journeybook/src/components/terminal.tsx:16-28,44-61`

**Interfaces:**
- Produces: `Terminal` with `label?: string`. When `label` is absent and `copy` is false, no header bar renders at all and the `<pre>` aligns flush with the top of its container — which is what lets a shell block sit in Task 2's gutter layout without printing a second, redundant label beside the `<dt>`.
- Existing callers in `gate-diagram.tsx`, `reference-panels.tsx` and `case-row.tsx` all pass `label` and are unaffected.

- [ ] **Step 1: Make the prop optional**

In `journeybook/src/components/terminal.tsx`, change the props type:

```ts
export function Terminal({
  children,
  label,
  copy,
  tone = "command",
  className,
}: {
  children: string
  /**
   * Omit inside a labelled layout -- the case panel puts the label in its own
   * gutter column, and a second one here would say the same word twice.
   */
  label?: string
  copy?: boolean
  tone?: "command" | "output"
  className?: string
}) {
```

- [ ] **Step 2: Render the header bar only when it has something in it**

Replace the header `<div>` (currently lines 45-61) with:

```tsx
      {label || copy ? (
        <div className="label mb-1.5 flex items-center justify-between text-muted-foreground">
          <span>{label}</span>
          {copy ? (
            <button
              type="button"
              onClick={onCopy}
              className="focus-ring label inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-muted-foreground hover:text-foreground"
            >
              {copied ? (
                <Check className="size-3" aria-hidden="true" />
              ) : (
                <Copy className="size-3" aria-hidden="true" />
              )}
              {copied ? "Copied" : "Copy"}
            </button>
          ) : null}
        </div>
      ) : null}
```

An absent `label` leaves an empty `<span>`, and `justify-between` still pushes
the Copy button to the right edge. That is deliberate: it keeps the button in
the same place whether or not the bar carries a word.

- [ ] **Step 3: Verify**

Run: `cd journeybook && bun run typecheck && bun run lint`
Expected: both exit 0. `label` becoming optional is a widening, so no caller
breaks.

- [ ] **Step 4: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/src/components/terminal.tsx
git commit -m "refactor(journeybook): make the Terminal label optional

The case panel is about to put section labels in their own gutter
column, where a Terminal printing its own label would say the same word
twice. With no label and no copy button the header bar is dropped
entirely, so the transcript aligns flush with its row label."
```

---

### Task 2: The sectioned panel

**Files:**
- Modify: `journeybook/src/components/case-row.tsx:121-149`
- Modify: `journeybook/src/App.tsx:519-521`

**Interfaces:**
- Consumes: `Case.why`, `Case.verify`, `Case.after`, `Case.related`, `Case.source` and `Suite.context` from plan 01 Task 1; `Terminal`'s optional `label` from Task 1.
- Produces: nothing other components read. This is a leaf render change.

**Section order, fixed and unconditional** — each renders only when its field
is present, but never in a different order:

Why → Before → Run → Expected → Verify → After → Note → Related → Source

`notes` becomes the **Note** row. It is existing authored content — "why the
case exists, or what is easy to get wrong" — and it is not the same thing as
`why`, which is the system's mechanism. Keep both; do not migrate one into the
other.

- [ ] **Step 1: Add the relation labels and the row helper**

In `journeybook/src/components/case-row.tsx`, after the existing `flagLabel`
constant (line 24), add:

```tsx
const relationLabel: Record<Case["related"] extends
  | Array<infer R>
  | undefined
  ? R extends { rel: infer L }
    ? L
    : never
  : never, string> = {
  depends: "depends on",
  diverges: "diverges from",
  contrasts: "contrasts with",
}
```

That conditional type is unreadable. Import the type instead — replace the
block above with this, and add `Relation` to the existing type import on
line 5:

```tsx
const relationLabel: Record<Relation, string> = {
  depends: "depends on",
  diverges: "diverges from",
  contrasts: "contrasts with",
}

/**
 * One labelled section of the expanded panel.
 *
 * The label sits right-aligned in a 3.5rem gutter with content starting at
 * 5.5rem, so nine possible sections share one hard vertical rule rather than
 * nine headings interrupting the prose. Below 640px the grid collapses and the
 * label stacks above its content.
 */
function Row({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <>
      <dt className="label mt-3.5 text-muted-foreground first:mt-0 sm:mt-0 sm:text-right">
        {label}
      </dt>
      <dd className="min-w-0">{children}</dd>
    </>
  )
}

/** Prose shared by Why, Before, After, Note and the Verify commentary. */
function Text({ children }: { children: string }) {
  return (
    <p className="max-w-[68ch] text-[13px] leading-relaxed text-muted-foreground">
      <Prose>{children}</Prose>
    </p>
  )
}
```

Line 5 becomes:

```tsx
import type { Case, Relation } from "@/data/types"
```

- [ ] **Step 2: Replace the expanded panel**

Replace the whole `{open ? ( ... ) : null}` block (lines 121-149) with:

```tsx
      {open ? (
        <div id={panelId} className="pt-1 pr-3 pb-5 pl-5">
          <dl className="grid grid-cols-1 gap-y-1 sm:grid-cols-[3.5rem_minmax(0,1fr)] sm:gap-x-3 sm:gap-y-4">
            {item.why ? (
              <Row label="Why">
                <Text>{item.why}</Text>
              </Row>
            ) : null}

            {item.precondition ? (
              <Row label="Before">
                <Text>{item.precondition}</Text>
              </Row>
            ) : null}

            <Row label="Run">
              <Terminal copy>{item.command}</Terminal>
            </Row>

            <Row label="Expected">
              <Terminal tone="output">{item.expected}</Terminal>
            </Row>

            {item.verify ? (
              <Row label="Verify">
                <div className="space-y-2">
                  {item.verify.command ? (
                    <Terminal copy>{item.verify.command}</Terminal>
                  ) : null}
                  <Text>{item.verify.look}</Text>
                </div>
              </Row>
            ) : null}

            {item.after ? (
              <Row label="After">
                <Text>{item.after}</Text>
              </Row>
            ) : null}

            {item.notes ? (
              <Row label="Note">
                <Text>{item.notes}</Text>
              </Row>
            ) : null}

            {item.related?.length ? (
              <Row label="Related">
                <ul className="flex flex-wrap gap-x-4 gap-y-1.5">
                  {item.related.map((r) => (
                    <li key={r.id} className="text-[13px] leading-relaxed">
                      <a
                        href={`#case-${r.id}`}
                        className="focus-ring rounded-sm font-mono text-foreground underline decoration-border underline-offset-2 hover:decoration-foreground"
                      >
                        {r.id}
                      </a>
                      <span className="ml-1.5 text-muted-foreground">
                        {relationLabel[r.rel]}
                      </span>
                    </li>
                  ))}
                </ul>
              </Row>
            ) : null}

            {item.source ? (
              <Row label="Source">
                <p className="max-w-[68ch] text-[12.5px] leading-relaxed text-muted-foreground/80">
                  {item.source}
                </p>
              </Row>
            ) : null}
          </dl>
        </div>
      ) : null}
```

Three things here are load-bearing:

- The panel's left padding drops from `pl-5 sm:pl-[4.4rem]` to plain `pl-5`.
  The old value aligned content with the row title; the gutter now occupies
  that space instead, and content lands at 5.5rem.
- `Source` renders as plain text, not `<Prose>`. It is a file path or a
  document section, and passing a path containing backticks through the
  two-marker renderer would silently turn part of it into a code chip.
- The related links are ordinary in-page anchors. They work from `file://`
  with no JavaScript, and `App.tsx`'s bare-letter shortcut handler ignores
  anchors, so `j`/`k` keep working with one focused.

- [ ] **Step 3: Render the suite context**

In `journeybook/src/App.tsx`, after the `premise` paragraph (line 519-521),
add:

```tsx
                      {s.context?.map((para) => (
                        <p
                          key={para.slice(0, 48)}
                          className="mt-2.5 max-w-[74ch] pl-[1.6rem] text-[13.5px] leading-relaxed text-muted-foreground"
                        >
                          <Prose>{para}</Prose>
                        </p>
                      ))}
```

The key is a prefix of the paragraph rather than the index, because these are
authored content with stable text — if a paragraph is inserted mid-journey,
keying on the index would remount every paragraph after it.

- [ ] **Step 4: Look at it**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run typecheck && bun run lint && bun scripts/check-contrast.mjs
bun run dev
```

Open `http://localhost:5174`, expand any case, and confirm four things:

1. Run and Expected sit in the new gutter layout with their labels
   right-aligned, and neither prints a duplicate label above the transcript.
2. No case yet shows Why, Verify, After, Related or Source — none are
   authored until plan 03. The panel must look correct with only the three
   sections it has today.
3. Narrow the window below 640px. Labels stack above their content and
   nothing scrolls sideways.
4. Toggle the theme. `bun scripts/check-contrast.mjs` reports zero failures,
   which is the standing requirement in `journeybook/CLAUDE.md`.

- [ ] **Step 5: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/src/components/case-row.tsx journeybook/src/App.tsx
git commit -m "feat(journeybook): render case detail as a sectioned panel

Nine possible sections in one fixed reading order, labels right-aligned
in a 3.5rem gutter with content at 5.5rem, so the panel has a single
hard vertical rule instead of nine headings breaking up the prose.
Labels stay sentence case per authoring-cases.md.

Six of the nine sections are empty until the backfill lands, so this is
inert today by design -- the three existing ones must look right first.

Suite.context renders as journey prose below the premise."
```

---

### Task 3: Carry the mechanism into the defect report

**Files:**
- Modify: `journeybook/src/lib/report.ts:28-37`

**Interfaces:**
- Consumes: `Case.why` and `Case.verify` from plan 01 Task 1.
- Produces: no exported change. `buildReport` keeps its signature.

**Why:** a report saying "J4 failed, expected the vault purged" is not
triageable. One that adds the mechanism tells whoever picks the ticket up
where to look, and this is the highest-value placement of the new text — it
costs a tester nothing at read time and travels with the defect.

- [ ] **Step 1: Add the two lines**

In `journeybook/src/lib/report.ts`, inside the `for (const c of fail)` loop,
after the `expected:` push and before `lines.push("")`:

```ts
      if (c.why) {
        lines.push(`  why:      ${c.why.replace(/\n/g, " ")}`)
      }
      if (c.verify?.command) {
        lines.push(`  verify:   ${c.verify.command.split("\n")[0]}`)
      }
```

`why` is prose and may wrap across lines in the data file, so newlines
collapse to spaces — a report is pasted into a ticket field where a hard
newline breaks the two-space indent. `verify.command` takes only its first
line, matching how `command` is already truncated two lines above.

- [ ] **Step 2: Update the doc comment**

Replace the comment above `buildReport` (lines 4-8) with:

```ts
/**
 * A plain-text summary a tester can paste straight into a defect ticket or a
 * standup message. Failures come first and carry the expected output, the
 * mechanism and the verification command, because "A7 failed" is not a report
 * -- "A7 failed, expected 403, got 200, and here is why it should have been
 * 403" is one somebody else can act on.
 */
```

- [ ] **Step 3: Verify**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run typecheck && bun run lint && bun run build
```

Expected: all three exit 0, and `dist/journeybook.html` plus
`dist/index.html` are written. Open `dist/journeybook.html` directly from
`file://`, fail one case, and press "Copy the result summary". The pasted
text has no `why:` or `verify:` line yet — nothing is authored until plan 03 —
which is the correct output today.

- [ ] **Step 4: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/src/lib/report.ts
git commit -m "feat(journeybook): put the mechanism in the defect report

A failed check now pastes its why and its verify command into the
ticket. \"J4 failed, expected the vault purged\" is not triageable; the
mechanism tells whoever picks it up where to look, and it costs the
tester nothing at read time."
```

---

## When this plan is complete

Tick every checkbox above, then:

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run typecheck && bun run lint && bun run check:links && bun scripts/check-contrast.mjs && bun run build
git -C .. log --oneline -3
```

Expected: five clean exits and three new commits. The page renders exactly as
it did before this plan, because no case carries any of the new fields yet.
That is the correct end state — the plumbing is proven before any data flows
through it.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-03-pilot-j.md`

---

## Self-Review

**Spec coverage:** the spec's "The panel" section is Tasks 1 and 2; its
`buildReport` paragraph is Task 3. `Suite.context` rendering is Task 2 Step 3.
The spec's gates and backfill belong to plans 03 onward.

**Placeholder scan:** none. Task 2 Step 1 deliberately shows a wrong first
attempt (the conditional type) and then replaces it, because an implementer
reaching for `Record<...>` over an inline union would otherwise write exactly
that and think it correct — showing the trap and the fix costs four lines and
saves a debugging session.

**Type consistency:** `Relation` is imported in Task 2 Step 1 and is the exact
name exported by plan 01 Task 1. `item.verify.command` and `item.verify.look`
match the `Verify` interface. `Terminal`'s `label` is optional from Task 1 and
Task 2 relies on that — Task 1 must land first.

**Known risk:** the gutter is 3.5rem and "Expected" at 11.5px JetBrains Mono
measures about 55px, which is within 56px by a single pixel. If a future
section needs a longer label, widen the grid column rather than shrinking the
label's type — the `.label` size is shared with the rail and the masthead.
