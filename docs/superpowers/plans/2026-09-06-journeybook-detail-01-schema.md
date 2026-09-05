# Journeybook Detail — Schema and Tooling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the five optional `Case` fields and `Suite.context` to the journeybook's type layer, and build the two scripts that make a 245-case backfill safe to apply mechanically.

**Architecture:** Types first, because every later plan writes data against them. Then a merge script that inserts enrichment into the existing `src/data/*.ts` case objects by brace-matching, so no subagent ever edits those files directly. Then a link checker, because `related` introduces the first cross-reference in this codebase that can dangle.

**Tech Stack:** TypeScript 6 strict, Bun (runs `.ts` directly, which is why the checker can import the data modules without a build step), Prettier, Biome.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Followed by:** `2026-09-06-journeybook-detail-02-panel.md`, which renders these fields. The types are inert until then — nothing in the UI reads them yet, and that is expected at the end of this plan.

## Global Constraints

- Case ids are permanent. This plan adds fields; it renames nothing and removes nothing. The `localStorage` key stays `journeybook-run-v1`.
- Every new field is optional. A case with none of them must still typecheck and render exactly as it does today.
- Package manager is **bun**. Do not create a second lockfile by running npm, yarn or pnpm.
- `bun run typecheck` must keep the `-b` flag and `bun run lint` must keep `--error-on-warnings`. Both are load-bearing; see `journeybook/README.md`.
- `src/components/ui/` is byte-identical to the shadcn registry and is in `.prettierignore`. Do not edit anything in it.
- All commits are GPG-signed. `commit.gpgsign` is already `true` in this repo, so a plain `git commit` signs.
- Run `bun run typecheck` and `bun run lint` before every commit.

---

### Task 1: Extend the type layer

**Files:**
- Modify: `journeybook/src/data/types.ts`

**Interfaces:**
- Produces: `Relation`, `Related`, `Verify` types, `Case.why`, `Case.verify`, `Case.after`, `Case.related`, `Case.source`, and `Suite.context`. Task 2's merge script emits TypeScript matching these exactly; plan 02's panel reads all of them; plans 04–08 have subagents author JSON that maps onto them.

- [x] **Step 1: Add the three new types above `Case`**

In `journeybook/src/data/types.ts`, insert immediately after the `Surface`
type alias and before `export interface Case {`:

```ts
/**
 * How one check relates to another. Three values rather than a free string,
 * because a tester scanning a cross-reference needs to know which kind it is:
 * `depends` means this check is meaningless unless that one passed first,
 * `diverges` means the same authority produces a different answer there
 * (Journey K's CLI/HTTP purge split is the archetype), and `contrasts` is the
 * neighbouring case showing the opposite outcome -- usually the allow beside
 * the deny.
 */
export type Relation = "depends" | "diverges" | "contrasts"

export interface Related {
  /** Must resolve to a real case id. scripts/check-links.mjs enforces it. */
  id: string
  rel: Relation
}

/**
 * How to settle pass from fail when `expected` leaves a margin.
 *
 * One object, not an array. Rule 3 of .claude/authoring-cases.md is one
 * assertion per case, so a check needing two independent verifications is two
 * checks.
 */
export interface Verify {
  /**
   * Transcribed from the journeys doc, or built only from flags confirmed to
   * exist by reading the cobra registration in cmd/. Never inferred: a
   * verification command carrying a flag that does not exist wastes a
   * tester's time and teaches them to distrust the page.
   */
  command?: string
  /** What in the result settles it. Required whenever `verify` is present. */
  look: string
}
```

- [x] **Step 2: Add the five fields to `Case`**

In the same file, inside `export interface Case`, after the existing `flag`
field and before the closing brace:

```ts
  /**
   * The mechanism. Why the system behaves this way, not what the command
   * does. A tester whose run does not match needs something to reason with.
   *
   * Requires `source`. An absent `why` is honest; an invented one is the
   * failure mode the whole enrichment exists to avoid.
   */
  why?: string
  /** How to settle pass from fail. Requires `source`. */
  verify?: Verify
  /** What this leaves behind, and what to undo first. Requires `source`. */
  after?: string
  /** Other checks this one leans on or contradicts. */
  related?: Related[]
  /**
   * Provenance for `why`, `verify` and `after`. Either a document section
   * (`VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J -- the purge trap`) or a
   * code location (`internal/services/vaults/vault_service.go:214`). Several
   * citations are separated by `; `.
   */
  source?: string
```

- [x] **Step 3: Add `context` to `Suite`**

In the same file, inside `export interface Suite`, after `premise` and before
`cases`:

```ts
  /**
   * The journey-level prose the document carries between its command blocks,
   * one string per paragraph. `premise` stays the one-sentence summary shown
   * on the collapsed suite; this is what a tester reads before starting.
   */
  context?: string[]
```

- [x] **Step 4: Verify nothing broke**

Run: `cd journeybook && bun run typecheck && bun run lint`
Expected: both exit 0. Every field is optional, so all 245 existing cases
still satisfy `Case` unchanged.

- [x] **Step 5: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/src/data/types.ts
git commit -m "feat(journeybook): add case detail fields to the type layer

Five optional Case fields (why, verify, after, related, source) and
Suite.context, for the enrichment described in the 2026-09-06 spec.

Every field is optional and nothing reads them yet, so all 245 existing
cases are unchanged and the stored-run key stays journeybook-run-v1."
```

---

### Task 2: The enrichment merge script

**Files:**
- Create: `journeybook/scripts/apply-enrichment.mjs`

**Interfaces:**
- Consumes: the `Case` field names from Task 1.
- Produces: `bun scripts/apply-enrichment.mjs <enrichment.json>...`, which mutates `src/data/journeys-*.ts` in place. Plans 03 and 09 are its only callers.

**Why a script rather than editing by hand:** hand-editing 245 cases
reintroduces exactly the transcription errors this whole effort removes, and
escaping backticks and `${` inside TypeScript template literals is mechanical
work a script does correctly every time and a human does correctly most of the
time. It also means five subagents can produce data concurrently without ever
opening the same file.

- [x] **Step 1: Write the script**

Create `journeybook/scripts/apply-enrichment.mjs`:

```js
/**
 * Applies enrichment JSON onto the journeybook case data.
 *
 * Subagents never edit src/data/*.ts -- five of them writing four files
 * concurrently corrupts those files, and a reviewer needs the claim beside its
 * citation rather than a diff. They emit JSON keyed by case id instead, and
 * this applies it.
 *
 * Usage:
 *   bun scripts/apply-enrichment.mjs out/a-f.json out/g-m.json ...
 *   bun scripts/apply-enrichment.mjs --dry-run out/a-f.json
 *
 * The insertion is brace-matched rather than regex-replaced: it finds the case
 * object containing `id: "<ID>"`, walks to its matching close brace while
 * skipping strings and comments, and inserts before it. Anything ambiguous is
 * a hard failure -- a partially applied data file is worse than none.
 */

import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, resolve } from "node:path"

const here = dirname(fileURLToPath(import.meta.url))
const dataDir = resolve(here, "../src/data")
const DATA_FILES = [
  "journeys-a-f.ts",
  "journeys-g-m.ts",
  "journeys-n-u.ts",
  "journeys-v-w.ts",
]

const args = process.argv.slice(2)
const dryRun = args.includes("--dry-run")
const inputs = args.filter((a) => a !== "--dry-run")

if (inputs.length === 0) {
  console.error("usage: bun scripts/apply-enrichment.mjs [--dry-run] <file.json>...")
  process.exit(2)
}

/** Merge every input file into one id -> enrichment map, refusing overlaps. */
const enrichment = new Map()
for (const path of inputs) {
  const parsed = JSON.parse(readFileSync(path, "utf8"))
  for (const [id, value] of Object.entries(parsed)) {
    if (enrichment.has(id)) {
      fail(`${id} appears in two input files. Each case belongs to one group.`)
    }
    enrichment.set(id, value)
  }
}

/** A TypeScript string literal. Template only when the text has newlines. */
function lit(s) {
  if (!s.includes("\n")) return JSON.stringify(s)
  const escaped = s
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/\$\{/g, "\\${")
  return "`" + escaped + "`"
}

/**
 * The index just past the object that starts at `open`.
 * Skips over string literals, template literals and comments so a brace inside
 * an expected-output line cannot end the object early.
 */
function matchBrace(src, open) {
  let depth = 0
  for (let i = open; i < src.length; i++) {
    const c = src[i]
    if (c === "/" && src[i + 1] === "/") {
      i = src.indexOf("\n", i)
      if (i === -1) return -1
      continue
    }
    if (c === "/" && src[i + 1] === "*") {
      i = src.indexOf("*/", i + 2)
      if (i === -1) return -1
      i++
      continue
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c
      i++
      while (i < src.length && src[i] !== quote) {
        if (src[i] === "\\") i++
        i++
      }
      continue
    }
    if (c === "{") depth++
    else if (c === "}") {
      depth--
      if (depth === 0) return i
    }
  }
  return -1
}

/** Render the enrichment for one case as TypeScript object properties. */
function properties(e) {
  const out = []
  if (e.why) out.push(`why: ${lit(e.why.text)},`)
  if (e.verify) {
    const parts = []
    if (e.verify.command) parts.push(`command: ${lit(e.verify.command)},`)
    parts.push(`look: ${lit(e.verify.look)},`)
    out.push(`verify: { ${parts.join(" ")} },`)
  }
  if (e.after) out.push(`after: ${lit(e.after.text)},`)
  if (e.related?.length) {
    const items = e.related
      .map((r) => `{ id: ${JSON.stringify(r.id)}, rel: ${JSON.stringify(r.rel)} }`)
      .join(", ")
    out.push(`related: [${items}],`)
  }
  // Per-field provenance is what a verifier needs; a tester needs to know
  // where the case came from, not which sentence came from where. So the
  // distinct citations collapse to one string, in first-seen order.
  const sources = []
  for (const field of [e.why, e.verify, e.after]) {
    if (field?.source && !sources.includes(field.source)) sources.push(field.source)
  }
  if (sources.length) out.push(`source: ${lit(sources.join("; "))},`)
  return out
}

function fail(message) {
  console.error(`apply-enrichment: ${message}`)
  process.exit(1)
}

const applied = new Set()
const found = new Set()
let changedFiles = 0

for (const name of DATA_FILES) {
  const path = resolve(dataDir, name)
  let src = readFileSync(path, "utf8")
  let touched = 0

  // Apply from the end of the file backwards, so every insertion offset
  // computed before it stays valid.
  const targets = []
  for (const [id, e] of enrichment) {
    const needle = `id: ${JSON.stringify(id)},`
    const at = src.indexOf(needle)
    if (at === -1) continue
    if (src.indexOf(needle, at + 1) !== -1) {
      fail(`${id} matches ${needle} more than once in ${name}.`)
    }
    targets.push({ id, e, at })
    found.add(id)
  }
  targets.sort((a, b) => b.at - a.at)

  for (const { id, e, at } of targets) {
    const open = src.lastIndexOf("{", at)
    if (open === -1) fail(`${id}: no opening brace before its id.`)
    const close = matchBrace(src, open)
    if (close === -1) fail(`${id}: unbalanced braces from its object.`)

    const props = properties(e)
    if (props.length === 0) continue

    // Guard against a double application. Re-running must be a no-op, not a
    // duplicate-key TypeScript error.
    const body = src.slice(open, close)
    for (const p of props) {
      const key = p.slice(0, p.indexOf(":"))
      if (new RegExp(`\\n\\s*${key}:`).test(body)) {
        fail(`${id} already has a "${key}" property. Refusing to apply twice.`)
      }
    }

    src = src.slice(0, close) + props.join("\n") + "\n" + src.slice(close)
    applied.add(id)
    touched++
  }

  if (touched > 0) {
    changedFiles++
    if (!dryRun) writeFileSync(path, src)
    console.log(`${dryRun ? "would update" : "updated"} ${name}: ${touched} case(s)`)
  }
}

// A case id that matches no case anywhere is a typo in the enrichment, and
// silently ignoring it would drop authored work on the floor.
const missing = [...enrichment.keys()].filter((id) => !found.has(id))
if (missing.length) {
  fail(`no case found for: ${missing.join(", ")}`)
}

// `needs-code` is an open question, not a substitute for the fields beside it.
// A case may carry finished fields and an unresolved question at once, so
// these are reported rather than blocking the applied fields.
const open = []
for (const [id, e] of enrichment) {
  for (const q of e["needs-code"] ?? []) open.push(`${id}: ${q}`)
}

console.log(
  `${dryRun ? "dry run: " : ""}${applied.size} case(s) across ${changedFiles} file(s).`
)
if (open.length) {
  console.log(`\n${open.length} unresolved, for the phase 2 code pass:`)
  for (const q of open) console.log(`  ${q}`)
}
if (!dryRun && applied.size > 0) {
  console.log("Now run: bun run format && bun run typecheck && bun run lint")
}
```

- [x] **Step 2: Prove it works on a fixture, and prove it refuses to run twice**

The point of this step is that a script nobody has watched fail is a script
nobody can trust. Run it against one real case in dry-run, then for real, then
again to confirm the double-application guard fires.

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
mkdir -p /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
cat > /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/fixture.json <<'JSON'
{
  "A8": {
    "why": {
      "text": "Both doors agree here. `HasDataAction` has no admin short-circuit, so the vault-scoped route refuses an admin holding no role assignment in `prod` exactly as the CLI did in A7.",
      "source": "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey A"
    },
    "related": [{ "id": "A7", "rel": "contrasts" }]
  }
}
JSON
bun scripts/apply-enrichment.mjs --dry-run /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/fixture.json
```

Expected: `would update journeys-a-f.ts: 1 case(s)` and `dry run: 1 case(s)
across 1 file(s).` No file on disk changes — confirm with `git diff --stat`,
which must be empty.

```bash
bun scripts/apply-enrichment.mjs /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/fixture.json
git diff --stat journeybook/src/data/journeys-a-f.ts
```

Expected: the file gains `why:` and `related:` inside the `A8` object only.
Read the diff and confirm the properties landed inside `A8`'s braces and not
inside `A7`'s or `A9`'s.

```bash
bun scripts/apply-enrichment.mjs /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/fixture.json
```

Expected: exits 1 with `A8 already has a "why" property. Refusing to apply
twice.` If it instead applies a second copy, the guard is broken — fix it
before continuing, because plan 09 re-runs this script over every group.

- [x] **Step 3: Revert the fixture and commit only the script**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git checkout journeybook/src/data/journeys-a-f.ts
git add journeybook/scripts/apply-enrichment.mjs
git commit -m "feat(journeybook): add the enrichment merge script

Subagents backfilling 245 cases emit JSON keyed by case id rather than
editing src/data/*.ts. Five agents writing four files concurrently
corrupts them, and a verifier needs each claim beside its citation
rather than a diff.

Insertion is brace-matched, skipping strings and comments so a brace
inside expected output cannot close an object early. Re-running is a
hard failure rather than a duplicate property, because plan 09 applies
every group in one pass and a half-applied data file is worse than none."
```

---

### Task 3: The cross-reference checker

**Files:**
- Create: `journeybook/scripts/check-links.mjs`
- Modify: `journeybook/package.json`

**Interfaces:**
- Consumes: `allCases` from `src/data/index.ts`, and `Case.related` from Task 1.
- Produces: `bun run check:links`. Plan 09 runs it before the final commit.

**Why this exists:** `related` is the first cross-reference in this codebase
that can dangle. There is no test runner in `journeybook/`, and
`journeybook/CLAUDE.md` says to add one rather than assume `bun test` is
wired — so this follows the established shape of `scripts/check-contrast.mjs`
instead: a standalone script that reads the source directly and exits non-zero.

- [x] **Step 1: Write the checker**

Create `journeybook/scripts/check-links.mjs`:

```js
/**
 * Fails if any Case.related points at a case id that does not exist, or at
 * itself.
 *
 * A dangling cross-reference renders as a plausible-looking id a tester will
 * go hunting for. That is the misleading outcome the enrichment spec exists to
 * prevent, so it is a build failure rather than a runtime shrug.
 *
 * Bun executes TypeScript directly, so this imports the data modules with no
 * build step -- the same reason check-contrast.mjs can parse index.css.
 */

import { allCases } from "../src/data/index.ts"

const ids = new Set(allCases.map((c) => c.id))
const problems = []

for (const c of allCases) {
  for (const r of c.related ?? []) {
    if (r.id === c.id) {
      problems.push(`${c.id}: related to itself`)
    } else if (!ids.has(r.id)) {
      problems.push(`${c.id}: related id "${r.id}" does not exist`)
    }
  }
}

// A `why`, `verify` or `after` with no `source` is a rule-1 violation: the
// claim cannot be traced, so a reader has no way to check it.
for (const c of allCases) {
  const claims = ["why", "verify", "after"].filter((f) => c[f] !== undefined)
  if (claims.length > 0 && !c.source) {
    problems.push(`${c.id}: has ${claims.join(", ")} but no source`)
  }
}

if (problems.length) {
  console.error(`check-links: ${problems.length} problem(s)\n`)
  for (const p of problems) console.error(`  ${p}`)
  process.exit(1)
}

const withDetail = allCases.filter((c) => c.why || c.verify || c.after).length
console.log(
  `check-links: ${allCases.length} cases, ${withDetail} carrying detail, 0 problems.`
)
```

- [x] **Step 2: Add the npm script**

In `journeybook/package.json`, add to `"scripts"` after `"typecheck"`:

```json
    "check:links": "bun scripts/check-links.mjs",
```

- [x] **Step 3: Run it, and prove it catches a bad link**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run check:links
```

Expected: `check-links: 245 cases, 0 carrying detail, 0 problems.`

Now prove the failure path. Temporarily add `related: [{ id: "ZZ9", rel:
"depends" }],` to the `A8` case in `src/data/journeys-a-f.ts` and re-run.

Expected: exits 1 with `A8: related id "ZZ9" does not exist`. Then
`git checkout journeybook/src/data/journeys-a-f.ts` to revert.

A checker that has only ever printed success has not been tested.

- [x] **Step 4: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault
git add journeybook/scripts/check-links.mjs journeybook/package.json
git commit -m "feat(journeybook): check case cross-references and provenance

related is the first cross-reference here that can dangle, and a
dangling id renders as a plausible case number a tester goes hunting
for. Also fails a why/verify/after that carries no source, which is the
rule-1 violation the enrichment spec is built to prevent.

Follows scripts/check-contrast.mjs rather than adding a test runner --
journeybook has none, and CLAUDE.md says to add one deliberately rather
than assume bun test is wired up."
```

---

## When this plan is complete

Tick every checkbox above, then confirm all three of these before moving on:

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
bun run typecheck && bun run lint && bun run check:links
git -C .. log --oneline -3
```

Expected: three clean exits, and three new commits. `git status` shows no
modified data files — Tasks 2 and 3 both revert their fixtures.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-02-panel.md`

---

## Self-Review

**Spec coverage:** the spec's Schema section is Task 1 in full. The "Agents do
not edit the data files" section is Task 2. Verification items 1 and 2 are
Task 3. The panel, the report change, the backfill and the gates belong to
plans 02 onward and are deliberately absent here.

**Placeholder scan:** none. Every step carries the literal file content or the
literal command. Task 2 Step 2 and Task 3 Step 3 both specify the exact
failure text to expect, not "verify it fails".

**Type consistency:** the merge script emits `why`, `verify: { command, look }`,
`after`, `related: [{ id, rel }]` and `source`, matching Task 1's `Case`
exactly. The script reads its input as `e.why.text` / `e.why.source` — nested,
because provenance is per-field in the JSON and collapses to one `Case.source`
on merge, which is what the spec's "Agents do not edit the data files" section
specifies. `check-links.mjs` reads `c.related[].id` and `c.source`, both from
Task 1. `needs-code` is the one input key with no `Case` counterpart: it is an
open question for plan 06, never a field, so the script reports it and applies
whatever finished fields sit beside it rather than skipping the case.

**Known risk:** `matchBrace` assumes the data files stay Prettier-formatted, so
that `id: "A8",` appears exactly once per file with that spacing. They are
formatted today and `bun run format` is in the loop. If a future edit hand-wrote
`id:"A8"`, the script would report no case found rather than mis-applying —
loud, not silent, which is the correct failure direction.
