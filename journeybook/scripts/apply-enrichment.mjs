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
