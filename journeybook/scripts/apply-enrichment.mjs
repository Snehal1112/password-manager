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
 *
 * Two or more input files may cover the same case id, as long as they supply
 * different fields for it -- a later code-answering pass fills in `after` for
 * a case an earlier extraction pass already gave a `why`. Two files supplying
 * the SAME field for the same case is the real conflict and fails.
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

function fail(message) {
  console.error(`apply-enrichment: ${message}`)
  process.exit(1)
}

function describeType(v) {
  if (v === null) return "null"
  if (Array.isArray(v)) return "an array"
  return typeof v
}

function expectObject(id, field, value, path) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${id}: "${field}" must be an object, got ${describeType(value)} (in ${path}).`)
  }
}

function expectString(id, field, value, path) {
  if (typeof value !== "string") {
    fail(`${id}: "${field}" must be a string, got ${describeType(value)} (in ${path}).`)
  }
}

const RELATIONS = new Set(["depends", "diverges", "contrasts"])

/**
 * Validates one case's enrichment shape as read from one input file, before
 * anything is merged or rendered. Every ambiguity here must fail() with the
 * case id and field name attached -- a raw TypeError from a malformed value
 * reaching lit() deep inside properties() is much harder to trace back to the
 * offending file than a named failure here.
 */
function validateShape(id, value, path) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${id}: enrichment entry must be an object, got ${describeType(value)} (in ${path}).`)
  }
  if (value.why !== undefined) {
    expectObject(id, "why", value.why, path)
    expectString(id, "why.text", value.why.text, path)
    if (value.why.source !== undefined) expectString(id, "why.source", value.why.source, path)
  }
  if (value.verify !== undefined) {
    expectObject(id, "verify", value.verify, path)
    expectString(id, "verify.look", value.verify.look, path)
    if (value.verify.command !== undefined) {
      expectString(id, "verify.command", value.verify.command, path)
    }
    if (value.verify.source !== undefined) {
      expectString(id, "verify.source", value.verify.source, path)
    }
  }
  if (value.after !== undefined) {
    expectObject(id, "after", value.after, path)
    expectString(id, "after.text", value.after.text, path)
    if (value.after.source !== undefined) expectString(id, "after.source", value.after.source, path)
  }
  if (value.related !== undefined) {
    if (!Array.isArray(value.related)) {
      fail(`${id}: "related" must be an array, got ${describeType(value.related)} (in ${path}).`)
    }
    value.related.forEach((r, idx) => {
      if (typeof r !== "object" || r === null || Array.isArray(r)) {
        fail(`${id}: related[${idx}] must be an object, got ${describeType(r)} (in ${path}).`)
      }
      expectString(id, `related[${idx}].id`, r.id, path)
      if (!RELATIONS.has(r.rel)) {
        fail(
          `${id}: related[${idx}].rel must be one of depends/diverges/contrasts, ` +
            `got ${JSON.stringify(r.rel)} (in ${path}).`
        )
      }
    })
  }
  if (value["needs-code"] !== undefined && !Array.isArray(value["needs-code"])) {
    fail(`${id}: "needs-code" must be an array, got ${describeType(value["needs-code"])} (in ${path}).`)
  }
}

// The Case fields a case's enrichment may carry. Each one must come from
// exactly one input file; `needs-code` is not in this list because it merges
// by concatenation instead -- see the merge loop below.
const MERGE_FIELDS = ["why", "verify", "after", "related"]

/**
 * Merge every input file into one id -> merged-enrichment map, field by
 * field. Two files may enrich the same case as long as they supply different
 * fields for it (an extraction pass giving `why`, a code pass giving `after`
 * for the same case is the expected shape of a later plan). Two files
 * supplying the same field for the same case is a real authoring conflict.
 */
const enrichment = new Map()
for (const path of inputs) {
  const parsed = JSON.parse(readFileSync(path, "utf8"))
  for (const [id, value] of Object.entries(parsed)) {
    validateShape(id, value, path)

    let merged = enrichment.get(id)
    if (!merged) {
      merged = { fields: {}, fieldSource: {}, needsCode: [] }
      enrichment.set(id, merged)
    }

    for (const field of MERGE_FIELDS) {
      if (value[field] === undefined) continue
      if (field in merged.fields) {
        fail(
          `${id}: "${field}" is supplied by both ${merged.fieldSource[field]} and ${path}. ` +
            `Each field must come from exactly one input file.`
        )
      }
      merged.fields[field] = value[field]
      merged.fieldSource[field] = path
    }

    if (Array.isArray(value["needs-code"])) {
      merged.needsCode.push(...value["needs-code"])
    }
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
 * Walks the object literal starting at `open` (its opening brace), skipping
 * string literals, template literals and comments so a brace or a bare word
 * inside an expected-output line cannot be mistaken for structure. Returns
 * the index of the object's matching close brace, and the set of its own
 * top-level property names -- properties of any object nested inside it
 * (`verify: { ... }`, `related: [{ ... }]`) are not included.
 *
 * Both matchBrace's old job and the double-application guard's job need this
 * exact walk, so there is one walker rather than a brace-matcher plus a
 * separate regex that does not know where the strings are.
 */
function scanObject(src, open) {
  let depth = 0
  const topKeys = new Set()
  for (let i = open; i < src.length; i++) {
    const c = src[i]
    if (c === "/" && src[i + 1] === "/") {
      i = src.indexOf("\n", i)
      if (i === -1) return { close: -1, topKeys }
      continue
    }
    if (c === "/" && src[i + 1] === "*") {
      i = src.indexOf("*/", i + 2)
      if (i === -1) return { close: -1, topKeys }
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
    if (depth === 1 && /[A-Za-z_$]/.test(c)) {
      const ident = /^[A-Za-z_$][A-Za-z0-9_$]*/.exec(src.slice(i))[0]
      let j = i + ident.length
      while (src[j] === " " || src[j] === "\t") j++
      if (src[j] === ":") topKeys.add(ident)
      i = j - 1
      continue
    }
    if (c === "{") depth++
    else if (c === "}") {
      depth--
      if (depth === 0) return { close: i, topKeys }
    }
  }
  return { close: -1, topKeys }
}

/** Render the enrichment for one case as TypeScript object properties. */
function properties(fields) {
  const out = []
  if (fields.why) out.push(`why: ${lit(fields.why.text)},`)
  if (fields.verify) {
    const parts = []
    if (fields.verify.command) parts.push(`command: ${lit(fields.verify.command)},`)
    parts.push(`look: ${lit(fields.verify.look)},`)
    out.push(`verify: { ${parts.join(" ")} },`)
  }
  if (fields.after) out.push(`after: ${lit(fields.after.text)},`)
  if (fields.related?.length) {
    const items = fields.related
      .map((r) => `{ id: ${JSON.stringify(r.id)}, rel: ${JSON.stringify(r.rel)} }`)
      .join(", ")
    out.push(`related: [${items}],`)
  }
  // Per-field provenance is what a verifier needs; a tester needs to know
  // where the case came from, not which sentence came from where. So the
  // distinct citations collapse to one string, in first-seen order. This
  // still works when why/verify/after arrived from different input files --
  // by the time properties() runs they are just values on one object.
  const sources = []
  for (const field of [fields.why, fields.verify, fields.after]) {
    if (field?.source && !sources.includes(field.source)) sources.push(field.source)
  }
  if (sources.length) out.push(`source: ${lit(sources.join("; "))},`)
  return out
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
  for (const [id, merged] of enrichment) {
    const needle = `id: ${JSON.stringify(id)},`
    const at = src.indexOf(needle)
    if (at === -1) continue
    if (src.indexOf(needle, at + 1) !== -1) {
      fail(`${id} matches ${needle} more than once in ${name}.`)
    }
    targets.push({ id, merged, at })
    found.add(id)
  }
  targets.sort((a, b) => b.at - a.at)

  for (const { id, merged, at } of targets) {
    const open = src.lastIndexOf("{", at)
    if (open === -1) fail(`${id}: no opening brace before its id.`)
    const { close, topKeys } = scanObject(src, open)
    if (close === -1) fail(`${id}: unbalanced braces from its object.`)

    const props = properties(merged.fields)
    if (props.length === 0) continue

    // Guard against a double application. Re-running must be a no-op, not a
    // duplicate-key TypeScript error. Tested against the object's own
    // top-level keys (from scanObject's string-aware walk), not a regex over
    // its raw text -- a multi-line command or expected-output string can
    // contain a line that looks like "source:" without being one.
    for (const p of props) {
      const key = p.slice(0, p.indexOf(":"))
      if (topKeys.has(key)) {
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
for (const [id, merged] of enrichment) {
  for (const q of merged.needsCode) open.push(`${id}: ${q}`)
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
