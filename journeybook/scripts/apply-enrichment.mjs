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
 * Case objects are located structurally, not by searching for `id: "<ID>"` as
 * raw text: enrichment adds `related: [{ id: "K3", rel: "diverges" }]` arrays,
 * so that text can legitimately appear twice in a file -- once as some other
 * case's cross-reference, once as K3's own id. This walks each `cases: [...]`
 * array and records only each element's own top-level id, skipping strings,
 * templates and comments throughout, so a related item's nested id never
 * enters the map and an id-shaped string inside a command or expected value
 * never confuses the walk. Anything ambiguous is a hard failure -- a
 * partially applied data file is worse than none.
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
 * If position `i` in `src` starts a line comment, a block comment or a
 * string/template literal, returns the index just past it. Otherwise -1.
 * Every walker below shares this so a brace, colon or the word "cases"
 * inside a command or expected-output value is never mistaken for
 * structure.
 */
function skipNonStructural(src, i) {
  const c = src[i]
  if (c === "/" && src[i + 1] === "/") {
    const nl = src.indexOf("\n", i)
    return nl === -1 ? src.length : nl
  }
  if (c === "/" && src[i + 1] === "*") {
    const end = src.indexOf("*/", i + 2)
    return end === -1 ? src.length : end + 2
  }
  if (c === '"' || c === "'" || c === "`") {
    const quote = c
    let j = i + 1
    while (j < src.length && src[j] !== quote) {
      if (src[j] === "\\") j++
      j++
    }
    return j + 1
  }
  return -1
}

/**
 * Walks the object literal starting at `open` (its opening brace), skipping
 * string literals, template literals and comments so a brace or a bare word
 * inside an expected-output line cannot be mistaken for structure. Returns
 * the index of the object's matching close brace, the set of its own
 * top-level property names -- properties of any object nested inside it
 * (`verify: { ... }`, `related: [{ ... }]`) are not included -- and, when
 * present, the string value of its own top-level `id` property.
 *
 * The double-application guard's job and the case-locator's job both need
 * this exact walk, so there is one walker rather than a brace-matcher plus a
 * separate pass that does not know where the strings are.
 */
function scanObject(src, open) {
  let depth = 0
  const topKeys = new Set()
  const values = {}
  for (let i = open; i < src.length; ) {
    const skip = skipNonStructural(src, i)
    if (skip !== -1) {
      i = skip
      continue
    }
    const c = src[i]
    if (depth === 1 && /[A-Za-z_$]/.test(c)) {
      const ident = /^[A-Za-z_$][A-Za-z0-9_$]*/.exec(src.slice(i))[0]
      let j = i + ident.length
      while (src[j] === " " || src[j] === "\t") j++
      if (src[j] === ":") {
        topKeys.add(ident)
        if (ident === "id") {
          let k = j + 1
          while (src[k] === " " || src[k] === "\t") k++
          if (src[k] === '"' || src[k] === "'" || src[k] === "`") {
            const quote = src[k]
            let m = k + 1
            let value = ""
            while (m < src.length && src[m] !== quote) {
              if (src[m] === "\\") {
                value += src[m + 1]
                m += 2
                continue
              }
              value += src[m]
              m++
            }
            values.id = value
          }
        }
      }
      i = j
      continue
    }
    if (c === "{") {
      depth++
      i++
      continue
    }
    if (c === "}") {
      depth--
      if (depth === 0) return { close: i, topKeys, values }
      i++
      continue
    }
    i++
  }
  return { close: -1, topKeys, values }
}

/**
 * Finds every `cases: [...]` array in the file and returns the offset just
 * past its opening `[`. Skips a match found inside a string, template or
 * comment via the same shared walk, so an expected-output value that happens
 * to contain the text "cases: [" cannot be mistaken for a real array.
 */
function findCasesArrayStarts(src) {
  const starts = []
  for (let i = 0; i < src.length; ) {
    const skip = skipNonStructural(src, i)
    if (skip !== -1) {
      i = skip
      continue
    }
    const prev = src[i - 1]
    if (src.startsWith("cases", i) && !/[A-Za-z0-9_$]/.test(prev ?? "")) {
      const m = /^cases\s*:\s*\[/.exec(src.slice(i))
      if (m) {
        starts.push(i + m[0].length)
        i += m[0].length
        continue
      }
    }
    i++
  }
  return starts
}

/**
 * Maps each case id in `src` to its own object's brace span, by walking only
 * the direct elements of every `cases: [...]` array. An id nested inside a
 * `related: [...]` entry lives at depth 2 relative to its enclosing case
 * object and is never a direct array element, so it can never enter this
 * map -- the ambiguity that made raw `id: "<ID>"` text search unsafe once
 * `related` existed cannot occur here. Two distinct case objects genuinely
 * declaring the same id is still a real authoring error and fails loudly.
 */
function collectCaseSpans(src, fileName) {
  const spans = new Map()
  for (const arrayStart of findCasesArrayStarts(src)) {
    let i = arrayStart
    while (i < src.length) {
      const skip = skipNonStructural(src, i)
      if (skip !== -1) {
        i = skip
        continue
      }
      const c = src[i]
      if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === ",") {
        i++
        continue
      }
      if (c === "]") break
      if (c !== "{") {
        i++
        continue
      }
      const { close, topKeys, values } = scanObject(src, i)
      if (close === -1) {
        fail(`malformed case object in ${fileName} (unbalanced braces at offset ${i}).`)
      }
      if (values.id !== undefined) {
        if (spans.has(values.id)) {
          fail(`${values.id} appears in two case objects in ${fileName}.`)
        }
        spans.set(values.id, { open: i, close, topKeys })
      }
      i = close + 1
    }
  }
  return spans
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

  const caseSpans = collectCaseSpans(src, name)

  // Apply from the end of the file backwards, so every insertion offset
  // computed before it stays valid.
  const targets = []
  for (const [id, merged] of enrichment) {
    const span = caseSpans.get(id)
    if (!span) continue
    targets.push({ id, merged, span })
    found.add(id)
  }
  targets.sort((a, b) => b.span.open - a.span.open)

  for (const { id, merged, span } of targets) {
    const props = properties(merged.fields)
    if (props.length === 0) continue

    // Guard against a double application. Re-running must be a no-op, not a
    // duplicate-key TypeScript error. Tested against the object's own
    // top-level keys (from scanObject's string-aware walk), not a regex over
    // its raw text -- a multi-line command or expected-output string can
    // contain a line that looks like "source:" without being one.
    for (const p of props) {
      const key = p.slice(0, p.indexOf(":"))
      if (span.topKeys.has(key)) {
        fail(`${id} already has a "${key}" property. Refusing to apply twice.`)
      }
    }

    src = src.slice(0, span.close) + props.join("\n") + "\n" + src.slice(span.close)
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
