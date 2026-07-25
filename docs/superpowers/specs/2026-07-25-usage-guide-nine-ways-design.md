# RocketVault Usage Guide — "9 Ways to Use RocketVault" — Design Spec

**Date:** 2026-07-25
**Status:** Approved (design phase)
**Author:** Brainstormed with the maintainer

---

## Goal

Produce a single, comprehensive, self-contained **usage guide** that documents every
distinct way a person or system can use RocketVault, each with a working example — plus
a short "pick your path" entry point that routes readers to the right section. This is
new user-facing documentation, separate from `docs/admin-manual.html` (operational admin
handbook) and the existing deep-dive guides; some content will necessarily overlap with
those, by design (see Decisions).

## Decisions (locked)

| Decision | Choice |
|----------|--------|
| Relationship to existing docs | Fully self-contained — duplicate full detail for all 9 ways inline, even where a deep-dive guide (cli-guide.md, admin-manual.html, consuming-secrets-guide.md, api-developer-guide.md, hsm-softhsm2-testing.md) already covers it. Deep-dive docs remain linked for readers who want more. |
| Output files | Two: `docs/getting-started.md` (short "pick your path" index) and `docs/usage-guide.md` (the comprehensive doc) |
| Gaps (ways with no existing deep-dive) | Written in full inline: OAuth2/service accounts, JWKS consumption, backup/restore, health/monitoring integration, deployment modes |
| Existing-docs maintenance | Spot-check `admin-manual.html`, `cli-guide.md`, `consuming-secrets-guide.md`, `api-developer-guide.md`, `README.md` for drift vs. current code; fix concrete inaccuracies only, no rewrite |
| Execution mechanism | Workflow tool, multi-agent, per user's explicit request |
| Long-term maintenance | Manual diff-based refresh skill (modeled on the existing `kb-refresh` skill) + a git `post-commit` hook that reminds (never auto-edits) when doc-relevant paths drift. No CronCreate (recurring jobs auto-expire after 7 days — not durable enough) and no CI/API-key automation for this iteration. |

## The 9 ways (canonical list, in doc order)

1. CLI (human-driven)
2. REST API (programmatic)
3. OAuth2 / Service Accounts (machine-to-machine)
4. Vault Client library (embedded secret consumption)
5. JWKS endpoint (token verification by external services)
6. Backup / restore tooling
7. Health / monitoring integration
8. HSM-backed mode (PKCS#11)
9. Deployment modes (standalone binary / Docker / SQLite vs. PostgreSQL)

## Output files

### `docs/usage-guide.md`

One `##` section per way, each following the template below. Verified against actual
source (`cmd/`, `api/`, `config/`, `.rocketvault.yaml`), not against other docs — existing
docs are known to have drifted before (see `.claude/known-bugs.md`).

### `docs/getting-started.md`

A short table: user intent → which of the 9 ways fits → link to its `usage-guide.md`
section. Generated last, from the finished guide, so links and framing are accurate.

## Per-section template

```markdown
## N. <Way Name>

**What it is:** 1-2 sentences.
**Use it when:** bullet list of concrete scenarios.
**Prerequisites:** config keys, binaries, tokens needed.

### Example
<working command(s) or code, copy-pasteable, verified against actual source>

### Notes & gotchas
<real constraints pulled from code — auth requirements, rate limits, known issues>

**Deep dive:** link to existing doc, if one exists.
```

## Orchestration plan (Workflow tool, multi-agent, model-tiered)

**Phase 1 — Audit** *(runs in parallel with Phase 2)*
1 Sonnet agent reads `admin-manual.html`, `cli-guide.md`, `consuming-secrets-guide.md`,
`api-developer-guide.md`, `README.md`, and `.claude/known-bugs.md`, and flags concrete
staleness/inaccuracies against current source. Output: a findings list, not edits.

**Phase 2 — Research + Draft** *(pipeline, one agent per way, concurrent)*
9 Sonnet agents, one per usage-way. Each reads the actual source for its way (relevant
`cmd/` subpackage, `api/` handlers, `config/`, `.rocketvault.yaml`) and drafts its
section per the template above. Sonnet tier: requires real codebase comprehension, not
just prose generation.

**Phase 3 — Synthesis** *(barrier — needs all 9 drafts + audit findings together)*
1 Opus agent merges the 9 sections into `docs/usage-guide.md`: consistent voice, intro,
table of contents, resolves cross-references, folds in relevant caveats (e.g. the known
`deleted_at` column bug where user-visible). Opus tier: highest-judgment step — decides
what's redundant, what's missing, how the doc reads as a whole.

**Phase 4 — Verify** *(adversarial check)*
1 Opus agent cross-checks every command, endpoint, config key, and flag in the finished
guide against actual source, flagging anything fabricated, outdated, or wrong.

**Phase 5 — Fix + finalize**
- 1 Sonnet agent applies Phase 4's corrections to `usage-guide.md`.
- 1 Sonnet agent applies Phase 1's concrete fixes to the existing docs (only real drift,
  no padding, no scope creep into a rewrite).
- 1 Haiku agent generates `docs/getting-started.md` from the finished guide's section
  headers/summaries — mechanical extraction/summarization, cheap tier fits.
- 1 Sonnet agent does a final consistency/readability pass across both new files, and
  adds a link to `docs/getting-started.md` from `README.md`'s Documentation section.

**Phase 6 — Long-term maintenance setup** *(after Phase 5 finalize; needs the finishing commit)*
1 Sonnet agent builds the three artifacts below, seeding the manifest's `globs` per
section from the source paths each Phase 2 agent actually cited, and its
`lastVerifiedCommit` from the commit that lands `docs/usage-guide.md` +
`docs/getting-started.md`.

Total: ~17 agents. Exceeds the session's "under 15" guideline slightly; justified by the
scope (9 independently-researched sections, audit/verify/fix passes across three
categories of output, plus one-time maintenance-pipeline setup).

## Long-term maintenance (regeneration pipeline)

Three artifacts, built once in Phase 6, that together let the guide be kept current
without a full re-run of Phases 1-5:

**1. Manifest — `docs/.usage-guide-map.json`**
Mirrors the existing `.kb-map.json` pattern: `lastVerifiedCommit`, `lastVerifiedDate`,
and a per-section table `{ section: "3-oauth2-service-accounts", file: "docs/usage-guide.md",
globs: ["api/**/oauth2*", "internal/services/auth/**", ...] }` for all 9 sections plus
`getting-started` (globs = the union of all section globs, since it's derived from them).

**2. Refresh skill — `.claude/skills/usage-guide-refresh/SKILL.md`**
Project-scoped skill (this repo already has `.claude/skills/migration-add` and
`.claude/skills/coverage-check` as precedent for project skills). On invocation
("refresh the usage guide"):
- Diff `lastVerifiedCommit..HEAD`, map changed files to affected sections via the
  manifest's globs (same matching logic as `kb-refresh`).
- No affected sections → report up to date, stop, don't touch the manifest.
- Affected sections → one Sonnet agent per section, re-verify against current source and
  patch surgically (preserve untouched content, no full-section rewrites).
- Regenerate `getting-started.md` only if a section's heading/summary changed enough to
  affect its routing table entry.
- Rewrite the manifest with the new `lastVerifiedCommit` (HEAD) and today's date.
- Report which sections were refreshed and why, and which were skipped as unaffected.

**3. Drift reminder — git `post-commit` hook**
Pure shell, no AI call, no API cost, no expiry:
- `scripts/hooks/post-commit` reads the manifest, diffs `lastVerifiedCommit..HEAD`, checks
  the changed files against every section's globs, and if any match, prints one line:
  `usage-guide.md may be stale (N section(s) affected) — run the usage-guide-refresh skill`.
  Silent if nothing matches.
- `scripts/install-hooks.sh` runs `git config core.hooksPath scripts/hooks` so the hook is
  version-controlled and shared across clones (raw `.git/hooks/` isn't tracked by git).
  One-time step per clone; documented in the README's Contributing section.

## Non-goals

- No changes to RocketVault application code.
- No rewrite of `admin-manual.html` or the other existing guides — only concrete drift
  fixes identified by the Phase 1 audit.
- No CI-based or CronCreate-based automation for this iteration (see Decisions table) —
  the hook only reminds, it never edits or commits on its own.

## Success criteria

- `docs/usage-guide.md` covers all 9 ways, each self-contained per the template, each
  example verified against actual source.
- `docs/getting-started.md` correctly routes each plausible user intent to a section.
- Phase 4 verification finds zero unresolved fabricated/incorrect examples in the final
  guide.
- Any concrete inaccuracies found in existing docs during Phase 1 are fixed, not just
  reported.
- README.md's Documentation section links to the new `getting-started.md` as an entry
  point.
- `docs/.usage-guide-map.json` exists, covers all 9 sections + getting-started, and its
  `lastVerifiedCommit` matches the commit that lands the guide.
- Running the `usage-guide-refresh` skill with no drift reports "up to date" and makes no
  edits; run against a synthetic drifted commit, it refreshes only the affected section(s).
- `scripts/install-hooks.sh` correctly wires the post-commit hook; a commit touching a
  doc-relevant path prints the reminder, an unrelated commit stays silent.
