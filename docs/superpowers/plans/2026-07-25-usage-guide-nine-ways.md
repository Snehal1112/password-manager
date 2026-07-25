# RocketVault Usage Guide ("9 Ways") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `docs/usage-guide.md` (9 fully self-contained ways to use RocketVault, each verified against source) and `docs/getting-started.md` (a "pick your path" router), plus a durable, low-cost long-term maintenance pipeline (manifest + refresh skill + git hook) so the guide doesn't silently rot.

**Architecture:** A single multi-agent Workflow run (Phases 1-6, model-tiered Sonnet/Opus/Haiku) generates all content and maintenance tooling into the working tree without committing. Humans review and commit in discrete, independently-revertible steps. The hook and skill are then functionally tested against synthetic scenarios before being trusted.

**Tech Stack:** Workflow tool (JS orchestration script), Agent tool subagents (Sonnet/Opus/Haiku), Markdown, bash (git hook), JSON (manifest).

## Global Constraints

- No changes to RocketVault application code — only `docs/`, `docs/superpowers/`, `.claude/skills/`, `scripts/hooks/`, `scripts/install-hooks.sh`, and `README.md`'s Documentation section.
- `docs/usage-guide.md` must be fully self-contained: every one of the 9 sections gets full inline detail, even where a deep-dive doc already exists (per the approved spec, `docs/superpowers/specs/2026-07-25-usage-guide-nine-ways-design.md`).
- Every command, route, config key, and flag written into the guide must be verified against actual source, not against other docs.
- No CI-based or `CronCreate`-based automation. The git hook only reminds; it never edits or commits.
- Existing docs (`admin-manual.html`, `cli-guide.md`, `consuming-secrets-guide.md`, `api-developer-guide.md`) get concrete drift fixes only — no rewrite.
- Model tiers: Sonnet for research/drafting/fixing (needs real codebase comprehension), Opus for synthesis and adversarial verification (highest judgment), Haiku for mechanical extraction (`getting-started.md` generation).
- No agent in the generation Workflow commits to git — all commits happen in later tasks, reviewed by a human first.

---

### Task 1: Run the content-generation + maintenance-setup Workflow

**Files:**
- Produces (uncommitted, in working tree): `docs/usage-guide.md`, `docs/getting-started.md`, `docs/.usage-guide-map.json`, `.claude/skills/usage-guide-refresh/SKILL.md`, `scripts/hooks/post-commit`, `scripts/install-hooks.sh`
- May modify (only if drift found): `docs/admin-manual.html`, `docs/cli-guide.md`, `docs/consuming-secrets-guide.md`, `docs/api-developer-guide.md`, `README.md`

**Interfaces:**
- Produces: the six files above, all readable/parseable independently (valid Markdown, valid JSON manifest, valid bash for the hook/installer).
- No interfaces consumed — this is the first task.

- [ ] **Step 1: Invoke the Workflow tool with this exact script**

Call the `Workflow` tool with this `script` (this is the complete script — no placeholders):

```javascript
export const meta = {
  name: 'usage-guide-nine-ways',
  description: 'Build docs/usage-guide.md (9 ways to use RocketVault) + docs/getting-started.md + long-term maintenance tooling',
  phases: [
    { title: 'Audit' },
    { title: 'Research+Draft' },
    { title: 'Synthesis', model: 'opus' },
    { title: 'Verify', model: 'opus' },
    { title: 'Fix+Finalize' },
    { title: 'Maintenance setup' },
  ],
}

const CONSTRAINTS = `Hard constraints for this task:
- Only touch files under docs/, .claude/skills/, scripts/hooks/, scripts/install-hooks.sh, or README.md's Documentation section. Never edit cmd/, api/, internal/, config/, or any .go file.
- Never run "git commit", "git add", or any other git write operation. Only write files with the Write/Edit tools.
- Every technical claim (command, route, config key, flag) must be verified by actually reading the relevant source file in this repo, not assumed or copied from memory.`

const WAYS = [
  { key: 'cli', num: 1, title: 'CLI (human-driven)',
    hint: 'cmd/ package (Cobra framework). Global auth flags --username/--password/--totp-code, --output table|json|yaml. Look at cmd/root.go, cmd/secrets/, cmd/keys/, cmd/certificates/, cmd/users/.',
    deepDiveHint: 'docs/cli-guide.md likely covers this in depth — check it and link if genuinely relevant.' },
  { key: 'rest-api', num: 2, title: 'REST API (programmatic)',
    hint: 'api/ package. JWT bearer auth via POST /api/v1/users/login. Look at api/*.go route registration and docs/api-specification.yaml for the full route inventory.',
    deepDiveHint: 'docs/api-developer-guide.md likely covers this in depth — check it and link if genuinely relevant.' },
  { key: 'oauth2-service-accounts', num: 3, title: 'OAuth2 / Service Accounts (machine-to-machine)',
    hint: 'Client credentials grant. Look at the api handler(s) for POST /api/v1/oauth2/token and /api/v1/service-accounts routes, and internal/services/auth for token issuance logic.',
    deepDiveHint: 'No dedicated deep-dive doc currently exists for this — write it in full. Check docs/admin-manual.html in case it has a relevant section to link.' },
  { key: 'vault-client', num: 4, title: 'Vault Client library (embedded secret consumption)',
    hint: 'vault_client config block in .rocketvault.yaml (used by a *consuming* application, not the vault server). Look at examples/consumer-service and the vault client package it imports.',
    deepDiveHint: 'docs/consuming-secrets-guide.md likely covers this in depth — check it and link if genuinely relevant.' },
  { key: 'jwks', num: 5, title: 'JWKS endpoint (token verification by external services)',
    hint: 'GET /jwks.json (public, no auth). Look at jwt.key_source config (os_store/self_pki/external_pki) and the handler/service that serves the JWKS document.',
    deepDiveHint: 'No dedicated deep-dive doc currently exists for this — write it in full.' },
  { key: 'backup-restore', num: 6, title: 'Backup / restore tooling',
    hint: 'CLI backup create/restore commands, plus per-item backup endpoints (POST /api/v1/secrets/{id}/backup etc.). Look at cmd/ backup command(s) and the internal backup package.',
    deepDiveHint: 'No dedicated deep-dive doc currently exists for this — write it in full.' },
  { key: 'health-monitoring', num: 7, title: 'Health / monitoring integration',
    hint: '/api/v1/health, /api/v1/health/ready, /api/v1/health/live, /api/v1/health/database endpoints, plus the rocketvault_crypto_op_duration_seconds Prometheus histogram. Look at internal/health.',
    deepDiveHint: 'No dedicated deep-dive doc currently exists for this — write it in full.' },
  { key: 'hsm', num: 8, title: 'HSM-backed mode (PKCS#11)',
    hint: 'hsm.* config block (enabled, lib_path, token_label, pin). Look at internal/crypto for the PKCS#11 integration.',
    deepDiveHint: 'docs/hsm-softhsm2-testing.md covers SoftHSM2 setup in depth — check it and link.' },
  { key: 'deployment', num: 9, title: 'Deployment modes',
    hint: 'Standalone binary (go build / build.sh), Docker (Dockerfile, docker-compose.yml), SQLite (dev) vs PostgreSQL (prod) via database.type config. Look at Dockerfile, docker-compose.yml, config/ package.',
    deepDiveHint: 'No single dedicated deep-dive doc — README.md has partial coverage (Installation, Building, Deployment sections); check and link if useful.' },
]

const AUDIT_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' },
          issue: { type: 'string' },
          fix: { type: 'string' },
        },
        required: ['file', 'issue', 'fix'],
      },
    },
  },
  required: ['findings'],
}

const SECTION_SCHEMA = {
  type: 'object',
  properties: {
    key: { type: 'string' },
    num: { type: 'number' },
    title: { type: 'string' },
    markdown: { type: 'string' },
    sourceGlobs: { type: 'array', items: { type: 'string' } },
  },
  required: ['key', 'num', 'title', 'markdown', 'sourceGlobs'],
}

const SYNTHESIS_SCHEMA = {
  type: 'object',
  properties: {
    confirmation: { type: 'string' },
    sections: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          key: { type: 'string' },
          num: { type: 'number' },
          title: { type: 'string' },
          sourceGlobs: { type: 'array', items: { type: 'string' } },
        },
        required: ['key', 'num', 'title', 'sourceGlobs'],
      },
    },
  },
  required: ['confirmation', 'sections'],
}

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    corrections: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          section: { type: 'string' },
          wrong: { type: 'string' },
          correct: { type: 'string' },
        },
        required: ['section', 'wrong', 'correct'],
      },
    },
  },
  required: ['corrections'],
}

const SECTION_TEMPLATE = `## N. <Way Name>

**What it is:** 1-2 sentences.
**Use it when:** bullet list of concrete scenarios.
**Prerequisites:** config keys, binaries, tokens needed.

### Example
<working command(s) or code, copy-pasteable, verified against actual source>

### Notes & gotchas
<real constraints pulled from code — auth requirements, rate limits, known issues>

**Deep dive:** link to existing doc, if one exists (omit this line entirely if none is relevant).`

function researchDraftStage(way) {
  return agent(
    `${CONSTRAINTS}\n\nYou are writing ONE section of a comprehensive "how to use RocketVault" guide (repo root is your cwd). This is section ${way.num} of 9: "${way.title}".\n\nWhere to find ground truth in this repo: ${way.hint}\n\nDeep-dive doc hint: ${way.deepDiveHint}\n\nRead the actual source files, actual config keys in .rocketvault.yaml, and (if relevant) the hinted deep-dive doc. Write the section as Markdown following exactly this template (replace "N. <Way Name>" with "${way.num}. ${way.title}"):\n\n${SECTION_TEMPLATE}\n\nEvery command/route/flag/config key in your "Example" and "Notes & gotchas" must come from something you actually read in this repo's source, not from general Key Vault knowledge. Return via the required schema: markdown is the full section text, sourceGlobs is the list of file globs you actually read to verify this section's technical content (e.g. ["cmd/secrets/**", ".rocketvault.yaml"]).`,
    { phase: 'Research+Draft', schema: SECTION_SCHEMA, label: `draft:${way.key}` }
  )
}

phase('Audit')
log('Auditing existing docs for drift while drafting all 9 sections in parallel...')

const [auditResult, sectionDrafts] = await parallel([
  () => agent(
    `${CONSTRAINTS}\n\nAudit RocketVault's existing user-facing docs for drift against current source code (repo root is your cwd). Read: docs/admin-manual.html, docs/cli-guide.md, docs/consuming-secrets-guide.md, docs/api-developer-guide.md, README.md, and .claude/known-bugs.md. For each doc, spot-check claims (commands, routes, config keys, flags) against the actual current source (cmd/, api/, config/, .rocketvault.yaml). Only report CONCRETE, VERIFIED inaccuracies — not style nits, not missing-but-not-wrong content. For each finding, give the exact file, the exact issue, and the exact fix. If you find nothing wrong, return an empty findings list — do not manufacture findings to have something to report.`,
    { phase: 'Audit', schema: AUDIT_SCHEMA, label: 'audit-existing-docs' }
  ),
  () => pipeline(WAYS, researchDraftStage),
])

const validDrafts = sectionDrafts.filter(Boolean).sort((a, b) => a.num - b.num)
if (validDrafts.length !== WAYS.length) {
  log(`Warning: only ${validDrafts.length}/${WAYS.length} section drafts succeeded — proceeding with what we have.`)
}

const combinedDraftsText = validDrafts
  .map(s => `--- SECTION ${s.num} DRAFT (key: ${s.key}) ---\n${s.markdown}\n--- source globs verified: ${JSON.stringify(s.sourceGlobs)} ---`)
  .join('\n\n')

const auditText = auditResult && auditResult.findings.length
  ? auditResult.findings.map(f => `- ${f.file}: ${f.issue} -> fix: ${f.fix}`).join('\n')
  : '(no drift found)'

phase('Synthesis')
const synthesisReport = await agent(
  `${CONSTRAINTS}\n\nWrite docs/usage-guide.md for this repo (repo root is your cwd). It must be a single comprehensive guide: a short intro (what RocketVault is, that this guide covers all 9 ways to use it), a table of contents linking to 9 "## N. <Way Name>" sections in numeric order, then those 9 sections built from the drafts below. Merge them into one consistent voice and Markdown formatting, do not lose any example or gotcha from any draft, dedupe overlapping prose between sections, and add short one-line transitions between sections where it helps readability. If there are audit findings below, add a brief "Known gaps" callout near the intro summarizing them (do not fix the other docs here, that happens in a later step).\n\nAudit findings (context only):\n${auditText}\n\nDrafts (already verified against source by earlier agents — trust their technical content, only edit for consistency/voice/structure, do not re-verify facts yourself):\n${combinedDraftsText}\n\nUse the Write tool to create docs/usage-guide.md with this merged content. Then return the required schema: confirmation is a one-line summary of what you wrote, sections is the final list of the 9 sections with their key/num/title/sourceGlobs exactly as given in the drafts (do not change these values, just pass them through).`,
  { phase: 'Synthesis', model: 'opus', schema: SYNTHESIS_SCHEMA, label: 'synthesize-guide' }
)

phase('Verify')
const verifyReport = await agent(
  `${CONSTRAINTS}\n\nRead docs/usage-guide.md in this repo (just written). For every command, HTTP route, config key, CLI flag, and code reference in it, verify it actually exists in the current source (cmd/, api/, config/, .rocketvault.yaml, internal/). List every mismatch as a correction with: which section it's in, exactly what's wrong, and exactly what it should say instead. Also flag anything technically accurate but confusingly worded enough to mislead a reader. This is an adversarial pass against a doc written by other agents — assume it contains at least one subtle error and look hard before concluding otherwise. Only return an empty corrections list if you've checked every code block and route against source and found nothing wrong.`,
  { phase: 'Verify', model: 'opus', schema: VERIFY_SCHEMA, label: 'verify-guide' }
)

phase('Fix+Finalize')
const correctionsText = verifyReport.corrections.length
  ? verifyReport.corrections.map(c => `- [section: ${c.section}] wrong: "${c.wrong}" -> correct: "${c.correct}"`).join('\n')
  : '(none — guide passed verification with zero corrections)'

log(`Verification found ${verifyReport.corrections.length} correction(s) to apply.`)

const fixReport = verifyReport.corrections.length
  ? await agent(
      `${CONSTRAINTS}\n\nRead docs/usage-guide.md in this repo (already written). Apply exactly these corrections, each anchored to the section named, and nothing else:\n${correctionsText}\nUse the Edit tool for each correction. Do not make any other changes. Report which corrections you applied.`,
      { phase: 'Fix+Finalize', label: 'apply-guide-corrections' }
    )
  : 'No corrections needed — skipped.'

const [existingDocsFix, gettingStarted] = await parallel([
  () => agent(
    `${CONSTRAINTS}\n\nApply these concrete, pre-verified fixes to RocketVault's existing docs in this repo. Each fix names its target file and the exact issue/fix — apply only these specific fixes, do not rewrite surrounding content, do not add unrelated improvements:\n${auditText}\nIf the list says "(no drift found)", do nothing and report that no changes were needed.`,
    { phase: 'Fix+Finalize', label: 'fix-existing-docs' }
  ),
  () => agent(
    `${CONSTRAINTS}\n\nRead the finished docs/usage-guide.md in this repo. Write docs/getting-started.md: a short "pick your path" page for someone new to RocketVault. Include a short intro sentence, then a table with two columns — "If you want to..." and "Use this way" — mapping realistic user intents (e.g. "script vault administration from a terminal", "call RocketVault from my own backend service", "let another service authenticate without a human logging in", "have my Go app pull a secret at startup", "let a third party verify my JWTs", "back up my vault before an upgrade", "wire vault health into my monitoring stack", "use a hardware security module for key storage", "decide how to deploy RocketVault") to the correct one of the 9 ways, each row linking to that section's anchor in usage-guide.md (e.g. docs/usage-guide.md#3-oauth2--service-accounts — use the actual anchor text GitHub/markdown would generate from the real heading). Keep the whole file under 60 lines — this is a router, not a summary. Use the Write tool.`,
    { phase: 'Fix+Finalize', model: 'haiku', label: 'write-getting-started' }
  ),
])

const finalPass = await agent(
  `${CONSTRAINTS}\n\nDo a final consistency and readability pass across docs/usage-guide.md and docs/getting-started.md in this repo (both already written). Fix any heading-level inconsistencies, broken internal anchors/links between the two files, or awkward transitions — small edits only, not a rewrite. Then edit README.md: find its "Documentation" section (look for a "### Core Documentation" list), and add one new line at the top of that list linking to docs/getting-started.md as the entry point, e.g.: "- [Getting Started — Pick Your Path](docs/getting-started.md) - Which of the 9 ways to use RocketVault fits your use case". Use Read/Edit tools. Report a short summary of every change you made.`,
  { phase: 'Fix+Finalize', label: 'final-consistency-pass' }
)

phase('Maintenance setup')
const sectionsMeta = (synthesisReport.sections && synthesisReport.sections.length ? synthesisReport.sections : validDrafts)
  .map(s => ({ key: s.key, num: s.num, title: s.title, sourceGlobs: s.sourceGlobs }))

const sectionsMetaForManifest = sectionsMeta.map(s => ({
  key: s.key,
  num: s.num,
  title: s.title,
  globs: s.sourceGlobs,
  anchor: `docs/usage-guide.md#${s.num}-${s.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')}`,
}))
const allGlobsDeduped = Array.from(new Set(sectionsMetaForManifest.flatMap(s => s.globs)))

const maintenanceReport = await agent(
  `${CONSTRAINTS}\n\nSet up long-term maintenance tooling for the just-written docs/usage-guide.md in this repo (repo root is your cwd). Build exactly these three artifacts:\n\n1. docs/.usage-guide-map.json — run "git rev-parse HEAD" via Bash right now and use that real value, do not fabricate it, and run "date +%Y-%m-%d" via Bash for today's date. Write this exact JSON shape (the "sections" and "gettingStarted" arrays below are already fully computed for you — copy them verbatim, just fill in lastVerifiedCommit and lastVerifiedDate from the Bash commands above):\n{\n  "lastVerifiedCommit": "<real HEAD sha>",\n  "lastVerifiedDate": "<real YYYY-MM-DD>",\n  "sections": ${JSON.stringify(sectionsMetaForManifest)},\n  "gettingStarted": { "file": "docs/getting-started.md", "globs": ${JSON.stringify(allGlobsDeduped)} }\n}\n\n2. .claude/skills/usage-guide-refresh/SKILL.md — first read .claude/skills/migration-add/SKILL.md in this repo to copy its exact frontmatter conventions (name, description fields). Then write a project-scoped skill for refreshing docs/usage-guide.md, modeled on this behavior: (a) read docs/.usage-guide-map.json for lastVerifiedCommit and the section->globs table, (b) run "git diff --name-only <lastVerifiedCommit> HEAD" to get changed files, (c) match changed files against each section's globs (simple prefix/glob match) to find affected sections, (d) if none affected, report up to date and stop without touching the manifest, (e) if some affected, spawn one agent per affected section (Sonnet tier) that re-verifies that section's claims against current source and patches ONLY that section in docs/usage-guide.md, preserving every other section exactly, (f) regenerate docs/getting-started.md only if an affected section's title/anchor changed, (g) rewrite docs/.usage-guide-map.json with the new HEAD commit and today's date, (h) report which sections were refreshed (with the reason) and which were skipped as unaffected. The skill's description field must mention it's for refreshing docs/usage-guide.md and trigger on phrases like "refresh the usage guide".\n\n3. scripts/hooks/post-commit and scripts/install-hooks.sh:\n- scripts/hooks/post-commit: bash script (add #!/usr/bin/env bash shebang). It must: exit 0 silently if docs/.usage-guide-map.json does not exist (never block a commit on a missing manifest). Otherwise, read lastVerifiedCommit from the manifest (use jq if "command -v jq" succeeds, else fall back to grep/sed extraction of the "lastVerifiedCommit" value), run "git diff --name-only <lastVerifiedCommit> HEAD", and for each section in the manifest check whether any changed file matches any of that section's globs (simple case: glob ending in /** matches any path starting with the prefix before /**; a glob with no wildcard matches an exact path). If one or more sections match, echo exactly one line: "usage-guide.md may be stale (N section(s) affected: key1, key2, ...) - run the usage-guide-refresh skill" where N and the keys are the real matched sections. If none match, produce no output at all. Always exit 0 (a doc reminder must never block or fail a commit).\n- scripts/install-hooks.sh: bash script that runs "git config core.hooksPath scripts/hooks", then "chmod +x scripts/hooks/post-commit", then echoes a one-line confirmation that the hook is installed and what it does.\n\nUse the Write tool for all three artifacts (create directories with Bash mkdir -p as needed). Do not commit anything to git. Report the three file paths you created and confirm the manifest's lastVerifiedCommit is a real 40-character git SHA (not a placeholder).`,
  { phase: 'Maintenance setup', label: 'build-maintenance-tooling' }
)

return {
  audit: auditResult,
  sectionsWritten: validDrafts.map(s => ({ key: s.key, num: s.num, title: s.title })),
  synthesis: synthesisReport,
  verify: verifyReport,
  fix: fixReport,
  existingDocsFix,
  gettingStarted,
  finalPass,
  maintenance: maintenanceReport,
}
```

- [ ] **Step 2: Wait for the workflow to complete and read its return value**

The Workflow tool runs in the background and you'll get a task notification. Do not poll. When it completes, read the returned object (or `<transcriptDir>/journal.jsonl` if the return value seems incomplete) and confirm:
- `sectionsWritten` has 9 entries, numbered 1-9, no duplicates.
- `verify.corrections` — note the count; if non-empty, `fix` should confirm they were applied.
- `maintenance` report confirms all three artifacts were created with a real commit SHA.

- [ ] **Step 3: Verify the produced files structurally**

Run:
```bash
test -f docs/usage-guide.md && grep -c '^## [0-9]\. ' docs/usage-guide.md
test -f docs/getting-started.md && wc -l docs/getting-started.md
test -f docs/.usage-guide-map.json && python3 -m json.tool docs/.usage-guide-map.json > /dev/null && echo "manifest JSON valid"
test -f .claude/skills/usage-guide-refresh/SKILL.md
test -f scripts/hooks/post-commit && bash -n scripts/hooks/post-commit && echo "post-commit syntax OK"
test -f scripts/install-hooks.sh && bash -n scripts/install-hooks.sh && echo "install-hooks syntax OK"
```
Expected: the `grep -c` count is exactly `9`; the JSON tool prints the manifest with no error; both bash syntax checks print their OK line. If anything fails, do not proceed to Task 2 — re-run the specific failed agent's step manually (via the Agent tool) with a corrective prompt referencing the exact gap, then re-check.

- [ ] **Step 4: Spot-check the manifest's commit SHA is real**

```bash
python3 -c "import json; d=json.load(open('docs/.usage-guide-map.json')); print(d['lastVerifiedCommit'])"
git cat-file -e "$(python3 -c "import json; print(json.load(open('docs/.usage-guide-map.json'))['lastVerifiedCommit'])")" && echo "commit exists"
```
Expected: `commit exists` prints. If it errors, the maintenance agent fabricated a SHA — fix `docs/.usage-guide-map.json`'s `lastVerifiedCommit` by hand to the actual `git rev-parse HEAD` output before continuing.

---

### Task 2: Review and commit the generated documentation

**Files:**
- Modify (review, possibly hand-edit): `docs/usage-guide.md`, `docs/getting-started.md`, `docs/.usage-guide-map.json`, `README.md`, and any of `docs/admin-manual.html` / `docs/cli-guide.md` / `docs/consuming-secrets-guide.md` / `docs/api-developer-guide.md` that Task 1 touched.

**Interfaces:**
- Consumes: the files produced by Task 1, Step 1-4 (already verified structurally).
- Produces: a committed baseline that Task 3's hook and Task 4's skill test can diff against.

- [ ] **Step 1: Read the full diff**

```bash
git status
git diff -- docs/admin-manual.html docs/cli-guide.md docs/consuming-secrets-guide.md docs/api-developer-guide.md README.md
```
Read `docs/usage-guide.md` and `docs/getting-started.md` in full (they're new files, so `git diff` won't show a useful diff for them — use the Read tool). Confirm: all 9 sections read as genuinely useful and accurate (spot-check 2-3 example commands yourself against the actual source), `getting-started.md` links resolve to real anchors in `usage-guide.md`, and the existing-doc edits are narrowly scoped fixes, not rewrites.

- [ ] **Step 2: Fix anything that doesn't hold up**

If you find an inaccuracy the Verify phase missed, or a getting-started.md link that doesn't match an actual heading anchor, fix it directly with the Edit tool now — don't re-run the whole Workflow for a small fix.

- [ ] **Step 3: Stage and commit**

```bash
git add docs/usage-guide.md docs/getting-started.md docs/.usage-guide-map.json README.md \
        docs/admin-manual.html docs/cli-guide.md docs/consuming-secrets-guide.md docs/api-developer-guide.md
git status
```
Only `git add` the existing docs if Task 1 actually modified them (check `git status` first — don't add unchanged files).

```bash
git commit -m "$(cat <<'EOF'
docs: add usage guide covering all 9 ways to use RocketVault

Adds docs/usage-guide.md (CLI, REST API, OAuth2/service accounts, Vault
Client library, JWKS, backup/restore, health/monitoring, HSM mode,
deployment modes) and docs/getting-started.md as an entry-point router.
Fixes concrete drift found in existing docs during the audit pass.
EOF
)"
```

- [ ] **Step 4: Verify the commit**

```bash
git log -1 --stat
git rev-parse HEAD
```
Confirm the commit SHA is now different from (later than) the `lastVerifiedCommit` recorded in `docs/.usage-guide-map.json` — this is expected and correct (the manifest records the source-verification commit, not the doc-commit; the guide's *content* wasn't re-verified by adding it to git).

---

### Task 3: Install and functionally test the git post-commit hook

**Files:**
- Test: none (manual functional test via real commits in a scratch scenario)
- Modify: `scripts/hooks/post-commit` (only if Step 2 finds a bug)

**Interfaces:**
- Consumes: `docs/.usage-guide-map.json`'s `sections[].globs`, `scripts/hooks/post-commit`, `scripts/install-hooks.sh` (all from Task 1).
- Produces: an installed, working `core.hooksPath` pointing at `scripts/hooks`.

- [ ] **Step 1: Install the hook**

```bash
bash scripts/install-hooks.sh
git config --get core.hooksPath
```
Expected: prints `scripts/hooks`.

- [ ] **Step 2: Test the negative case (unrelated commit stays silent)**

```bash
echo "# scratch" >> /tmp/rocketvault-hook-test-unrelated.md
cp /tmp/rocketvault-hook-test-unrelated.md ./HOOK_TEST_UNRELATED.md
git add HOOK_TEST_UNRELATED.md
git commit -m "test: unrelated file for hook negative-case check" 2>&1 | tee /tmp/hook-test-negative.log
grep -q "may be stale" /tmp/hook-test-negative.log && echo "FAIL: hook fired on unrelated change" || echo "PASS: hook stayed silent"
git reset --hard HEAD~1
rm -f HOOK_TEST_UNRELATED.md /tmp/rocketvault-hook-test-unrelated.md /tmp/hook-test-negative.log
```
Expected: `PASS: hook stayed silent`. (The `git reset --hard HEAD~1` only removes the throwaway test commit just made — confirm `git log -1` shows Task 2's commit before running it.)

- [ ] **Step 3: Test the positive case (doc-relevant commit triggers the reminder)**

Pick one glob from `docs/.usage-guide-map.json` (e.g. a `cmd/**` entry) and make a real, content-level change to a file matching it — `touch` alone won't work, since git diffs content, not mtime:
```bash
echo "// hook-test no-op comment" >> cmd/root.go  # or another file matching a real section glob from the manifest — confirm which one first
git add cmd/root.go
git commit -m "test: hook positive-case check" 2>&1 | tee /tmp/hook-test-positive.log
grep -q "may be stale" /tmp/hook-test-positive.log && echo "PASS: hook fired" || echo "FAIL: hook stayed silent on relevant change"
git reset --hard HEAD~1
rm -f /tmp/hook-test-positive.log
```
Expected: `PASS: hook fired`, and the printed reminder names the correct section key (e.g. `cli`). If it fails, fix the glob-matching logic in `scripts/hooks/post-commit` (most likely bug: naive string matching not handling the `**` suffix correctly) and re-run Steps 2-3 until both pass. As in Step 2, confirm `git log -1` shows only this throwaway test commit before running `git reset --hard HEAD~1`.

- [ ] **Step 4: Commit the hook infrastructure (if not already committed in Task 2)**

```bash
git status
git add scripts/hooks/post-commit scripts/install-hooks.sh
```
If Task 1/2 already committed these (check `git status` — they'd show as unmodified), skip the commit. Otherwise:
```bash
git commit -m "$(cat <<'EOF'
chore: add post-commit hook reminding when usage-guide.md drifts

Pure-shell, no AI/API cost, no expiry. Silent unless a commit touches
a source path mapped to a usage-guide.md section in
docs/.usage-guide-map.json. Install via scripts/install-hooks.sh.
EOF
)"
```

---

### Task 4: Functionally test the usage-guide-refresh skill against a synthetic drift scenario

**Files:**
- Modify: `.claude/skills/usage-guide-refresh/SKILL.md` (only if Step 3 finds a bug in its instructions)
- Modify (test artifact, reverted after): `docs/.usage-guide-map.json`

**Interfaces:**
- Consumes: `.claude/skills/usage-guide-refresh/SKILL.md`, `docs/.usage-guide-map.json`, `docs/usage-guide.md` (all from Task 1/2).
- Produces: confidence the skill actually refreshes only affected sections before it's relied on months from now.

- [ ] **Step 1: Read the skill and pick a real drift target**

Read `.claude/skills/usage-guide-refresh/SKILL.md` and `docs/.usage-guide-map.json`. Pick one section (e.g. `backup-restore`) and note its recorded `globs`.

- [ ] **Step 2: Manufacture a synthetic "stale" manifest**

```bash
cp docs/.usage-guide-map.json /tmp/usage-guide-map.backup.json
git log --oneline -5
```
Edit `docs/.usage-guide-map.json`'s `lastVerifiedCommit` to an older commit SHA from the `git log` output above — one that predates the current HEAD by a few commits but is still an ancestor of HEAD (so the skill has a real, non-empty diff to react to).

- [ ] **Step 3: Invoke the skill and observe behavior**

Invoke the `usage-guide-refresh` skill (e.g. via the Skill tool with `skill: "usage-guide-refresh"`, or by asking "refresh the usage guide" per its trigger phrasing). Confirm:
- It correctly identifies the changed-files diff between the (now-older) `lastVerifiedCommit` and HEAD.
- It maps those to the right section(s) via glob matching — cross-check by hand that the sections it flags are the ones whose globs actually match the changed files.
- It only edits the flagged section(s) in `docs/usage-guide.md` (diff the file before/after — untouched sections must be byte-identical).
- It rewrites `docs/.usage-guide-map.json`'s `lastVerifiedCommit` back to current HEAD.

- [ ] **Step 4: Fix the skill if behavior didn't match, then restore state**

If any check in Step 3 failed, edit `.claude/skills/usage-guide-refresh/SKILL.md` to correct the described procedure and re-run Steps 2-3.

Once it passes:
```bash
git diff docs/usage-guide.md docs/.usage-guide-map.json
```
Decide whether the skill's actual refresh output (if it found real, valid improvements) should be kept, or whether to restore the pre-test manifest since this was a synthetic drill:
```bash
# If the refresh only proved the mechanism works and found nothing substantively new to say:
cp /tmp/usage-guide-map.backup.json docs/.usage-guide-map.json
git checkout -- docs/usage-guide.md
rm /tmp/usage-guide-map.backup.json
```
```bash
# If the refresh genuinely improved a section, keep both changes as-is instead of restoring.
```

- [ ] **Step 5: Commit skill fixes, if any**

```bash
git status
```
If `.claude/skills/usage-guide-refresh/SKILL.md` has uncommitted changes from Step 4's corrections:
```bash
git add .claude/skills/usage-guide-refresh/SKILL.md
git commit -m "fix: correct usage-guide-refresh skill behavior found during dry-run test"
```
If the dry-run left a genuine content improvement in `docs/usage-guide.md` / `docs/.usage-guide-map.json` (you chose not to restore in Step 4), commit that too, separately:
```bash
git add docs/usage-guide.md docs/.usage-guide-map.json
git commit -m "docs: apply usage-guide-refresh output from dry-run validation"
```

---

### Task 5: Final sanity pass

**Files:** none created; verification only.

**Interfaces:** none — this is the closing task confirming nothing else broke.

- [ ] **Step 1: Confirm the Go build and vet are untouched**

```bash
go build ./...
go vet ./...
```
Expected: both succeed with no output/errors — this change should be 100% docs/tooling, so a failure here means something outside the allowed file list got touched. If either fails, run `git diff --stat` against the base commit from before Task 1 and investigate any non-doc file in the list.

- [ ] **Step 2: Confirm README's Documentation section renders sensibly**

```bash
grep -A3 "Getting Started" README.md
```
Expected: the new entry-point line from Task 1's final-consistency-pass agent, positioned first in the Documentation list.

- [ ] **Step 3: Final review of full history for this feature**

```bash
git log --oneline -8
```
Confirm the commit sequence reads cleanly (docs guide → hook infra → skill fix, in that order or close to it) and nothing was force-pushed or squashed unexpectedly.

- [ ] **Step 4: Report completion**

Summarize for the user: files added/modified, agent/model counts actually used (compare to the ~17 estimated in the spec), verification corrections found and applied, and confirm the hook is installed locally (note: `core.hooksPath` is a local git config, not committed — other clones need to run `scripts/install-hooks.sh` themselves; this is a known one-time step already documented in Task 1's `final-consistency-pass` output/README edit — spot check it's actually mentioned there, and if not, add a one-line note to README's Contributing section yourself).
