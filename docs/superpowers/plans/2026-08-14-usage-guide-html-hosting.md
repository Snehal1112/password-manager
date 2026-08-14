# Usage Guide HTML Hosting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render `docs/usage-guide.md` into a styled `docs/usage-guide.html` via RocketVault's existing markdown→HTML docs pipeline, and host it alongside `docs/admin-manual.html` with working cross-links in both directions.

**Architecture:** `scripts/docsgen` (a standalone Go module, `github.com/yuin/goldmark`-based) already renders a `docsList` of markdown files into styled HTML pages sharing `docs/assets/doc-theme.css`/`.js` with `docs/admin-manual.html` — see `docs/api-developer-guide.html`, `docs/consuming-secrets-guide.html`, `docs/hsm-softhsm2-testing.html` for existing examples of the pattern. `docs/usage-guide.md` is simply missing from that list. This plan adds it, fixes three of `usage-guide.md`'s own internal links so they point at the `.html` siblings the pipeline already produces (instead of raw `.md`, which won't render usefully once hosted), and adds one link from `admin-manual.html`'s Quick Start section back to the new page, matching the file's established `<p class="see-also">` convention. No new code, no new templates, no design decisions — this is wiring an existing, working mechanism onto a file that was never added to it.

**Tech Stack:** Go (`scripts/docsgen`, `goldmark` markdown renderer), static HTML/CSS/JS (`docs/assets/doc-theme.{css,js}`).

**Spec:** No separate spec file — this plan is self-contained; see the Architecture section above and the file-structure findings inline in each task for the evidence that grounds it.

## Global Constraints

- Do not hand-write `docs/usage-guide.html` — it is a generated artifact. The only way to produce or update it is running `./scripts/docs.sh build` (a thin wrapper around `go run ./scripts/docsgen build`) from the repo root after editing `scripts/docsgen/docs.go` and/or `docs/usage-guide.md`.
- `docs/*.html` files are checked into git (not gitignored) — the regenerated `docs/usage-guide.html` must be committed alongside its source changes in the same task, not left untracked.
- Every `./scripts/docs.sh build` run regenerates **every** file in `docsList`, not just the one you changed. After each build in this plan, run `git status --short docs/` and confirm the diff is limited to what that task intended — an unexpected diff in an unrelated already-built `.html` file means something in `scripts/docsgen` changed in a way this plan didn't account for, and must be investigated before continuing, not committed blindly.
- Do not touch `docs/cli-guide.md`'s link in `usage-guide.md` §1 — `cli-guide.md` is not in `docsList` and has no `.html` sibling yet; changing that link to `.html` would point at a file that doesn't exist. Leave it as `.md`. (This is a known, separate gap — out of scope for this plan.)

---

### Task 1: Register `docs/usage-guide.md` in the docsgen pipeline and generate its HTML

**Files:**
- Modify: `scripts/docsgen/docs.go` (append one entry to the `docsList` slice, which currently ends at line 39-40 with the `v4.0.0-azure-rbac.md` entry)
- Generated (do not hand-edit): `docs/usage-guide.html`

**Interfaces:**
- Consumes: nothing new — uses the existing `docEntry{Src, Out string}` struct and `renderDoc`/`buildDocs` functions already in `scripts/docsgen/render.go`, unchanged.
- Produces: `docs/usage-guide.html` on disk, a real file later tasks read and edit.

- [ ] **Step 1: Add the docsList entry**

In `scripts/docsgen/docs.go`, the `docsList` slice currently ends:

```go
	{"docs/hsm-softhsm2-testing.md", "docs/hsm-softhsm2-testing.html"},
	{"docs/integration-examples.md", "docs/integration-examples.html"},
	{"docs/release-notes/v4.0.0-azure-rbac.md", "docs/release-notes/v4.0.0-azure-rbac.html"},
}
```

Change it to:

```go
	{"docs/hsm-softhsm2-testing.md", "docs/hsm-softhsm2-testing.html"},
	{"docs/integration-examples.md", "docs/integration-examples.html"},
	{"docs/release-notes/v4.0.0-azure-rbac.md", "docs/release-notes/v4.0.0-azure-rbac.html"},
	{"docs/usage-guide.md", "docs/usage-guide.html"},
}
```

- [ ] **Step 2: Build the docs site**

Run from the repo root:

```bash
./scripts/docs.sh build
```

Expected: a line `built docs/usage-guide.html` in the output, among the other `built ...` lines for every other `docsList` entry, and exit code 0.

- [ ] **Step 3: Confirm only the intended file is new/changed**

```bash
git status --short docs/
```

Expected: `docs/usage-guide.html` appears as a new untracked file (`??`). No other file under `docs/` should show as modified (`M`) — if one does, stop and investigate before proceeding; do not commit an unexplained diff in an unrelated generated file.

- [ ] **Step 4: Spot-check the generated file**

Open `docs/usage-guide.html` and verify, by reading the file directly (not guessing):

1. `<title>RocketVault Usage Guide — RocketVault Docs</title>` — the H1 text from `docs/usage-guide.md`'s first line (`# RocketVault Usage Guide`) was correctly extracted as the page title.
2. `<h1 class="doc-title">RocketVault Usage Guide</h1>` appears in the header.
3. The back-link in the header reads `<a class="doc-back" href="admin-manual.html">← Admin Manual</a>` — no `../` prefix, since `docs/usage-guide.html` and `docs/admin-manual.html` are siblings in the same directory (verify this is the actual computed relative path — `render.go`'s `renderDoc` computes it via `filepath.Rel`, so this should be automatic, but confirm the literal string in the file).
4. There is **no** `<nav class="doc-toc">` block — `docs/usage-guide.md` has its own `## Table of contents` heading (source line 17), and `render.go`'s `hasOwnTOC` detection (case-insensitive match on that exact heading text) should suppress the auto-generated TOC nav. If a `doc-toc` nav IS present in the output, the detection didn't fire — stop and report this as a finding rather than proceeding, since it means either the heading text doesn't match exactly or the detection logic needs a look.
5. At least one fenced code block (e.g. the CLI bootstrap example near the top) is wrapped in `<div class="codewrap"><div class="code-hd">...<button class="copy-btn">Copy</button></div><pre class="code with-hd">...` — confirming `wrapCodeBlocks` ran correctly.

- [ ] **Step 5: Commit**

```bash
git add scripts/docsgen/docs.go docs/usage-guide.html
git commit -m "docs: render docs/usage-guide.md into the HTML docs pipeline"
```

---

### Task 2: Point `usage-guide.md`'s own Deep-dive links at the `.html` siblings that already exist

**Files:**
- Modify: `docs/usage-guide.md` (four link-href edits, in the "Deep dive" line of sections 2, 3, 4, and 8)
- Regenerated: `docs/usage-guide.html`

**Interfaces:**
- Consumes: the `docs/usage-guide.html` produced by Task 1 — this task edits the markdown source and rebuilds, so if Task 1 isn't done first this task has nothing to rebuild against.
- Produces: nothing new for later tasks — this is the last content edit to `usage-guide.md` in this plan.

Three files already have real, working `.html` renders on disk from before this plan started (`docs/api-developer-guide.html`, `docs/consuming-secrets-guide.html`, `docs/hsm-softhsm2-testing.html` — all pre-existing `docsList` entries, unrelated to Task 1). `docs/usage-guide.md`'s own "Deep dive" lines still link to the raw `.md` versions of three of these, which is a broken/awkward link once `usage-guide.md` itself is hosted as HTML (a browser hitting a bare `.md` href either downloads it or shows raw text, not the styled page). Fix exactly these three link hrefs — do not touch anything else in the file, and do not touch the `docs/cli-guide.md` link in section 1 (see Global Constraints — no `.html` sibling exists for it).

- [ ] **Step 1: Fix section 2's Deep dive link**

In `docs/usage-guide.md`, find (in section `## 2. REST API (programmatic)`):

```markdown
**Deep dive:** [docs/api-developer-guide.md](api-developer-guide.md) — full endpoint reference, error format, and JavaScript/Python/Go SDK examples. Its one remaining discrepancy is its "Base URL" section, which shows a placeholder `https://api.rocketvault.local` domain rather than the real default `http://localhost:8774`.
```

Change only the link href (not the link text, not the rest of the sentence):

```markdown
**Deep dive:** [docs/api-developer-guide.md](api-developer-guide.html) — full endpoint reference, error format, and JavaScript/Python/Go SDK examples. Its one remaining discrepancy is its "Base URL" section, which shows a placeholder `https://api.rocketvault.local` domain rather than the real default `http://localhost:8774`.
```

- [ ] **Step 2: Fix section 3's Deep dive link**

In `docs/usage-guide.md`, find (in section `## 3. OAuth2 / Service Accounts (machine-to-machine)`):

```markdown
**Deep dive:** [docs/consuming-secrets-guide.md](consuming-secrets-guide.md) and [Admin Manual — OAuth2 Service Accounts](admin-manual.html#service-accounts).
```

Change to:

```markdown
**Deep dive:** [docs/consuming-secrets-guide.md](consuming-secrets-guide.html) and [Admin Manual — OAuth2 Service Accounts](admin-manual.html#service-accounts).
```

(The second link, to `admin-manual.html#service-accounts`, is already correct — leave it untouched.)

- [ ] **Step 3: Fix section 4's Deep dive link**

In `docs/usage-guide.md`, find (in section `## 4. Vault Client library (embedded secret consumption)`):

```markdown
**Deep dive:** [docs/consuming-secrets-guide.md](consuming-secrets-guide.md) — see "Option A — Go application using the `vaultclient` package", plus the full service-account creation and access-policy walkthrough and the Troubleshooting table.
```

Change to:

```markdown
**Deep dive:** [docs/consuming-secrets-guide.md](consuming-secrets-guide.html) — see "Option A — Go application using the `vaultclient` package", plus the full service-account creation and access-policy walkthrough and the Troubleshooting table.
```

- [ ] **Step 4: Fix section 8's Deep dive link**

In `docs/usage-guide.md`, find (in section `## 8. HSM-backed mode (PKCS#11)`):

```markdown
**Deep dive:** [docs/hsm-softhsm2-testing.md](hsm-softhsm2-testing.md) — full SoftHSM2 install and init walkthrough, verifying token contents with `pkcs11-tool`, and running the PKCS#11 integration test suite.
```

Change to:

```markdown
**Deep dive:** [docs/hsm-softhsm2-testing.md](hsm-softhsm2-testing.html) — full SoftHSM2 install and init walkthrough, verifying token contents with `pkcs11-tool`, and running the PKCS#11 integration test suite.
```

- [ ] **Step 5: Confirm section 1's link is untouched**

```bash
grep -n "cli-guide" docs/usage-guide.md
```

Expected: exactly one match, `**Deep dive:** [docs/cli-guide.md](cli-guide.md) — full walkthrough...` — still pointing at `cli-guide.md`, not `.html`. If this line was accidentally changed, revert it.

- [ ] **Step 6: Rebuild**

```bash
./scripts/docs.sh build
```

Expected: `built docs/usage-guide.html` in the output (and every other file rebuilt identically to before — see Global Constraints).

- [ ] **Step 7: Verify the four link hrefs landed correctly in the rebuilt HTML**

```bash
grep -o 'href="[a-z0-9-]*\.\(md\|html\)"' docs/usage-guide.html | sort -u
```

Expected output includes `href="api-developer-guide.html"`, `href="consuming-secrets-guide.html"` (appearing twice — sections 3 and 4 — `sort -u` will fold them to one line), `href="hsm-softhsm2-testing.html"`, and `href="cli-guide.md"`. There should be **no** `href="api-developer-guide.md"`, `href="consuming-secrets-guide.md"`, or `href="hsm-softhsm2-testing.md"` in the list.

- [ ] **Step 8: Confirm no other file drifted**

```bash
git status --short docs/
```

Expected: only `docs/usage-guide.md` (modified) and `docs/usage-guide.html` (modified) show up.

- [ ] **Step 9: Commit**

```bash
git add docs/usage-guide.md docs/usage-guide.html
git commit -m "docs(usage-guide): link to the .html siblings that already exist, not raw .md"
```

---

### Task 3: Link the Usage Guide from the Admin Manual's Quick Start section

**Files:**
- Modify: `docs/admin-manual.html` (one new line inside `<section id="quick-start">`)

**Interfaces:**
- Consumes: `docs/usage-guide.html` from Task 1 — the link added here points at it, so this task must run after Task 1.
- Produces: nothing later tasks depend on.

`docs/admin-manual.html` never mentions `usage-guide` anywhere today (confirmed by `grep -n "usage-guide" docs/admin-manual.html` returning nothing before this plan). Every other cross-doc reference in this file uses the exact pattern `<p class="see-also">See also: <a href="TARGET.html">LABEL</a></p>`, e.g. line 1133 (`<a href="consuming-secrets-guide.html">Consuming Secrets Guide</a>`) and line 1665 (`<a href="hsm-softhsm2-testing.html">SoftHSM2 Testing Guide</a>`). `docs/usage-guide.md` itself calls itself "the single entry point for all nine ways to use RocketVault" — it's a peer overview doc, not a deep-dive off one narrow admin-manual topic, so it belongs at the top of the reading path: the Quick Start section (`<section id="quick-start">`, starting at line 415), right after the "End-to-end walkthrough" steps and before the section closes.

- [ ] **Step 1: Find the exact insertion point**

In `docs/admin-manual.html`, `<section id="quick-start">` ends with a "What's next" callout block, exactly:

```html
  <div class="callout callout-accent" style="margin-top:24px">
    <div class="callout-label">What's next</div>
    <p><strong style="color:var(--text)">New admins:</strong> Configure users → <a href="#users">User Management</a>, set up vault RBAC → <a href="#vault-rbac">Vault RBAC &amp; Role Assignments</a>, enable audit logging → <a href="#audit">Audit &amp; Compliance</a>.<br>
    <strong style="color:var(--text)">Developers:</strong> Multiple secrets → <a href="#consuming">Consuming Secrets</a>, rotate credentials → <a href="#secret-rotation">Secret Rotation</a>, CI/CD → <a href="#cicd">CI/CD</a>.</p>
  </div>
</section>
```

If a `grep -n "What's next" docs/admin-manual.html` match doesn't land in this exact block, the file has changed since this plan was written — re-read the `id="quick-start"` section fresh and find its actual closing `</div>\n</section>` pair before proceeding, rather than guessing.

- [ ] **Step 2: Add the see-also line**

Insert a new line between the callout's closing `</div>` and the section's closing `</section>`, so the block becomes:

```html
  <div class="callout callout-accent" style="margin-top:24px">
    <div class="callout-label">What's next</div>
    <p><strong style="color:var(--text)">New admins:</strong> Configure users → <a href="#users">User Management</a>, set up vault RBAC → <a href="#vault-rbac">Vault RBAC &amp; Role Assignments</a>, enable audit logging → <a href="#audit">Audit &amp; Compliance</a>.<br>
    <strong style="color:var(--text)">Developers:</strong> Multiple secrets → <a href="#consuming">Consuming Secrets</a>, rotate credentials → <a href="#secret-rotation">Secret Rotation</a>, CI/CD → <a href="#cicd">CI/CD</a>.</p>
  </div>
  <p class="see-also">See also: <a href="usage-guide.html">Usage Guide — all nine ways to use RocketVault</a></p>
</section>
```

(Only the one new `<p class="see-also">` line is added; everything else in the snippet is unchanged context, shown so the edit anchors unambiguously.)

- [ ] **Step 3: Verify the file is still well-formed**

```bash
python3 -c "
import re
content = open('docs/admin-manual.html').read()
print('div opens:', len(re.findall(r'<div', content)), 'div closes:', len(re.findall(r'</div>', content)))
print('section opens:', len(re.findall(r'<section', content)), 'section closes:', len(re.findall(r'</section>', content)))
"
```

Expected: div open/close counts equal each other, and section open/close counts equal each other (both counts should be unchanged from before this edit, since a `<p>` tag was added, not a `<div>` or `<section>`).

- [ ] **Step 4: Confirm the link text and target**

```bash
grep -n "usage-guide" docs/admin-manual.html
```

Expected: exactly one match, the line added in Step 2.

- [ ] **Step 5: Commit**

```bash
git add docs/admin-manual.html
git commit -m "docs(admin-manual): link the Usage Guide from Quick Start"
```

---

### Task 4: Final full docs build and verification

**Files:** none modified — this task is verification-only. If it finds drift, that drift must be reported, not silently fixed by editing generated files by hand.

**Interfaces:**
- Consumes: the state left by Tasks 1-3 — this is the final gate confirming they compose correctly.
- Produces: a go/no-go signal for the whole plan. Nothing later depends on this task's outputs beyond "the docs site builds cleanly and both new links resolve."

- [ ] **Step 1: Clean full rebuild**

```bash
./scripts/docs.sh build
```

Expected: every `docsList` entry (11 files as of this plan, including the new `docs/usage-guide.md` entry from Task 1) prints a `built ...` line, exit code 0.

- [ ] **Step 2: Confirm zero uncommitted drift**

```bash
git status --short docs/
```

Expected: empty output. Every file the build touched should already be committed from Tasks 1-3. If anything shows as modified here, the build is not idempotent against what was committed — stop and investigate rather than committing blindly (this would mean a build run between commits produced different bytes than what got committed, which should not happen for a deterministic renderer).

- [ ] **Step 3: Serve the docs site locally and confirm both new links resolve**

```bash
./scripts/docs.sh serve docs 8000 &
SERVER_PID=$!
sleep 1
curl -s -o /dev/null -w "usage-guide.html: %{http_code}\n" http://localhost:8000/usage-guide.html
curl -s -o /dev/null -w "admin-manual.html: %{http_code}\n" http://localhost:8000/admin-manual.html
curl -s http://localhost:8000/admin-manual.html | grep -q 'href="usage-guide.html"' && echo "admin-manual -> usage-guide link: OK" || echo "admin-manual -> usage-guide link: MISSING"
curl -s http://localhost:8000/usage-guide.html | grep -q 'href="admin-manual.html"' && echo "usage-guide -> admin-manual back-link: OK" || echo "usage-guide -> admin-manual back-link: MISSING"
kill $SERVER_PID
```

Expected: both `http_code` lines read `200`, and both link-presence checks report `OK`.

- [ ] **Step 4: Report**

No commit needed for this task (verification-only, nothing changed). Report the plan complete.
