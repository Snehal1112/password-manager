# Document OIDC in the Admin Manual — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `docs/admin-manual.html` has zero mentions of OIDC anywhere — the `/oidc/login`/`/oidc/callback` endpoints, the `oidc:` config block, and the SSO-logout caveat (RocketVault session revocation doesn't end the IdP session) are all completely undocumented. This plan adds a full "OIDC / SSO Login" section matching the file's existing conventions exactly, plus the small cross-references (config table row, sidebar nav link, endpoint-index mention) that make it discoverable.

**Architecture:** One new `<section id="oidc-login">` inserted between the existing `#authentication` and `#jwt-signing` sections (both content- and topic-adjacent — it's an alternative login path), following the exact same internal structure `#authentication` already uses: "What it is" / "When to use it" prose, a `.flow` diagram, `.ep` endpoint blocks with tabbed cURL/Response panes, and a `.callout` for the one behavior an admin most needs to know before relying on this (the logout caveat). Three small, mechanical cross-reference edits (config table row, sidebar nav link, endpoint-index subsystem list) make the new section actually reachable and consistent with the rest of the doc. All example values in the new section are generic/placeholder (`idp.example.com`, `rocketvault` client, etc.) — matching this file's own convention for config examples (see the `#hsm` section's `/usr/lib/softhsm/...` example) — not this operator's specific test infrastructure, since this is a public-facing reference doc for any deployment.

**Tech Stack:** Static HTML/CSS (no build step for this file — it's hand-authored, distinct from the `scripts/docsgen`-rendered markdown docs). The file's existing `.tab-btn`/`.tab-pane` JS wiring (`docs/admin-manual.html`'s inline `<script>`, querying generically by class within each `.ep` container) auto-wires any new `.ep` block with no JS changes needed — confirmed by reading the script during planning.

## Global Constraints

- This is a hand-authored HTML file with no linter/build step — "done" means the new markup visually matches the surrounding sections' structure and CSS class usage exactly (`.flow`, `.ep`, `.tab-bar`/`.tab-pane`, `.callout callout-info`/`.callout callout-warn`, `.see-also`), not a compiler passing.
- Every new class name used must already exist in the file's `<style>` block (verified during planning: `flow`, `flow-title`, `flow-nodes`, `flow-node`, `flow-node hl`, `flow-arrow`, `flow-caption`, `ep`, `ep-hd`, `meth meth-get`, `ep-path`, `ep-auth`, `ep-label`, `tab-bar`, `tab-btn`, `tab-btn active`, `tab-pane`, `tab-pane active`, `callout callout-info`, `callout callout-warn`, `callout-label`, `see-also`, `collapse` — do not invent a new CSS class not already in the file's `<style>` block).
- All three tasks touch only `docs/admin-manual.html`, at four distinct, non-overlapping locations. Re-verify each task's exact anchor text against the live file immediately before editing — this is a shared repo with a concurrent session sometimes active.
- Do not touch `docs/usage-guide.md` or any `scripts/docsgen`-rendered file — this plan is scoped to the hand-authored admin manual only.

---

### Task 1: Add the `oidc` row to the Configuration Reference table

**Files:**
- Modify: `docs/admin-manual.html` (the `#configuration` section's table, currently around line 688-704)

**Interfaces:**
- Consumes: nothing new — documents the existing `oidc:` config block (`enabled`, `issuer_url`, `client_id`, `client_secret`, `redirect_url`, `scopes`, `ca_cert_path`) already read by `internal/container/service_container.go`.
- Produces: nothing consumed by later tasks — independent of Tasks 2-3, no ordering dependency.

- [ ] **Step 1: Verify the current table matches this plan's anchor**

Run: `grep -n '<tr><td><code>oauth2</code>' docs/admin-manual.html`

Expected: one match, immediately followed (next table row) by the `hsm` row. If the surrounding rows differ from what's shown below, stop and report the mismatch rather than guessing a new insertion point.

- [ ] **Step 2: Insert the new row**

In `docs/admin-manual.html`, find:

```html
      <tr><td><code>oauth2</code></td><td><code>token_expiry</code>, <code>issuer</code></td></tr>
      <tr><td><code>hsm</code></td><td><code>enabled</code>, <code>lib_path</code>, <code>token_label</code>, <code>pin</code>, <code>slot_id</code></td></tr>
```

Replace with:

```html
      <tr><td><code>oauth2</code></td><td><code>token_expiry</code>, <code>issuer</code></td></tr>
      <tr><td><code>oidc</code></td><td><code>enabled</code>, <code>issuer_url</code>, <code>client_id</code>, <code>client_secret</code>, <code>redirect_url</code>, <code>scopes</code>, <code>ca_cert_path</code></td></tr>
      <tr><td><code>hsm</code></td><td><code>enabled</code>, <code>lib_path</code>, <code>token_label</code>, <code>pin</code>, <code>slot_id</code></td></tr>
```

- [ ] **Step 3: Verify the insertion**

Run: `grep -n '<code>oidc</code>' docs/admin-manual.html`

Expected: one match, between the `oauth2` and `hsm` rows.

- [ ] **Step 4: Commit**

```bash
git add docs/admin-manual.html
git commit -m "docs(admin-manual): add oidc row to the Configuration Reference table"
```

---

### Task 2: Add the "OIDC / SSO Login" section

**Files:**
- Modify: `docs/admin-manual.html` (insert a new `<section id="oidc-login">` between the closing `</section>` of `#authentication` and the opening `<section id="jwt-signing">`, currently around line 786-788)

**Interfaces:**
- Consumes: nothing new — documents `api/oidc.go`'s `GET /oidc/login`/`GET /oidc/callback` handlers and `internal/services/auth/oidc_service.go`'s behavior (both already implemented and covered by this session's earlier manual-testing work).
- Produces: the new `id="oidc-login"` anchor — consumed by Task 3's sidebar nav link (`href="#oidc-login"`). Task 3 should run after this task so its link target exists, though this is a soft/display-only dependency, not a build-breaking one.

- [ ] **Step 1: Verify the current boundary matches this plan's anchor**

Run: `grep -n 'Manual Testing §5\|section id="jwt-signing"' docs/admin-manual.html`

Expected: two matches close together — the `see-also` line inside `#authentication`'s closing content, then `#jwt-signing`'s opening tag a few lines later. If anything else sits between them already, stop and report rather than guessing.

- [ ] **Step 2: Insert the new section**

In `docs/admin-manual.html`, find:

```html
  <p class="see-also">See also: <a href="../MANUAL_TESTING.html">Manual Testing §5</a></p>
</section>

<section id="jwt-signing">
```

Replace with:

```html
  <p class="see-also">See also: <a href="../MANUAL_TESTING.html">Manual Testing §5</a></p>
</section>

<section id="oidc-login">
  <h2>OIDC / SSO Login</h2>
  <h3>What it is</h3>
  <p>An additional login path via any standards-compliant OpenID Connect provider (Okta, Keycloak, Entra ID, etc.) — an external identity provider authenticates the principal, then RocketVault issues the exact same JWT/refresh-token pair local login does. Local username/password/TOTP login (see <a href="#authentication">Authentication</a>) is completely unaffected and stays available.</p>
  <h3>When to use it</h3>
  <ul>
    <li>Centralize authentication behind an existing corporate identity provider instead of maintaining a separate username/password/TOTP per person in RocketVault.</li>
    <li>Users with an active SSO session already open in their browser get an instant login with no prompt at all.</li>
  </ul>
  <h3>Configuration</h3>
  <pre class="code">oidc:
  enabled: true
  issuer_url: "https://idp.example.com"
  client_id: "rocketvault"
  client_secret: "&lt;from your IdP's client registration&gt;"
  redirect_url: "https://vault.example.com/api/v1/oidc/callback"
  scopes: ["openid", "profile", "email"]
  # Optional: trust a private/internal CA for the issuer's TLS certificate,
  # instead of the SSL_CERT_FILE environment variable.
  ca_cert_path: "/etc/rocketvault/idp-ca.pem"</pre>
  <div class="callout callout-info">
    <div class="callout-label">Disabled by default</div>
    <p><code>oidc.enabled</code> defaults to <code>false</code>. When unset, <code>GET /oidc/login</code> and <code>GET /oidc/callback</code> return <code>503</code> and the server never attempts a network call to the issuer at startup.</p>
  </div>
  <div class="flow">
    <div class="flow-title">OIDC login flow</div>
    <div class="flow-nodes">
      <div class="flow-node hl">GET /oidc/login</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">302 to IdP</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">user authenticates</div>
    </div>
    <div class="flow-nodes" style="margin-top:8px">
      <div class="flow-node">IdP redirects back</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node hl">GET /oidc/callback</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">token exchange + verify</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">JWT + refresh_token</div>
    </div>
    <div class="flow-caption">State and nonce are stored in short-lived, HttpOnly, Secure cookies and re-verified on callback — a mismatched or missing state is rejected before any call is made to the IdP's token endpoint.</div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/oidc/login</span> <span class="ep-label">Start the OIDC flow</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -sv $BASE/api/v1/oidc/login</pre></div>
    <div class="tab-pane"><pre class="code">HTTP/1.1 302 Found
Location: https://idp.example.com/authorize?client_id=rocketvault&amp;response_type=code&amp;...
Set-Cookie: oidc_state=...; HttpOnly; Secure; SameSite=Lax
Set-Cookie: oidc_nonce=...; HttpOnly; Secure; SameSite=Lax</pre></div>
    <details class="collapse"><summary>Errors</summary><div class="inner">503 if <code>oidc.enabled</code> is false</div></details>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/oidc/callback</span> <span class="ep-label">Complete the flow, issue a session</span></div>
    <div class="tab-bar"><button class="tab-btn active">Response</button></div>
    <div class="tab-pane active"><pre class="code">{
  "token": "&lt;redacted-jwt&gt;",
  "refresh_token": "&lt;redacted-jwt&gt;",
  "user_id": "219b78ec-089f-4c71-838d-d223910ba258",
  "username": "jdoe@example.com",
  "role": "user"
}</pre></div>
    <details class="collapse"><summary>Errors</summary><div class="inner">400 missing/mismatched state or nonce · 401 code exchange or ID-token verification failed · 503 if <code>oidc.enabled</code> is false</div></details>
  </div>

  <h3>First login vs. repeat login</h3>
  <ul>
    <li>The first login for a given IdP subject creates a new user with the least-privilege <code>role: user</code> and zero vault access — an admin must grant a vault role separately, same as any other user (see <a href="#vault-rbac">Vault RBAC</a>).</li>
    <li>Every later login for that same subject reuses the existing user row — it does not create a duplicate, and it does not reset a role an admin has since changed.</li>
    <li>If the ID token is missing <code>name</code>/<code>email</code>/<code>preferred_username</code> (common with some providers), RocketVault falls back to the provider's userinfo endpoint, then to the IdP's raw subject claim if that's empty too.</li>
  </ul>

  <div class="callout callout-warn">
    <div class="callout-label">Logging out does not end the IdP session</div>
    <p>Revoking a RocketVault session (<code>DELETE /users/sessions/{id}</code> or <code>DELETE /users/sessions</code> — see <a href="#authentication">Authentication</a>) only revokes RocketVault's own session. RocketVault does not call the IdP's <code>end_session_endpoint</code> (no RP-initiated logout is implemented), so a user with an active SSO session in their browser can hit <code>GET /oidc/login</code> again immediately afterward and be silently re-authenticated with no prompt. A full logout requires separately ending the session at the identity provider.</p>
  </div>

  <p class="see-also">See also: <a href="#authentication">Authentication</a> (session revocation), <a href="#vault-rbac">Vault RBAC</a> (granting access to a new OIDC user)</p>
</section>

<section id="jwt-signing">
```

- [ ] **Step 3: Verify the insertion**

Run: `grep -n 'section id="oidc-login"\|section id="jwt-signing"\|section id="authentication"' docs/admin-manual.html`

Expected: three matches in order — `authentication`'s opening tag (much earlier in the file), then `oidc-login`'s opening tag, then `jwt-signing`'s opening tag — confirming correct placement between the two.

Run: `grep -c '<section id=' docs/admin-manual.html`

Expected: one more than the pre-edit count (35 → 36) — confirms exactly one new section was added, not zero or two.

- [ ] **Step 4: Commit**

```bash
git add docs/admin-manual.html
git commit -m "docs(admin-manual): add OIDC / SSO Login section"
```

---

### Task 3: Wire up navigation — sidebar link and endpoint-index mention

**Files:**
- Modify: `docs/admin-manual.html` (the sidebar `<nav>` around line 373, and the `#appendix-endpoints` subsystems list around line 1828-1831 — exact line numbers will have shifted after Task 2's insertion; use the anchor text, not line numbers)

**Interfaces:**
- Consumes: `id="oidc-login"` (Task 2) — the sidebar link's `href="#oidc-login"` only makes sense once that section exists. Run this task after Task 2.
- Produces: nothing consumed elsewhere — last task in this plan.

- [ ] **Step 1: Verify both anchors match this plan's assumptions**

Run: `grep -n 'href="#authentication"\|href="#jwt-signing"' docs/admin-manual.html`

Expected: the sidebar's `#authentication` link immediately followed (next `sb-item` line) by the sidebar's `#jwt-signing` link.

Run: `grep -n 'oauth2/token, jwks' docs/admin-manual.html`

Expected: one match, inside the `#appendix-endpoints` subsystems paragraph.

- [ ] **Step 2: Add the sidebar nav link**

In `docs/admin-manual.html`, find:

```html
    <a class="sb-item" href="#authentication">Authentication</a>
    <a class="sb-item" href="#jwt-signing">JWT Signing</a>
```

Replace with:

```html
    <a class="sb-item" href="#authentication">Authentication</a>
    <a class="sb-item" href="#oidc-login">OIDC / SSO Login</a>
    <a class="sb-item" href="#jwt-signing">JWT Signing</a>
```

- [ ] **Step 3: Add the endpoint-index subsystem mention**

In `docs/admin-manual.html`, find:

```html
  <p>Subsystems: vaults (+ role-assignments), secrets (+ versions, generate, export/import, item backup), users
    (+ sessions), keys (+ wrap/unwrap, sign/verify, encrypt/decrypt, rotate, versions),
    certificates (+ policy), deleted (restore/purge), access-policies, service-accounts,
    audit (logs, SOC2/GDPR, config), oauth2/token, jwks (+ rotate), config, health.</p>
```

Replace with:

```html
  <p>Subsystems: vaults (+ role-assignments), secrets (+ versions, generate, export/import, item backup), users
    (+ sessions), oidc (login, callback), keys (+ wrap/unwrap, sign/verify, encrypt/decrypt, rotate, versions),
    certificates (+ policy), deleted (restore/purge), access-policies, service-accounts,
    audit (logs, SOC2/GDPR, config), oauth2/token, jwks (+ rotate), config, health.</p>
```

- [ ] **Step 4: Verify both insertions**

Run: `grep -n 'href="#oidc-login"' docs/admin-manual.html`

Expected: two matches — the sidebar link and Task 2's `<section id="oidc-login">` (the id itself also matches the `href="#..."` grep pattern's prefix loosely; if this is confusing, instead run `grep -n 'oidc-login"' docs/admin-manual.html` and expect exactly two hits: `<a class="sb-item" href="#oidc-login">` and `<section id="oidc-login">`).

Run: `grep -n 'oidc (login, callback)' docs/admin-manual.html`

Expected: one match, inside the appendix-endpoints subsystems list.

- [ ] **Step 5: Commit**

```bash
git add docs/admin-manual.html
git commit -m "docs(admin-manual): link the new OIDC section from the sidebar nav and endpoint index"
```

---

## Self-Review Notes (from plan authoring)

- **Spec coverage:** the user asked to document "OIDC configuration and how to use it... with example" — Task 1 covers configuration (table row), Task 2 covers usage with a full worked example (config block, flow diagram, both endpoints with request/response examples, first-login-vs-repeat-login behavior, and the logout caveat this whole effort was originally motivated by), Task 3 makes it discoverable. Nothing in the ask is left uncovered.
- **Placeholder scan:** no TBD/TODO; every HTML block is complete and copy-pasteable. Example values are deliberately generic placeholders (`idp.example.com`, `rocketvault` client, `jdoe@example.com`), matching this file's own established convention for config examples elsewhere (e.g. `#hsm`'s `/usr/lib/softhsm/...` example) — not a placeholder in the "TBD" sense.
- **Type/name consistency:** `id="oidc-login"` used identically in Task 2 (section definition) and Task 3 (sidebar href, verified via grep in Task 3's Step 1/4). CSS classes used in Task 2 (`flow`, `ep`, `callout callout-info`, `callout callout-warn`, etc.) were individually confirmed to already exist in the file's `<style>` block during planning, not invented.
- **Verified against source, not assumed:** the `.tab-btn`/`.tab-pane` JS auto-wiring (confirmed via `docs/admin-manual.html`'s inline script, which queries generically within each `.ep` container — no per-instance JS needed for Task 2's two new `.ep` blocks), the exact current table/section/nav boundaries (all read live during planning, not recalled from an earlier session), and the section-count baseline for Task 2's Step 3 verification (35 `<section id=` matches before this plan's edits).
