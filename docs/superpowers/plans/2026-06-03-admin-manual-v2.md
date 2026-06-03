# RocketVault Administrator Manual v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework `docs/admin-manual.html` into a deeper, interactive, production-grade manual — per-endpoint cards with live-captured request/response examples, client-side search, copy-on-code, tabbed CLI/API/Response, and collapsibles — superseding `MANUAL_TESTING.md`.

**Architecture:** Single static HTML file, same design system as today. A data-capture step first produces `docs/.manual-capture.json` (real responses from a local server, secrets redacted), which later section tasks copy example JSON from. Then the interactive scaffold (search, tab/copy/back-to-top JS) is added, then production framing + a Quick Start, then sections are deepened part-by-part, then MANUAL_TESTING.md is reduced to a pointer, then a full browser verification.

**Tech Stack:** HTML5, CSS3 (custom properties), vanilla JS (IntersectionObserver, `<details>`, `navigator.clipboard`), `marked@15` (already vendored via CDN for the doc viewer). Capture uses the built Go binary, `oathtool`, `jq`, `curl`. No build pipeline.

**Spec:** `docs/superpowers/specs/2026-06-03-admin-manual-v2-design.md`

---

## Proven facts (verified live during planning — rely on these)

- **Admin bootstrap is CLI-only.** `POST /api/v1/users/admin` returns `api.not_found`. Use:
  `rocketvault users admin --config <cfg> --admin-username admin --admin-password admin123 --bootstrap-token <tok>`.
  Its stdout contains `TOTP Secret: otpauth://...&secret=<BASE32>`.
- **Login response keys:** `refresh_token, role, token, user_id, username`.
- **Secret create response keys:** `created_at, enabled, id, name, tags, version` — **`value` is NOT returned on create** (only on GET). `version` starts at 1.
- **Key create response keys:** `bits, created_at, enabled, id, name, revoked, tags, type, user_id` (RSA also has public `n`/`e` on GET; private material never returned).
- **Vault create response keys:** `created_at, created_by, enabled, id, name, purge_protection, retention_days`.
- Bootstrap token (dev): `***SECRET-REMOVED-2026-08-17***`.
- `oathtool`, `jq`, `curl` are installed.

---

## File Structure

- `docs/admin-manual.html` — the deliverable (reworked in place).
- `docs/.manual-capture.json` — captured real responses, redacted. Committed as a reference
  artifact so examples are reproducible and reviewable. (Leading dot keeps it visually grouped
  as supporting data.)
- `scripts/capture-manual-examples.sh` — the capture harness (committed; rerunnable).
- `MANUAL_TESTING.md` — reduced to a pointer in the final task.

No automated HTML test framework exists. **Verification per task:**
1. Structural: a Python check (sidebar links ↔ section ids, no dups) + `node --check` on inline JS.
2. Behavioral (scaffold/section tasks): serve over http and drive a headless browser to confirm
   search/tabs/copy/collapsibles work and there are no console errors.

Commit after each task.

---

## Task 1: Capture harness and live response data

**Files:**
- Create: `scripts/capture-manual-examples.sh`
- Create (generated): `docs/.manual-capture.json`

- [ ] **Step 1: Write the capture script**

Create `scripts/capture-manual-examples.sh`:

```bash
#!/usr/bin/env bash
# Capture real RocketVault API responses for the admin manual, with secrets redacted.
# Produces docs/.manual-capture.json. Rerunnable; uses a throwaway DB.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFG=/tmp/rv-capture.yaml
DB=/tmp/rv-capture.db
BIN=/tmp/rocketvault-capture
TOK="***SECRET-REMOVED-2026-08-17***"
B=http://localhost:8774

cp "$ROOT/.rocketvault.yaml" "$CFG"
sed -i "s#./dev-rocketvault.db#$DB#" "$CFG"
rm -f "$DB"
( cd "$ROOT" && go build -o "$BIN" . )

# Bootstrap admin (CLI-only) and extract the TOTP base32 secret.
SECRET=$("$BIN" users admin --config "$CFG" --admin-username admin \
  --admin-password admin123 --bootstrap-token "$TOK" 2>/dev/null \
  | grep -oE 'secret=[A-Z2-7]+' | head -1 | cut -d= -f2)

# Start the server on the throwaway DB.
"$BIN" serve --config "$CFG" >/tmp/rv-capture-server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for i in $(seq 1 20); do curl -sf "$B/api/v1/health/live" >/dev/null && break; sleep 0.5; done

CODE=$(oathtool --totp --base32 "$SECRET")
LOGIN=$(curl -s -X POST "$B/api/v1/users/login" -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$CODE\"}")
TOKEN=$(echo "$LOGIN" | jq -r .token)
A="Authorization: Bearer $TOKEN"

post(){ curl -s -X POST "$B$1" -H "$A" -H "Content-Type: application/json" -d "$2"; }
get(){ curl -s "$B$1" -H "$A"; }

# Exercise endpoints; collect into one object keyed by a stable label.
SECRET_OBJ=$(post /api/v1/secrets '{"name":"db-password","value":"s3cret","tags":["database"]}')
SID=$(echo "$SECRET_OBJ" | jq -r .id)
KEY_OBJ=$(post /api/v1/keys '{"name":"my-rsa-key","type":"RSA","bits":2048}')
VAULT_OBJ=$(post /api/v1/vaults '{"name":"team-alpha"}')
SA_OBJ=$(post /api/v1/service-accounts '{"name":"ci-pipeline","description":"CI"}')
HEALTH_OBJ=$(get /api/v1/health)
JWKS_OBJ=$(curl -s "$B/jwks.json")

# Assemble, then redact sensitive fields to placeholders.
jq -n \
  --argjson login "$LOGIN" \
  --argjson secret "$SECRET_OBJ" \
  --argjson secret_get "$(get /api/v1/secrets/$SID)" \
  --argjson key "$KEY_OBJ" \
  --argjson vault "$VAULT_OBJ" \
  --argjson sa "$SA_OBJ" \
  --argjson health "$HEALTH_OBJ" \
  --argjson jwks "$JWKS_OBJ" \
  '{login:$login, secret_create:$secret, secret_get:$secret_get, key_create:$key,
    vault_create:$vault, service_account:$sa, health:$health, jwks:$jwks}' \
| jq '
   (.login.token, .login.refresh_token) |= "<redacted-jwt>"
 | (.service_account.client_secret) |= "<shown-once-redacted>"
 | (.secret_get.value) |= "<decrypted-value>"
 | (.key.n) |= (if . then "<base64url-modulus>" else . end)
 | (.jwks.keys[]?.n) |= "<base64url-modulus>"
' > "$ROOT/docs/.manual-capture.json"

echo "Wrote docs/.manual-capture.json"
```

- [ ] **Step 2: Make it executable and run it**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
chmod +x scripts/capture-manual-examples.sh
bash scripts/capture-manual-examples.sh
```
Expected: prints `Wrote docs/.manual-capture.json` and exits 0.

- [ ] **Step 3: Verify the capture is real and redacted**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
jq 'keys' docs/.manual-capture.json
jq '.login.token, .service_account.client_secret, .secret_get.value' docs/.manual-capture.json
jq '.secret_create | keys' docs/.manual-capture.json
```
Expected: top-level keys include `login, secret_create, secret_get, key_create, vault_create,
service_account, health, jwks`; the three sensitive fields print `"<redacted-jwt>"`,
`"<shown-once-redacted>"`, `"<decrypted-value>"`; `secret_create` keys are
`created_at, enabled, id, name, tags, version`.

- [ ] **Step 4: Confirm no real secrets leaked**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
grep -iE '"(token|refresh_token|client_secret)": *"eyJ|"value": *"s3cret"' docs/.manual-capture.json && echo "LEAK" || echo "clean"
```
Expected: `clean`.

- [ ] **Step 5: Commit**

```bash
git add scripts/capture-manual-examples.sh docs/.manual-capture.json
git commit -S -m "docs(manual): capture harness and live API response data"
```

---

## Task 2: Interactive scaffold — search, tabs, copy, back-to-top, card CSS

**Files:**
- Modify: `docs/admin-manual.html`

This task adds the CSS and JS infrastructure the section rework needs. It does not yet convert
section content — existing sections keep working. Insert CSS before the `/* Markdown doc viewer */`
comment, and JS before the closing `</script>`.

- [ ] **Step 1: Add CSS for search, endpoint cards, tabs, copy, back-to-top**

In `docs/admin-manual.html`, immediately BEFORE the line `/* Markdown doc viewer (slides in when a .md link is clicked) */`, insert:

```css
/* Search box */
.sb-search{width:100%;padding:7px 10px;margin-bottom:14px;border:1px solid var(--border-strong);
  border-radius:var(--r-sm);font-size:13px;font-family:var(--font-sans);background:var(--surface)}
.sb-link.hidden,.sb-group.hidden{display:none}
.search-empty{font-size:12px;color:var(--text-muted);padding:6px 10px}

/* Endpoint cards */
.ep{border:1px solid var(--border);border-radius:var(--r-md);margin:12px 0;overflow:hidden}
.ep-hd{display:flex;align-items:center;gap:8px;padding:9px 12px;background:var(--surface-alt);
  border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:12.5px;flex-wrap:wrap}
.meth{font-family:var(--font-mono);font-size:11px;font-weight:600;color:#fff;padding:1px 7px;border-radius:4px}
.meth-get{background:#16A34A}.meth-post{background:#2563A8}.meth-put{background:#B97D0D}
.meth-patch{background:#6B5ED4}.meth-delete{background:#C2460C}
.ep-auth{font-size:10.5px;font-family:var(--font-mono);padding:1px 8px;border-radius:999px;
  background:var(--green-bg);border:1px solid var(--green-bd);color:#065F46}
.ep-label{color:var(--text-muted)}
.tabs{display:flex;gap:0;padding:0 8px;border-bottom:1px solid var(--border);background:var(--surface)}
.tab{padding:6px 13px;font-size:12px;cursor:pointer;border:none;background:none;
  border-bottom:2px solid transparent;color:var(--text-secondary);font-family:var(--font-sans)}
.tab.active{border-bottom-color:var(--accent);color:var(--accent);font-weight:600}
.tabpane{display:none}.tabpane.active{display:block}

/* Copy button on code blocks */
.codewrap{position:relative}
.copy-btn{position:absolute;top:6px;right:6px;font-size:10.5px;font-family:var(--font-sans);
  border:1px solid var(--border-strong);border-radius:5px;padding:2px 8px;background:var(--surface);
  color:var(--text-secondary);cursor:pointer;opacity:0;transition:opacity .15s}
.codewrap:hover .copy-btn,.copy-btn:focus{opacity:1}
.copy-btn.done{color:var(--green-bd);border-color:var(--green-bd)}

/* Collapsibles */
details.collapse{border:1px solid var(--border);border-radius:var(--r-sm);margin:8px 0}
details.collapse>summary{cursor:pointer;padding:8px 12px;font-size:12.5px;font-weight:600;
  background:var(--surface-alt);list-style:none}
details.collapse>summary::-webkit-details-marker{display:none}
details.collapse>summary::before{content:"▸ ";color:var(--text-muted)}
details.collapse[open]>summary::before{content:"▾ "}
details.collapse .inner{padding:2px 12px 10px}

/* Back to top */
#to-top{position:fixed;bottom:22px;right:22px;z-index:30;display:none;border:1px solid var(--border-strong);
  background:var(--surface);border-radius:50%;width:40px;height:40px;font-size:16px;cursor:pointer;
  box-shadow:0 2px 10px rgba(0,0,0,.12)}
#to-top.show{display:block}

```

- [ ] **Step 2: Add the search box to the sidebar and the back-to-top button**

In `docs/admin-manual.html`, find:

```html
    <div class="sb-sub">Self-hosted secrets manager · Go</div>
```

Insert immediately after it:

```html
    <input class="sb-search" id="sb-search" type="search" placeholder="Search…  (press /)" aria-label="Search the manual"/>
```

Then find `<div class="layout">` and immediately BEFORE it insert:

```html
<button id="to-top" aria-label="Back to top" title="Back to top">↑</button>
```

- [ ] **Step 3: Add the scaffold JS (search, tabs, copy, back-to-top)**

In `docs/admin-manual.html`, immediately BEFORE the closing `</script>` of the main inline
script (the line right before `</body>` region — it is the script that ends with the doc-viewer
click handler), insert:

```javascript

// --- Sidebar search: filter links and groups by text. ---
const search = document.getElementById('sb-search');
if(search){
  const allLinks = [...document.querySelectorAll('.sb-link')];
  const groups = [...document.querySelectorAll('.sb-group')];
  search.addEventListener('input', () => {
    const q = search.value.trim().toLowerCase();
    allLinks.forEach(l => l.classList.toggle('hidden', q && !l.textContent.toLowerCase().includes(q)));
    // Hide a group header if all links until the next header are hidden.
    groups.forEach(g => {
      let n = g.nextElementSibling, anyVisible = false;
      while(n && !n.classList.contains('sb-group')){
        if(n.classList.contains('sb-link') && !n.classList.contains('hidden')) anyVisible = true;
        n = n.nextElementSibling;
      }
      g.classList.toggle('hidden', q && !anyVisible);
    });
  });
  // "/" focuses search (unless already typing in a field).
  document.addEventListener('keydown', e => {
    if(e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA'){
      e.preventDefault(); search.focus();
    }
  });
}

// --- Tab switchers inside endpoint cards. ---
document.querySelectorAll('.tabs').forEach(tabbar => {
  const tabs = [...tabbar.querySelectorAll('.tab')];
  const panes = [...tabbar.parentElement.querySelectorAll('.tabpane')];
  tabs.forEach((tab, i) => tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    panes.forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    if(panes[i]) panes[i].classList.add('active');
  }));
});

// --- Copy-to-clipboard on every code block. ---
document.querySelectorAll('pre.code').forEach(pre => {
  const wrap = document.createElement('div');
  wrap.className = 'codewrap';
  pre.parentNode.insertBefore(wrap, pre);
  wrap.appendChild(pre);
  const btn = document.createElement('button');
  btn.className = 'copy-btn'; btn.type = 'button'; btn.textContent = 'Copy';
  btn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(pre.textContent); btn.textContent = 'Copied'; btn.classList.add('done'); }
    catch { btn.textContent = 'Select & copy'; }
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1500);
  });
  wrap.appendChild(btn);
});

// --- Back to top. ---
const toTop = document.getElementById('to-top');
if(toTop){
  window.addEventListener('scroll', () => toTop.classList.toggle('show', window.scrollY > 600));
  toTop.addEventListener('click', () => window.scrollTo({top:0, behavior:'smooth'}));
}
```

- [ ] **Step 4: Verify structure and JS validity**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
python3 - <<'PY'
import re
html=open('docs/admin-manual.html').read()
links=re.findall(r'class="sb-link" href="#([^"]+)"',html)
ids=re.findall(r'<section id="([^"]+)"',html)
print("links",len(links),"sections",len(ids),"mismatch",set(links)^set(ids) or "NONE")
scripts=re.findall(r'<script>(.*?)</script>', html, re.S)
open('/tmp/m.js','w').write(scripts[-1])
PY
node --check /tmp/m.js && echo JS_OK; rm -f /tmp/m.js
```
Expected: `links 31 sections 31 mismatch NONE` and `JS_OK`.

- [ ] **Step 5: Behavioral check in a browser**

Run a local server, then drive a headless browser (the project has Playwright MCP available to
the controller; if running this task manually, open the URL and check by hand):
```bash
cd /home/numericlabs/data/rocket/rocketvault
python3 -m http.server 8099 >/tmp/h.log 2>&1 & echo $! >/tmp/h.pid; sleep 1
```
Confirm at `http://localhost:8099/docs/admin-manual.html`: typing "keys" in the search box hides
non-matching sidebar links; a code block shows a "Copy" button on hover that copies; no console
errors. Then:
```bash
kill $(cat /tmp/h.pid); rm -f /tmp/h.pid /tmp/h.log
```

- [ ] **Step 6: Commit**

```bash
git add docs/admin-manual.html
git commit -S -m "docs(manual): add interactive scaffold (search, tabs, copy, back-to-top)"
```

---

## Task 3: Production framing — header metadata, prerequisites, Quick Start

**Files:**
- Modify: `docs/admin-manual.html`

- [ ] **Step 1: Add version + last-updated metadata to the header**

In `docs/admin-manual.html`, find:

```html
    <h1>RocketVault Administrator Manual</h1>
    <p class="lede">The authoritative operational guide to every RocketVault feature —
      installation, identity, secrets, keys, certificates, governance, and integration.</p>
```

Replace with:

```html
    <h1>RocketVault Administrator Manual</h1>
    <p class="lede">The authoritative operational guide to every RocketVault feature —
      installation, identity, secrets, keys, certificates, governance, and integration.</p>
    <p style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-muted);margin-top:-30px;margin-bottom:36px">
      RocketVault · self-hosted Azure Key Vault alternative · Go · API <code>/api/v1</code> ·
      Last updated 2026-06-03</p>
```

- [ ] **Step 2: Add "Before you begin" and "Quick Start" sidebar links**

In the sidebar, find:

```html
    <div class="sb-group">Getting Started</div>
    <a class="sb-link" href="#introduction">1. Introduction &amp; Model</a>
```

Replace with:

```html
    <div class="sb-group">Getting Started</div>
    <a class="sb-link" href="#before-you-begin">0. Before You Begin</a>
    <a class="sb-link" href="#quick-start">Quick Start (end-to-end)</a>
    <a class="sb-link" href="#introduction">1. Introduction &amp; Model</a>
```

- [ ] **Step 3: Add the two new sections at the top of the content**

In `docs/admin-manual.html`, find `<section id="introduction">` and insert immediately BEFORE it:

```html
<section id="before-you-begin">
  <h2>0. Before You Begin</h2>
  <h3>Prerequisites</h3>
  <ul>
    <li>Go 1.24+ to build and run the server (<code>go run main.go serve</code>).</li>
    <li><code>curl</code> and <code>jq</code> for the API examples; <code>oathtool</code> to mint TOTP codes without a phone.</li>
    <li>A populated <code>.rocketvault.yaml</code> (the only config the server reads). Key settings: <code>server.listen_addr</code> (default <code>:8774</code>), <code>security.bootstrap_token</code> equivalents, <code>jwt.*</code>.</li>
    <li>The server running and an admin bootstrapped (see Quick Start).</li>
  </ul>
  <h3>Conventions in this manual</h3>
  <ul>
    <li><code>$BASE</code> is <code>http://localhost:8774</code>; <code>$TOKEN</code> is an admin JWT from login.</li>
    <li>Example responses are <strong>captured from a live server</strong>; secret values, key material, and tokens are shown as <code>&lt;redacted&gt;</code> placeholders.</li>
    <li>Each operation shows three tabs — <strong>cURL</strong>, <strong>CLI</strong>, and a real <strong>Response</strong>.</li>
  </ul>
</section>

<section id="quick-start">
  <h2>Quick Start — End to End</h2>
  <p>This walkthrough goes from a fresh server to an application reading a secret. Every command
    is copy-pasteable; responses are real (redacted).</p>
  <h3>1. Start the server</h3>
  <pre class="code">go run main.go serve
export BASE=http://localhost:8774
curl -s $BASE/api/v1/health/live      # {"status":"OK"}</pre>
  <h3>2. Bootstrap the first admin (CLI only)</h3>
  <pre class="code">go run main.go users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token &lt;your-bootstrap-token&gt;
# stdout includes:  TOTP Secret: otpauth://...&amp;secret=&lt;BASE32&gt;</pre>
  <div class="note">Register the <code>otpauth://</code> URL in an authenticator app, or mint codes
    with <code>oathtool --totp --base32 &lt;BASE32&gt;</code>. Every login needs a TOTP code.</div>
  <h3>3. Log in</h3>
  <pre class="code">TOKEN=$(curl -s -X POST $BASE/api/v1/users/login -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"'"$(oathtool --totp --base32 &lt;BASE32&gt;)"'"}' \
  | jq -r .token)</pre>
  <h3>4. Store a secret</h3>
  <pre class="code">curl -s -X POST $BASE/api/v1/secrets -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"DB_PASSWORD","value":"s3cret"}' | jq .id   # save this UUID</pre>
  <h3>5. Create a service account and grant it read access</h3>
  <pre class="code">SA=$(curl -s -X POST $BASE/api/v1/service-accounts -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"my-app"}')                 # client_secret shown ONCE
SECRET=$(echo "$SA" | jq -r .client_secret); SA_ID=$(echo "$SA" | jq -r .id)
curl -s -X POST $BASE/api/v1/access-policies -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"app-read","principal_id":"'"$SA_ID"'","resource_type":"secret","resource_id":"&lt;secret-uuid&gt;","actions":["read"]}'</pre>
  <h3>6. Consume the secret as the application</h3>
  <pre class="code">APP_TOKEN=$(curl -s -X POST $BASE/api/v1/oauth2/token \
  -u "my-app:$SECRET" -d "grant_type=client_credentials" | jq -r .access_token)
curl -s $BASE/api/v1/secrets/&lt;secret-uuid&gt; -H "Authorization: Bearer $APP_TOKEN" | jq .value</pre>
  <p class="see-also">Each step is detailed in its own section below.</p>
</section>
```

- [ ] **Step 4: Verify structure**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
python3 - <<'PY'
import re
html=open('docs/admin-manual.html').read()
links=re.findall(r'class="sb-link" href="#([^"]+)"',html)
ids=re.findall(r'<section id="([^"]+)"',html)
print("links",len(links),"sections",len(ids),"mismatch",set(links)^set(ids) or "NONE")
PY
```
Expected: `links 33 sections 33 mismatch NONE` (added `before-you-begin` and `quick-start`).

- [ ] **Step 5: Commit**

```bash
git add docs/admin-manual.html
git commit -S -m "docs(manual): add prerequisites, version metadata, and Quick Start walkthrough"
```

---

## Task 4: Deepen Identity sections (Authentication, Users, Service Accounts) into endpoint cards

**Files:**
- Modify: `docs/admin-manual.html`
- Read: `docs/.manual-capture.json` (for the Response tab JSON)

This task converts three sections to the endpoint-card + tabs pattern, using captured responses.
It establishes the exact card markup the remaining section tasks reuse. Replace each existing
`<section id="...">…</section>` block wholesale.

- [ ] **Step 1: Replace the Authentication section**

Find the entire `<section id="authentication">…</section>` block and replace it with:

```html
<section id="authentication">
  <h2>5. Authentication</h2>
  <p>Login requires username + password + a TOTP code and returns a short-lived JWT plus a
    refresh token. Sessions are tracked and individually revocable.</p>
  <h3>When to use it</h3>
  <p>Every human caller authenticates here. Machine callers use service accounts (§9) instead.</p>
  <h3>Operations</h3>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> /api/v1/users/login <span class="ep-label">Authenticate, get a JWT</span></div>
    <div class="tabs"><button class="tab active">cURL</button><button class="tab">CLI</button><button class="tab">Response</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X POST $BASE/api/v1/users/login -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"123456"}'</pre></div>
    <div class="tabpane"><pre class="code">rocketvault users login \
  --username admin --password admin123 --totp-code 123456</pre></div>
    <div class="tabpane"><pre class="code">{
  "token": "&lt;redacted-jwt&gt;",
  "refresh_token": "&lt;redacted-jwt&gt;",
  "user_id": "f99945c6-ded6-4d6d-96be-7a10a1fbe6fe",
  "username": "admin",
  "role": "admin"
}</pre></div>
    <details class="collapse"><summary>Errors</summary><div class="inner">401 bad credentials or TOTP · 429 rate-limited (5/min)</div></details>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> /api/v1/users/refresh <span class="ep-label">Exchange a refresh token</span></div>
    <div class="tabs"><button class="tab active">cURL</button><button class="tab">Response</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X POST $BASE/api/v1/users/refresh -H "Content-Type: application/json" \
  -d '{"refresh_token":"&lt;rt&gt;"}'</pre></div>
    <div class="tabpane"><pre class="code">{ "token": "&lt;redacted-jwt&gt;", "refresh_token": "&lt;redacted-jwt&gt;" }</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> /api/v1/users/sessions <span class="ep-auth">JWT</span> <span class="ep-label">List active sessions</span></div>
    <div class="tabs"><button class="tab active">cURL</button></div>
    <div class="tabpane active"><pre class="code">curl -s $BASE/api/v1/users/sessions -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> /api/v1/users/sessions/{id} <span class="ep-auth">JWT</span> <span class="ep-label">Revoke one (or all with no id)</span></div>
    <div class="tabs"><button class="tab active">cURL</button></div>
    <div class="tabpane active"><pre class="code"># one session
curl -s -X DELETE $BASE/api/v1/users/sessions/&lt;id&gt; -H "Authorization: Bearer $TOKEN"
# all sessions for the caller
curl -s -X DELETE $BASE/api/v1/users/sessions -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <div class="note">Auth endpoints are rate-limited (default 5 req/min) — see §21.</div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §5</a></p>
</section>
```

- [ ] **Step 2: Replace the User Management section**

Find the entire `<section id="users">…</section>` block and replace it with:

```html
<section id="users">
  <h2>7. User Management</h2>
  <p>Admins create, list, update, and delete users. Each user has a role (<code>admin</code>,
    <code>user</code>, or a scoped manager role) and a TOTP secret issued at creation.</p>
  <h3>When to use it</h3>
  <p>Onboard human operators. For automation, prefer a service account (§9).</p>
  <h3>Operations</h3>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> /api/v1/users <span class="ep-auth">JWT · admin</span> <span class="ep-label">Create a user</span></div>
    <div class="tabs"><button class="tab active">cURL</button><button class="tab">CLI</button><button class="tab">Response</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X POST $BASE/api/v1/users -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"alice","password":"alicepassword123","role":"user"}'</pre></div>
    <div class="tabpane"><pre class="code">rocketvault users create --username alice --role user \
  --username admin --password admin123 --totp-code 123456</pre></div>
    <div class="tabpane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "username": "alice",
  "role": "user",
  "totp_secret": "&lt;base32-secret&gt;"
}</pre></div>
    <details class="collapse"><summary>Errors</summary><div class="inner">400 invalid role (one of secrets_manager, crypto_manager, certificate_manager, admin, user) · 401/403 non-admin caller</div></details>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> /api/v1/users <span class="ep-auth">JWT · admin</span> <span class="ep-label">List users</span></div>
    <div class="tabs"><button class="tab active">cURL</button></div>
    <div class="tabpane active"><pre class="code">curl -s $BASE/api/v1/users -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-put">PUT</span> /api/v1/users/{id} <span class="ep-auth">JWT · admin</span> <span class="ep-label">Update a user</span></div>
    <div class="tabs"><button class="tab active">cURL</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X PUT $BASE/api/v1/users/&lt;id&gt; -H "Authorization: Bearer $TOKEN" \
  -d '{"role":"admin"}'</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> /api/v1/users/{id} <span class="ep-auth">JWT · admin</span> <span class="ep-label">Delete a user</span></div>
    <div class="tabs"><button class="tab active">cURL</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/users/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §7</a></p>
</section>
```

- [ ] **Step 3: Replace the Service Accounts section**

Find the entire `<section id="service-accounts">…</section>` block and replace it with:

```html
<section id="service-accounts">
  <h2>9. OAuth2 Service Accounts</h2>
  <p>A service account is a machine identity (Azure KV service-principal equivalent) that
    authenticates via the OAuth2 client-credentials flow — no TOTP. Service accounts are
    <strong>read-only consumers</strong>: they retrieve secrets/keys/certs an admin granted them.</p>
  <h3>When to use it</h3>
  <p>CI/CD pipelines, apps fetching config at runtime, service-to-service secrets, scheduled jobs.</p>
  <h3>Operations</h3>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> /api/v1/service-accounts <span class="ep-auth">JWT · admin</span> <span class="ep-label">Create (secret shown once)</span></div>
    <div class="tabs"><button class="tab active">cURL</button><button class="tab">Response</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X POST $BASE/api/v1/service-accounts -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"ci-pipeline","description":"CI/CD"}'</pre></div>
    <div class="tabpane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "ci-pipeline",
  "client_secret": "&lt;shown-once-redacted&gt;"
}</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> /api/v1/oauth2/token <span class="ep-auth">Basic</span> <span class="ep-label">Client-credentials token</span></div>
    <div class="tabs"><button class="tab active">cURL</button><button class="tab">Response</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X POST $BASE/api/v1/oauth2/token \
  -u "ci-pipeline:$SECRET" -d "grant_type=client_credentials"</pre></div>
    <div class="tabpane"><pre class="code">{ "access_token": "&lt;redacted-jwt&gt;", "token_type": "Bearer", "expires_in": 3600 }</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> /api/v1/service-accounts/{id}/rotate <span class="ep-auth">JWT · admin</span> <span class="ep-label">Rotate the secret</span></div>
    <div class="tabs"><button class="tab active">cURL</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X POST $BASE/api/v1/service-accounts/&lt;id&gt;/rotate -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> /api/v1/service-accounts/{id} <span class="ep-auth">JWT · admin</span> <span class="ep-label">Delete (invalidates tokens)</span></div>
    <div class="tabs"><button class="tab active">cURL</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/service-accounts/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <div class="note">The <code>client_id</code> is the service-account <strong>name</strong>, not its
    UUID. Delete or rotate immediately invalidates live tokens.</div>
  <p class="see-also">See also: <a href="consuming-secrets-guide.md">Consuming Secrets Guide</a>, <a href="../MANUAL_TESTING.md">Manual Testing §14</a></p>
</section>
```

- [ ] **Step 4: Verify structure + tabs/copy work**

Run the structure check (expect `links 33 sections 33 mismatch NONE`) and `node --check` as in
Task 2 Step 4. Then serve over http and confirm in a browser: the Authentication card's
Response tab shows the JSON; switching tabs works; copy buttons appear. No console errors.

- [ ] **Step 5: Commit**

```bash
git add docs/admin-manual.html
git commit -S -m "docs(manual): deepen identity sections into endpoint cards with live responses"
```

---

## Task 5: Deepen Core Resource sections (Secrets, Versions, Keys, Certificates, Vaults, Soft-Delete)

**Files:**
- Modify: `docs/admin-manual.html`
- Read: `docs/.manual-capture.json`

Convert each listed section to the endpoint-card pattern established in Task 4 (same markup:
`.ep` / `.ep-hd` / `.meth-*` / `.ep-auth` / `.tabs` + `.tab` / `.tabpane` / `details.collapse`).
Use captured JSON for Response tabs.

- [ ] **Step 1: Replace the Secrets section (id="secrets")**

Replace the whole `<section id="secrets">…</section>` with a version that has endpoint cards for:
POST /secrets (Response: `{"id":"<uuid>","name":"db-password","tags":["database"],"version":1,"enabled":true,"created_at":"2026-06-03T07:44:46Z"}` — note value NOT returned on create),
GET /secrets/{id} (Response includes `"value":"<decrypted-value>"`),
PUT /secrets/{id}, DELETE /secrets/{id}, POST /secrets/generate, POST /secrets/export, POST /secrets/import.
Each card: method badge, path, `JWT` auth pill, cURL tab (+ Response tab where captured), and a
Notes collapsible. Keep the existing "What it is" / "When to use" prose. Footer see-also to
Manual Testing §8.

Use exactly this card skeleton for each endpoint (fill method/path/body/response):

```html
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> /api/v1/secrets <span class="ep-auth">JWT</span> <span class="ep-label">Create a secret</span></div>
    <div class="tabs"><button class="tab active">cURL</button><button class="tab">Response</button></div>
    <div class="tabpane active"><pre class="code">curl -s -X POST $BASE/api/v1/secrets -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"db-password","value":"s3cret","tags":["database"]}'</pre></div>
    <div class="tabpane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "db-password",
  "tags": ["database"],
  "version": 1,
  "enabled": true,
  "created_at": "2026-06-03T07:44:46Z"
}</pre></div>
    <details class="collapse"><summary>Notes</summary><div class="inner">The plaintext <code>value</code> is not returned on create; read it back with GET. Updating the value creates a new version (§11).</div></details>
  </div>
```

- [ ] **Step 2: Replace the Secret Versions section (id="secret-versions")**

Endpoint cards for GET /secrets/{id}/versions, GET /secrets/{id}/versions/{n},
GET /secrets/{id}/versions/latest. Add a CLI tab using `rocketvault version list|get|latest`.
Keep prose; footer see-also Manual Testing §9.

- [ ] **Step 3: Replace the Keys section (id="keys")**

Endpoint cards for POST /keys (Response from capture: keys `bits, created_at, enabled, id, name,
revoked, tags, type, user_id`; show the create body for both RSA `{"type":"RSA","bits":2048}`
and ECDSA `{"type":"ECDSA","curve":"P-256"}`), POST /keys/{id}/rotate, /wrap, /unwrap, /sign,
/verify, /encrypt, /decrypt, GET /keys/{id}/versions, PUT /keys/{id}, DELETE /keys/{id}. Keep the
`bits`/`curve` note. Footer see-also Manual Testing §10. Use this Response block for create:

```html
    <div class="tabpane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "my-rsa-key",
  "type": "RSA",
  "bits": 2048,
  "enabled": true,
  "revoked": false,
  "tags": [],
  "user_id": "&lt;uuid&gt;",
  "created_at": "2026-06-03T07:44:46Z"
}</pre></div>
```

- [ ] **Step 4: Replace the Certificates section (id="certificates")**

Endpoint cards for POST /certificates, GET/PUT/DELETE /certificates/{id},
GET/PUT/DELETE /certificates/{id}/policy. Keep prose about auto-renew policy. Footer Manual Testing §11.

- [ ] **Step 5: Replace the Multi-Vault section (id="multi-vault")**

Keep the visibility-model table. Add endpoint cards for POST /vaults (Response from capture:
keys `created_at, created_by, enabled, id, name, purge_protection, retention_days`),
GET /vaults, GET /vaults/{name}, PATCH /vaults/{name}, DELETE /vaults/{name} (note 204 + refuses
`default`). Add a CLI tab using `rocketvault vaults create|recover|purge`. Keep the
`vaults:manage` note. Footer Manual Testing §12.5. Create response block:

```html
    <div class="tabpane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "team-alpha",
  "enabled": true,
  "purge_protection": false,
  "retention_days": 90,
  "created_by": "&lt;uuid&gt;",
  "created_at": "2026-06-03T07:44:46Z"
}</pre></div>
```

- [ ] **Step 6: Replace the Soft-Delete section (id="soft-delete")**

Endpoint cards for the flat routes (GET /deleted/secrets, POST /deleted/secrets/{id}/restore,
DELETE /deleted/secrets/{id}/purge) and the vault-scoped equivalents
(/vaults/{name}/deleted/secrets[...]). Keep the note that key/cert restore/purge are flat-only.
Footer Manual Testing §12.

- [ ] **Step 7: Verify structure + browser**

Structure check (expect `links 33 sections 33 mismatch NONE`), `node --check`, then a browser
pass confirming tabs/copy/collapsibles work across the Keys and Vaults cards. No console errors.

- [ ] **Step 8: Commit**

```bash
git add docs/admin-manual.html
git commit -S -m "docs(manual): deepen core-resource sections into endpoint cards"
```

---

## Task 6: Deepen remaining API sections (JWT Signing, Access Policies, Audit, Backup, Health)

**Files:**
- Modify: `docs/admin-manual.html`
- Read: `docs/.manual-capture.json`

Convert these to endpoint cards (same skeleton). Sections without request/response payloads
(Rate Limiting, Performance, Migrations, API Versioning, the Integration trio, Secret Rotation
which is CLI-only) keep their current prose/tables — do NOT force cards onto them.

- [ ] **Step 1: JWT Signing (id="jwt-signing")** — keep the provider table; add cards for
  GET /jwks.json (Response from capture `jwks`, with `n` redacted) and POST /api/v1/jwks/rotate
  (note self_pki-only, os_store returns 400). Keep the keychain note.

- [ ] **Step 2: Access Policies (id="access-policies")** — cards for GET/POST /access-policies,
  GET/PUT/DELETE /access-policies/{id}, GET /access-policies/principal/{id}. Keep RBAC prose.

- [ ] **Step 3: Audit (id="audit")** — cards for GET /audit/logs (note the `integrity_ok` field
  in the response), GET /audit/reports/soc2, GET /audit/reports/gdpr, GET/PATCH /audit/config.
  All `JWT · admin`.

- [ ] **Step 4: Backup (id="backup")** — keep the full-vs-item framing; CLI tab for
  `rocketvault backup create|list|restore`; cards for POST /secrets/{id}/backup and
  POST /secrets/restore (and note keys/certs have the same shape).

- [ ] **Step 5: Health (id="health")** — cards for GET /health/live, /health/ready, /health,
  /health/database. Response tab for /health from the captured `health` object (trimmed to the
  notable fields: status, database, metrics). No auth pill on the first three; `JWT` on /database.

- [ ] **Step 6: Verify structure + browser** — structure check, `node --check`, browser pass on
  the Audit and Health cards. No console errors.

- [ ] **Step 7: Commit**

```bash
git add docs/admin-manual.html
git commit -S -m "docs(manual): deepen jwt, access-policy, audit, backup, health sections"
```

---

## Task 7: Supersede MANUAL_TESTING.md and finalize cross-references

**Files:**
- Modify: `MANUAL_TESTING.md`
- Modify: `docs/admin-manual.html` (update see-also wording)

- [ ] **Step 1: Reduce MANUAL_TESTING.md to a pointer that keeps the endpoint table**

Replace the top of `MANUAL_TESTING.md` (everything from the title down to but NOT including the
`## Quick Reference — All Endpoints` heading) with:

```markdown
# RocketVault — Manual Testing Guide

> **This guide has been superseded by the [Administrator Manual](docs/admin-manual.html).**
> The manual is the canonical, interactive reference — every feature, with per-endpoint cards,
> live-captured request/response examples, search, and copy-paste commands. Open it over http
> (e.g. `python3 -m http.server` then `http://localhost:8000/docs/admin-manual.html`).
>
> The complete endpoint table is retained below for quick reference.

---
```

Keep the existing `## Quick Reference — All Endpoints` section and everything after it intact.

- [ ] **Step 2: Update the manual's see-also wording**

In `docs/admin-manual.html`, the see-also links currently say "Manual Testing §N". Since the
manual now holds the canonical detail, change the recurring phrasing from implying MANUAL_TESTING
is authoritative to a cross-reference. Replace all occurrences of the text
`>Manual Testing §` with `>Endpoint table — Manual Testing §` so each link reads
"Endpoint table — Manual Testing §N". (Do this with a single replace-all.)

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
python3 - <<'PY'
p='docs/admin-manual.html'; s=open(p).read()
s=s.replace('>Manual Testing §','>Endpoint table — Manual Testing §')
open(p,'w').write(s)
print("done")
PY
```

- [ ] **Step 3: Verify**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
grep -c "superseded by the" MANUAL_TESTING.md          # expect 1
grep -c "Quick Reference — All Endpoints" MANUAL_TESTING.md  # expect 1 (table kept)
python3 - <<'PY'
import re
html=open('docs/admin-manual.html').read()
links=re.findall(r'class="sb-link" href="#([^"]+)"',html)
ids=re.findall(r'<section id="([^"]+)"',html)
print("links",len(links),"sections",len(ids),"mismatch",set(links)^set(ids) or "NONE")
PY
```
Expected: `1`, `1`, and `mismatch NONE`.

- [ ] **Step 4: Commit**

```bash
git add MANUAL_TESTING.md docs/admin-manual.html
git commit -S -m "docs(manual): supersede MANUAL_TESTING.md with the admin manual"
```

---

## Task 8: Full verification

**Files:** none (verification only; fix earlier files if issues found).

- [ ] **Step 1: Structural + JS validity**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
python3 - <<'PY'
import re
html=open('docs/admin-manual.html').read()
links=re.findall(r'class="sb-link" href="#([^"]+)"',html)
ids=re.findall(r'<section id="([^"]+)"',html)
assert len(links)==len(set(links)), "dup links"
assert len(ids)==len(set(ids)), "dup ids"
assert set(links)==set(ids), f"mismatch {set(links)^set(ids)}"
print(f"OK {len(ids)} sections")
print("open/close section:", html.count('<section'), html.count('</section>'))
print("placeholders:", sum(html.count(x) for x in ('TBD','FIXME','lorem')))
scripts=re.findall(r'<script>(.*?)</script>',html,re.S); open('/tmp/m.js','w').write(scripts[-1])
PY
node --check /tmp/m.js && echo JS_OK; rm -f /tmp/m.js
# No real secrets leaked into the manual or capture file.
grep -REi '"value": *"s3cret"|eyJ[A-Za-z0-9_-]{20,}' docs/admin-manual.html docs/.manual-capture.json && echo LEAK || echo clean
```
Expected: `OK 33 sections`, equal open/close, `placeholders: 0`, `JS_OK`, `clean`.

- [ ] **Step 2: Behavioral browser pass**

Serve over http and drive a headless browser (controller has Playwright MCP). Confirm:
search filters sidebar; clicking a Response tab on the Keys card shows JSON; copy button copies a
code block; a `<details>` collapsible toggles; the Markdown doc viewer still opens a `.md` link;
back-to-top appears after scrolling; **zero console errors**.
```bash
cd /home/numericlabs/data/rocket/rocketvault
python3 -m http.server 8099 >/tmp/h.log 2>&1 & echo $! >/tmp/h.pid; sleep 1
# ... browser checks at http://localhost:8099/docs/admin-manual.html ...
kill $(cat /tmp/h.pid); rm -f /tmp/h.pid /tmp/h.log
```

- [ ] **Step 3: Commit any fixes**

```bash
git add -A
git commit -S -m "docs(manual): final verification fixes" || echo "nothing to fix"
```

---

## Self-Review notes (for the implementer)

- **Spec coverage:** content depth (Tasks 4-6 endpoint cards), live capture (Task 1), the 5
  interactive features + back-to-top (Task 2), production framing + Quick Start (Task 3),
  supersede MANUAL_TESTING.md (Task 7), verification (Task 8). All spec items mapped.
- **Section count invariant:** starts at 31; Task 3 adds `before-you-begin` + `quick-start` → 33.
  Tasks 4-6 only REPLACE existing sections (no count change). Tasks 4-8 assert `33`.
- **Card markup is defined once** (Task 4 Step 1) and reused verbatim by Tasks 5-6 — same class
  names (`ep`, `ep-hd`, `meth-*`, `ep-auth`, `tabs`, `tab`, `tabpane`, `collapse`) that Task 2's
  CSS/JS target. No name drift.
- **Capture realism:** Task 1's commands and the response shapes in Tasks 4-6 were verified
  against a live server during planning (see "Proven facts"). Bootstrap is CLI-only; secret
  create omits `value`; the documented response keys are real.
- **GPG:** every commit uses `-S`.
```
