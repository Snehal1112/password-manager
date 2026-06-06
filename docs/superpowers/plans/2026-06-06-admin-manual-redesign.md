# Admin Manual Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `docs/admin-manual.html` with a fully redesigned dark-theme developer doc that serves both new admins and app developers with clear "why" context, flow diagrams, step guides, and rich callouts.

**Architecture:** Single-file HTML replacement. All CSS inline in `<style>`, all JS inline in `<script>`. No build step, no new files (except the HTML itself). Preserves all existing anchor IDs so inbound links don't break. Content extracted verbatim from current file and re-wrapped in new component markup.

**Tech Stack:** HTML5, CSS custom properties, vanilla JS — Inter + Fira Code from Google Fonts CDN.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `docs/admin-manual.html` | **Replace** | Full redesigned document |
| `docs/admin-manual copy.html` | Keep as backup during work, delete after | Reference for content extraction |

---

## Task 1: Shell + CSS foundation

**Files:**
- Replace: `docs/admin-manual.html`

Build the complete CSS system and page shell with empty `<main>` — no content yet. This validates the visual design before any content work.

- [ ] **Step 1: Back up the current file**

```bash
cp docs/admin-manual.html "docs/admin-manual copy.html"
```

- [ ] **Step 2: Write the new shell**

Replace `docs/admin-manual.html` with this complete shell (empty main, full CSS + JS skeleton):

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>RocketVault — Administrator Manual</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0D1117;
  --surface:#161B22;
  --surface2:#1C2230;
  --surface3:#21283A;
  --border:rgba(255,255,255,.08);
  --border2:rgba(255,255,255,.14);
  --text:#E6EDF3;
  --text2:#8B949E;
  --text3:#484F58;
  --accent:#4ECCA3;
  --accent-dim:rgba(78,204,163,.15);
  --accent-border:rgba(78,204,163,.3);
  --warn:#F0A84B;
  --warn-dim:rgba(240,168,75,.12);
  --warn-border:rgba(240,168,75,.3);
  --info:#58A6FF;
  --info-dim:rgba(88,166,255,.12);
  --info-border:rgba(88,166,255,.3);
  --danger:#F85149;
  --sidebar-w:260px;
  --font:'Inter',system-ui,sans-serif;
  --mono:'Fira Code',monospace;
}
html{scroll-behavior:smooth}
body{font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.6;font-size:14px}

/* ── Layout ── */
.layout{display:flex;min-height:100vh}
nav.sidebar{position:sticky;top:0;height:100vh;width:var(--sidebar-w);flex:0 0 var(--sidebar-w);
  overflow-y:auto;background:var(--surface);border-right:1px solid var(--border);padding:20px 0}
main{flex:1;max-width:880px;padding:48px 52px 120px;
  background-image:
    radial-gradient(ellipse 80% 40% at 60% -10%,rgba(78,204,163,.07),transparent 60%),
    radial-gradient(ellipse 50% 30% at 90% 80%,rgba(88,166,255,.05),transparent 55%),
    url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Ccircle cx='20' cy='20' r='1' fill='rgba(255,255,255,0.025)'/%3E%3C/svg%3E");
  background-attachment:local}

/* ── Sidebar ── */
.sb-brand{display:flex;align-items:center;gap:10px;padding:0 20px 20px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sb-logo{width:28px;height:28px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#0D1117;flex-shrink:0}
.sb-name{font-weight:600;font-size:14px;color:var(--text)}
.sb-ver{font-size:10px;color:var(--text3);font-family:var(--mono)}
.sb-search{margin:0 12px 16px;position:relative}
.sb-search input{width:100%;background:var(--surface2);border:1px solid var(--border2);border-radius:6px;
  padding:7px 10px 7px 30px;font-size:12px;color:var(--text);font-family:var(--font);outline:none}
.sb-search input::placeholder{color:var(--text3)}
.sb-search::before{content:"⌕";position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:14px}
.sb-group{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);padding:6px 20px 4px}
.sb-item{display:flex;align-items:center;gap:8px;padding:5px 20px;font-size:13px;color:var(--text2);
  text-decoration:none;cursor:pointer;border-left:2px solid transparent;transition:all .12s}
.sb-item:hover{color:var(--text);background:rgba(255,255,255,.04)}
.sb-item.active{color:var(--accent);background:var(--accent-dim);border-left-color:var(--accent);font-weight:500}
.sb-item.hidden{display:none}
.sb-group.hidden{display:none}
.sb-badge{font-size:9px;font-family:var(--mono);background:var(--surface3);color:var(--text3);padding:1px 5px;border-radius:3px;margin-left:auto}
.search-empty{font-size:12px;color:var(--text3);padding:6px 20px;display:none}

/* ── Page header ── */
.page-header{margin-bottom:36px}
.page-title{font-size:26px;font-weight:700;color:var(--text);margin-bottom:8px}
.page-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.page-lede{color:var(--text2);font-size:14px;margin-top:8px;margin-bottom:0}

/* ── Chips ── */
.chip{display:inline-flex;align-items:center;font-size:11px;font-family:var(--mono);padding:2px 8px;border-radius:4px;border:1px solid}
.chip-green{background:var(--accent-dim);border-color:var(--accent-border);color:var(--accent)}
.chip-blue{background:var(--info-dim);border-color:var(--info-border);color:var(--info)}
.chip-warn{background:var(--warn-dim);border-color:var(--warn-border);color:var(--warn)}
.chip-muted{background:var(--surface2);border-color:var(--border2);color:var(--text3)}

/* ── Section headings ── */
section{margin-bottom:64px;scroll-margin-top:24px}
h2{font-size:20px;font-weight:700;color:var(--text);margin:0 0 6px;padding-bottom:10px;border-bottom:1px solid var(--border)}
h3{font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.07em;margin:24px 0 10px}
p{color:var(--text2);font-size:13px;margin-bottom:10px}
ul,ol{color:var(--text2);font-size:13px;margin:0 0 10px 20px}
li{margin-bottom:4px}
a{color:var(--accent)}
code{font-family:var(--mono);font-size:12px;background:var(--surface2);padding:1px 5px;border-radius:4px;color:var(--text)}

/* ── Callouts ── */
.callout{border-radius:8px;padding:14px 16px;margin:12px 0;border:1px solid}
.callout-accent{background:var(--accent-dim);border-color:var(--accent-border)}
.callout-warn{background:var(--warn-dim);border-color:var(--warn-border)}
.callout-info{background:var(--info-dim);border-color:var(--info-border)}
.callout-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.callout-accent .callout-label{color:var(--accent)}
.callout-warn .callout-label{color:var(--warn)}
.callout-info .callout-label{color:var(--info)}
.callout p{font-size:13px;color:var(--text2);margin:0}

/* ── Code blocks ── */
.codewrap{position:relative;margin:8px 0}
.code-hd{display:flex;align-items:center;justify-content:space-between;background:var(--surface3);
  border:1px solid var(--border);border-bottom:none;border-radius:6px 6px 0 0;padding:6px 12px}
.code-lang{font-size:10px;font-family:var(--mono);color:var(--text3)}
.copy-btn{font-size:10px;font-family:var(--font);border:1px solid var(--border2);border-radius:4px;
  padding:2px 8px;background:transparent;color:var(--text2);cursor:pointer}
.copy-btn:hover{color:var(--text);border-color:var(--text2)}
.copy-btn.done{color:var(--accent);border-color:var(--accent-border)}
pre.code{font-family:var(--mono);font-size:12.5px;line-height:1.65;background:var(--surface2);
  border:1px solid var(--border);border-radius:6px;padding:12px 16px;overflow-x:auto;color:var(--accent);margin:0}
pre.code.no-hd{border-radius:6px}
pre.code.with-hd{border-top:none;border-radius:0 0 6px 6px}

/* ── Tables ── */
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:12.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--text3);background:var(--surface2)}
td{color:var(--text2)}
td code{font-size:11.5px}

/* ── Steps ── */
.steps{display:flex;flex-direction:column}
.step{display:flex;gap:16px;position:relative}
.step:not(:last-child)::after{content:'';position:absolute;left:14px;top:31px;bottom:0;width:1px;background:var(--border2)}
.step-num{width:30px;height:30px;background:var(--surface2);border:1px solid var(--accent-border);border-radius:8px;
  display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;
  color:var(--accent);font-family:var(--mono);flex-shrink:0;margin-top:2px;position:relative;z-index:1}
.step-body{flex:1;padding-bottom:24px}
.step-title{font-size:14px;font-weight:600;color:var(--text);margin-bottom:6px;display:flex;align-items:center;gap:8px}
.step-time{font-size:10px;font-family:var(--mono);color:var(--text3)}
.step-desc{font-size:13px;color:var(--text2);margin-bottom:10px}

/* ── Audience path cards ── */
.paths{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:28px}
.path-card{background:var(--surface);border:1px solid var(--border2);border-radius:10px;padding:16px;transition:border-color .15s}
.path-card:hover{border-color:var(--accent)}
.path-icon{font-size:20px;margin-bottom:8px}
.path-title{font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px}
.path-desc{font-size:12px;color:var(--text2);line-height:1.5;margin-bottom:8px}
.path-steps{display:flex;gap:4px;flex-wrap:wrap}
.path-step{font-size:10px;font-family:var(--mono);background:var(--surface2);color:var(--text3);padding:2px 6px;border-radius:3px}

/* ── Flow diagram ── */
.flow{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin:16px 0}
.flow-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:14px}
.flow-nodes{display:flex;align-items:center;gap:0;flex-wrap:wrap;row-gap:8px}
.flow-node{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;
  padding:8px 14px;font-size:12px;color:var(--text2);text-align:center;min-width:90px}
.flow-node.hl{border-color:var(--accent-border);color:var(--accent);background:var(--accent-dim)}
.flow-arrow{color:var(--text3);font-size:16px;padding:0 6px;flex-shrink:0}
.flow-caption{margin-top:10px;font-size:11px;color:var(--text3)}

/* ── Endpoint cards ── */
.ep{border:1px solid var(--border);border-radius:8px;margin:12px 0;overflow:hidden}
.ep-hd{display:flex;align-items:center;gap:8px;padding:9px 12px;background:var(--surface2);
  border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12.5px;flex-wrap:wrap}
.meth{font-family:var(--mono);font-size:10px;font-weight:700;color:#fff;padding:1px 7px;border-radius:4px;flex-shrink:0}
.meth-get{background:#16A34A}.meth-post{background:#2563A8}.meth-put{background:#B97D0D}
.meth-patch{background:#6B5ED4}.meth-delete{background:#C2460C}
.ep-path{color:var(--text);font-size:12.5px}
.ep-auth{font-size:10px;font-family:var(--mono);padding:1px 8px;border-radius:999px;
  background:var(--accent-dim);border:1px solid var(--accent-border);color:var(--accent)}
.ep-label{color:var(--text3);font-size:12px;font-family:var(--font)}
.tab-bar{display:flex;background:var(--surface2);border-bottom:1px solid var(--border)}
.tab-btn{padding:7px 14px;font-size:12px;border:none;background:none;color:var(--text2);cursor:pointer;
  font-family:var(--font);border-bottom:2px solid transparent;transition:all .12s}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-pane{display:none}.tab-pane.active{display:block}
.tab-pane pre.code{border-radius:0;border:none;border-top:none}

/* ── Op grid (2-col code) ── */
.op-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:8px 0}
.op-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);font-weight:600;margin-bottom:4px}
@media(max-width:780px){.op-grid{grid-template-columns:1fr}}

/* ── Collapsible ── */
details.collapse{border:1px solid var(--border);border-radius:6px;margin:8px 0}
details.collapse>summary{cursor:pointer;padding:8px 12px;font-size:12px;font-weight:600;color:var(--text2);
  background:var(--surface2);list-style:none}
details.collapse>summary::-webkit-details-marker{display:none}
details.collapse>summary::before{content:"\25B8  ";color:var(--text3)}
details.collapse[open]>summary::before{content:"\25BE  "}
details.collapse .inner{padding:8px 12px;font-size:12.5px;color:var(--text2)}

/* ── See also ── */
.see-also{font-size:12px;background:var(--surface2);border-radius:6px;padding:8px 12px;margin-top:16px;color:var(--text2)}

/* ── Back to top ── */
#to-top{position:fixed;bottom:22px;right:22px;z-index:30;display:none;border:1px solid var(--border2);
  background:var(--surface);border-radius:50%;width:40px;height:40px;font-size:16px;cursor:pointer;color:var(--text2);
  box-shadow:0 2px 10px rgba(0,0,0,.3)}
#to-top.show{display:flex;align-items:center;justify-content:center}

/* ── Mobile ── */
#sb-toggle{display:none}
@media(max-width:900px){
  nav.sidebar{position:fixed;left:0;top:0;z-index:20;transform:translateX(-100%);transition:transform .2s}
  nav.sidebar.open{transform:none}
  #sb-toggle{display:block;position:fixed;top:12px;left:12px;z-index:30;background:var(--surface);
    border:1px solid var(--border2);border-radius:6px;padding:6px 11px;font-size:13px;cursor:pointer;color:var(--text)}
  main{padding:48px 20px 80px}
}
</style>
</head>
<body>
<button id="sb-toggle" aria-label="Toggle navigation">☰ Menu</button>
<button id="to-top" aria-label="Back to top" title="Back to top">↑</button>
<div class="layout">

<nav class="sidebar" id="sidebar">
  <div class="sb-brand">
    <div class="sb-logo">R</div>
    <div>
      <div class="sb-name">RocketVault</div>
      <div class="sb-ver">v4.0.0 · admin manual</div>
    </div>
  </div>
  <div class="sb-search"><input type="search" id="sb-search" placeholder="Search…  /" aria-label="Search"/></div>
  <div class="search-empty" id="search-empty">No results</div>

  <div class="sb-group">Getting Started</div>
  <a class="sb-item" href="#quick-start">Quick Start <span class="sb-badge">5 min</span></a>
  <a class="sb-item" href="#before-you-begin">Before You Begin</a>
  <a class="sb-item" href="#installation">Installation &amp; Config</a>
  <a class="sb-item" href="#introduction">Mental Model</a>

  <div class="sb-group">Identity &amp; Access</div>
  <a class="sb-item" href="#authentication">Authentication</a>
  <a class="sb-item" href="#jwt-signing">JWT Signing</a>
  <a class="sb-item" href="#users">Users</a>
  <a class="sb-item" href="#access-policies">RBAC &amp; Policies</a>
  <a class="sb-item" href="#service-accounts">Service Accounts</a>

  <div class="sb-group">Core Resources</div>
  <a class="sb-item" href="#secrets">Secrets</a>
  <a class="sb-item" href="#secret-versions">Secret Versions</a>
  <a class="sb-item" href="#secret-rotation">Secret Rotation</a>
  <a class="sb-item" href="#keys">Keys</a>
  <a class="sb-item" href="#certificates">Certificates</a>
  <a class="sb-item" href="#multi-vault">Multi-Vault</a>
  <a class="sb-item" href="#soft-delete">Soft-Delete &amp; Purge</a>

  <div class="sb-group">Operations</div>
  <a class="sb-item" href="#audit">Audit &amp; Compliance</a>
  <a class="sb-item" href="#backup">Backup &amp; Restore</a>
  <a class="sb-item" href="#hsm">HSM / PKCS#11</a>
  <a class="sb-item" href="#health">Health &amp; Monitoring</a>
  <a class="sb-item" href="#rate-limiting">Rate Limiting</a>
  <a class="sb-item" href="#performance">Performance</a>
  <a class="sb-item" href="#migrations">DB Migrations</a>
  <a class="sb-item" href="#api-versioning">API Versioning</a>

  <div class="sb-group">Integration</div>
  <a class="sb-item" href="#consuming">Consuming Secrets</a>
  <a class="sb-item" href="#cicd">CI/CD</a>
  <a class="sb-item" href="#multi-env">Multi-Environment</a>

  <div class="sb-group">Reference</div>
  <a class="sb-item" href="#appendix-endpoints">Endpoint Index</a>
  <a class="sb-item" href="#appendix-cli">CLI Command Tree</a>
  <a class="sb-item" href="#appendix-troubleshooting">Troubleshooting</a>
  <a class="sb-item" href="#appendix-security">Security Checklist</a>
</nav>

<main id="main">
  <!-- CONTENT GOES HERE — added in Tasks 2–8 -->
</main>
</div>

<script>
// Tab switching — scoped to nearest .ep
function switchTab(btn, paneIdx) {
  const ep = btn.closest('.ep');
  ep.querySelectorAll('.tab-btn').forEach((b,i) => {
    b.classList.toggle('active', i === paneIdx);
    ep.querySelectorAll('.tab-pane')[i].classList.toggle('active', i === paneIdx);
  });
}
// Wire tabs on load
document.querySelectorAll('.ep').forEach(ep => {
  ep.querySelectorAll('.tab-btn').forEach((btn, i) => {
    btn.addEventListener('click', () => switchTab(btn, i));
  });
});

// Copy buttons
document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const pre = btn.closest('.codewrap').querySelector('pre');
    navigator.clipboard.writeText(pre.innerText).then(() => {
      btn.textContent = 'Copied!'; btn.classList.add('done');
      setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1500);
    });
  });
});

// Sidebar search
const search = document.getElementById('sb-search');
const empty = document.getElementById('search-empty');
search.addEventListener('input', () => {
  const q = search.value.toLowerCase().trim();
  let any = false;
  document.querySelectorAll('.sb-item').forEach(item => {
    const match = !q || item.textContent.toLowerCase().includes(q);
    item.classList.toggle('hidden', !match);
    if (match) any = true;
  });
  document.querySelectorAll('.sb-group').forEach(g => {
    let next = g.nextElementSibling;
    let hasVisible = false;
    while (next && !next.classList.contains('sb-group')) {
      if (!next.classList.contains('hidden')) hasVisible = true;
      next = next.nextElementSibling;
    }
    g.classList.toggle('hidden', !hasVisible);
  });
  empty.style.display = any ? 'none' : 'block';
});

// / shortcut focuses search
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement !== search) {
    e.preventDefault(); search.focus();
  }
});

// Active nav via IntersectionObserver
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.sb-item[href^="#"]');
const obs = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + entry.target.id));
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });
sections.forEach(s => obs.observe(s));

// Back to top
const toTop = document.getElementById('to-top');
window.addEventListener('scroll', () => toTop.classList.toggle('show', window.scrollY > 300));
toTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));

// Mobile sidebar toggle
const sbToggle = document.getElementById('sb-toggle');
const sidebar = document.getElementById('sidebar');
sbToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
document.addEventListener('click', e => {
  if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && e.target !== sbToggle) {
    sidebar.classList.remove('open');
  }
});
</script>
</body>
</html>
```

- [ ] **Step 3: Open in browser and verify**

```bash
# open in browser
xdg-open docs/admin-manual.html 2>/dev/null || open docs/admin-manual.html
```

Expected: dark page, sidebar visible with all nav groups, empty main content area with dot-grid texture and glow.

- [ ] **Step 4: Commit**

```bash
git add docs/admin-manual.html "docs/admin-manual copy.html"
git commit -m "feat(docs): add redesigned admin manual shell with dark theme CSS and JS"
```

---

## Task 2: Getting Started sections (Quick Start, Before You Begin, Installation, Mental Model)

**Files:**
- Modify: `docs/admin-manual.html` — add content inside `<main>`

These 4 sections are the highest-value for new users. Quick Start gets the full treatment (audience cards, flow diagram, numbered steps).

- [ ] **Step 1: Insert Getting Started content**

Inside `<main id="main">`, replace the `<!-- CONTENT GOES HERE -->` comment with:

```html
<section id="quick-start">
  <div class="page-header">
    <div class="page-title">Quick Start</div>
    <div class="page-meta">
      <span class="chip chip-green">5 min</span>
      <span class="chip chip-blue">New admin</span>
      <span class="chip chip-warn">App developer</span>
    </div>
  </div>

  <div class="paths">
    <div class="path-card">
      <div class="path-icon">🔧</div>
      <div class="path-title">I'm setting up RocketVault</div>
      <div class="path-desc">Install, bootstrap admin, configure vault for your team.</div>
      <div class="path-steps">
        <span class="path-step">install</span>
        <span class="path-step">bootstrap</span>
        <span class="path-step">configure</span>
        <span class="path-step">first secret</span>
      </div>
    </div>
    <div class="path-card">
      <div class="path-icon">⚡</div>
      <div class="path-title">I'm building an app that reads secrets</div>
      <div class="path-desc">Create a service account and read secrets from your app.</div>
      <div class="path-steps">
        <span class="path-step">service account</span>
        <span class="path-step">access policy</span>
        <span class="path-step">fetch secret</span>
      </div>
    </div>
  </div>

  <div class="callout callout-accent">
    <div class="callout-label">What you'll build</div>
    <p>Running vault server → bootstrap first admin → store a secret → create a service account → app reads it via OAuth2 client credentials. Every command is copy-pasteable; responses are real (redacted).</p>
  </div>

  <div class="flow">
    <div class="flow-title">How it fits together</div>
    <div class="flow-nodes">
      <div class="flow-node">Your App</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">OAuth2 Token</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node hl">RocketVault API</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">AES-256 Store</div>
    </div>
    <div class="flow-caption">Admins authenticate with JWT + TOTP. Apps authenticate as service accounts via client credentials — no TOTP needed.</div>
  </div>

  <h3>End-to-end walkthrough</h3>
  <div class="steps">
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">
        <div class="step-title">Start the server <span class="step-time">~10s</span></div>
        <div class="step-desc">Run from source. The server reads <code>.rocketvault.yaml</code> from the working directory.</div>
        <div class="codewrap">
          <div class="code-hd"><span class="code-lang">bash</span><button class="copy-btn">Copy</button></div>
          <pre class="code with-hd">go run main.go serve
export BASE=http://localhost:8774
curl -s $BASE/api/v1/health/live   # → {"status":"OK"}</pre>
        </div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">
        <div class="step-title">Bootstrap the first admin <span class="step-time">~30s</span></div>
        <div class="step-desc">CLI-only, one-time. Uses the <code>bootstrap_token</code> from your config. The response includes a TOTP secret — register it before step 3.</div>
        <div class="codewrap">
          <div class="code-hd"><span class="code-lang">bash</span><button class="copy-btn">Copy</button></div>
          <pre class="code with-hd">go run main.go users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token &lt;your-bootstrap-token&gt;
# stdout → TOTP Secret: otpauth://totp/...&secret=&lt;BASE32&gt;</pre>
        </div>
        <div class="callout callout-warn" style="margin-top:10px">
          <div class="callout-label">Register TOTP now</div>
          <p>Scan the <code>otpauth://</code> URL in Google Authenticator, Authy, or 1Password. Or mint codes on the CLI: <code>oathtool --totp --base32 &lt;BASE32&gt;</code>. Every login requires a TOTP code.</p>
        </div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        <div class="step-title">Log in and capture the JWT <span class="step-time">~15s</span></div>
        <div class="step-desc">Returns a short-lived access token and a refresh token. Store the access token in <code>$TOKEN</code>.</div>
        <div class="ep">
          <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/users/login</span> <span class="ep-label">Authenticate, get a JWT</span></div>
          <div class="tab-bar">
            <button class="tab-btn active">cURL</button>
            <button class="tab-btn">CLI</button>
            <button class="tab-btn">Response</button>
          </div>
          <div class="tab-pane active"><pre class="code">TOKEN=$(curl -s -X POST $BASE/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"123456"}' \
  | jq -r .token)</pre></div>
          <div class="tab-pane"><pre class="code">rocketvault users login \
  --username admin --password admin123 --totp-code 123456</pre></div>
          <div class="tab-pane"><pre class="code">{
  "token": "&lt;redacted-jwt&gt;",
  "refresh_token": "&lt;redacted-jwt&gt;",
  "user_id": "f99945c6-ded6-4d6d-96be-7a10a1fbe6fe",
  "username": "admin",
  "role": "admin"
}</pre></div>
        </div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">4</div>
      <div class="step-body">
        <div class="step-title">Store a secret <span class="step-time">~10s</span></div>
        <div class="step-desc">Secrets are encrypted at rest with AES-256-GCM. Only the owner or admin can read them without an access policy.</div>
        <div class="codewrap">
          <div class="code-hd"><span class="code-lang">bash</span><button class="copy-btn">Copy</button></div>
          <pre class="code with-hd">SECRET_ID=$(curl -s -X POST $BASE/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"DB_PASSWORD","value":"s3cret"}' | jq -r .id)
echo $SECRET_ID</pre>
        </div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">5</div>
      <div class="step-body">
        <div class="step-title">Create a service account and grant read access <span class="step-time">~30s</span></div>
        <div class="step-desc">Service accounts are machine identities — no TOTP, authenticate via OAuth2 client credentials. The <code>client_secret</code> is shown only once.</div>
        <div class="codewrap">
          <div class="code-hd"><span class="code-lang">bash</span><button class="copy-btn">Copy</button></div>
          <pre class="code with-hd">SA=$(curl -s -X POST $BASE/api/v1/service-accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-app","description":"reads DB_PASSWORD"}')
CLIENT_SECRET=$(echo "$SA" | jq -r .client_secret)
SA_ID=$(echo "$SA" | jq -r .id)

curl -s -X POST $BASE/api/v1/access-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"app-read","principal_id":"'"$SA_ID"'","resource_type":"secret","resource_id":"'"$SECRET_ID"'","actions":["read"]}'</pre>
        </div>
        <div class="callout callout-info" style="margin-top:10px">
          <div class="callout-label">Why access policies?</div>
          <p>Roles gate broad operations. Access policies grant a specific principal access to a specific resource. A service account with no policies can authenticate but read nothing — principle of least privilege.</p>
        </div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">6</div>
      <div class="step-body">
        <div class="step-title">Consume the secret as your app <span class="step-time">~15s</span></div>
        <div class="step-desc">Exchange client credentials for a bearer token, then read the secret. This is the pattern your app repeats at runtime.</div>
        <div class="codewrap">
          <div class="code-hd"><span class="code-lang">bash</span><button class="copy-btn">Copy</button></div>
          <pre class="code with-hd">APP_TOKEN=$(curl -s -X POST $BASE/api/v1/oauth2/token \
  -u "my-app:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" | jq -r .access_token)

curl -s $BASE/api/v1/secrets/$SECRET_ID \
  -H "Authorization: Bearer $APP_TOKEN" | jq .value
# → "s3cret"</pre>
        </div>
      </div>
    </div>
  </div>

  <div class="callout callout-accent" style="margin-top:24px">
    <div class="callout-label">What's next</div>
    <p><strong style="color:var(--text)">New admins:</strong> Configure users → <a href="#users">User Management</a>, set up RBAC → <a href="#access-policies">RBAC &amp; Policies</a>, enable audit logging → <a href="#audit">Audit &amp; Compliance</a>.<br>
    <strong style="color:var(--text)">Developers:</strong> Multiple secrets → <a href="#consuming">Consuming Secrets</a>, rotate credentials → <a href="#secret-rotation">Secret Rotation</a>, CI/CD → <a href="#cicd">CI/CD</a>.</p>
  </div>
</section>

<section id="before-you-begin">
  <h2>Before You Begin</h2>
  <h3>Prerequisites</h3>
  <ul>
    <li>Go 1.24+ to build and run the server (<code>go run main.go serve</code>).</li>
    <li><code>curl</code> and <code>jq</code> for the API examples; <code>oathtool</code> to mint TOTP codes without a phone.</li>
    <li>A populated <code>.rocketvault.yaml</code> (the only config the server reads). Key settings: <code>server.listen_addr</code> (default <code>:8774</code>), the bootstrap token, and <code>jwt.*</code>.</li>
    <li>The server running and an admin bootstrapped (see Quick Start above).</li>
  </ul>
  <h3>Conventions in this manual</h3>
  <ul>
    <li><code>$BASE</code> is <code>http://localhost:8774</code>; <code>$TOKEN</code> is an admin JWT from login.</li>
    <li>Example responses are <strong>captured from a live server</strong>; secret values, key material, and tokens are shown as <code>&lt;redacted&gt;</code> placeholders.</li>
    <li>Each operation shows tabs — <strong>cURL</strong>, <strong>CLI</strong>, and a real <strong>Response</strong> where applicable.</li>
  </ul>
</section>

<section id="installation">
  <h2>Installation &amp; First Run</h2>
  <h3>What it is</h3>
  <p>RocketVault runs as a single Go binary. The server reads exactly one config file, <code>.rocketvault.yaml</code>, from the working directory or <code>--config</code>.</p>
  <div class="op-grid">
    <div>
      <div class="op-label">Run from source</div>
      <pre class="code no-hd">go run main.go serve
go run main.go serve --config /path/custom.yaml</pre>
    </div>
    <div>
      <div class="op-label">Verify it is up</div>
      <pre class="code no-hd">export BASE=http://localhost:8774
curl -s $BASE/api/v1/health/live</pre>
    </div>
  </div>
  <div class="callout callout-info">
    <div class="callout-label">Config notes</div>
    <p>The server listens on <code>:8774</code> by default (see <code>server.listen_addr</code>). Set <code>environment: development</code> or <code>production</code> to select DB pool defaults.</p>
  </div>
  <p class="see-also">See also: <a href="../doc/setup.md">Setup Guide</a></p>
</section>

<section id="introduction">
  <h2>Mental Model</h2>
  <h3>What it is</h3>
  <p>RocketVault is a self-hosted, open-source alternative to Azure Key Vault, written in Go. It manages secrets, RSA/ECDSA keys, and X.509 certificates through a REST API and a Cobra CLI, with JWT+TOTP authentication and RBAC.</p>
  <div class="flow">
    <div class="flow-title">Request flow</div>
    <div class="flow-nodes">
      <div class="flow-node hl">HTTP Request</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">Auth + RBAC Middleware</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">REST API Handlers</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">Service Container</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">Repositories</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">SQLite / PostgreSQL</div>
    </div>
    <div class="flow-caption">Secrets, keys, and certificates are encrypted at rest with AES-256-GCM. The CLI calls the service container directly, bypassing the HTTP layer.</div>
  </div>
  <p class="see-also">See also: <a href="rocketvault-architecture.html">System Architecture (interactive)</a></p>
</section>
```

- [ ] **Step 2: Open in browser and verify**

Check: sidebar active state on `#quick-start`, audience cards render side-by-side, steps have connector lines, tabs on step 3 work, copy buttons work.

- [ ] **Step 3: Commit**

```bash
git add docs/admin-manual.html
git commit -m "feat(docs): add Getting Started sections to redesigned admin manual"
```

---

## Task 3: Configuration + Identity & Access sections

**Files:**
- Modify: `docs/admin-manual.html` — append after the `</section>` closing the `#introduction` section

Add sections: Configuration Reference, Authentication (with JWT lifecycle flow diagram), JWT Signing, Users, RBAC & Policies, Service Accounts.

- [ ] **Step 1: Append configuration + authentication sections**

After the `</section>` that closes `#introduction`, append:

```html
<section id="bootstrap">
  <h2>Bootstrap — First Admin User</h2>
  <h3>What it is</h3>
  <p>A one-time bootstrap token creates the first admin without authentication. After use, the token is consumed. The response returns a TOTP secret you must register in an authenticator app — every login requires a TOTP code.</p>
  <h3>When to use it</h3>
  <ul>
    <li>Fresh install — no admin user exists yet.</li>
    <li>Emergency recovery — locked out with no active admin sessions.</li>
  </ul>
  <p>Bootstrap is a <strong>CLI-only</strong> operation — there is no HTTP endpoint.</p>
  <div class="codewrap">
    <div class="code-hd"><span class="code-lang">bash</span><button class="copy-btn">Copy</button></div>
    <pre class="code with-hd">rocketvault users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token &lt;token&gt;</pre>
  </div>
  <div class="callout callout-warn">
    <div class="callout-label">Register TOTP before logging in</div>
    <p>Register the returned <code>totp_qr_url</code> in your authenticator app. You can mint codes with <code>oathtool --totp --base32 &lt;secret&gt;</code>.</p>
  </div>
  <p class="see-also">See also: <a href="../doc/README_ADMIN_SETUP.md">Admin Setup Guide</a></p>
</section>

<section id="configuration">
  <h2>Configuration Reference</h2>
  <h3>What it is</h3>
  <p>All runtime behavior is driven by <code>.rocketvault.yaml</code>. The top-level sections below are read by the server at startup.</p>
  <table>
    <thead><tr><th>Section</th><th>Purpose</th></tr></thead>
    <tbody>
      <tr><td><code>master_key</code>, <code>jwt_secret</code>, <code>bootstrap_token</code></td><td>Master AES-256-GCM key, legacy JWT secret, and one-time bootstrap token</td></tr>
      <tr><td><code>jwt</code></td><td><code>key_source</code> (os_store/self_pki/external_pki), <code>key_cn</code>, <code>expiry</code>, <code>rotation_overlap</code>, <code>signing_key_file</code></td></tr>
      <tr><td><code>environment</code></td><td><code>development</code> | <code>production</code> — sets DB pool defaults</td></tr>
      <tr><td><code>database</code></td><td><code>connection</code>, <code>driver</code>, pool sizing (<code>max_open_conns</code>, …)</td></tr>
      <tr><td><code>log</code></td><td>level, file, format, rotation (<code>max_backups</code>, <code>max_age_days</code>, <code>max_size_mb</code>)</td></tr>
      <tr><td><code>rate_limit</code></td><td><code>default</code> (req/min) and <code>auth</code> (login endpoints)</td></tr>
      <tr><td><code>server</code></td><td><code>listen_addr</code>, timeouts, <code>cors_allowed_origins</code>, <code>http2</code>, <code>tls</code></td></tr>
      <tr><td><code>retry</code></td><td>database / external_services / circuit_breaker backoff config</td></tr>
      <tr><td><code>soft_delete</code></td><td><code>enabled</code>, <code>retention_days</code>, <code>purge_protection</code></td></tr>
      <tr><td><code>key_cache</code></td><td><code>enabled</code>, <code>ttl</code>, <code>max_entries</code>, <code>cleanup_interval</code></td></tr>
      <tr><td><code>oauth2</code></td><td><code>token_expiry</code>, <code>issuer</code></td></tr>
      <tr><td><code>hsm</code></td><td><code>enabled</code>, <code>lib_path</code>, <code>token_label</code>, <code>pin</code>, <code>slot_id</code></td></tr>
    </tbody>
  </table>
  <div class="callout callout-warn">
    <div class="callout-label">Required field</div>
    <p><code>jwt.expiry</code> is required — the service container reads it via <code>viper.GetDuration("jwt.expiry")</code>. Server fails to start without it.</p>
  </div>
</section>

<section id="authentication">
  <h2>Authentication</h2>
  <h3>What it is</h3>
  <p>Login requires username + password + a TOTP code and returns a short-lived JWT plus a refresh token. Sessions are tracked and individually revocable.</p>
  <h3>When to use it</h3>
  <ul>
    <li>Every human caller (admins, operators) authenticates here.</li>
    <li>Machine callers use service accounts (see <a href="#service-accounts">Service Accounts</a>) instead — no TOTP required.</li>
  </ul>
  <div class="flow">
    <div class="flow-title">JWT token lifecycle</div>
    <div class="flow-nodes">
      <div class="flow-node hl">POST /login</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">access_token (15 min)</div>
      <div class="flow-arrow">+</div>
      <div class="flow-node">refresh_token</div>
    </div>
    <div class="flow-nodes" style="margin-top:8px">
      <div class="flow-node">POST /refresh</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node hl">new access_token</div>
      <div class="flow-arrow">·</div>
      <div class="flow-node">DELETE /sessions/{id}</div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">revoked</div>
    </div>
    <div class="flow-caption">Refresh tokens are stored as hashes — never in plaintext. Sessions are tracked by JTI; revoking one session doesn't affect others.</div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/users/login</span> <span class="ep-label">Authenticate, get a JWT</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">CLI</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/users/login -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"123456"}'</pre></div>
    <div class="tab-pane"><pre class="code">rocketvault users login \
  --username admin --password admin123 --totp-code 123456</pre></div>
    <div class="tab-pane"><pre class="code">{
  "token": "&lt;redacted-jwt&gt;",
  "refresh_token": "&lt;redacted-jwt&gt;",
  "user_id": "f99945c6-ded6-4d6d-96be-7a10a1fbe6fe",
  "username": "admin",
  "role": "admin"
}</pre></div>
    <details class="collapse"><summary>Errors</summary><div class="inner">401 bad credentials or TOTP · 429 rate-limited (5/min)</div></details>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/users/refresh</span> <span class="ep-label">Exchange a refresh token</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/users/refresh -H "Content-Type: application/json" \
  -d '{"refresh_token":"&lt;rt&gt;"}'</pre></div>
    <div class="tab-pane"><pre class="code">{ "token": "&lt;redacted-jwt&gt;", "refresh_token": "&lt;redacted-jwt&gt;" }</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/users/sessions</span> <span class="ep-auth">JWT</span> <span class="ep-label">List active sessions</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/users/sessions -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/users/sessions/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Revoke one session (omit id to revoke all)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code"># one session
curl -s -X DELETE $BASE/api/v1/users/sessions/&lt;id&gt; -H "Authorization: Bearer $TOKEN"
# all sessions for the caller
curl -s -X DELETE $BASE/api/v1/users/sessions -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>

  <div class="callout callout-warn">
    <div class="callout-label">Rate limiting</div>
    <p>Auth endpoints are rate-limited (default 5 req/min) — see <a href="#rate-limiting">Rate Limiting</a>.</p>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §5</a></p>
</section>

<section id="jwt-signing">
  <h2>JWT Signing &amp; Key Sources</h2>
  <h3>What it is</h3>
  <p>JWTs are signed asymmetrically and verifiable via JWKS at <code>/jwks.json</code>. Three providers control where the signing key lives, set by <code>jwt.key_source</code>.</p>
  <table>
    <thead><tr><th>Provider</th><th>Storage</th><th>Algorithm</th><th>Rotation</th></tr></thead>
    <tbody>
      <tr><td><code>os_store</code> (default)</td><td>OS keychain, PEM-file fallback</td><td>RS256</td><td>No</td></tr>
      <tr><td><code>self_pki</code></td><td>RocketVault's own encrypted DB</td><td>ES256</td><td>Yes (runtime)</td></tr>
      <tr><td><code>external_pki</code></td><td>PEM from file or env var</td><td>RS256/ES256</td><td>No</td></tr>
    </tbody>
  </table>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/jwks.json</span> <span class="ep-label">Public JWK set (no auth)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/jwks.json | jq '.keys[0].alg'</pre></div>
    <div class="tab-pane"><pre class="code">{
  "keys": [{
    "kty": "RSA", "use": "sig", "alg": "RS256",
    "kid": "9d1c755f04ddbcfc",
    "n": "&lt;base64url-modulus&gt;", "e": "AQAB"
  }]
}</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/jwks/rotate</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Rotate (self_pki only)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/jwks/rotate -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="callout callout-info">
    <div class="callout-label">Why this works</div>
    <p>With <code>os_store</code> the key lives in the OS keychain and rotation returns 400 — only <code>self_pki</code> supports runtime rotation. Headless hosts fall back to <code>~/.local/share/rocketvault/jwt-signing.pem</code> (mode 0600).</p>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §§6,15,16</a></p>
</section>

<section id="users">
  <h2>User Management</h2>
  <h3>What it is</h3>
  <p>Admins create, list, update, and delete users. Each user has a role and a TOTP secret issued at creation.</p>
  <h3>When to use it</h3>
  <ul>
    <li>Onboard human operators who need CLI or API access.</li>
    <li>For automation and apps, prefer a <a href="#service-accounts">service account</a> — no TOTP overhead.</li>
  </ul>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/users</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Create a user</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">CLI</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/users -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alicepassword123","role":"user"}'</pre></div>
    <div class="tab-pane"><pre class="code">rocketvault users create \
  --username admin --password admin123 --totp-code 123456 \
  --new-username alice --new-password alicepassword123 --new-role user</pre></div>
    <div class="tab-pane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "username": "alice",
  "role": "user",
  "totp_secret": "&lt;base32-secret&gt;"
}</pre></div>
    <details class="collapse"><summary>Errors</summary><div class="inner">400 invalid role (one of secrets_manager, crypto_manager, certificate_manager, admin, user) · 401/403 non-admin caller</div></details>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/users</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">List users</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/users -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-put">PUT</span> <span class="ep-path">/api/v1/users/{id}</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Update a user</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X PUT $BASE/api/v1/users/&lt;id&gt; -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/users/{id}</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Delete a user</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/users/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §7</a></p>
</section>

<section id="access-policies">
  <h2>RBAC &amp; Access Policies</h2>
  <h3>What it is</h3>
  <p>Two complementary controls: <strong>roles</strong> gate broad operations, and <strong>access policies</strong> grant a specific principal access to a specific resource — a resource type/id plus allowed actions.</p>
  <h3>When to use it</h3>
  <ul>
    <li>Use a <strong>role</strong> when you want to broadly allow/deny a class of operations (e.g. a user who can manage all secrets).</li>
    <li>Use an <strong>access policy</strong> when you need fine-grained per-resource control (e.g. a service account that can only read one specific secret).</li>
  </ul>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/access-policies</span> <span class="ep-auth">JWT</span> <span class="ep-label">Create a policy</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/access-policies -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"read-db-secret","principal_id":"&lt;id&gt;","resource_type":"secret","resource_id":"&lt;id&gt;","actions":["read"]}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/access-policies</span> <span class="ep-auth">JWT</span> <span class="ep-label">List all</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/access-policies -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/access-policies/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Get one</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/access-policies/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-put">PUT</span> <span class="ep-path">/api/v1/access-policies/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Update</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X PUT $BASE/api/v1/access-policies/&lt;id&gt; -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"actions":["read","update"]}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/access-policies/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Delete</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/access-policies/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/access-policies/principal/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">List by principal</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/access-policies/principal/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §13</a></p>
</section>

<section id="service-accounts">
  <h2>OAuth2 Service Accounts</h2>
  <h3>What it is</h3>
  <p>A service account is a machine identity that authenticates via OAuth2 client-credentials flow — no TOTP. Service accounts are <strong>read-only consumers</strong>: they retrieve secrets/keys/certs an admin granted them via access policies.</p>
  <h3>When to use it</h3>
  <ul>
    <li>CI/CD pipelines, apps fetching config at runtime, service-to-service secrets, scheduled jobs.</li>
    <li>Any automated caller — prefer service accounts over human user credentials for machine access.</li>
  </ul>
  <div class="callout callout-info">
    <div class="callout-label">Why no TOTP?</div>
    <p>TOTP requires a human to read a time-based code. Service accounts use a long client secret instead — machine-readable, rotatable, and revocable without user involvement. The tradeoff is that the secret must be stored securely by the caller (e.g. in a CI secret store).</p>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/service-accounts</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Create (client_secret shown once)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/service-accounts -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-pipeline","description":"CI/CD"}'</pre></div>
    <div class="tab-pane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "ci-pipeline",
  "client_secret": "&lt;shown-once-redacted&gt;"
}</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/oauth2/token</span> <span class="ep-auth">Basic</span> <span class="ep-label">Client-credentials token</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/oauth2/token \
  -u "ci-pipeline:$SECRET" -d "grant_type=client_credentials"</pre></div>
    <div class="tab-pane"><pre class="code">{ "access_token": "&lt;redacted-jwt&gt;", "token_type": "Bearer", "expires_in": 3600 }</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/service-accounts/{id}/rotate</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Rotate the secret</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/service-accounts/&lt;id&gt;/rotate -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/service-accounts/{id}</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Delete (invalidates tokens immediately)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/service-accounts/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="callout callout-warn">
    <div class="callout-label">client_id is the name, not the UUID</div>
    <p>The <code>client_id</code> in the Basic auth header is the service-account <strong>name</strong> (e.g. <code>ci-pipeline</code>), not its UUID. Delete or rotate immediately invalidates live tokens.</p>
  </div>
  <p class="see-also">See also: <a href="consuming-secrets-guide.md">Consuming Secrets Guide</a>, <a href="../MANUAL_TESTING.md">Manual Testing §14</a></p>
</section>
```

- [ ] **Step 2: Open in browser and verify**

Check: config table renders, auth flow diagram shows two rows, JWT Signing table, all endpoint card tabs wire correctly.

- [ ] **Step 3: Commit**

```bash
git add docs/admin-manual.html
git commit -m "feat(docs): add Configuration and Identity sections to admin manual"
```

---

## Task 4: Core Resources sections (Secrets, Versions, Rotation, Keys, Certs, Multi-Vault, Soft-Delete)

**Files:**
- Modify: `docs/admin-manual.html` — append after `#service-accounts` section

Extract all Core Resources content from `docs/admin-manual copy.html` sections `#secrets` through `#soft-delete` and re-wrap with new component markup, adding callouts.

- [ ] **Step 1: Append Core Resources content**

After the `</section>` closing `#service-accounts`, append all of the following:

```html
<section id="secrets">
  <h2>Secrets</h2>
  <h3>What it is</h3>
  <p>Encrypted-at-rest key/value secrets. Only the owner or an admin can read a secret via the flat routes. Secrets support tags, generation, and import/export.</p>
  <h3>When to use it</h3>
  <ul>
    <li>Store application credentials, API keys, connection strings — anything an app needs at runtime but must not hold in plaintext.</li>
  </ul>
  <div class="callout callout-info">
    <div class="callout-label">AES-256-GCM encryption</div>
    <p>"Encrypted at rest" means the <code>value</code> field is encrypted with AES-256-GCM using the <code>master_key</code> before it is written to the database. The plaintext is only available after authenticated decryption — the database file alone is not enough to read your secrets.</p>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/secrets</span> <span class="ep-auth">JWT</span> <span class="ep-label">Create a secret</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/secrets -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"db-password","value":"s3cret","tags":["database"]}'</pre></div>
    <div class="tab-pane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "db-password",
  "tags": ["database"],
  "version": 1,
  "enabled": true,
  "created_at": "2026-06-03T07:44:46Z"
}</pre></div>
    <details class="collapse"><summary>Notes</summary><div class="inner">The plaintext <code>value</code> is not returned on create; read it back with GET. Updating the value creates a new version (see <a href="#secret-versions">Secret Versions</a>).</div></details>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/secrets/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Get a secret (decrypted)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/secrets/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
    <div class="tab-pane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "db-password",
  "value": "&lt;decrypted-value&gt;",
  "tags": ["database"],
  "version": 1,
  "enabled": true,
  "created_at": "2026-06-03T07:44:46Z"
}</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/secrets</span> <span class="ep-auth">JWT</span> <span class="ep-label">List secrets</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/secrets -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-put">PUT</span> <span class="ep-path">/api/v1/secrets/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Update (creates new version)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X PUT $BASE/api/v1/secrets/&lt;id&gt; -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"newpass","tags":["database"]}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/secrets/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Soft-delete</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/secrets/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/secrets/generate</span> <span class="ep-auth">JWT</span> <span class="ep-label">Generate a random value</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/secrets/generate -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"api-key","length":32,"type":"alphanumeric"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/secrets/export</span> <span class="ep-auth">JWT</span> <span class="ep-label">Export</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/secrets/export -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format":"json"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/secrets/import</span> <span class="ep-auth">JWT</span> <span class="ep-label">Import</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/secrets/import -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"secrets":[{"name":"imported","value":"v","tags":["x"]}]}'</pre></div>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §8</a></p>
</section>

<section id="secret-versions">
  <h2>Secret Versions</h2>
  <h3>What it is</h3>
  <p>Every value update creates a new, retained version. Old versions stay readable — no data is lost on update.</p>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/secrets/{id}/versions</span> <span class="ep-auth">JWT</span> <span class="ep-label">List versions</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">CLI</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/secrets/&lt;id&gt;/versions -H "Authorization: Bearer $TOKEN"</pre></div>
    <div class="tab-pane"><pre class="code">rocketvault version list &lt;secret-id&gt; --username admin --password admin123 --totp-code 123456</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/secrets/{id}/versions/{n}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Get version n</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/secrets/&lt;id&gt;/versions/1 -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/secrets/{id}/versions/latest</span> <span class="ep-auth">JWT</span> <span class="ep-label">Get latest</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">CLI</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/secrets/&lt;id&gt;/versions/latest -H "Authorization: Bearer $TOKEN"</pre></div>
    <div class="tab-pane"><pre class="code">rocketvault version latest &lt;secret-id&gt; --username admin --password admin123 --totp-code 123456</pre></div>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §9</a></p>
</section>

<section id="secret-rotation">
  <h2>Secret Rotation</h2>
  <h3>What it is</h3>
  <p>Rotation policies define how often a secret should rotate, with reminder windows and optional auto-rotate. History is tracked, and due rotations can be queried. Managed primarily through the CLI.</p>
  <div class="op-grid">
    <div>
      <div class="op-label">Manage policies</div>
      <pre class="code no-hd">rocketvault secrets rotation create --secret-id &lt;id&gt; --interval 30d \
  --username admin --password admin123 --totp-code 123456
rocketvault secrets rotation list   --username admin --password admin123 --totp-code 123456</pre>
    </div>
    <div>
      <div class="op-label">Operate</div>
      <pre class="code no-hd">rocketvault secrets rotation rotate  --secret-id &lt;id&gt; ...
rocketvault secrets rotation history --secret-id &lt;id&gt; ...
rocketvault secrets rotation status  ...</pre>
    </div>
  </div>
  <p class="see-also">See also: <a href="integration-examples.md">Integration Examples — rotation</a></p>
</section>

<section id="keys">
  <h2>Keys</h2>
  <h3>What it is</h3>
  <p>RSA and ECDSA private keys, encrypted at rest, with cryptographic operations (wrap/unwrap, sign/verify, encrypt/decrypt), rotation, and version history.</p>
  <h3>When to use it</h3>
  <ul>
    <li>Hold signing or encryption keys server-side so private material never leaves the vault.</li>
    <li>Perform crypto operations (sign, verify, encrypt, decrypt) without exposing the key to the caller.</li>
  </ul>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys</span> <span class="ep-auth">JWT</span> <span class="ep-label">Create a key</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code"># RSA: bits = 2048 | 3072 | 4096
curl -s -X POST $BASE/api/v1/keys -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-rsa-key","type":"RSA","bits":2048}'
# ECDSA: curve = P-256 | P-384 | P-521
curl -s -X POST $BASE/api/v1/keys -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-ec-key","type":"ECDSA","curve":"P-256"}'</pre></div>
    <div class="tab-pane"><pre class="code">{
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
    <details class="collapse"><summary>Notes</summary><div class="inner">Use <code>bits</code> for RSA and <code>curve</code> for ECDSA. Private key material is never returned; a GET includes only public components (RSA <code>n</code>/<code>e</code>).</div></details>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys/{id}/rotate</span> <span class="ep-auth">JWT</span> <span class="ep-label">Rotate</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/keys/&lt;id&gt;/rotate -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys/{id}/sign</span> <span class="ep-auth">JWT</span> <span class="ep-label">Sign</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/keys/&lt;id&gt;/sign -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"aGVsbG8=","algorithm":"RS256"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys/{id}/verify</span> <span class="ep-auth">JWT</span> <span class="ep-label">Verify</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/keys/&lt;id&gt;/verify -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"aGVsbG8=","signature":"&lt;sig&gt;","algorithm":"RS256"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys/{id}/wrap</span> <span class="ep-auth">JWT</span> <span class="ep-label">Wrap (encrypt)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/keys/&lt;id&gt;/wrap -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"..."}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys/{id}/unwrap</span> <span class="ep-auth">JWT</span> <span class="ep-label">Unwrap (decrypt)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/keys/&lt;id&gt;/unwrap -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext":"&lt;ct&gt;"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys/{id}/encrypt</span> <span class="ep-auth">JWT</span> <span class="ep-label">Encrypt</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/keys/&lt;id&gt;/encrypt -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"aGVsbG8=","algorithm":"RSA-OAEP"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/keys/{id}/decrypt</span> <span class="ep-auth">JWT</span> <span class="ep-label">Decrypt</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/keys/&lt;id&gt;/decrypt -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"&lt;ct&gt;","algorithm":"RSA-OAEP"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/keys/{id}/versions</span> <span class="ep-auth">JWT</span> <span class="ep-label">List key versions</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/keys/&lt;id&gt;/versions -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/keys/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Soft-delete</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/keys/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §10</a></p>
</section>

<section id="certificates">
  <h2>Certificates &amp; Certificate Policies</h2>
  <h3>What it is</h3>
  <p>Self-signed X.509 certificate lifecycle management. Each certificate may carry a policy describing auto-renewal (validity, key type/curve, SANs, issuer) used by the renewal scan.</p>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/certificates</span> <span class="ep-auth">JWT</span> <span class="ep-label">Create self-signed cert</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/certificates -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-tls-cert","common_name":"example.com","validity_days":365,"key_type":"RSA","key_size":2048}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/certificates/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Get</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/certificates/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-put">PUT</span> <span class="ep-path">/api/v1/certificates/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Update</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X PUT $BASE/api/v1/certificates/&lt;id&gt; -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"renamed"}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/certificates/{id}</span> <span class="ep-auth">JWT</span> <span class="ep-label">Soft-delete</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/certificates/&lt;id&gt; -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/certificates/{id}/policy</span> <span class="ep-auth">JWT</span> <span class="ep-label">Get policy</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/certificates/&lt;id&gt;/policy -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-put">PUT</span> <span class="ep-path">/api/v1/certificates/{id}/policy</span> <span class="ep-auth">JWT</span> <span class="ep-label">Upsert policy</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X PUT $BASE/api/v1/certificates/&lt;id&gt;/policy -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auto_renew":true,"days_before_expiry":30}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/certificates/{id}/policy</span> <span class="ep-auth">JWT</span> <span class="ep-label">Delete policy</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/certificates/&lt;id&gt;/policy -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="callout callout-info">
    <div class="callout-label">Force renewal</div>
    <p>The CLI offers <code>rocketvault certificate renew &lt;id&gt;</code> to force immediate renewal outside the auto-renew scan.</p>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §11</a></p>
</section>

<section id="multi-vault">
  <h2>Multi-Vault</h2>
  <h3>What it is</h3>
  <p>Resources live in named vaults (Azure KV parity). A built-in <code>default</code> vault holds everything created via the flat routes. Vault names are 3–63 lowercase alphanumerics/hyphens, no leading/trailing hyphen.</p>
  <h3>Visibility model</h3>
  <table>
    <thead><tr><th>Route family</th><th>Example</th><th>Visibility</th></tr></thead>
    <tbody>
      <tr><td>Flat</td><td><code>GET /api/v1/secrets</code></td><td>Per-user (owner only)</td></tr>
      <tr><td>Vault-scoped</td><td><code>GET /api/v1/vaults/{name}/secrets</code></td><td>Members see all</td></tr>
    </tbody>
  </table>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/vaults</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Create a vault</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">Response</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/vaults -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"team-alpha"}'</pre></div>
    <div class="tab-pane"><pre class="code">{
  "id": "&lt;uuid&gt;",
  "name": "team-alpha",
  "enabled": true,
  "purge_protection": false,
  "retention_days": 90,
  "created_by": "&lt;uuid&gt;",
  "created_at": "2026-06-03T07:44:46Z"
}</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/vaults</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">List (?include_deleted=true)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s "$BASE/api/v1/vaults?include_deleted=true" -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-patch">PATCH</span> <span class="ep-path">/api/v1/vaults/{name}</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Update</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X PATCH $BASE/api/v1/vaults/team-alpha -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days":7}'</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/vaults/{name}</span> <span class="ep-auth">JWT · admin</span> <span class="ep-label">Soft-delete (204; refuses default vault)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">CLI</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -i -X DELETE $BASE/api/v1/vaults/team-alpha -H "Authorization: Bearer $TOKEN"</pre></div>
    <div class="tab-pane"><pre class="code">rocketvault vaults create|recover|purge team-alpha ...</pre></div>
  </div>
  <div class="callout callout-warn">
    <div class="callout-label">default vault cannot be deleted</div>
    <p>Vault management requires the <code>vaults:manage</code> permission (admin only). The <code>default</code> vault cannot be deleted.</p>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §12.5</a></p>
</section>

<section id="soft-delete">
  <h2>Soft-Delete, Restore &amp; Purge</h2>
  <h3>What it is</h3>
  <p>Secrets, keys, and certificates are soft-deleted (retained, default 30 days) and can be restored or permanently purged. Purge protection can block permanent deletion.</p>
  <div class="flow">
    <div class="flow-title">Resource lifecycle</div>
    <div class="flow-nodes">
      <div class="flow-node hl">active</div>
      <div class="flow-arrow">DELETE →</div>
      <div class="flow-node">soft-deleted<br><span style="font-size:10px;color:var(--text3)">readable, restorable</span></div>
      <div class="flow-arrow">retention expires →</div>
      <div class="flow-node">auto-purged</div>
    </div>
    <div class="flow-nodes" style="margin-top:8px">
      <div class="flow-node" style="opacity:.4">soft-deleted</div>
      <div class="flow-arrow">POST /restore →</div>
      <div class="flow-node hl">active</div>
      <div class="flow-arrow" style="margin-left:20px">DELETE /purge →</div>
      <div class="flow-node">permanently gone</div>
    </div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/deleted/secrets</span> <span class="ep-auth">JWT</span> <span class="ep-label">List soft-deleted (flat, per-user)</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/deleted/secrets -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-post">POST</span> <span class="ep-path">/api/v1/deleted/secrets/{id}/restore</span> <span class="ep-auth">JWT</span> <span class="ep-label">Restore</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X POST $BASE/api/v1/deleted/secrets/&lt;id&gt;/restore -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/deleted/secrets/{id}/purge</span> <span class="ep-auth">JWT</span> <span class="ep-label">Purge permanently</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/deleted/secrets/&lt;id&gt;/purge -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-get">GET</span> <span class="ep-path">/api/v1/vaults/{name}/deleted/secrets</span> <span class="ep-auth">JWT</span> <span class="ep-label">Vault-scoped list</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button></div>
    <div class="tab-pane active"><pre class="code">curl -s $BASE/api/v1/vaults/default/deleted/secrets -H "Authorization: Bearer $TOKEN"</pre></div>
  </div>
  <div class="callout callout-info">
    <div class="callout-label">Keys and certificates</div>
    <p>Key and certificate restore/purge are exposed only on the flat <code>/deleted/keys/…</code> and <code>/deleted/certificates/…</code> routes.</p>
  </div>
  <p class="see-also">See also: <a href="../MANUAL_TESTING.md">Manual Testing §12</a></p>
</section>
```

- [ ] **Step 2: Verify in browser**

Check: Secrets section AES callout renders, soft-delete lifecycle flow diagram shows two rows of nodes, all endpoint tabs work.

- [ ] **Step 3: Commit**

```bash
git add docs/admin-manual.html
git commit -m "feat(docs): add Core Resources sections to admin manual"
```

---

## Task 5: Operations sections

**Files:**
- Modify: `docs/admin-manual.html` — append after `#soft-delete`

Extract Operations content from `docs/admin-manual copy.html` sections `#audit` through `#api-versioning` and re-wrap, adding callouts.

- [ ] **Step 1: Append Operations sections**

Open `docs/admin-manual copy.html`, find `<section id="audit">` through the closing `</section>` of `<section id="api-versioning">`. Copy all inner HTML. After the `</section>` closing `#soft-delete`, paste and then make the following targeted changes:

1. Change all `<div class="tabs">` → `<div class="tab-bar">`
2. Change all `<button class="tab active">` → `<button class="tab-btn active">`
3. Change all `<button class="tab">` → `<button class="tab-btn">`
4. Change all `<div class="tabpane active">` → `<div class="tab-pane active">`
5. Change all `<div class="tabpane">` → `<div class="tab-pane">`
6. Change all `<div class="ep-hd"><span class="meth meth-` → keep as-is (method classes unchanged)
7. Add `<span class="ep-path">` wrapper around the URL path in each `ep-hd` (the text after the method badge, before any `.ep-auth` or `.ep-label`)
8. Change `<div class="note">` → `<div class="callout callout-warn"><div class="callout-label">Note</div><p>` and close with `</p></div>`
9. Add to Backup section before the `see-also`:
```html
<div class="callout callout-warn">
  <div class="callout-label">Security warning</div>
  <p>Backup archives include master key material. Store them with at least the same access controls as your <code>.rocketvault.yaml</code> — anyone with the backup can decrypt all secrets.</p>
</div>
```

- [ ] **Step 2: Verify in browser**

Check: Audit, Backup, HSM, Health, Rate Limiting, Performance, Migrations, API Versioning sections all render. Backup warning callout visible.

- [ ] **Step 3: Commit**

```bash
git add docs/admin-manual.html
git commit -m "feat(docs): add Operations sections to admin manual"
```

---

## Task 6: Integration + Reference sections

**Files:**
- Modify: `docs/admin-manual.html` — append after `#api-versioning`

Extract Integration and Reference/Appendix content from `docs/admin-manual copy.html` and re-wrap with the same transformation rules as Task 5.

- [ ] **Step 1: Append Integration and Reference sections**

Open `docs/admin-manual copy.html`, find `<section id="consuming">` through the closing `</section>` of `<section id="appendix-security">`. Apply the same 9 transformation rules from Task 5. Paste after the `</section>` closing `#api-versioning`.

- [ ] **Step 2: Verify in browser**

Check: all 4 appendix sections render, no broken tabs, sidebar scrolls all the way to Security Checklist.

- [ ] **Step 3: Commit**

```bash
git add docs/admin-manual.html
git commit -m "feat(docs): add Integration and Reference appendix sections to admin manual"
```

---

## Task 7: Wire JS tab system + final validation

**Files:**
- Modify: `docs/admin-manual.html` — fix JS tab wiring

The tab JS in Task 1 wires by index position. Verify every endpoint card has its tabs wiring correctly and that the IntersectionObserver active-nav tracking works across all sections.

- [ ] **Step 1: Verify tab wiring works on all sections**

Open the file in a browser. Test tabs on at least:
- Quick Start step 3 (login — 3 tabs)
- Authentication POST /login (3 tabs)
- Users POST /users (3 tabs)
- Keys POST /keys (2 tabs)

Expected: clicking any tab shows its pane, hides others, active styling applies.

- [ ] **Step 2: Verify active nav tracking**

Scroll slowly down the page. Expected: sidebar active item updates to match the visible section.

- [ ] **Step 3: Verify search**

Type `secret` in the sidebar search. Expected: only secret-related items show, group headers for empty groups hide. Clear the search — all items return.

- [ ] **Step 4: Verify copy buttons**

Click a Copy button on any code block. Expected: text changes to "Copied!" for 1.5s then reverts, clipboard contains the code.

- [ ] **Step 5: Verify back-to-top**

Scroll down 400px, back-to-top button appears. Click it — page scrolls to top.

- [ ] **Step 6: If any tab wiring is broken, fix the JS**

Replace the tab wiring script in `<script>` with:

```javascript
// Wire all .ep tabs on load and after any DOM addition
function wireEpTabs() {
  document.querySelectorAll('.ep').forEach(ep => {
    const btns = ep.querySelectorAll('.tab-btn');
    const panes = ep.querySelectorAll('.tab-pane');
    btns.forEach((btn, i) => {
      btn.onclick = () => {
        btns.forEach((b,j) => { b.classList.toggle('active', j===i); panes[j].classList.toggle('active', j===i); });
      };
    });
  });
}
wireEpTabs();
```

- [ ] **Step 7: Commit**

```bash
git add docs/admin-manual.html
git commit -m "feat(docs): wire all interactive behaviors in admin manual"
```

---

## Task 8: Cleanup and final commit

**Files:**
- Delete: `docs/admin-manual copy.html`
- Verify: `docs/admin-manual.html`

- [ ] **Step 1: Delete the backup file**

```bash
rm "docs/admin-manual copy.html"
```

- [ ] **Step 2: Final visual check**

Open `docs/admin-manual.html`. Verify:
- All 33 sections present (check sidebar)
- Dark theme, dot-grid texture visible on main panel
- Glow effects (teal top-right, blue bottom-right) visible
- Sidebar search works
- Active nav tracking works while scrolling
- All tabs wire correctly
- All copy buttons work
- Back-to-top appears on scroll
- Mobile: sidebar toggles on `☰ Menu` button (resize browser to <900px)
- No broken links in see-also footers

- [ ] **Step 3: Commit**

```bash
git add docs/admin-manual.html
git rm "docs/admin-manual copy.html"
git commit -m "docs(admin-manual): complete redesign — dark theme, rich callouts, flow diagrams, step guides"
```

---

## Self-Review

**Spec coverage check:**
- Visual design (dark theme, colors, fonts, texture) → Task 1 CSS
- Sidebar grouped nav → Task 1 HTML
- Per-section content pattern (What it is, When to use, Why this works, See also) → Tasks 2–6
- Quick Start audience cards + flow diagram + steps + what's next → Task 2
- Authentication JWT lifecycle diagram → Task 3
- RBAC decision guidance (role vs policy) → Task 3
- Service Accounts "Why no TOTP" callout → Task 3
- Secrets AES-256-GCM callout → Task 4
- Soft-Delete lifecycle diagram → Task 4
- Backup security warning → Task 5
- JS behaviors (tabs, copy, search, observer, back-to-top, mobile toggle) → Tasks 1 + 7
- All 33 anchor IDs preserved → all Tasks (no anchors renamed)

**No placeholders found.**

**Type consistency:** CSS class names used consistently throughout: `.ep`, `.ep-hd`, `.ep-path`, `.ep-auth`, `.ep-label`, `.tab-bar`, `.tab-btn`, `.tab-pane`, `.callout`, `.callout-accent/.warn/.info`, `.callout-label`, `.step`, `.step-num`, `.step-body`, `.step-title`, `.step-time`, `.flow`, `.flow-nodes`, `.flow-node.hl`, `.flow-arrow`, `.flow-caption`, `.paths`, `.path-card`.
