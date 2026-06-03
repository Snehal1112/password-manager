# RocketVault Administrator Manual v2 — Design Spec

**Date:** 2026-06-03
**Status:** Approved (design phase)
**Supersedes:** the initial manual built per `2026-06-03-admin-manual-design.md`
**Target file:** `docs/admin-manual.html` (rework in place)

---

## Problem

The current `docs/admin-manual.html` (≈900 lines) summarizes ~5,000 lines of source docs.
Two gaps, confirmed by the maintainer:

1. **Shallow content** — sections give a couple of curl examples and defer to source docs.
   No request/response examples, expected outputs, parameter tables, or error/status codes.
   It does not read as a self-contained, production-grade reference.
2. **Static presentation** — only sidebar scroll-spy and the Markdown viewer. No search,
   no copy buttons, no per-endpoint detail, no tabbed examples, no collapsible depth.

## Goal

Rework the manual into a **deeper, interactive, production-grade** administrator manual that
**supersedes `MANUAL_TESTING.md`** (which becomes a thin pointer). All 24 feature sections
reach full self-contained depth, with real request/response examples and an interactive
presentation layer.

## Decisions (locked)

| Decision | Choice |
|----------|--------|
| Content depth | Full depth, all 24 sections (supersede MANUAL_TESTING.md) |
| Example JSON source | Captured from a live local server (real responses, secrets redacted) |
| Interactivity | Search, copy-on-code, tabbed CLI/API/Response, collapsible subsections, per-endpoint cards, small back-to-top |
| Dropped (YAGNI) | Dark mode, hover-anchors, reading-progress bar |
| Format | Single self-contained `docs/admin-manual.html`, same design system |

## Interactive features (presentation layer)

1. **Instant search / filter (⌘K)** — a search box (keyboard-shortcut focusable) that filters
   the sidebar and scrolls to matching sections/endpoints as the user types. Pure client-side
   over the in-page section/heading/endpoint text. No external dependency.
2. **Copy-to-clipboard** — every `pre.code` block gets a "Copy" button (uses
   `navigator.clipboard`; falls back to a select-text hint where unavailable).
3. **Tabbed CLI / API / Response** — each operation card has up to three tabs (cURL, CLI,
   Response). Vanilla JS tab switcher; first tab shown by default.
4. **Collapsible subsections** — native `<details>/<summary>` for "Example response", "Errors",
   and other long blocks, so depth does not overwhelm. Closed by default except the primary
   example.
5. **Per-endpoint detail cards** — each endpoint rendered as a card: color-coded method badge
   (GET/POST/PUT/PATCH/DELETE), path, auth pill, params table (field/type/notes), tabbed
   examples, collapsible response + errors.
6. **Back-to-top** — a small floating button after the user scrolls down.

The existing **scroll-spy sidebar** and **Markdown doc viewer** (the `marked`-based panel from
the prior commit) are kept.

## Per-section template (every feature section)

```
<h2> N. Title
One-line definition (+ Azure KV parity note where relevant)
When to use it — operational guidance
Operations:
  one endpoint-card per endpoint:
    [METHOD badge] path  [auth pill]  short label
    tabs: cURL | CLI | Response
    params table (field / type / notes)
    <details> Example response (200) — captured live
    <details> Errors — status codes + meaning
Configuration — relevant .rocketvault.yaml keys (table)
Notes & troubleshooting
See also — deep-dive links
```

Summary-only sections (Performance Internals, Multi-Environment) keep prose + see-also,
no endpoint cards.

## Production-readiness framing (new)

- **Header metadata:** product name, version, "Last updated" date, a one-line positioning
  statement.
- **Before you begin:** a prerequisites block (tools, config, server running, admin bootstrapped).
- **Quick Start / End-to-End Walkthrough:** a new early section taking an operator from zero —
  install → bootstrap admin → login (TOTP) → create a vault → store a secret → create a service
  account → grant access → consume the secret — as one continuous, copy-pasteable story using
  live-captured output.
- **Consistent terminology** and **redaction convention** (secrets/keys shown as
  `<redacted>`/placeholder, never real values).

## Data capture (live server)

Before authoring endpoint cards, run the server locally and capture real responses:

1. Build and start the server (`go run main.go serve`) against a throwaway SQLite DB.
2. Bootstrap an admin (CLI `users admin`), register/derive TOTP with `oathtool`, log in.
3. Exercise each endpoint group (secrets, versions, keys, certs, vaults, users, sessions,
   access-policies, service-accounts, audit, health, jwks, deleted/restore/purge, backup).
4. Record the real JSON responses; redact secret values, key material, tokens, and TOTP
   secrets to placeholders. Normalize volatile fields (ids/timestamps) to readable sample values.
5. These captured payloads populate the "Response" tabs and example blocks.

Capture tooling: `oathtool`, `jq`, `curl` (all present). If the existing dev admin's TOTP is
unknown, bootstrap a fresh admin on a throwaway DB for capture.

## Supersede MANUAL_TESTING.md

Once the manual carries the full endpoint detail, `MANUAL_TESTING.md` is reduced to a short
pointer ("This guide has moved into the Administrator Manual — see docs/admin-manual.html")
plus, optionally, the raw endpoint table. The manual's "See also" links to MANUAL_TESTING.md
are updated so they no longer imply it holds the canonical detail.

## Non-goals

- No changes to RocketVault server code.
- No server-side rendering / build pipeline — the manual stays a single static HTML file.
- No dark mode, hover-anchors, or progress bar.
- Not deleting the other deep-dive docs (consuming-secrets, integration-examples, hsm); they
  remain linked.

## Success criteria

- `docs/admin-manual.html` opens as one file; all 24 sections present at full depth.
- Search filters the sidebar and jumps to matches; every code block has a working Copy button;
  operation cards have working CLI/API/Response tabs; collapsibles expand/collapse.
- Endpoint cards show params, **live-captured** example responses, and error/status codes.
- A Quick Start walkthrough runs end-to-end from install to consuming a secret.
- Header shows version + last-updated; a prerequisites block is present.
- Example JSON contains no real secrets/keys/tokens (redacted).
- Structural integrity: every sidebar link resolves to a section id; no duplicate ids; valid,
  balanced HTML; inline JS passes `node --check`.
- Verified in a real browser (served over http): search, copy, tabs, collapsibles, and the
  Markdown viewer all work; no console errors.

## Build approach

Large enough to warrant a phased plan: (1) capture live data, (2) build the interactive
scaffold (search, tabs, copy, cards, back-to-top) + production framing, (3) fill sections
part-by-part using captured data, (4) supersede MANUAL_TESTING.md, (5) full browser
verification. Executed subagent-driven, like the prior manual.
