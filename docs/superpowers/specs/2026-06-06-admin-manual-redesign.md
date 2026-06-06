# Admin Manual Redesign Spec

**Date:** 2026-06-06
**File:** `docs/admin-manual.html` (single file, in-place replacement)
**Status:** Approved for implementation

---

## Goal

Replace the current 1451-line reference manual with a fully redesigned single-page HTML doc that serves both:
- **New admins** — setting up RocketVault for the first time
- **App developers** — integrating an app that reads secrets

All 28 existing sections must be preserved. No content removed — only restructured and enhanced.

---

## Visual Design

### Theme
- **Dark developer theme** — background `#0D1117`, surface layers `#161B22` / `#1C2230` / `#21283A`
- **Typography** — Inter (body) + Fira Code (mono), loaded from Google Fonts
- **Accent** — `#4ECCA3` (teal/green) for active states, highlights, step numbers
- **Secondary accents** — `#58A6FF` (info), `#F0A84B` (warnings), `#F85149` (danger/delete)

### Background texture (main content panel)
- Soft teal radial glow top-right: `radial-gradient(ellipse 80% 40% at 60% -10%, rgba(78,204,163,.07), transparent 60%)`
- Soft blue radial glow bottom-right: `radial-gradient(ellipse 50% 30% at 90% 80%, rgba(88,166,255,.05), transparent 55%)`
- Subtle dot-grid SVG pattern at `rgba(255,255,255,0.025)` — 40×40px repeat

### Sidebar
- Width: 260px, sticky, `#161B22` background, right border `rgba(255,255,255,.08)`
- Brand block: `R` logo tile (teal), name + version
- Search input (keyboard shortcut `/`)
- Grouped nav with section group labels (uppercase, muted)
- Active item: teal left border + teal text + dim accent background
- Badge chips for time estimates on quick-start items

---

## Information Architecture

### Sidebar groups (replaces flat 28-item list)

```
Getting Started
  Quick Start           [5 min badge]
  Installation & Config
  Mental Model

Identity & Access
  Authentication
  JWT Signing
  Users
  RBAC & Policies
  Service Accounts

Core Resources
  Secrets & Versions
  Secret Rotation
  Keys
  Certificates
  Soft-Delete & Purge

Operations
  Audit & Compliance
  Backup & Restore
  Health & Monitoring
  Rate Limiting
  HSM / PKCS#11
  Performance

Integration
  Consuming Secrets
  CI/CD
  Multi-Environment

Reference
  Endpoint Index
  CLI Command Tree
  Troubleshooting
  Security Checklist
```

---

## Per-Section Content Pattern

Every section must follow this structure:

1. **Page header** — title + meta chips (time estimate, audience badges where relevant)
2. **WHAT IT IS** — 1-sentence plain-English description
3. **WHEN TO USE** — 1–2 bullet decision triggers (when would I reach for this?)
4. **Operations** — endpoint cards with cURL / CLI / Response tabs (preserved from current)
5. **WHY THIS WORKS callout** — security/design rationale (1–2 sentences, info style)
6. **SEE ALSO** footer — links to related sections

Quick Start additionally gets:
- **Audience path cards** — "I'm setting up RocketVault" vs "I'm building an app" — each listing its step sequence
- **WHAT YOU'LL BUILD callout** — end-state description in plain English
- **Flow diagram** — HTML/CSS visual showing: Your App → OAuth2 Token → RocketVault API → AES-256 Store, with explanatory caption
- **WHAT'S NEXT callout** — branching "new admin" and "developer" paths with links

---

## Component Specs

### Step blocks (Quick Start + guided sections)
```
[num badge] Step title                    ~Xs
            Description sentence
            [code block]
            [optional callout]
```
- Number badge: 30×30px, `#1C2230` bg, `#4ECCA3` text, rounded 8px, teal border
- Vertical connector line between steps: 1px `rgba(255,255,255,.14)`, left-aligned under badge
- Time estimate chip: monospace, `#484F58` text, right-aligned in step title row

### Callout boxes
Three variants — all share: rounded 8px, left-label (`font-size:10px; uppercase; letter-spacing:.08em`)

| Variant | bg | border | label color | use for |
|---|---|---|---|---|
| accent | `rgba(78,204,163,.15)` | `rgba(78,204,163,.3)` | `#4ECCA3` | "What you'll build", "What's next" |
| warn | `rgba(240,168,75,.12)` | `rgba(240,168,75,.3)` | `#F0A84B` | TOTP warnings, one-time secrets |
| info | `rgba(88,166,255,.12)` | `rgba(88,166,255,.3)` | `#58A6FF` | "Why this works" rationale |

### Code blocks
- Header row: language label (left) + Copy button (right), `#1C2230` bg, border bottom none
- Body: `#1C2230` bg, `#4ECCA3` default text, syntax tints: strings `#F0A84B`, keywords `#58A6FF`, comments `#484F58`
- Copy button: wired to `navigator.clipboard.writeText`, "Copied!" feedback for 1.5s
- No header row for inline single-line blocks inside steps

### Endpoint cards (preserved, restyled)
- Outer border `rgba(255,255,255,.08)`, rounded 8px
- Header: method badge (colored) + path + auth badge + label, `#1C2230` bg
- Method badge colors: GET `#16A34A`, POST `#2563A8`, PUT `#B97D0D`, PATCH `#6B5ED4`, DELETE `#C2460C`
- Tab bar: cURL / CLI / Response / (Errors collapsible)
- Active tab: teal bottom border + teal text
- Auth badge (JWT / Basic / none): teal pill

### Flow diagram
- Container: `#161B22` bg, border, rounded 10px, padding 20px
- Nodes: `#1C2230` bg, border, rounded 8px, 90px min-width
- Highlighted node (RocketVault API): teal border + teal text + dim accent bg
- Arrows: `→` in muted color between nodes
- Caption below: 11px muted text explaining admin vs service account auth difference

### Audience path cards (Quick Start only)
- 2-column grid
- Each card: `#161B22` bg, border, rounded 10px, hover teal border
- Icon + title + description + step-sequence chips
- Step chips: monospace, `#1C2230` bg, muted text

---

## JavaScript Behavior

- **Tab switching** — `.tab-btn` / `.tab-pane` active class toggle, scoped to nearest `.tabs-wrap`
- **Copy buttons** — `navigator.clipboard.writeText(pre.innerText)`, "Copied!" → "Copy" after 1.5s
- **Search** — filter sidebar items by text, hide non-matching `.sb-item` and empty `.sb-group` labels; show `.search-empty` if nothing matches
- **Active nav highlighting** — `IntersectionObserver` on each `<section>`, updates `.sb-item.active` as user scrolls
- **Back-to-top button** — fixed bottom-right, appears after 300px scroll
- **Mobile sidebar toggle** — hamburger button, sidebar slides in/out via `translateX`, closes on overlay click
- **Keyboard shortcut** — `/` focuses search input

---

## Sections to enhance beyond current content

These sections currently have thin "What it is" content — add proper callouts and rationale:

| Section | Add |
|---|---|
| Authentication | Flow diagram of JWT lifecycle (login → refresh → revoke) |
| RBAC & Policies | Decision tree: "use a role" vs "use an access policy" |
| Service Accounts | "Why no TOTP?" rationale callout |
| Secrets | AES-256-GCM encryption callout (what "encrypted at rest" means) |
| Soft-Delete & Purge | Timeline diagram: active → soft-deleted → purged |
| Backup & Restore | Warning callout: backup includes master key material |

---

## What does NOT change

- All existing API endpoint paths, request/response examples, and CLI commands — preserved verbatim
- Section numbering in content (0–27 + appendices) — kept for link compatibility (anchor IDs unchanged)
- `see-also` links to external docs — kept
- Overall single-file HTML structure — no split into multiple files

---

## Implementation notes

- Single HTML file replacement — no new files, no build step
- All CSS inline in `<style>` block, all JS inline in `<script>` block
- Google Fonts CDN: Inter + Fira Code (same pattern as current IBM Plex load)
- `.superpowers/` should be in `.gitignore` (brainstorm artifacts)

---

## Out of scope

- Dark/light theme toggle (dark only)
- Search that queries content (filter sidebar only)
- Multi-page split
- Versioned docs
