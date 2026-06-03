# RocketVault Administrator Manual — Design Spec

**Date:** 2026-06-03
**Status:** Approved (design phase)
**Author:** Brainstormed with the maintainer

---

## Goal

Produce a single, authoritative **Administrator Manual** for RocketVault that explains
every feature operationally — what it is, when to use it, how an admin operates it, how
to configure it, and how to troubleshoot it. The manual becomes the canonical entry
point; the existing scattered docs are retained as linked deep-dives.

## Decisions (locked)

| Decision | Choice |
|----------|--------|
| Purpose | Single authoritative handbook (one operational entry point for all features) |
| Format | Single self-contained styled HTML page |
| Styling | Reuse the design system of `docs/rocketvault-architecture.html` (IBM Plex fonts, CSS variable palette, surfaces/borders), inline `<style>`, minimal vanilla JS |
| Coverage | Everything, including client/consumer integration folded in |
| Depth | Self-contained / supersede — manual is the source of truth; older docs become "See also" deep-dives |
| Sidebar | Grouped into 5 parts with scroll-spy highlighting |

## Output

- **File:** `docs/admin-manual.html`
- Self-contained: all CSS inline; only external dependency is Google Fonts (same as the
  architecture page). Minimal vanilla JS for sidebar scroll-spy and collapsible
  subsections. No build step, no runtime framework.

## Layout

- Fixed left **sidebar nav**: 5 grouped parts, each listing its feature sections, with
  scroll-spy highlighting the current section. Appendices listed at the bottom.
- Main content column: one `<section id="…">` per feature with a stable anchor.
- Sticky top bar with the manual title.

## Per-section template

Every feature section follows the same internal structure for predictability:

1. **What it is** — concise definition, Azure Key Vault parity note where relevant.
2. **When to use it** — operational guidance / scenarios.
3. **Admin operations** — CLI and API shown together (commands + curl).
4. **Configuration** — the relevant `.rocketvault.yaml` keys.
5. **Notes & troubleshooting** — gotchas, status codes, common errors.
6. **See also** — links to the deep-dive doc(s).

## Section outline

### Part I — Getting Started
1. Introduction & Mental Model (purpose, Azure KV parity, layered architecture)
2. Installation & First Run (prerequisites, `serve`, config location, environment modes)
3. Bootstrap — First Admin User (`POST /api/v1/users/admin` + `users admin` CLI, TOTP setup)
4. Configuration Reference (table of every top-level `.rocketvault.yaml` section: security,
   jwt, database, log, rate_limit, server, monitoring, health, development, retry,
   soft_delete, key_cache, oauth2, vault_client, frontend, hsm)

### Part II — Identity & Access
5. Authentication (login, TOTP/MFA, refresh tokens, sessions, revocation)
6. JWT Signing & Key Sources (os_store / self_pki / external_pki, JWKS, rotation, OS keychain)
7. User Management
8. RBAC & Access Policies (roles, principals, resource/operation/effect model)
9. OAuth2 Service Accounts (machine identities, client-credentials flow, rotation, expiry)

### Part III — Core Resources
10. Secrets (CRUD, generate, import/export, tags)
11. Secret Versions
12. Secret Rotation (policies, assign/unassign, history, reminders — CLI-driven)
13. Keys (RSA/ECDSA with correct `bits`/`curve`, wrap/unwrap, sign/verify, encrypt/decrypt,
    rotate, versions)
14. Certificates & Certificate Policies (self-signed, lifecycle, auto-renew policy, CLI `renew`)
15. Multi-Vault (vault management, vault-scoped routes, "members see all" vs per-user, default vault)
16. Soft-Delete, Restore & Purge (retention, purge protection, vault-scoped vs flat)

### Part IV — Operations & Governance
17. Audit Logs & Compliance (hash-chained logs, query filters, SOC2/GDPR reports, audit config)
18. Backup & Restore (full backups + per-item backup/restore)
19. HSM / PKCS#11 (SoftHSM2 setup, supported algorithms)
20. Health & Monitoring (probes, database health, monitoring config)
21. Rate Limiting
22. Performance Internals (caching, retry/circuit-breaker) — **summary + deep-link**
23. Database Migrations (`migrate`, `migrate:status`, `migrate:to`, `migrate:create`)
24. API Versioning (v1 deprecated → v2, sunset behavior)

### Part V — Integration (consumer-facing, folded in)
25. Consuming Secrets in Your Application (Go `vaultclient`, shell, direct HTTP)
26. CI/CD Integration (GitHub Actions, Jenkins — condensed)
27. Multi-Environment & Automation (rotation scripts, promotion, Prometheus exporter) —
    **summary + deep-link**

### Appendices
- A. Complete Endpoint Reference (full table)
- B. Complete CLI Command Tree
- C. Troubleshooting Matrix (consolidated)
- D. Security Checklist

## Accuracy requirements (verified against code, not docs)

The manual must reflect the real feature surface confirmed by code inspection:

- **Key creation:** `type` (RSA/ECDSA), `bits` for RSA (2048/3072/4096), `curve` for ECDSA
  (P-256/P-384/P-521). Fixes the known `bits` discrepancy in `MANUAL_TESTING.md`.
- **Admin bootstrap:** correct route `POST /api/v1/users/admin`.
- **Previously-undocumented subsystems to include:** key cache + secret cache
  (`key_cache.*`), retry/circuit-breaker (`retry.*`), API versioning (v1 deprecated → v2,
  sunset middleware), certificate policies (auto-renew), vault-name collision resolution,
  `vaults recover` / `vaults purge` CLI, `migrate:status` / `migrate:to` / `migrate:create`.
- **Full route inventory:** 11 subsystems (vaults, secrets, users, keys, certificates,
  health, deleted, access-policies, service-accounts, audit, oauth2/jwks/config) plus
  vault-scoped resource routes.

## Source docs absorbed / linked

| Existing doc | Treatment |
|--------------|-----------|
| `MANUAL_TESTING.md` | Endpoint walkthroughs absorbed; linked as testing deep-dive |
| `docs/consuming-secrets-guide.md` | Folded into §25; linked |
| `docs/integration-examples.md` | Condensed into §§25–27; linked for full language examples |
| `docs/hsm-softhsm2-testing.md` | Folded into §19; linked for full SoftHSM2 setup |
| `docs/rocketvault-architecture.html` | Distilled into §1; linked for full architecture |
| `docs/cli-guide.md`, `docs/api-developer-guide.md` | Linked from relevant sections + appendices |
| `doc/README_ADMIN_SETUP.md` | Folded into §3; linked |

## Non-goals

- No code changes to RocketVault itself.
- No automated doc-generation pipeline (manual is hand-authored HTML for this iteration).
- Sections 22 and 27 are intentionally summary + deep-link rather than fully inline.

## Success criteria

- One openable `docs/admin-manual.html` covering all 24 feature sections + 4 appendices.
- Sidebar navigation works (scroll-spy, anchor links) with the 5-part grouping.
- Every feature section follows the per-section template.
- Technical details match the code (key params, routes, CLI tree, config keys).
- Visual consistency with the architecture page.
