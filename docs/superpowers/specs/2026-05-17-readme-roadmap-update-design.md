---
name: readme-roadmap-update
description: Reorganise README Roadmap into Shipped/Planned sections and update Recent Achievements with dated release groups
metadata:
  type: project
---

# README Roadmap Update — Design Spec

**Date**: 2026-05-17
**Scope**: README.md only — Roadmap section and footer line

## Goal

The README Roadmap section is stale (last updated October 2025). Three features have shipped since then — content_type on secrets, key wrap/unwrap, and certificate auto-renewal — plus several security hardening fixes. The section should reflect this accurately and be easy to keep current going forward.

## Changes

### 1. Split Roadmap into two subsections

Replace the current two subsections (`### Planned Enhancements` and `### Recent Achievements (October 2025)`) with:

- `### Shipped` — all completed work, grouped by approximate release wave
- `### Planned` — unchanged list of future items (no items removed)

### 2. Shipped section — dated release groups

Items are grouped by wave with an inline italic date label. No per-line date — one label covers the whole group.

**Wave 1 — Oct 2025** (existing items, unchanged text):
- Complete domain-driven design architecture (A grade)
- Service container integration (95% compatibility)
- Database performance optimization (90%+ improvement)
- Comprehensive testing suite (50+ test cases, 94.9% coverage)
- Enterprise-grade connection pooling and monitoring
- Production-ready deployment with performance tuning
- Robust logging with automatic directory creation and graceful fallbacks
- Backup encryption flag fix for proper unencrypted backup support

**Wave 2 — Feb–May 2026** (new items derived from git log):
- Secret `content_type` field — domain, schema, repository, service validation, API and CLI
- Key wrap/unwrap operations — CryptoService, HTTP endpoints, CLI subcommands
- Certificate auto-renewal — ExpiresAt field, RenewalScheduler, HTTP API, CLI flags
- Security hardening: crypto/rand enforcement, role self-promotion blocking, ownership enforcement on rotation

### 3. Footer line update

Change:

```
**Status**: Production-Ready | **Architecture Grade**: A (94/100) | **Last Updated**: October 2025
```

To:

```
**Status**: Production-Ready | **Architecture Grade**: A (94/100) | **Last Updated**: May 2026
```

## Out of Scope

- No changes to any section other than Roadmap and the footer line.
- No changes to the Planned items list content (only reheading from "Planned Enhancements" to "Planned").
- No changes to CLAUDE.md, architecture docs, or any other file.

## Success Criteria

- README builds (renders correctly in Markdown).
- Roadmap section has exactly two subsections: `### Shipped` and `### Planned`.
- Shipped section contains two dated wave groups.
- Footer "Last Updated" reads May 2026.
- No other README content is altered.
