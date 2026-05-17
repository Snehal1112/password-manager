# Kopano MSP Agent Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a v1 copilot for Kopano Cloud that sources MSP leads, qualifies them, drafts outreach, manages follow-up tasks, and generates lightweight campaign content without auto-sending.

**Architecture:** Create a small standalone application inside this repository with a React frontend, a Go HTTP API, and workflow connectors for sheets and email drafts. Keep agent responsibilities separated into sourcing, qualification, outreach, and campaign services behind one review UI and one shared lead model.

**Tech Stack:** Go, SQLite, React, TypeScript, Vite, OpenAI API, Google Sheets or Airtable connector, Gmail/Outlook draft integration, Docker Compose

---

### Task 1: Scaffold the standalone app

**Files:**
- Create: `apps/kopano-msp-agent/README.md`
- Create: `apps/kopano-msp-agent/docker-compose.yml`
- Create: `apps/kopano-msp-agent/backend/go.mod`
- Create: `apps/kopano-msp-agent/backend/cmd/server/main.go`
- Create: `apps/kopano-msp-agent/frontend/package.json`
- Create: `apps/kopano-msp-agent/frontend/src/main.tsx`

**Step 1: Write the failing smoke check**

Create `apps/kopano-msp-agent/README.md` with a short “expected endpoints and UI routes” section that defines the initial contract:
- backend health route `/health`
- frontend routes `/leads`, `/campaigns`, `/settings`

**Step 2: Run a missing-file check**

Run: `rg "kopano-msp-agent" apps/kopano-msp-agent -n`
Expected: no results before scaffold files exist

**Step 3: Write minimal scaffold**

Create:
- backend module with an HTTP server exposing `/health`
- frontend Vite app rendering a placeholder page with links for `Leads`, `Campaigns`, and `Settings`
- Docker Compose file wiring frontend, backend, and SQLite volume

**Step 4: Run the smoke check**

Run: `go test ./...`
Expected: existing repository tests still pass and new module compiles when added to its own directory structure

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent
git commit -m "feat: scaffold kopano msp agent app"
```

### Task 2: Define the lead data model and storage

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/leads/model.go`
- Create: `apps/kopano-msp-agent/backend/internal/leads/store.go`
- Create: `apps/kopano-msp-agent/backend/internal/leads/store_test.go`
- Create: `apps/kopano-msp-agent/backend/internal/db/sqlite.go`

**Step 1: Write the failing test**

Add tests for:
- creating a lead
- updating status
- filtering by market
- filtering by outreach stage

Example fields to assert:
- `company_name`
- `market`
- `company_type`
- `lead_score`
- `recommended_angle`
- `next_followup_date`

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/leads -v`
Expected: FAIL because model and store do not exist yet

**Step 3: Write minimal implementation**

Implement:
- lead struct
- SQLite table creation
- CRUD methods
- simple filters by status, market, and stage

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/leads -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/leads apps/kopano-msp-agent/backend/internal/db
git commit -m "feat: add lead model and storage"
```

### Task 3: Build sourcing input and enrichment pipeline

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/sourcing/service.go`
- Create: `apps/kopano-msp-agent/backend/internal/sourcing/service_test.go`
- Create: `apps/kopano-msp-agent/backend/internal/sourcing/prompts.go`
- Create: `apps/kopano-msp-agent/backend/internal/http/sourcing_handler.go`

**Step 1: Write the failing test**

Test:
- ingesting a company URL
- storing source URL
- extracting company-level notes
- setting low-confidence flags when content is sparse

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/sourcing -v`
Expected: FAIL because sourcing service is missing

**Step 3: Write minimal implementation**

Implement:
- input endpoint accepting company URL and market hint
- basic website fetch adapter interface
- extraction pipeline for visible service signals
- safe placeholder parser that records findings without inventing contacts

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/sourcing -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/sourcing apps/kopano-msp-agent/backend/internal/http/sourcing_handler.go
git commit -m "feat: add lead sourcing ingestion flow"
```

### Task 4: Implement qualification and lead scoring

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/qualification/service.go`
- Create: `apps/kopano-msp-agent/backend/internal/qualification/service_test.go`
- Create: `apps/kopano-msp-agent/backend/internal/qualification/rules.go`

**Step 1: Write the failing test**

Test that:
- a business IT provider with cloud/email signals qualifies
- a generic agency does not
- EU and India market tags remain separate
- a recommended angle is always selected for qualified leads

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/qualification -v`
Expected: FAIL because qualification service is missing

**Step 3: Write minimal implementation**

Implement:
- rule-based ICP checks
- score calculation
- angle selection
- low-confidence and manual-review paths

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/qualification -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/qualification
git commit -m "feat: add qualification and scoring"
```

### Task 5: Add outreach sequence generation

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/outreach/service.go`
- Create: `apps/kopano-msp-agent/backend/internal/outreach/service_test.go`
- Create: `apps/kopano-msp-agent/backend/internal/outreach/prompts.go`
- Create: `apps/kopano-msp-agent/backend/internal/http/outreach_handler.go`

**Step 1: Write the failing test**

Test:
- first email includes the selected angle
- CTA defaults to demo
- trial is offered as secondary CTA
- follow-up sequence is generated with three stages
- EU and India templates differ

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/outreach -v`
Expected: FAIL because outreach service is missing

**Step 3: Write minimal implementation**

Implement:
- prompt builder
- structured output parser
- 3-email sequence generation
- reply classification templates for `pricing`, `trial`, `demo`, and `not now`

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/outreach -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/outreach apps/kopano-msp-agent/backend/internal/http/outreach_handler.go
git commit -m "feat: add outreach generation service"
```

### Task 6: Add follow-up scheduling logic

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/followups/service.go`
- Create: `apps/kopano-msp-agent/backend/internal/followups/service_test.go`
- Modify: `apps/kopano-msp-agent/backend/internal/leads/model.go`
- Modify: `apps/kopano-msp-agent/backend/internal/leads/store.go`

**Step 1: Write the failing test**

Test:
- default follow-up dates for no-reply leads
- different next actions for `wants demo`, `wants trial`, `not now`, and `not fit`
- closed leads do not get rescheduled

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/followups -v`
Expected: FAIL because scheduling service is missing

**Step 3: Write minimal implementation**

Implement:
- stage-based follow-up rules
- reply classification mapping
- next task generation
- lead updates for `last_contact_date` and `next_followup_date`

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/followups -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/followups apps/kopano-msp-agent/backend/internal/leads
git commit -m "feat: add followup scheduling"
```

### Task 7: Build campaign content generation

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/campaigns/service.go`
- Create: `apps/kopano-msp-agent/backend/internal/campaigns/service_test.go`
- Create: `apps/kopano-msp-agent/backend/internal/campaigns/prompts.go`
- Create: `apps/kopano-msp-agent/backend/internal/http/campaigns_handler.go`

**Step 1: Write the failing test**

Test:
- generating campaign copy by market
- generating newsletter ideas from recent lead data
- producing weekly summaries by angle and segment

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/campaigns -v`
Expected: FAIL because campaign service is missing

**Step 3: Write minimal implementation**

Implement:
- campaign prompt templates
- summary generator
- angle-based content suggestion service

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/campaigns -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/campaigns apps/kopano-msp-agent/backend/internal/http/campaigns_handler.go
git commit -m "feat: add campaign content generation"
```

### Task 8: Add review and approval UI

**Files:**
- Create: `apps/kopano-msp-agent/frontend/src/App.tsx`
- Create: `apps/kopano-msp-agent/frontend/src/routes/leads.tsx`
- Create: `apps/kopano-msp-agent/frontend/src/routes/campaigns.tsx`
- Create: `apps/kopano-msp-agent/frontend/src/routes/settings.tsx`
- Create: `apps/kopano-msp-agent/frontend/src/lib/api.ts`

**Step 1: Write the failing UI expectation**

Define the initial UI contract:
- leads table with filters
- lead detail with score, angle, and drafts
- approve/reject draft controls
- campaigns page for content generation
- settings page for CTA and prompt configuration

**Step 2: Run a build check to verify it fails**

Run: `cd apps/kopano-msp-agent/frontend && npm run build`
Expected: FAIL because routes and app files do not exist yet

**Step 3: Write minimal implementation**

Implement:
- basic routed UI
- review panel for lead and outreach draft
- approval actions that update lead status but do not send mail

**Step 4: Run build to verify it passes**

Run: `cd apps/kopano-msp-agent/frontend && npm run build`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/frontend
git commit -m "feat: add review ui for leads and campaigns"
```

### Task 9: Add Sheets/Airtable and email-draft connectors

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/integrations/sheets.go`
- Create: `apps/kopano-msp-agent/backend/internal/integrations/email_drafts.go`
- Create: `apps/kopano-msp-agent/backend/internal/integrations/integrations_test.go`
- Modify: `apps/kopano-msp-agent/backend/cmd/server/main.go`

**Step 1: Write the failing test**

Test:
- exporting qualified leads to a shared table
- creating an email draft payload from approved outreach
- refusing to send when only draft mode is enabled

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/integrations -v`
Expected: FAIL because integration adapters are missing

**Step 3: Write minimal implementation**

Implement:
- connector interfaces
- one concrete Sheets or Airtable adapter
- one Gmail or Outlook draft adapter
- config flag enforcing draft-only mode

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/integrations -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/integrations apps/kopano-msp-agent/backend/cmd/server/main.go
git commit -m "feat: add crm and email draft integrations"
```

### Task 10: Add prompt and policy configuration

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/config/config.go`
- Create: `apps/kopano-msp-agent/backend/internal/config/config_test.go`
- Create: `apps/kopano-msp-agent/.env.example`
- Modify: `apps/kopano-msp-agent/frontend/src/routes/settings.tsx`

**Step 1: Write the failing test**

Test:
- loading region-specific prompt settings
- loading CTA priority settings
- loading draft-only safety policy

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/config -v`
Expected: FAIL because config loader is missing

**Step 3: Write minimal implementation**

Implement:
- environment-backed config
- policy flags
- prompt version fields
- settings UI bindings

**Step 4: Run test to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/internal/config -v`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/backend/internal/config apps/kopano-msp-agent/.env.example apps/kopano-msp-agent/frontend/src/routes/settings.tsx
git commit -m "feat: add prompt and policy configuration"
```

### Task 11: Add end-to-end smoke tests and operator docs

**Files:**
- Create: `apps/kopano-msp-agent/backend/internal/e2e/smoke_test.go`
- Modify: `apps/kopano-msp-agent/README.md`
- Create: `apps/kopano-msp-agent/docs/operator-runbook.md`

**Step 1: Write the failing test**

Create a smoke test covering:
- ingest company URL
- qualify lead
- generate outreach
- approve draft
- create draft payload
- schedule follow-up

**Step 2: Run test to verify it fails**

Run: `go test ./apps/kopano-msp-agent/backend/internal/e2e -v`
Expected: FAIL because the end-to-end workflow is incomplete

**Step 3: Write minimal implementation**

Implement:
- test fixtures
- happy-path orchestration
- operator runbook for daily usage
- README setup and local run instructions

**Step 4: Run verification to verify it passes**

Run: `go test ./apps/kopano-msp-agent/backend/... -v`
Expected: PASS

Run: `cd apps/kopano-msp-agent/frontend && npm run build`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent
git commit -m "feat: document and verify kopano msp agent v1"
```

### Task 12: Launch with a controlled pilot

**Files:**
- Create: `apps/kopano-msp-agent/docs/pilot-checklist.md`
- Modify: `apps/kopano-msp-agent/docs/operator-runbook.md`

**Step 1: Write the pilot checklist**

Include:
- first 25 target companies
- approval owner
- message QA checklist
- success metrics for 2-week pilot

**Step 2: Review pilot readiness**

Run: `rg "TODO|FIXME" apps/kopano-msp-agent -n`
Expected: no unresolved critical placeholders in the pilot path

**Step 3: Write minimal pilot documentation**

Document:
- daily sourcing quota
- approval workflow
- follow-up cadence
- weekly reporting format

**Step 4: Run final verification**

Run: `go test ./apps/kopano-msp-agent/backend/... -v`
Expected: PASS

Run: `cd apps/kopano-msp-agent/frontend && npm run build`
Expected: PASS

**Step 5: Commit**

```bash
git add apps/kopano-msp-agent/docs
git commit -m "docs: add kopano msp agent pilot checklist"
```
