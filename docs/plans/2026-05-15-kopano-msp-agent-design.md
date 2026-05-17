# Kopano MSP Agent Design

**Goal:** Design a first-version agent system for Kopano Cloud that helps source MSP/partner leads, draft outreach, manage follow-ups, and support marketing campaigns.

**Validated Scope**

- Product: Kopano Cloud
- Target segments: small local IT providers and mid-sized hosting/MSP companies
- Markets: EU-wide and India
- Language: English
- Primary CTA: book a demo
- Secondary CTA: 30-day free trial

**Positioning**
The strongest partner message from the public site is:

`A GDPR-friendly, partner-operable Microsoft 365 alternative for MSPs that want to host, brand, and scale their own collaboration service.`

Key proof points inferred from `https://www.kopano.cloud/`:

- MSP-ready multi-tenant architecture
- Native Outlook, web, and mobile connectivity
- GDPR and data-sovereignty positioning
- White-label and branding support
- OCI/container-based deployment
- LDAP/AD sync and REST API
- Migration and training services

## Approach Options

### Option 1: Single All-in-One Agent

One agent handles sourcing, qualification, outreach, follow-ups, and campaigns.

Pros:

- Fastest to assemble
- Lowest orchestration overhead

Cons:

- Hard to debug
- Weak control boundaries
- Harder to improve specific stages

### Option 2: Four Focused Agents

Separate agents for sourcing, qualification, outreach, and campaign/reporting.

Pros:

- Clear responsibilities
- Easier testing and tuning
- Better operational safety

Cons:

- More setup work
- Requires shared data model

### Option 3: Copilot-First System

Automation researches, scores, drafts, and schedules, but a human approves sensitive actions.

Pros:

- Lower brand and compliance risk
- Better quality control
- Easier to trust early

Cons:

- Less autonomous
- Slower than full auto-send

## Recommended Approach

Use Option 2 and Option 3 together:

- four focused agents
- human approval before sending emails or launching campaigns

This gives enough automation to create pipeline without losing control over outbound quality.

## Architecture

### 1. Lead Sourcing Agent

Responsibility:

- discover MSPs and hosting providers in EU and India
- collect public company and service signals

Inputs:

- search patterns
- directories
- public company websites

Outputs:

- candidate company records
- source URL
- initial segment guess

### 2. Lead Qualification Agent

Responsibility:

- decide whether a company matches the ICP
- score fit and pick the recommended messaging angle

Inputs:

- website copy
- service pages
- source metadata

Outputs:

- `lead_score`
- `company_type`
- `market`
- `recommended_angle`
- contact priority

### 3. Outreach Agent

Responsibility:

- draft first-touch outbound and follow-ups
- tailor messaging by market and segment

Inputs:

- qualified lead record
- recommended angle
- CTA policy

Outputs:

- email 1
- follow-up 1
- follow-up 2
- short reply variants

### 4. Campaign Agent

Responsibility:

- produce campaign ideas, segment-specific messaging, and performance summaries

Inputs:

- aggregate lead and outreach data
- market/segment filters

Outputs:

- partner campaign copy
- newsletter ideas
- landing page variants
- weekly summary

## Data Model

Each lead should include:

- `company_name`
- `website`
- `country`
- `market`
- `company_type`
- `services_detected`
- `m365_signal`
- `hosting_signal`
- `privacy_signal`
- `contact_name`
- `contact_role`
- `contact_email`
- `lead_score`
- `status`
- `outreach_stage`
- `last_contact_date`
- `next_followup_date`
- `notes`
- `recommended_angle`
- `cta`

Recommended statuses:

- `new`
- `researched`
- `qualified`
- `contacted`
- `replied`
- `demo_booked`
- `trial_offered`
- `closed_lost`
- `nurture`

Recommended outreach angles:

- GDPR/data sovereignty
- white-label partner offering
- Outlook-compatible Microsoft 365 alternative
- migration support
- multi-tenant scalable platform

## Workflow

### Source

Use search and directories to find MSPs and hosting providers with patterns such as:

- managed service provider email hosting europe
- hosted exchange provider germany
- IT support company microsoft 365 reseller
- business email hosting provider india
- cloud MSP SMB email migration

### Qualify

For each company:

- confirm it serves business customers
- confirm it sells cloud, infrastructure, or email-adjacent services
- determine whether it resembles a reseller or partner candidate
- assign the best outreach angle

### Draft Outreach

Create:

- first email
- follow-up 1
- follow-up 2
- reply-handling templates

CTA policy:

- primary CTA: book a demo
- secondary CTA: 30-day free trial

### Human Approval

Before send in v1:

- review the lead
- review the message
- approve or reject

### Follow-up Management

Classify replies as:

- wants demo
- wants pricing
- wants trial
- not now
- not fit

Schedule the next action from the reply class.

### Campaign Support

Generate:

- segmented partner campaigns
- landing page ideas
- MSP-focused content ideas
- weekly reports by segment and angle

## Market-Specific Guidance

### EU-Wide

Lead with:

- GDPR
- local hosting and data sovereignty
- partner control
- Microsoft 365 alternative

### India

Lead with:

- white-label opportunity
- flexibility and control
- customization and partner-hosted operation
- migration and enablement support

Do not mix EU and India messaging in the same base sequence.

## Guardrails

- The system may research, score, draft, and schedule.
- It must not auto-send emails in v1.
- It must not fabricate contacts or firmographic data.
- It must surface low-confidence fields explicitly.
- It must keep region-specific positioning separate.
- It must not spend advertising budget automatically.

## Success Metrics

- qualified MSP leads per week
- reply rate by segment
- demo booking rate
- trial interest rate
- best-performing outreach angle
- follow-up completion rate

## Recommended v1 Scope

Build only:

- lead sourcing
- qualification
- outreach draft generation
- follow-up task generation
- simple campaign copy generation
- shared CRM or sheet updates

Do not build first:

- autonomous send
- paid ads automation
- social autoposting
- complex multi-channel orchestration

## Recommended v1 Stack

- OpenAI model for reasoning and drafting
- Google Sheets or Airtable as lightweight CRM
- n8n for workflow orchestration
- Gmail or Outlook for draft creation and reply ingestion
- a small web app for review, approvals, and prompt/config control

## Decision

Start with an `MSP Partner Prospecting Copilot` that:

- ingests company websites
- classifies fit
- recommends the best angle
- drafts a 3-email sequence
- assigns follow-up dates
- generates weekly partner campaign ideas

This is the narrowest version that can realistically create outbound pipeline.
