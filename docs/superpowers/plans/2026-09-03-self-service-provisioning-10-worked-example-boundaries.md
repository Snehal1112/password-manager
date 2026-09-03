# Worked Example: Provisioning Boundaries — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A second §5 worked example proving the *negative* half of self-service provisioning — what a grantee cannot do — plus the audit and diagnostic checks, all captured live.

**Architecture:** No production code. Plan 09 showed the feature working; this one attacks it. Every step here is an attempt that must fail, because a bounded right is only as good as its boundary, and a boundary nobody tested is a claim rather than a property.

**Tech Stack:** the built `rocketvault` binary, `curl`, `jq`, `sqlite3`.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §4, §5

**Depends on:** `…-09-worked-example-lifecycle.md` — reuse its scratch-instance setup rather than describing it twice.
**Followed by:** nothing. This closes release 1's documentation.

## Global Constraints

- **Every refusal must be observed, not predicted.** A boundary example whose failures were written from the source is worthless — the whole point is catching the case where the code doesn't refuse.
- **A passing step here can be a bug report.** If an attempt that should fail succeeds, stop, record it, and raise it before writing anything else. Do not soften the document to match the behaviour.
- Never paste a real secret, token, TOTP secret or bootstrap token into the document.
- Use an isolated instance on a non-default port with an isolated `HOME`, per plan 09's constraints.
- `.claude/manual-testing-plan.md` is gitignored; do not `git add -f` without asking.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Run the boundary attempts

**Files:**
- Create: `/tmp/rv-prov/boundaries.log` (raw transcript, scratch only)

**Interfaces:**
- Consumes: plan 09's scratch instance, `msp-bot` grantee, `acme-prod` vault, and admin `$TOKEN`.
- Produces: a raw transcript task 2 turns into prose.

Run each attempt and record the exact status code and body. Expected outcome in
brackets — treat a mismatch as a finding, not as something to reconcile.

- [ ] **Step 1: Cross-vault denial**

As `msp-bot`, against a vault it did **not** create (`default`), attempt each of:

```bash
curl -s -w " [%{http_code}]\n" $BASE/vaults/default/secrets            -H "Authorization: Bearer $BOT_TOKEN"
curl -s -w " [%{http_code}]\n" -X PATCH $BASE/vaults/default          -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"description":"mine now"}'
curl -s -w " [%{http_code}]\n" -X DELETE $BASE/vaults/default         -H "Authorization: Bearer $BOT_TOKEN"
curl -s -w " [%{http_code}]\n" -X POST $BASE/vaults/default/role-assignments -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"principal":"msp-bot","role":"Key Vault Administrator"}'
```

[all `403`] The last one matters most: it is the self-escalation path. A grantee
that can grant itself a role in a vault it does not own has defeated the entire
model.

Repeat the same four through the CLI. The CLI bypasses `PolicyMiddleware`
entirely, so an HTTP `403` says nothing about the CLI path — they are separate
enforcement points and both must be checked.

- [ ] **Step 2: Self-quota escalation**

As `msp-bot`, attempt to raise its own quota and to revoke its own grant:

```bash
curl -s -w " [%{http_code}]\n" -X PUT $BASE/vault-provisioning-grants/$BOT_ID \
  -H "Authorization: Bearer $BOT_TOKEN" -H 'Content-Type: application/json' -d '{"quota":99}'
curl -s -w " [%{http_code}]\n" -X DELETE $BASE/vault-provisioning-grants/$BOT_ID \
  -H "Authorization: Bearer $BOT_TOKEN"
curl -s -w " [%{http_code}]\n" $BASE/vault-provisioning-grants -H "Authorization: Bearer $BOT_TOKEN"
```

[all `403`] Also try it via the CLI's `vault-provisioning grant` as `msp-bot`.

- [ ] **Step 3: Does holding a vault role help?**

Grant `msp-bot` `Key Vault Administrator` in `acme-prod` (it should already have
it from creation), then retry step 2. [still `403`] This is the check that
proves the grant tier is genuinely non-delegable rather than merely
role-gated — full data-plane authority in a vault confers nothing over grants.

- [ ] **Step 4: Revocation is not a cascade**

As admin, revoke `msp-bot`'s grant. Then as `msp-bot`:

```bash
# create a new vault           -> [403 or a clear "no grant" error]
# read a secret in acme-prod   -> [200: existing rights survive revocation]
# list vaults                  -> [200, still shows acme-prod]
```

Record all three. The surprise here is deliberate: revocation stops future
creation and nothing else.

- [ ] **Step 5: Verify the audit trail names somebody**

```bash
sqlite3 /tmp/rv-prov/rv.db \
  "SELECT action, outcome, user_id FROM audit_logs
   WHERE action LIKE '%provisioning_grant%' OR action='create_vault' ORDER BY rowid DESC LIMIT 10;"
```

Every row must carry a non-empty, non-zero `user_id`. The CLI has no middleware
to stamp an actor, so a command that discarded its authz helper's returned
principal produces a row naming nobody — that is the failure this check exists
to catch, and it is invisible from the command's own output.

- [ ] **Step 6: Verify the startup diagnostic**

Create a global `vaults:manage` policy by hand, restart, and confirm the warn
line from plan 08 names that principal:

```bash
curl -s -X POST $BASE/access-policies -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"principal_id\":\"$BOT_ID\",\"principal_type\":\"user\",\"resource_type\":\"vaults\",\"operation\":\"manage\",\"effect\":\"allow\"}"
# restart, then:
grep -i "global vaults:manage" /tmp/rv-prov/server.log
```

Then confirm what that policy now buys `msp-bot` — in release 1 it still confers
management of every vault. Record it. That is precisely the behaviour release 2
removes, and having it written down is what lets you diff the two releases.

---

### Task 2: Write the boundary example

**Files:**
- Modify: `.claude/manual-testing-plan.md` (§5, a second worked example after plan 09's)

**Interfaces:**
- Consumes: `/tmp/rv-prov/boundaries.log` from task 1.

- [ ] **Step 1: Write the concept blockquote**

Open `### Worked example: what a provisioning grantee cannot do`. The concept to
convey: the grant is bounded on three independent axes — **scope** (only vaults
it created), **count** (the quota), and **authority** (it cannot amend its own
grant) — and each is enforced in a different place. Scope is
`CanManageVault`/`HasDataAction`, count is inside `CreateVault`'s transaction,
authority is `requireGrantAdmin`. A reader who understands only "there's a
quota" will not know to test the other two.

- [ ] **Step 2: Write the walkthrough from the transcript**

Paste the real commands and real responses from task 1, in the order they were
run. Where a status code alone is the whole result, show it as `[403]` rather
than padding with an invented body.

- [ ] **Step 3: Write the gotchas section**

At minimum: revocation is not a cascade (step 4); an HTTP `403` does not imply a
CLI `403`, they are separate enforcement points (step 1); and a global
`vaults:manage` policy still confers instance-wide vault management in release 1
(step 6). Add anything the run actually surprised you with.

- [ ] **Step 4: Add a forward pointer to release 2**

State plainly that the narrowing has not shipped, name the startup diagnostic as
the way to find affected principals, and link the design doc's §2 and §9. A
reader running these steps must not conclude the escalation path is already
closed.

- [ ] **Step 5: Cross-link the two examples**

Plan 09's example ends where this one begins. Add a one-line pointer at the end
of plan 09's example and at the top of this one, so neither reads as the whole
story.

---

### Task 3: Integrate and verify the whole document

**Files:**
- Modify: `.claude/manual-testing-plan.md` (header note, §5 checklist dedupe)

**Interfaces:** none — documentation only.

- [ ] **Step 1: Dedupe against plan 08's checklist**

Plan 08 added a `- [ ]` checklist for provisioning in §5. That is intentional
and should stay — the document's pattern is a quick checklist plus deep worked
examples, exactly as §5 already does for vault lifecycle. But remove any
checklist item now fully covered by a worked example's walkthrough, and replace
it with a pointer, so the same procedure does not exist twice and drift.

- [ ] **Step 2: Update the header's reconciliation note**

The top-of-file note records what each pass added. Append this pass: two §5
worked examples for self-service provisioning, captured live, with the date.

- [ ] **Step 3: Verify the document end to end**

```bash
grep -c '^```' .claude/manual-testing-plan.md   # must be even: fences balanced
grep -n '^## ' .claude/manual-testing-plan.md   # section numbering still sequential
```

Then re-read §5 in full. Check that the three worked examples (vault lifecycle,
webhook, and the two new provisioning ones) do not contradict each other on
setup, and that no example assumes state another one tore down.

- [ ] **Step 4: Confirm no secrets leaked into the document**

```bash
grep -nE '"[A-Za-z0-9+/_-]{35,}={0,2}"' .claude/manual-testing-plan.md
grep -niE 'bootstrap_token: "[^"]+"|master_key: "[^"]+"|eyJhbGci' .claude/manual-testing-plan.md
```

Every hit must be a placeholder, a `GENERATE_WITH` line, or a deliberate
non-secret test vector. A real value from the scratch run is a finding — remove
it and say so.

- [ ] **Step 5: Report**

Tell the user: which examples were added, anything the live run contradicted in
the spec or the plans, and that the `.claude/` edits are uncommitted because the
directory is gitignored. Ask before force-adding.
