# Worked Example: Provisioning Lifecycle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A runnable §5 worked example for self-service provisioning — grant, create, quota, soft-delete, purge — with every command and every response captured from a real instance.

**Architecture:** No production code. This plan *runs* the feature and writes down what actually happened. The manual-testing-plan's worked examples state that their gotchas "were reproduced live against a scratch instance, not inferred from reading the code alone" — that is the standard this plan must meet, and the reason it exists separately from plan 08's checklist.

**Tech Stack:** the built `rocketvault` binary, `curl`, `jq`, `sqlite3`, `python3`.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md`

**Depends on:** plans 01-08 — the feature must be fully implemented and its tests green. **Do not start this plan against a partially implemented feature**; a worked example written from a half-built path is worse than none.
**Followed by:** `…-10-worked-example-boundaries.md`.

## Global Constraints

- **Every command and every response in the finished example must be copy-pasted from a real run.** Do not compose plausible-looking JSON. If a step cannot be run, it does not go in the document.
- **Never paste a real secret into the document.** The scratch instance's `master_key`, `bootstrap_token`, TOTP secret and JWTs stay out. An earlier revision of the manual-testing-plan quoted a live bootstrap token inline; that is the incident (`.claude/known-bugs.md` § B10), not a convenience. Redact to a shape (`"signing_secret":"<43-char base64url>"`) or truncate with `...`.
- **Use an isolated instance.** Scratch config, scratch DB, and a **non-default port** — port 8774 is often already occupied by the developer's own instance. Also isolate `HOME`, or the CLI will pick up the developer's saved contexts and cached sessions and silently run in remote mode.
- `.claude/manual-testing-plan.md` is gitignored (`.gitignore:127`). Edit it; do not `git add -f` without asking.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Stand up an isolated instance and capture the prerequisites block

**Files:**
- Create: `/tmp/rv-prov/` (scratch working directory, not in the repo)
- Modify: `.claude/manual-testing-plan.md` (§5, the `#### Prerequisites` block of the new worked example)

**Interfaces:**
- Produces: a running scratch instance, an admin JWT in `$TOKEN`, a `$BASE` URL, and a non-admin principal to act as the grantee. Tasks 2 and 3 both use these.

- [ ] **Step 1: Build and configure**

```bash
mkdir -p /tmp/rv-prov/home && cd /home/numericlabs/data/rocket/rocketvault
go build -o /tmp/rv-prov/rocketvault .
cp .rocketvault.yaml.example /tmp/rv-prov/rv.yaml
sed -i "s|^master_key:.*|master_key: \"$(openssl rand -base64 32)\"|; \
        s|^bootstrap_token:.*|bootstrap_token: \"$(openssl rand -base64 32)\"|; \
        s|^  listen_addr: \":8774\"|  listen_addr: \":18774\"|" /tmp/rv-prov/rv.yaml
# point the DB at scratch, and disable HSM + OIDC
```

Edit `database.connection` to `/tmp/rv-prov/rv.db`, and set `hsm.enabled: false`
and `oidc.enabled: false`. Both default to `false` in the committed example
template, but a developer's own config may differ — check rather than assume.

- [ ] **Step 2: Start it and confirm health**

```bash
cd /home/numericlabs/data/rocket/rocketvault   # run from repo root: i18n assets resolve relative to cwd
/tmp/rv-prov/rocketvault --config /tmp/rv-prov/rv.yaml serve > /tmp/rv-prov/server.log 2>&1 &
sleep 5
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:18774/api/v1/health/live   # expect 200
```

Two traps worth recording if you hit them: starting from a directory other than
the repo root logs `Unable to initialize the localization`, and a port clash
exits with `bind: address already in use` after appearing to boot normally.

- [ ] **Step 3: Bootstrap admin and log in**

```bash
BT=$(grep '^bootstrap_token:' /tmp/rv-prov/rv.yaml | cut -d'"' -f2)
HOME=/tmp/rv-prov/home /tmp/rv-prov/rocketvault --config /tmp/rv-prov/rv.yaml users admin \
  --admin-username=admin --admin-password='<choose-one>' --bootstrap-token="$BT"
```

Note the `HOME` override: without it the CLI resolves the developer's saved
context and refuses with `remote mode ... is not yet supported for "rocketvault users admin"`.

Capture the TOTP secret it prints, generate a code, and `POST /api/v1/users/login`
to get `$TOKEN`. **Do not record the secret or the token in the document.**

- [ ] **Step 4: Create the grantee principal**

Create a second, non-admin user (`msp-bot`) with no role grants anywhere — this
is the principal that will hold the provisioning grant. Also create an OAuth2
service account (§3.5) and note its UUID: task 2 issues a grant to it, which is
the case a username-only path would fail.

- [ ] **Step 5: Write the Prerequisites block**

Add to `.claude/manual-testing-plan.md` §5, after the webhook worked example,
opening a new `### Worked example: self-service provisioning, quotas, and what a
soft-delete costs you`. Write the `#### Prerequisites` section listing exactly
what steps 1-4 required, following the format of the existing §5 examples.

- [ ] **Step 6: Commit**

```bash
git commit -S --allow-empty -m "chore: capture provisioning worked-example prerequisites"
```

(The doc itself is gitignored; this commit records the checkpoint. Tell the user the doc edits are uncommitted.)

---

### Task 2: Run and write the happy path

**Files:**
- Modify: `.claude/manual-testing-plan.md` (walkthrough steps 1-5 of the new example)

**Interfaces:**
- Consumes: the running instance and identities from task 1.
- Produces: the example's `#### Concept` blockquote and its first five walkthrough steps.

- [ ] **Step 1: Confirm the pre-feature failure mode, then fix it**

Before issuing any grant, have `msp-bot` attempt a create and record the refusal
verbatim. This is what makes the example show a *change*, not just a success:

```bash
curl -s -X POST $BASE/vaults -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"acme-prod"}'
```

- [ ] **Step 2: Issue a grant, both ways**

Run the CLI and the HTTP form, and record both:

```bash
HOME=/tmp/rv-prov/home /tmp/rv-prov/rocketvault --config /tmp/rv-prov/rv.yaml \
  vault-provisioning grant msp-bot --quota 2
curl -s -X PUT $BASE/vault-provisioning-grants/$BOT_ID \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"quota":2}'
```

Record the status codes precisely: first issue is `201`, a re-quota is `200`.

- [ ] **Step 3: Issue a grant to the service account by UUID**

This is the MSP automation's real identity and cannot be addressed by username.
Record the command and result.

- [ ] **Step 4: Create, and confirm the creator's rights are real**

As `msp-bot`, create `acme-prod`. Then, in that vault only, prove the grant
actually conferred something: write and read a secret, and list role assignments
to show the `Key Vault Administrator` row the create wrote. Record each response.

- [ ] **Step 5: Confirm listing works**

`rocketvault vaults list` as `msp-bot` — it must show `acme-prod` and **not**
`default`. Record the output. This is the step that would have failed before
plan 05, and is worth calling out as such.

- [ ] **Step 6: Write the concept blockquote**

Now that the behaviour is confirmed, write the `> **Concept: ...**` opening.
Cover: a provisioning grant is bounded where a global `vaults:manage` is not;
the creator becomes full manager of what it created and nothing else; and quota
counts by `created_by`, while listing filters by policy. Cite `file:line` for
each claim, as the neighbouring examples do.

- [ ] **Step 7: Commit the checkpoint**

```bash
git commit -S --allow-empty -m "chore: capture provisioning happy-path transcript"
```

---

### Task 3: Run and write the quota lifecycle

**Files:**
- Modify: `.claude/manual-testing-plan.md` (the `#### The N gotchas this example surfaces` section and walkthrough steps 6-9)

**Interfaces:**
- Consumes: the instance and the `acme-prod` vault from task 2.

This task exists to surface the counter-intuitive half of the feature: a
grantee at quota who deletes a vault does **not** get the slot back.

- [ ] **Step 1: Exhaust the quota**

With quota 2 and one vault created, create a second, then attempt a third.
Record the third's exact status code and message — it should name the count and
the limit.

- [ ] **Step 2: Soft-delete and retry — the slot is NOT released**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE $BASE/vaults/acme-prod \
  -H "Authorization: Bearer $BOT_TOKEN"
# then attempt a create again -- must STILL be refused
```

Confirm in the database that the row is still present, which is why it still
counts:

```bash
sqlite3 /tmp/rv-prov/rv.db \
  "SELECT name, deleted_at IS NOT NULL AS soft_deleted FROM vaults WHERE created_by='$BOT_ID';"
```

- [ ] **Step 3: Purge, and confirm the slot returns**

Purge the soft-deleted vault, re-run the create, and record that it now
succeeds. This is the full cycle: only a purge frees a slot.

- [ ] **Step 4: Confirm purge_protection is refused**

As `msp-bot`, attempt a create with `"purge_protection": true`. Record the
refusal. Then explain in the document *why* it is refused — with it, step 3's
purge would fail and the slot would be pinned permanently.

- [ ] **Step 5: Confirm the purge cleaned up its role assignment**

```bash
sqlite3 /tmp/rv-prov/rv.db \
  "SELECT COUNT(*) FROM role_assignments WHERE vault_id NOT IN (SELECT id FROM vaults);"
```

Expect `0`. A non-zero result means plan 02's fix regressed — the FK cascade is
inert on SQLite, so nothing else would catch it.

- [ ] **Step 6: Write the gotchas section**

Write `#### The N gotchas this example surfaces` from what steps 1-5 actually
produced — not from this plan's predictions. If a step behaved differently than
described here, **document what happened** and raise it; the plan is a
hypothesis, the run is the evidence.

- [ ] **Step 7: Write the teardown section**

Include stopping the server, and deleting `/tmp/rv-prov/`.

- [ ] **Step 8: Verify the document reads correctly**

Re-read the whole new example top to bottom as someone who has never seen the
feature. Every command must be runnable in order, with no undefined variable and
no step depending on state a previous step didn't create.

- [ ] **Step 9: Tear down and commit**

```bash
pkill -f "rocketvault --config /tmp/rv-prov/rv.yaml"
rm -rf /tmp/rv-prov
git commit -S --allow-empty -m "chore: capture provisioning quota-lifecycle transcript"
```

Tell the user the `.claude/manual-testing-plan.md` edits are uncommitted because
`.claude/` is gitignored, and ask before force-adding.
