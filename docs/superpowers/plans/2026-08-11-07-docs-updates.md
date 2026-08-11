# Docs Updates — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Document the four new roles, the fixed Data Access Administrator limitation, the new purge endpoint, and the CLI authorization-gap fix across the three places that currently describe the pre-fix state.

**Architecture:** Pure content edits — no code. This plan should run **last**, after Plans 1-6 have landed, since it documents their actual shipped behavior rather than the plan.

**Tech Stack:** Markdown, HTML (no build step for either).

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` — the source of truth for every claim in this plan.
- Do not describe `Key Vault Crypto Service Release User` as available — it is explicitly not implemented (design §6).
- Match each file's existing tone and structure exactly (see the "Doing tasks" conventions already in place in each file) — do not restructure sections beyond what's specified below.

---

### Task 1: `.claude/azure-keyvault-parity.md`

**Files:**
- Modify: `.claude/azure-keyvault-parity.md:105-123` (the "Built-in role permission boundaries" table and surrounding prose)

**Interfaces:** none (documentation only).

- [ ] **Step 1: Add the four new roles' parity status**

Insert a new subsection immediately after the closing of the existing "Built-in role permission boundaries" table and before the `**Net:**` paragraph (currently between lines 115 and 117):

```markdown

Four more built-in roles were added 2026-08-11 (see
`docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md`),
closing part of the gap between RocketVault's seven original roles and
Azure's full built-in set:

| Role | Azure grants (`dataActions`) | RocketVault grants | Status |
|---|---|---|---|
| Purge Operator | Purge a soft-deleted **vault** | `Key Vault Purge Operator`: `ActionVaultPurge` only | ✅ |
| Certificate User | Read a certificate **including its private-key portion** (Azure certs are a linked cert+key+secret object) | `Key Vault Certificate User`: `ActionCertificatesRead` only — RocketVault has no cert/key/secret linkage yet (P5), so this is currently identical to Reader's certificate slice | 🟡 placeholder parity — exists now, gains real meaning once P5 lands |
| Crypto Service Encryption User | Read key metadata + wrap/unwrap only (disk-encryption scenarios) | `Key Vault Crypto Service Encryption User`: `ActionKeysRead`, `ActionKeysWrap`, `ActionKeysUnwrap` | ✅ |
| Data Access Administrator | Manage role assignments for the other data-plane roles, scoped to the vault | `Key Vault Data Access Administrator`: `ActionRoleAssignmentsWrite`, `ActionRoleAssignmentsDelete` | ✅ — also closes the "role-assignment management is global-admin-only" known limitation from the v4.0.0 release notes |

**Not added:** `Key Vault Crypto Service Release User` (confidential-compute key release) — RocketVault has no TEE/attestation flow to gate at all (see §2's "Release (confidential compute)" row, still ❌). Adding the role name without a real capability behind it would repeat the exact anti-pattern the legacy vault-role vocabulary (`vault-reader`, `secrets-officer`, etc.) was retired for. **Not added either:** `Key Vault Contributor` — a control-plane role for Azure Resource Manager, not a data-plane concept RocketVault's self-hosted model has an equivalent for.
```

- [ ] **Step 2: Verify the edit renders correctly**

Run: `grep -c '^|' .claude/azure-keyvault-parity.md` before and after — the count should increase by exactly 5 (4 new role rows + 1 table header separator row already counted once). No automated test exists for this file; review the rendered Markdown manually (e.g. `glow .claude/azure-keyvault-parity.md` or open in a Markdown previewer) to confirm the table isn't malformed.

- [ ] **Step 3: Commit**

```bash
git add .claude/azure-keyvault-parity.md
git commit -m "docs(parity): add four new built-in roles, document Release User as blocked"
```

---

### Task 2: `docs/admin-manual.html` `#vault-rbac` section

**Files:**
- Modify: `docs/admin-manual.html` (the `#vault-rbac` section — role table, the "global-admin-only" callout, add the purge endpoint)

**Interfaces:** none (documentation only). Follow the existing design system exactly: `.ep`/`.tab-bar`/`.tab-pane` for endpoints, `.callout-warn`/`.callout-info` for callouts, `<table>` for the role list — all classes already defined in the page's `<style>` block; do not introduce new CSS.

- [ ] **Step 1: Extend "The seven built-in roles" table to eleven**

Find the `<h3>The seven built-in roles</h3>` heading inside `<section id="vault-rbac">` and its following `<table>...</table>` (seven `<tr>` rows, one per role, ending with `Key Vault Certificates Officer`). Change the heading to:

```html
  <h3>The built-in roles</h3>
```

and add four rows immediately before the table's closing `</tbody>`:

```html
      <tr><td><code>Key Vault Purge Operator</code></td><td>Permanently purge a soft-deleted vault</td></tr>
      <tr><td><code>Key Vault Certificate User</code></td><td>Read certificates — currently identical to Reader's certificate access; gains full parity once certificates are linked to key/secret material</td></tr>
      <tr><td><code>Key Vault Crypto Service Encryption User</code></td><td>Read key metadata plus wrap/unwrap only — narrower than Crypto User</td></tr>
      <tr><td><code>Key Vault Data Access Administrator</code></td><td>Grant and revoke role assignments within its own vault</td></tr>
```

Immediately after the table's closing `</table>`, add:

```html
  <div class="callout callout-info">
    <div class="callout-label">Key Vault Crypto Service Release User is not available</div>
    <p>RocketVault has no confidential-computing/TEE attestation flow to gate, so this Azure role is intentionally not implemented — granting it would confer no capability at all.</p>
  </div>
```

- [ ] **Step 2: Replace the "global-admin-only" callout**

Find the callout block (inside `#vault-rbac`):

```html
  <div class="callout callout-info">
    <div class="callout-label">Managing role assignments is currently global-admin-only</div>
    <p>The handler's own check accepts a per-vault <code>vaults:manage</code> access policy, but a global RBAC gate ahead of it currently rejects non-admins first — a known limitation. For now, only the <code>admin</code> account role can grant or revoke role assignments.</p>
  </div>
```

Replace with:

```html
  <div class="callout callout-info">
    <div class="callout-label">Delegating role-assignment management</div>
    <p>Granting or revoking role assignments requires the <code>admin</code> account role, a vault-scoped <code>vaults:manage</code> access policy, or the <code>Key Vault Data Access Administrator</code> role in that vault. Grant a non-admin operator that role to let them manage access for one vault without making them a global admin: <code>rocketvault vault-access grant alice --role "Key Vault Data Access Administrator" --vault prod --username admin --password admin123 --totp-code 123456</code>.</p>
  </div>
```

- [ ] **Step 3: Add the purge endpoint**

Immediately before the closing `<p class="see-also">` of `#vault-rbac`, add a new `.ep` block documenting the purge endpoint:

```html
  <div class="ep">
    <div class="ep-hd"><span class="meth meth-delete">DELETE</span> <span class="ep-path">/api/v1/vaults/{vault_name}/purge</span> <span class="ep-auth">JWT</span> <span class="ep-label">Permanently purge a vault</span></div>
    <div class="tab-bar"><button class="tab-btn active">cURL</button><button class="tab-btn">CLI</button></div>
    <div class="tab-pane active"><pre class="code">curl -s -X DELETE $BASE/api/v1/vaults/prod/purge -H "Authorization: Bearer $TOKEN"</pre></div>
    <div class="tab-pane"><pre class="code">rocketvault vaults purge prod --username admin --password admin123 --totp-code 123456</pre></div>
    <details class="collapse"><summary>Notes</summary><div class="inner">Requires the <code>Key Vault Purge Operator</code> role (or admin) in the target vault — a role assignment, not an access policy, since this is a vault data-plane route. Refuses the default vault and any vault with purge protection enabled (400 either way). 404 if the vault doesn't exist.</div></details>
  </div>
```

- [ ] **Step 4: Verify the HTML is well-formed**

Run:

```bash
python3 -c "
import re
c = open('docs/admin-manual.html').read()
for tag in ['section','div','table','tr']:
    o = len(re.findall(r'<'+tag+r'\b', c))
    cl = len(re.findall(r'</'+tag+r'>', c))
    print(tag, o, cl, 'OK' if o==cl else 'MISMATCH')
"
```

Expected: `OK` for every tag.

- [ ] **Step 5: Commit**

```bash
git add docs/admin-manual.html
git commit -m "docs(admin-manual): document the four new roles, Data Access Administrator delegation, and the purge endpoint"
```

---

### Task 3: Release notes addendum

**Files:**
- Create: `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Write the release note**

Create `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`:

```markdown
# v4.1.0 — Role parity and vault-authorization fix

Adds four Azure Key Vault built-in roles and fixes a root-cause authorization
bug that made several existing per-vault checks unreachable in production.
Full design: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md`.

## New roles

| Role | Grants |
|---|---|
| Key Vault Purge Operator | Purge a soft-deleted vault |
| Key Vault Certificate User | Read certificates (currently identical to Reader's certificate access — see the parity doc for why) |
| Key Vault Crypto Service Encryption User | Read key metadata plus wrap/unwrap only |
| Key Vault Data Access Administrator | Grant and revoke role assignments within its own vault |

`Key Vault Crypto Service Release User` is intentionally not included —
RocketVault has no confidential-computing/TEE attestation flow to gate.

## Fixed: role-assignment management was global-admin-only

The known limitation documented in the v4.0.0 release notes ("Managing role
assignments for a vault currently requires the global admin role") is fixed.
Grant `Key Vault Data Access Administrator` in a vault to let a non-admin
manage that vault's role assignments without full admin.

## Fixed: vault-management routes were unreachable for non-admins regardless of grant

`GET/PATCH/DELETE /vaults/{name}` and `POST/GET /vaults` were gated by a
global, vault-blind admin-only permission ahead of their own per-vault
checks. A principal with a `vaults:manage` access-policy grant scoped to a
specific vault could not use it — the global gate rejected the request
first, in every version since the vault-management authorization fix of
2026-07-19 (which fixed a different bug in the same code path but did not
catch this one; see the design doc's "Relationship to the 2026-07-19 fix").
`createVault` and `listVaults` had no per-vault check at all and were
reachable only by admins as a side effect of the same bug.

**This is a breaking authorization change if you were relying on the bug**:
a non-admin who could previously only reach vault-management routes because
they held the *global* `admin` role continues to work unchanged. A non-admin
who holds a `vaults:manage` grant can now reach `createVault`/`listVaults`
only via a **global** (`vault_id: null`) grant — not a vault-specific one
(see the design doc §2 for why). Audit your access-policy grants if you
depend on this distinction.

## Fixed: CLI vault-admin commands had no authorization check

`rocketvault vaults create/update/delete/recover/purge` previously called the
service layer directly with **zero** authorization check — any successfully
authenticated user, any role, could delete or purge any vault via the CLI.
This is now gated identically to the HTTP API (`vaults:manage` for
create/update/delete/recover, `Key Vault Purge Operator` for purge).

**If you have automation scripts or non-admin operators currently running
these CLI commands successfully without an admin account**, they will start
failing with `permission denied` after upgrading, unless the calling
principal holds the matching grant. This is the intended fix for a real
authorization hole, not a regression — grant the appropriate role via
`rocketvault vault-access grant` before or immediately after upgrading.

## New endpoint

`DELETE /api/v1/vaults/{vault_name}/purge` — vault purge is now reachable
over HTTP, not just the CLI, and is authorized the same way every other
vault data-plane route is (deny-by-default role-assignment check), rather
than the CLI's previous ad hoc — and, until this release, entirely
absent — gate.
```

- [ ] **Step 2: Cross-link from the existing v4.0.0 release notes**

In `docs/release-notes/v4.0.0-azure-rbac.md`, under the existing `## Known limitations` section, find the paragraph beginning "Managing role assignments for a vault (`POST`/`GET`/`DELETE` on `/vaults/{vault}/role-assignments`) currently requires the global admin role." and append, as a new line immediately after that paragraph (inside the same list item, or as a following sentence):

```markdown
  **Fixed in v4.1.0** — see `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/release-notes/v4.1.0-role-parity-and-authz-fix.md docs/release-notes/v4.0.0-azure-rbac.md
git commit -m "docs(release-notes): add v4.1.0 role parity and authz-fix notes"
```

---

## Verification Gate (run before considering this plan complete)

```bash
python3 -c "
import re
c = open('docs/admin-manual.html').read()
for tag in ['section','div','table','tr']:
    o = len(re.findall(r'<'+tag+r'\b', c))
    cl = len(re.findall(r'</'+tag+r'>', c))
    assert o == cl, f'{tag}: {o} vs {cl}'
print('admin-manual.html: all tags balanced')
"
ls docs/release-notes/v4.1.0-role-parity-and-authz-fix.md
```

Both must succeed. This plan has no `go build`/`go test` gate — it is documentation-only.
