# Security Review and Branch Finish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Review the whole branch for security defects, verify every claim the code and docs make, and decide whether it merges.

**Architecture:** Three passes. An adversarial review of the security-critical paths, a full verification sweep, then the merge decision — in that order, because a clean test run tells you nothing about whether the design holds.

**Tech Stack:** Go 1.25, the `security-review` skill, `superpowers:finishing-a-development-branch`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — the whole document is the requirements source for this plan.

**Plan-of-plans:** This is plan 31 of 31. Requires plans 01-30 committed.

## Global Constraints

- **A failing check is a defect to fix, not a test to adjust.** That rule has held for thirty plans and matters most here.
- **Nothing merges with a known unfixed security finding.** A documented deferral is acceptable only with an explicit decision recorded in `.claude/known-bugs.md`.
- Commits signed with GPG key `61D246B30285ED35`.

## Why this plan is not just "run the tests"

The suite is comprehensive, and it will pass. That is not the question.

The question is whether the *design* holds — whether the single egress point is genuinely single, whether a disabled tier is genuinely unreachable, whether the documentation describes what the code does. Those are properties no test asserts directly, because a test asserts what its author thought to check.

This plan looks for the gap between what was intended and what was built.

---

### Task 1: Adversarial review of the security-critical paths

**Files:**
- Read: the whole branch
- Modify: whatever the review finds
- Create: `.claude/known-bugs.md` entries for anything deferred

**Interfaces:** None. This is a review.

**Approach:** run the project's `security-review` skill over the branch, then work the specific checklist below. The skill catches general classes; the checklist covers the invariants this design depends on, which a general review would not know to look for.

- [ ] **Step 1: Run the security review skill**

```bash
git diff v-4.0.0...feat/mcp-server --stat
```

Then invoke the `security-review` skill on the branch. Record every finding,
including ones judged not to apply, with the reason.

- [ ] **Step 2: Work the invariant checklist**

Each of these is a property some plan claimed. Verify it against the code as
built, not against the plan that promised it.

**Egress and redaction**

```bash
# Reveal() outside the two sanctioned sites.
grep -rn "\.Reveal()" --include="*.go" internal/mcpserver/ internal/vaultapi/ | grep -v _test
```
Expected: `redact.go` (the egress point), `tools_crypto.go` (decrypt, gated on
both flags), `secrets_write.go` (putting a caller-supplied value on the wire).
**Anything else is a finding.**

```bash
# SecretValue must redact on all three paths.
grep -n "func (v SecretValue)" internal/vaultapi/secretvalue.go
```
Expected: `Reveal`, `String`, `GoString`, `MarshalJSON`, `Zero`. A missing
`GoString` means `%#v` leaks.

**Registration and gating**

```bash
# AddTool outside register().
grep -rn "mcp\.AddTool(" --include="*.go" internal/mcpserver/ | grep -v _test | grep -v server.go
```
Expected: nothing.

```bash
# Tools reading cfg.Vault directly instead of ResolveVault.
grep -rn "cfg\.Vault\|s\.cfg\.Vault" --include="*.go" internal/mcpserver/ | grep -v _test
```
Expected: only `gating.go` (inside `ResolveVault`) and `server.go` (the log
line). A tool reading it directly bypasses the allowlist.

**Confirmation**

```bash
# Every destructive tool must call requireConfirmation.
grep -n "requireConfirmation" internal/mcpserver/tools_destructive.go
```
Expected: four calls, one per tool. Confirm each precedes the network call.

**Authentication**

```bash
# No credential in any error path.
grep -rn "ClientSecret\|RefreshToken" --include="*.go" internal/vaultapi/ cmd/mcp.go | grep -i "errorf\|sprintf\|log"
```
Expected: nothing.

**Retry**

```bash
# Only idempotent methods are retried.
grep -n "func isIdempotent" -A 4 internal/vaultapi/client.go
```
Expected: `GET` and `HEAD` only.

**Documentation claims** — plan 30 flagged these three specifically, since a
documentation error here is a security error:

```bash
# Key Vault Reader must exclude secrets/getSecret.
grep -n "RoleKeyVaultReader:" -A 6 model/azure_roles.go
```
Expected: `ActionSecretsReadMetadata`, `ActionKeysRead`,
`ActionCertificatesRead` — and **not** `ActionSecretsGet`.

```bash
# A disabled tier's tools must be absent, not refusing.
go test ./internal/mcpserver/ -run TestGating_DisabledTiersAreAbsentFromToolsList -v
```

```bash
# require_service_account must refuse to start, not fall back.
go test ./cmd/ -run TestResolveMCPTokenSource_RequireServiceAccountRefusesTheSession -v
```

- [ ] **Step 3: Consider what the tests do not cover**

Read these paths by eye. Each is somewhere a test could pass while the property
fails:

1. **`withLifecycle`'s ordering.** Rate limit, then deadline, then correlation
   ID, then recovery, then the handler. A refused call must not have started a
   timer or made a request. Confirm by reading, not by test.
2. **`Wrap`'s neutralisation under nesting.** What happens to
   `<<UNTRUSTED-VAULT-DATA>><</UNTRUSTED-VAULT-DATA>>` as input? The
   replacement is not recursive, which is correct — but confirm the result
   cannot reconstruct a delimiter.
3. **The `include_value` schema split.** With `allow_secret_values` false, the
   argument must be absent from the *advertised schema*, not merely ignored.
   Check `tools/list` output by hand.
4. **`purge_vault`'s missing default.** Confirm no code path supplies
   `cfg.Vault` when the argument is empty.
5. **Session refresh persistence.** Confirm both the access token and the
   rotated refresh token are written, since only the second failure is
   delayed and therefore hard to attribute.

- [ ] **Step 4: Fix or record every finding**

For each finding: fix it, or record it in `.claude/known-bugs.md` with root
cause, impact and the reason for deferring. **Nothing merges with an unfixed,
unrecorded security finding.**

Use the existing entry format in that file.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -S --gpg-sign=61D246B30285ED35 -m "fix(mcp): address security review findings

<one line per finding, or 'No findings; the invariant checklist passed as
written' if the review was clean>"
```

If the review was clean, commit only the `.claude/known-bugs.md` note recording
that the review ran and what it covered — a review that leaves no trace cannot
be relied on later.

---

### Task 2: Full verification sweep

**Files:** None modified unless something fails.

**Interfaces:** None.

**The rule:** every command's real output is checked. A sweep where the output
is assumed is not a sweep.

- [ ] **Step 1: Build and vet**

```bash
go build ./...
go vet ./...
```
Expected: both silent.

- [ ] **Step 2: The full suite, with the race detector**

```bash
go test ./... -race
```

Expected: all packages pass. **This includes the pre-existing suite** — if
anything outside `internal/mcpserver`, `internal/vaultapi`, `cmd` or `config`
now fails, this branch broke it and that is a blocker.

- [ ] **Step 3: The integration suite**

```bash
go test -tags=integration ./internal/mcpserver/ -v -timeout 10m
```

Expected: passes against a real server.

- [ ] **Step 4: The CI gates, run locally**

```bash
go test ./internal/mcpserver/ -run 'TestGatingTable_|TestLeakSweep_' -race -v
```

And both grep gates from plan 28:

```bash
grep -rn "mcp\.AddTool(" --include="*.go" internal/mcpserver/ | grep -v _test | grep -v server.go
grep -rn "\.Reveal()" --include="*.go" internal/mcpserver/ | grep -v _test | grep -v redact.go | grep -v tools_crypto.go
```
Expected: both silent.

- [ ] **Step 5: Lint and docs**

```bash
golangci-lint run ./... 2>&1 | tail -20
./scripts/docs.sh build
```

The project has known lint debt predating this branch. **Only new findings in
this branch's files are blockers.** Check with:

```bash
golangci-lint run ./internal/mcpserver/... ./internal/vaultapi/... ./cmd/... ./config/...
```

- [ ] **Step 6: End-to-end by hand**

Automated tests do not prove the thing works in a real client. Do this once:

```bash
go build -o rocketvault .
./rocketvault serve &
./rocketvault users login --username admin
./rocketvault mcp --check
```

Register it with Claude Code and confirm by eye:

- The tool list shows exactly ten tools.
- `get_secret` has no `include_value` argument.
- Asking it to list secrets returns names, no values.
- Enabling `allow_write` and restarting shows nineteen tools.
- A destructive tool, with `allow_destructive` on, prompts before running.

**Record what you actually observed**, including anything that felt wrong even
if it passed. The hand check exists to catch what the suite cannot describe.

- [ ] **Step 7: Record the result**

Write the sweep's real output into the commit message — not a claim that it
passed, the actual counts:

```bash
git commit -S --gpg-sign=61D246B30285ED35 --allow-empty -m "chore(mcp): record the pre-merge verification sweep

go build ./...            <result>
go vet ./...              <result>
go test ./... -race       <package count, failures>
integration suite         <result>
gating table + leak sweep <result>
lint (branch files only)  <result>
docs.sh build             <result>
hand check in Claude Code <what was observed>"
```

---

### Task 3: The merge decision

**Files:**
- Modify: `CLAUDE.md` (documentation history)
- Possibly: `.claude/known-bugs.md`

**Interfaces:** None.

**This task is a decision, not a procedure.** The work is done; the question is
whether it should land, and that is the operator's call informed by what Tasks
1 and 2 found.

- [ ] **Step 1: Assemble the state**

```bash
git log --oneline v-4.0.0..feat/mcp-server | wc -l
git diff v-4.0.0...feat/mcp-server --stat | tail -1
```

Summarise honestly:

- What works, verified how.
- What is deferred, and why.
- What is known-imperfect and shipped anyway, with the reasoning.

The four things this design knowingly does not do, all decided deliberately and
all worth restating at the merge point:

1. **`query_audit_log` cannot work under least privilege.** It needs a global
   admin principal; no per-vault grant provides one.
2. **The confirmation guard is not a security boundary.** It reduces drive-by
   risk; it does not stop a determined injection.
3. **There is no CLI command to create a service account**, so the recommended
   production posture is reachable only through `curl`.
4. **`rotate_secret` does not exist**, because secrets have no rotation-policy
   route.

None is a defect in this branch. All four should be visible to whoever decides.

- [ ] **Step 2: Update the documentation history**

Add to `CLAUDE.md` under **Documentation History**:

```markdown
- **2026-08-21**: Added the MCP server (`rocketvault mcp`) — a Model Context
  Protocol interface exposing the vault to Claude Code and Claude Desktop over
  stdio. Read-only by default (10 tools), with independently gated tiers for
  writes, destructive operations, crypto and secret values (27 tools fully
  enabled). Built on a new `internal/vaultapi` typed REST client, which the
  pending CLI remote-mode work is expected to reuse. Design:
  `docs/superpowers/specs/2026-08-21-mcp-server-design.md`; guide:
  `docs/mcp-server.md`.
```

- [ ] **Step 3: Record the outstanding items**

Add to `.claude/known-bugs.md`, in the deferred section:

```markdown
### D-MCP1: No CLI command to create a service account

`cmd/` has no `service-accounts` group; the capability exists only as
`POST /api/v1/service-accounts` (`api/service_accounts.go`). The MCP server's
recommended production posture requires a service account, so setting it up
runs through `curl` — documented that way in `docs/mcp-server.md`.

**Impact**: friction on the recommended path, not a security gap.
**Fix**: add a `rocketvault service-accounts create` command.
**Deferred because**: out of scope for the MCP work, which deliberately added
no new API surface.

### D-MCP2: `query_audit_log` requires a global admin principal

`GET /api/v1/audit/logs` gates on the global admin role
(`api/audit.go:66`), not a data action, so no per-vault grant unlocks it. An
MCP server running as a least-privilege service account gets 403 from that
tool every time.

**Impact**: audit querying and least privilege are mutually exclusive through
MCP. Both the tool's error and the runbook say so.
**Fix**: a `Microsoft.KeyVault/vaults/audit/read` data action would let this be
granted per vault.
**Deferred because**: changing the audit route's authorization is a server
change with its own security review, well beyond this branch.
```

- [ ] **Step 4: Finish the branch**

Invoke `superpowers:finishing-a-development-branch`, which covers the merge
options and their trade-offs.

Before that, confirm the branch is clean and every commit is signed:

```bash
git status --porcelain
git log v-4.0.0..feat/mcp-server --format="%G? %h %s" | grep -v "^G" || echo "all commits signed"
```

Expected: a clean tree, and every commit showing `G`.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md .claude/known-bugs.md
git commit -S --gpg-sign=61D246B30285ED35 -m "docs(mcp): record the MCP server in the project history

Adds the documentation-history entry and records the two deferred items:
there is no CLI command to create a service account, so the recommended
production posture runs through curl; and query_audit_log needs a global admin
principal, making audit querying and least privilege mutually exclusive
through MCP.

Neither is a defect in this work. Both are visible at the merge point rather
than discovered later."
```

---

## Verification

The whole plan is verification. The final state should be:

```bash
go build ./... && go test ./... -race && go vet ./...
go test -tags=integration ./internal/mcpserver/ -timeout 10m
./scripts/docs.sh build
git status --porcelain
```

Expected: everything passes, and the tree is clean.

## What was built

For the record at the point of merge:

| Component | What it is |
|---|---|
| `internal/vaultapi` | Typed REST client: two auth modes, name resolution, safe retry, body-free errors |
| `internal/mcpserver` | 27 tools across four independently gated tiers, with deadlines, rate limiting, recovery, redaction and untrusted-content marking |
| `cmd/mcp.go` | `rocketvault mcp` over stdio, plus `--check` preflight |
| `config` | `LoadMCPConfig` with validation that fails at startup |
| `docs/mcp-server.md` | Install guide, least-privilege roles, threat model, attribution |

Default posture: ten read-only tools, no secret values, no mutations.

**The most important property, and the one to re-verify if anything is ever
changed here:** a tool that is not registered cannot be called, and
registration is decided once at startup from configuration that no tool can
reach. Everything else in the design rests on that.
