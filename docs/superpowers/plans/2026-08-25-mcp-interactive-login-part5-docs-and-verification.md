# MCP Interactive Login — Part 5: Docs and Final Verification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Before starting:** create one Task (via the TaskCreate tool) per task
> below. Set a task `in_progress` before starting it and `completed`
> immediately after its commit step. Run TaskList at any checkpoint to see
> where this plan stands.

**Goal:** Document the `login` tool in `docs/mcp-server.md`, then run the full verification sweep across every plan in this series.

**Architecture:** Doc-only change plus a checklist, no new code. `docs/mcp-server.md`'s "Identity" section currently states "There is no per-user authentication" as an unqualified fact — Part 3 made that no longer strictly true, so this plan corrects it rather than leaving a stale claim next to the new feature.

**Tech Stack:** Markdown, `go build`/`go vet`/`go test`.

**Spec:** `docs/superpowers/specs/2026-08-25-mcp-interactive-login-design.md`

## Global Constraints

- Depends on Parts 1-4 — do not start until all four are merged and their tests pass.
- This is the last plan in the series — there is no Part 6.

## Plan Chain

**This is Part 5 of 5, the final plan.** Previous: `2026-08-25-mcp-interactive-login-part4-cmd-wiring-and-tests.md`. Next plan: none — after this plan's tasks are done, the feature is complete.

---

### Task 1: Document the login tool

**Files:**
- Modify: `docs/mcp-server.md` (`## Identity` section, `## Enabling more` table)

**Interfaces:**
- Consumes: nothing — this task only writes prose.
- Produces: accurate documentation. No later task depends on this one's content.

- [ ] **Step 1: Correct the now-inaccurate opening claim**

In `docs/mcp-server.md`, find this paragraph under `## Identity` (currently lines 163-167):

```markdown
## Identity

The server holds one identity for its whole lifetime. There is no per-user
authentication — the server is a child process of your MCP client, running as
you.
```

Replace it with:

```markdown
## Identity

The server resolves one identity at startup and normally keeps it for its
whole lifetime — the server is a child process of your MCP client, running
as you. The one exception is the `login` tool below, off by default, which
lets a chat message replace that identity while the process keeps running.
```

- [ ] **Step 2: Add the login tool subsection**

Immediately after the `**Service account**` paragraph and before `There is **no CLI command to create a service account**`, insert:

```markdown
### Interactive login

With `mcp.allow_interactive_login: true`, a `login` tool is registered:

```yaml
mcp:
  allow_interactive_login: true
```

Call it with a username, password and current TOTP code, the same three
things `rocketvault users login` asks for:

> login(username: "admin", password: "...", totp_code: "123456")

On success, every later tool call in the conversation authenticates as that
user, until the process restarts or `login` is called again. The response
confirms who you're now acting as (`username`, `roles`, `expires_at`) — it
never includes the token itself.

**Only available under a cached-session identity.** `login` is not
registered at all when `mcp.require_service_account: true`, regardless of
`allow_interactive_login` — a service account's whole point is that the
agent cannot act as a human, and a login tool able to override that would
defeat it. Run `rocketvault mcp --check` to confirm which identity mode a
given server is running under.

**Credentials are chat text.** Typing a password and TOTP code into a
message puts them in the model's context and in this conversation's
transcript, not just your shell history. That is a real trade-off against
running `rocketvault users login` in a terminal first — weigh it before
enabling this flag, particularly on a shared or logged conversation.
```

- [ ] **Step 3: Add the row to the capability tiers table**

Find the table under `## Enabling more` (the one with `allow_write`, `allow_destructive`, `allow_crypto`, `allow_secret_values` rows) and add a row:

```markdown
| `allow_interactive_login` | A `login` tool to re-authenticate mid-conversation | 1 (never under a service account) |
```

- [ ] **Step 4: Proofread**

Read the full `## Identity` section and the `## Enabling more` table once more, in order, to confirm the new prose reads coherently next to the existing text (no leftover reference to "no per-user authentication" elsewhere in the file — search for that phrase and fix any other occurrence).

Run: `grep -n "no per-user authentication" docs/mcp-server.md`
Expected: no matches (the phrase should exist nowhere in the file after Step 1's edit).

- [ ] **Step 5: Commit**

```bash
git add docs/mcp-server.md
git commit -m "$(cat <<'EOF'
docs(mcp): document the login tool

Corrects the Identity section's now-inaccurate "no per-user
authentication" claim, adds an Interactive login subsection covering
the allow_interactive_login flag, the service-account exclusion, and
the credentials-in-chat trade-off, and adds the flag to the capability
tiers table.
EOF
)"
```

---

### Task 2: Full verification sweep

**Files:** none — this task runs checks, it does not edit code.

**Interfaces:** none.

- [ ] **Step 1: Build and vet everything**

Run:
```bash
go build ./...
go vet ./...
```
Expected: both clean, no output.

- [ ] **Step 2: Run the full unit test suite with the race detector**

Run:
```bash
go test ./... -race
```
Expected: PASS across every package, including `internal/vaultapi`, `internal/mcpserver`, `config`, and `cmd`.

- [ ] **Step 3: Run the MCP integration suite**

Run:
```bash
go test -tags=integration ./internal/mcpserver/... -v
```
Expected: PASS, including `TestLive_LoginSwapsIdentityForSubsequentCalls` and `TestLive_LoginIsAbsentWithoutTheFlag` from Part 4, and every pre-existing `TestLive_*`/`TestHarness_*` test.

- [ ] **Step 4: Manually reproduce the original 2026-08-24 scenario end to end**

This is the scenario that started this whole feature. Confirm it by hand once, against a real running instance, since Part 4's automated tests prove the two mechanisms separately but this is the only place both run together exactly as a user would hit them:

```bash
# Terminal 1
./rocketvault serve &

# Terminal 2 -- start the MCP subprocess with an already-valid session
./rocketvault users login --username admin
./rocketvault mcp &
MCP_PID=$!

# Terminal 2, continued -- log in again, simulating a session refresh
# that happened after the subprocess above started
./rocketvault users login --username admin

# Terminal 3 -- exercise the subprocess without restarting it. Use
# whatever MCP client you have wired to this binary (e.g. Claude Code's
# /mcp reconnect against the already-running process, or a direct
# stdio JSON-RPC call) and confirm a read tool succeeds immediately,
# with no "session not found or expired" error and no need to kill
# $MCP_PID.
```

Expected: the read tool succeeds without restarting the subprocess — this is the exact failure this whole feature series exists to fix. If it does not, stop here and re-open Part 1, Task 2 rather than proceeding.

- [ ] **Step 5: Manually verify the login tool once, end to end**

With the same running `rocketvault mcp` subprocess (started under a session identity, `mcp.allow_interactive_login: true`, `mcp.require_service_account` unset or `false`), call `login` from your MCP client with a different valid user's credentials than the one the subprocess started as, then call a read tool and confirm the audit log (`rocketvault audit logs`) now attributes it to the new user, not the original one.

- [ ] **Step 6: Report completion**

No commit for this task — it is verification only. If every step above passed, the feature is complete: all five plans in this series are done, and `docs/superpowers/specs/2026-08-25-mcp-interactive-login-design.md` is fully implemented.

---

## After this plan

Nothing further in this series. If any step in Task 2 surfaced a problem, open a new small plan (or drop back into `superpowers:systematic-debugging`) rather than patching code without a failing test reproducing it first.
