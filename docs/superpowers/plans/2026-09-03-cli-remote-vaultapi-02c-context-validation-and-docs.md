# Context Validation and Remote-Mode Doc Corrections — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject a malformed server URL when a context is saved rather than at request time, and correct the help text and usage guide that still claim nothing acts on the current context.

**Architecture:** No architectural change. Both tasks are small corrections that phase 2 leaves behind: one input validation in `context add`, and two pieces of prose that stopped being true when the secrets adapter landed on 2026-08-24.

**Tech Stack:** Go 1.24, cobra, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

**Depends on:** `2026-09-03-cli-remote-vaultapi-02b-remote-login.md` — Task 2's prose must describe the guard's final phase-2 shape, which `02b` sets by admitting `users login`/`logout`.

## Global Constraints

- Existing saved contexts must keep loading; validation applies to new writes, not to what is already on disk.
- Documentation must state what is true at the commit that lands it, not what is planned.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Validate the server URL in `context add`

Small, and it belongs here: a context saved without a scheme fails at request time with an opaque transport error, which is confusing precisely when someone is first setting up remote mode.

**Files:**
- Modify: `cmd/context/add.go:42-44`
- Test: `cmd/context/add_test.go`

**Interfaces:**
- Produces: nothing importable.

- [ ] **Step 1: Write the failing test**

```go
func TestContextAdd_RejectsServerWithoutScheme(t *testing.T) {
	common.ContextFilePath = filepath.Join(t.TempDir(), "contexts.json")

	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"prod", "--server", "vault.example.com"})
	err := cmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestContextAdd_AcceptsHTTPS(t *testing.T) {
	common.ContextFilePath = filepath.Join(t.TempDir(), "contexts.json")

	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"prod", "--server", "https://vault.example.com"})
	require.NoError(t, cmd.Execute())
}
```

Match `newAddCmdForTest` to however the existing tests in `cmd/context/` construct a command; if no such helper exists, build the command with `InitContextAdd` onto a fresh parent.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/context/ -run TestContextAdd_Rejects -v`
Expected: FAIL — the malformed server is accepted.

- [ ] **Step 3: Validate**

In `cmd/context/add.go`, replace the non-empty check:

```go
			if server == "" {
				return fmt.Errorf("--server is required")
			}
			parsed, err := url.Parse(server)
			if err != nil {
				return fmt.Errorf("--server %q is not a valid URL: %w", server, err)
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				return fmt.Errorf(
					"--server %q needs an http:// or https:// scheme (got %q)", server, parsed.Scheme)
			}
			if parsed.Host == "" {
				return fmt.Errorf("--server %q has no host", server)
			}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/context/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/context/add.go cmd/context/add_test.go
git commit -S -m "fix(cli): validate the server URL in context add

A context saved as 'vault.example.com' was accepted and then failed at
request time with an opaque transport error, which is confusing exactly
when someone is first configuring remote mode."
```

---

### Task 2: Correct the stale help text and docs

**Files:**
- Modify: `cmd/context/use.go:16-17`
- Modify: `cmd/root.go:71-75` (root command `Long` help text)
- Modify: `docs/usage-guide.md` (the remote-target guard paragraph)

- [ ] **Step 1: Fix the help text**

`cmd/context/use.go` claims "no other command yet acts on the current context", which the secrets adapters made false. Replace with a statement of what is actually true after this plan:

```go
		Long: `Mark a saved context as current, so later commands target its server.

Commands with a remote adapter act on it directly. Every other command
refuses to run while a context is current, rather than silently operating
on the local instance -- run 'context unset' to return to local mode.`,
```

- [ ] **Step 2: Fix the root help text**

`cmd/root.go:71-75` is the most visible instance of the same stale claim, and the one a new user meets first: "Remote mode (--server, ROCKETVAULT_ADDR, or an active context) is implemented only for the context group — every other command refuses to run while a remote target is set". That has been false since the secrets adapter landed on 2026-08-24 and is false again after `02b`.

Replace it with a sentence that states the rule — commands with a remote adapter act on the target; the rest refuse rather than silently falling back — without enumerating which groups qualify. The paragraph immediately below it already tells the user to "Log in once with 'rocketvault users login'", advice that only became true for remote mode in `02b`; check it still reads correctly.

- [ ] **Step 3: Fix the usage guide**

In `docs/usage-guide.md`, the paragraph beginning "A remote-target guard now blocks nearly every command" states "no resource command (`secrets`, `keys`, `certificate`, `users`, etc.) actually talks to a remote server yet". That has been false since the secrets adapter landed on 2026-08-24, and `02b` made it false for `users login`/`logout` too.

Replace it with a statement that points at `remoteCapableCommands` in `cmd/root.go` as the authority on which groups are remote-capable, rather than restating the list. The list grows with every adapter phase; prose that enumerates it goes stale the moment plan `03b` lands `vault-access`. Name `secrets` and `users login`/`logout` as examples if a concrete anchor helps the reader, but make the code the source of truth.

- [ ] **Step 4: Verify**

Run: `go build -o rocketvault . && ./rocketvault context use --help && ./rocketvault --help`
Expected: the new text in both, with no claim that nothing acts on the context or that only the context group supports remote mode. (`go build ./...` compiles every package but writes no binary, so it cannot be followed by running one.)

- [ ] **Step 5: Commit**

```bash
git add cmd/context/use.go cmd/root.go docs/usage-guide.md
git commit -S -m "docs(cli): correct stale claims about remote mode

The root help text, the 'context use' help text and the usage guide all
stated that remote mode reaches only the context group, or that no
command acts on the current context. That stopped being true when the
secrets adapter landed on 2026-08-24, and again when users login/logout
gained remote support.

The replacements point at the guard's own allowlist rather than
enumerating groups, so the next adapter phase does not have to remember
to edit prose."
```

---

### Task 3: Add a remote-server journey to the journeys doc

`docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` carries 21 end-to-end scenarios organized by actor, and every one of them runs against a local instance. Remote mode appears only as a flag in the global list at line 79, a `preview-migration` caveat that refuses `--server`, and a `context add` example around line 1472. There is no journey for "operate against a deployed server", which is the workflow phase 2 exists to enable.

Write it against what has actually landed by this point — `secrets`, `users login`, `users logout`, and nothing else. Do not describe `vault-access` remotely; that arrives in `03b`, and this doc's own discipline is that commands come from `cmd/`, never from what is planned.

**Files:**
- Modify: `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`

**Interfaces:**
- Produces: nothing importable.

- [ ] **Step 1: Read the conventions before writing**

Read two existing journeys end to end — Journey B (onboarding, line 169) for the actor-and-narrative shape, and Journey K (the CLI/HTTP purge divergence, line 694) for how the doc handles a capability gap. Match them. In particular:

- Each journey opens with an **Actor** line naming a person and their role.
- Commands are copied from `cmd/`, with real flags. Verify each against the source before writing it.
- Where a capability is missing, the journey says so plainly rather than showing an invocation that would fail. This journey has several such points and they are the most valuable part of it.

- [ ] **Step 2: Write the journey**

Add it after Journey Q, following the existing heading pattern. It should cover, in narrative order:

1. Saving a context (`rocketvault context add`, `context use`) and what the current-context pointer means.
2. Logging in against it — `rocketvault users login --username … --password … --totp-code …` — and where the session lands: `~/.rocketvault/sessions/srv_<host>__<user>.json`, with `current` pointing at it, separate from any local session for the same username.
3. Running a bare `rocketvault secrets list` with no credentials, and the transparent refresh when the access token expires.
4. `rocketvault users logout`, and that it clears only this server's session — the local one survives.
5. `rocketvault context unset` to return to local mode, showing the same command now reads the local instance.

Then the honest limits, which are the point of putting this in *this* doc rather than the CLI guide:

- Only `secrets` and `users login`/`logout` work remotely at this commit. Every other group — `keys`, `certificates`, `vaults`, `vault-access`, `audit` — is refused by the remote-target guard with a message telling the user to run against the local instance. Name `remoteCapableCommands` in `cmd/root.go` as the authority rather than listing groups that will change.
- `vaults preview-migration` refuses `--server` by design: it reads the local database file directly. The existing note at line 128 already says this; cross-reference it rather than restating it.
- Service-account credentials (`--client-id`/`--client-secret`, from `02a`) authenticate with no session file at all, which is the CI shape. Worth its own short subsection since no other journey covers unattended auth.

- [ ] **Step 3: Verify every command**

For each command in the new journey, confirm the flag exists in `cmd/`:

Run: `go build -o rocketvault . && ./rocketvault context add --help && ./rocketvault users login --help && ./rocketvault users logout --help`
Expected: every flag used in the journey appears. Fix the journey, not the code, on any mismatch.

Then walk the journey end to end against a running server exactly as written, including the failure cases — a guarded command must produce the message the journey claims.

- [ ] **Step 4: Commit**

```bash
git add docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
git commit -S -m "docs(journeys): add a remote-server journey

Every one of the 21 existing journeys runs against a local instance,
so the workflow phase 2 exists to enable had no narrative anywhere:
save a context, log in against it, run bare commands off the cached
session, log out without touching the local session.

Includes the limits, which is why it belongs here rather than in the
CLI guide -- only secrets and users login/logout are remote-capable at
this commit, and preview-migration refuses --server by design."
```

---

## Self-Review

**Spec coverage:** Tasks 1 and 2 are the last items the spec lists for phase 2 outside the auth work itself. The third documentation correction (`known-issues-gotchas.md`) lives in the cross-project KB, outside this repo, and is left to the `kb-refresh` skill. Task 3 is beyond the spec: the journeys doc had no remote-mode scenario at all, which only became a visible gap once remote login worked.

**Placeholder scan:** One step defers to surrounding code rather than prescribing it — `newAddCmdForTest` in Task 1 Step 1 — because it must match however `cmd/context/`'s existing tests construct a command. It says so and states the fallback. No TBDs.

**Type consistency:** Neither task produces an importable interface; nothing downstream depends on their shapes.

**Ordering:** Task 1 is independent. Tasks 2 and 3 both depend on `02b` for accuracy — Task 3 more strictly, since its journey logs in with `users login` against a remote target, which does not work until `02b` Task 3 lands.

**Known risk:** documentation that enumerates which command groups are remote-capable goes stale on every adapter phase — this plan exists partly because the last such sentence sat wrong for months. Task 2 Step 2 therefore points readers at `remoteCapableCommands` in `cmd/root.go` as the authority instead of restating the list. If a reviewer pushes back and wants the explicit list in the guide, add a note to plan `03b` to update it, because nothing else will catch it.
