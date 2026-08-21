# CLI Example Coverage Sweep — Design

**Date:** 2026-06-06
**Status:** Superseded on 2026-08-21 by `.claude/cli-help-conventions.md`
**Author:** brainstorming session

> **Superseded.** Rule 4 below ("include auth flags on every invocation") was
> correct when written, but the 2026-08-15 CLI session-cache migration made it
> obsolete: `rocketvault users login` now caches a session and leaf commands
> need no credential flags. Examples following Rule 4 teach a superseded
> workflow. The current house style is `.claude/cli-help-conventions.md`, and
> `cmd/help_examples_test.go` now enforces it — which also reverses this
> spec's "no test guard and no CI check are added" decision.

## Problem

RocketVault has 75 cobra commands across `cmd/` (counting real `Use:` fields
only, excluding test files and commented examples). 55 carry an `Example:`
field; 20 are blank. Users running `<command> --help` on the blank ones get no
usage guidance. The existing examples are also inconsistent — some include the
`rocketvault` binary prefix and auth flags, some omit both, and only a few use
the richer multi-line form.

## Goal

Every cobra command carries a multi-line `Example:` field so `--help` teaches
real, copy-paste-runnable usage. Help output is consistent across the whole CLI.

## Scope

- **All commands** in `cmd/*.go` and the subdirectories
  `cmd/{audit,certificates,keys,secrets,users,vaults,vault-access}/`.
- **Leaf commands** (actions: create, get, list, delete, rotate, etc.).
- **Parent/group commands** (bare `keys`, `secrets`, `audit`) — these get an
  example pointing at their most common subcommands, aiding discovery.
- **Normalize existing examples**: the 55 commands that already have an
  `Example:` field are rewritten into the standard format below.
- **One-time fill only.** No test guard and no CI check are added. Future
  commands may again ship without examples; that is accepted.

Out of scope: any logic change, flag changes, refactoring unrelated to the
`Example:` fields.

## Example Format (standard)

Multi-line, 2–3 realistic cases per command. Each case has a leading `#`
comment describing intent. Every invocation line is prefixed with the
`rocketvault` binary. Auth flags (`--username` / `--password` / `--totp-code`)
are **included** on every invocation so each example is fully copy-paste
runnable.

```go
Example: `  # Get a key
  rocketvault keys get <key-id> \
    --username admin --password admin123 --totp-code <code>

  # As JSON output
  rocketvault keys get <key-id> --output json \
    --username admin --password admin123 --totp-code <code>`,
```

Rules:

1. Multi-line string literal (backticks), 2–3 cases.
2. Each case opens with a `#` comment.
3. Binary prefix `rocketvault` on every invocation line.
4. Include auth flags on every invocation.
5. Show the command's own flags and positional args, reflecting the actual
   flag registration — never guessed.
6. Group commands point at their top 2–3 subcommands.

## Components / Units of Work

Each cobra command is self-contained, so work splits cleanly by file. Natural
batches, largest first:

| Batch | Files | Commands | Blank | Normalize |
|-------|-------|----------|-------|-----------|
| 1 | `cmd/secrets/` | 8 | 5 | 3 |
| 2 | `cmd/vaults/` | 7 | 5 | 2 |
| 3 | `cmd/keys/` | 8 | 0 | 8 |
| 4 | `cmd/certificates/` | 6 | 0 | 6 |
| 5 | `cmd/users/` | 7 | 0 | 7 |
| 6 | `cmd/audit/` | 4 | 1 | 3 |
| 7 | `cmd/vault-access/` | 4 | 3 | 1 |
| 8 | top-level `cmd/*.go` (root, serve, migrate, rotation, version, backup, etc.) | 31 | 6 | 25 |

Totals: 75 commands, 20 blank, 55 normalized.

## Data Flow

Pure edits to `Example:` struct fields. No runtime or logic change. Cobra
renders the field under the `Examples:` section of `--help` automatically.

## Authoring Procedure (per command)

1. Read the command's flag registration (`Flags().*Var`, `MarkFlagRequired`,
   `Args`) before writing anything.
2. Write 2–3 examples using the standard format, reflecting the real flags and
   positional arguments.
3. For group commands, reference their most common subcommands.

This read-before-write step is the bulk of the effort and prevents examples
that reference flags that do not exist.

## Error Handling

Not applicable — no runtime behaviour changes. The only failure mode is a
malformed backtick string literal breaking compilation, which is caught
immediately by `go build`.

## Verification

- `go build ./...` — confirms every edited string literal compiles.
- `go vet ./...`.
- Spot-check: run `rocketvault <cmd> --help` on a sample command per batch and
  confirm the examples render correctly.
- No new tests are added (per scope decision).

## Risks

- **Malformed string literals** breaking the build — caught by `go build`.
- **Examples referencing non-existent flags** — mitigated by the
  read-before-write authoring procedure.
