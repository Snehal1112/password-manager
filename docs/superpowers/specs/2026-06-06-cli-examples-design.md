# CLI Example Coverage Sweep — Design

**Date:** 2026-06-06
**Status:** Approved
**Author:** brainstorming session

## Problem

RocketVault has roughly 200 cobra commands across `cmd/`. Only about 57 carry
an `Example:` field; roughly 140 are blank. Users running `<command> --help`
get no usage guidance for most commands. The existing examples are also
inconsistent — some include the `rocketvault` binary prefix and auth flags,
some omit both, and only a few use the richer multi-line form.

## Goal

Every cobra command carries a multi-line `Example:` field so `--help` teaches
real, copy-paste-runnable usage. Help output is consistent across the whole CLI.

## Scope

- **All commands** in `cmd/*.go` and the subdirectories
  `cmd/{audit,certificates,keys,secrets,users,vaults,vault-access}/`.
- **Leaf commands** (actions: create, get, list, delete, rotate, etc.).
- **Parent/group commands** (bare `keys`, `secrets`, `audit`) — these get an
  example pointing at their most common subcommands, aiding discovery.
- **Normalize existing examples**: the ~57 commands that already have an
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

| Batch | Files | ~Commands |
|-------|-------|-----------|
| 1 | `cmd/secrets/` | 46 |
| 2 | `cmd/users/` | 44 |
| 3 | `cmd/vaults/` | 28 |
| 4 | `cmd/keys/` | 21 |
| 5 | `cmd/certificates/` | 18 |
| 6 | `cmd/audit/` | 11 |
| 7 | `cmd/vault-access/` | 5 |
| 8 | top-level `cmd/*.go` (root, serve, migrate, rotation, version, etc.) | remainder |

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
