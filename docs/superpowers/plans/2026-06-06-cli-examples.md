# CLI Example Coverage Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every RocketVault cobra command a multi-line, copy-paste-runnable `Example:` field so `--help` teaches real usage.

**Architecture:** Pure edits to the `Example:` struct field on each `&cobra.Command{}`. No logic, flag, or behaviour changes. Cobra renders the field under the `Examples:` section of `--help` automatically. Work is split into 8 batches by directory; each batch is one task: edit the files, build-verify, commit.

**Tech Stack:** Go 1.25, cobra CLI framework. Build/verify via `./build.sh`.

---

## Background facts (verified)

- 75 commands total; 20 have no `Example:`; 55 have a single-line example to normalize.
- Auth + global flags are **persistent**, registered in `cmd/root.go:75-85`, so every command accepts them:
  - `--username`, `--password`, `--totp-code` (auth/MFA)
  - `--output table|json|yaml`
  - `--vault <name>`
  - `--config <path>`
- Standard example format (per spec `docs/superpowers/specs/2026-06-06-cli-examples-design.md`):
  - Multi-line backtick string, 2–3 cases.
  - Each case opens with a `#` comment.
  - Every invocation line prefixed with `rocketvault`.
  - Auth flags included on every invocation (`\`-continued line).
  - Reflects the command's actual flags/args — never guess; read the file first.
- Reference example already in the right style: `cmd/rotation.go` (group) and
  `cmd/vault-access/grant.go:20` (leaf).

## Format template (copy this shape)

```go
Example: `  # <intent of first case>
  rocketvault <command> <args> <flags> \
    --username admin --password admin123 --totp-code <code>

  # <intent of second case>
  rocketvault <command> <args> <other-flags> \
    --username admin --password admin123 --totp-code <code>`,
```

Group commands instead point at their top subcommands (see Task 6/8 audit/migrate).

---

## Task 1: secrets batch (`cmd/secrets/`)

**Files:**
- Modify (blank → add): `cmd/secrets/get.go`, `cmd/secrets/list.go`, `cmd/secrets/delete.go`, `cmd/secrets/generate.go`, `cmd/secrets/update.go`
- Modify (normalize existing): `cmd/secrets/create.go`, `cmd/secrets/export.go`, `cmd/secrets/import.go`

Verified flags/args:
- `get [id]` — ExactArgs(1), no own flags.
- `list` — `--tags` (StringSlice).
- `delete [id]` — one positional id.
- `generate-password` — `--length` (int 16), `--uppercase/--lowercase/--numbers/--special` (bool true).
- `update [id] [value]` — ExactArgs(2), `--tags` (StringSlice), `--content-type` (string).

- [ ] **Step 1: Add Example to `cmd/secrets/get.go`**

Insert an `Example:` field right after the `Use:   "get [id]"` line:

```go
	Example: `  # Get a secret by id
  rocketvault secrets get <id> \
    --username admin --password admin123 --totp-code <code>

  # Get a secret as JSON
  rocketvault secrets get <id> --output json \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 2: Add Example to `cmd/secrets/list.go`**

```go
	Example: `  # List all secrets
  rocketvault secrets list \
    --username admin --password admin123 --totp-code <code>

  # List secrets filtered by tags, as JSON
  rocketvault secrets list --tags prod,db --output json \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 3: Add Example to `cmd/secrets/delete.go`**

```go
	Example: `  # Soft-delete a secret by id
  rocketvault secrets delete <id> \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 4: Add Example to `cmd/secrets/generate.go`**

```go
	Example: `  # Generate a 16-character password (default)
  rocketvault secrets generate-password \
    --username admin --password admin123 --totp-code <code>

  # Generate a 32-character password without special characters
  rocketvault secrets generate-password --length 32 --special=false \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 5: Add Example to `cmd/secrets/update.go`**

```go
	Example: `  # Update a secret's value
  rocketvault secrets update <id> <new-value> \
    --username admin --password admin123 --totp-code <code>

  # Update value, tags and content type
  rocketvault secrets update <id> <new-value> --tags prod,db --content-type text/plain \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 6: Normalize existing examples in create/export/import**

Read each file's current `Example:` and current flags, then rewrite into the
template above (multi-line, `rocketvault` prefix, auth flags, `#` comments).
Keep the flags each command actually registers — read the file before editing.

- [ ] **Step 7: Build-verify the batch**

Run: `go build ./cmd/...`
Expected: no output, exit 0 (any backtick typo fails here).

- [ ] **Step 8: Spot-check help renders**

Run: `go run . secrets get --help`
Expected: an `Examples:` section showing the multi-line block.

- [ ] **Step 9: Commit**

```bash
git add cmd/secrets/
git commit -S -m "docs(cli): add usage examples to secrets commands"
```

---

## Task 2: vaults batch (`cmd/vaults/`)

**Files:**
- Modify (blank → add): `cmd/vaults/get.go`, `cmd/vaults/list.go`, `cmd/vaults/delete.go`, `cmd/vaults/purge.go`, `cmd/vaults/recover.go`
- Modify (normalize existing): `cmd/vaults/create.go`, `cmd/vaults/update.go`

Verified flags/args:
- `get <name>` — ExactArgs(1).
- `list` — `--include-deleted` (bool).
- `delete <name>` / `purge <name>` / `recover <name>` — ExactArgs(1).

- [ ] **Step 1: Add Example to `cmd/vaults/get.go`**

```go
	Example: `  # Get a vault by name
  rocketvault vaults get <name> \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 2: Add Example to `cmd/vaults/list.go`**

```go
	Example: `  # List vaults
  rocketvault vaults list \
    --username admin --password admin123 --totp-code <code>

  # Include soft-deleted vaults
  rocketvault vaults list --include-deleted \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 3: Add Example to `cmd/vaults/delete.go`**

```go
	Example: `  # Soft-delete a vault by name
  rocketvault vaults delete <name> \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 4: Add Example to `cmd/vaults/purge.go`**

```go
	Example: `  # Permanently purge a soft-deleted vault
  rocketvault vaults purge <name> \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 5: Add Example to `cmd/vaults/recover.go`**

```go
	Example: `  # Recover a soft-deleted vault
  rocketvault vaults recover <name> \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 6: Normalize create/update**

Read `cmd/vaults/create.go` and `cmd/vaults/update.go` current examples and
flags; rewrite into the template format.

- [ ] **Step 7: Build-verify**

Run: `go build ./cmd/...`
Expected: exit 0.

- [ ] **Step 8: Commit**

```bash
git add cmd/vaults/
git commit -S -m "docs(cli): add usage examples to vaults commands"
```

---

## Task 3: keys batch — normalize only (`cmd/keys/`)

**Files (all have an existing single-line example to normalize):**
`create.go`, `delete.go`, `get.go`, `list.go`, `rotate.go`, `unwrap.go`, `update.go`, `wrap.go`

Verified flags (from existing examples + file read required per command):
- `get/delete/rotate <key-id>` — ExactArgs(1).
- `list` — `--type`, `--tags`.
- `update <key-id>` — `--name`, `--revoked`.
- `wrap/unwrap` — `--key-id`, `--key-material` / `--wrapped-key`.

- [ ] **Step 1: Normalize `cmd/keys/get.go`**

Replace the existing single-line `Example:` with:

```go
	Example: `  # Get a key by id
  rocketvault keys get <key-id> \
    --username admin --password admin123 --totp-code <code>

  # Get a key as JSON
  rocketvault keys get <key-id> --output json \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 2: Normalize `cmd/keys/list.go`**

```go
	Example: `  # List all keys
  rocketvault keys list \
    --username admin --password admin123 --totp-code <code>

  # Filter by type and tags
  rocketvault keys list --type RSA --tags prod,secure \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 3: Normalize `cmd/keys/create.go`**

Read the file's registered flags first (the current example `keys create --name <name> --type <type>` omits the binary prefix and auth). Rewrite:

```go
	Example: `  # Create an RSA key
  rocketvault keys create --name <name> --type RSA \
    --username admin --password admin123 --totp-code <code>`,
```

Adjust flags to match what `create.go` actually registers.

- [ ] **Step 4: Normalize delete/rotate/update/wrap/unwrap**

For each: read its flags, then rewrite the existing example into the template
format (binary prefix, auth flags, `#` comment, multi-line). Use the verified
flags above; confirm against each file before editing.

- [ ] **Step 5: Build-verify**

Run: `go build ./cmd/...`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add cmd/keys/
git commit -S -m "docs(cli): normalize key command examples to standard format"
```

---

## Task 4: certificates batch — normalize only (`cmd/certificates/`)

**Files:** `create.go`, `delete.go`, `get.go`, `list.go`, `renew.go`, `update.go` (all have existing examples).

- [ ] **Step 1: Normalize each certificate command**

For each of the six files: read its `Use:`, `Args:`, and registered flags, then
rewrite the existing `Example:` into the template. Pattern for the leaf
commands taking an id:

```go
	Example: `  # Get a certificate by id
  rocketvault certificates get <cert-id> \
    --username admin --password admin123 --totp-code <code>

  # Get a certificate as JSON
  rocketvault certificates get <cert-id> --output json \
    --username admin --password admin123 --totp-code <code>`,
```

Apply the matching shape to `create`, `delete`, `list`, `renew`, `update`,
substituting that command's real flags/args.

- [ ] **Step 2: Build-verify**

Run: `go build ./cmd/...`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/certificates/
git commit -S -m "docs(cli): normalize certificate command examples to standard format"
```

---

## Task 5: users batch — normalize only (`cmd/users/`)

**Files:** `admin.go`, `create.go`, `delete.go`, `get.go`, `list.go`, `login.go`, `update.go` (all have existing examples).

Note: `login.go` and `admin.go` are auth-establishing commands. For these, the
auth flags ARE the point of the example — keep them inline (they are the
command's real flags, not boilerplate). `admin` also takes `--bootstrap-token`.

- [ ] **Step 1: Normalize each user command**

For each file: read its flags, rewrite the existing example into the template.
Example shape for `login` (auth flags are the command's own flags here):

```go
	Example: `  # Log in and obtain a session token
  rocketvault users login \
    --username admin --password admin123 --totp-code <code>`,
```

Example shape for `get`:

```go
	Example: `  # Get a user by id
  rocketvault users get <id> \
    --username admin --password admin123 --totp-code <code>`,
```

Apply matching shapes to `admin` (include `--bootstrap-token`), `create`,
`delete`, `list`, `update`, using each command's real flags.

- [ ] **Step 2: Build-verify**

Run: `go build ./cmd/...`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/users/
git commit -S -m "docs(cli): normalize user command examples to standard format"
```

---

## Task 6: audit batch (`cmd/audit/`)

**Files:**
- Modify (blank → add, group command): `cmd/audit/audit.go`
- Modify (normalize existing): `cmd/audit/config.go`, `cmd/audit/logs.go`, `cmd/audit/report.go`

`audit.go` is a group command with subcommands `logs`, `report`, `config`.

- [ ] **Step 1: Add Example to the `audit` group in `cmd/audit/audit.go`**

```go
	Example: `  # View recent audit log entries
  rocketvault audit logs \
    --username admin --password admin123 --totp-code <code>

  # Generate a compliance report
  rocketvault audit report --type soc2 \
    --username admin --password admin123 --totp-code <code>

  # Show audit retention config
  rocketvault audit config \
    --username admin --password admin123 --totp-code <code>`,
```

Confirm `report`'s real flag name (`--type` vs other) by reading
`cmd/audit/report.go` before finalizing.

- [ ] **Step 2: Normalize config/logs/report**

Read each file's flags, rewrite existing examples into the template.

- [ ] **Step 3: Build-verify**

Run: `go build ./cmd/...`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add cmd/audit/
git commit -S -m "docs(cli): add and normalize audit command examples"
```

---

## Task 7: vault-access batch (`cmd/vault-access/`)

**Files:**
- Modify (blank → add): `cmd/vault-access/list.go`, `cmd/vault-access/revoke.go`, `cmd/vault-access/roles.go`
- Already has example (reference, leave or align): `cmd/vault-access/grant.go`

Verified:
- `list` — uses `--vault` to target a vault.
- `revoke <assignment-id>` — ExactArgs(1), `--vault`.
- `roles` — no auth needed conceptually but keep consistent; lists built-in roles.
- `grant <principal>` existing example: `rocketvault vault-access grant alice --role secrets-user --vault prod`.

- [ ] **Step 1: Add Example to `cmd/vault-access/list.go`**

```go
		Example: `  # List role assignments in a vault
  rocketvault vault-access list --vault prod \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 2: Add Example to `cmd/vault-access/revoke.go`**

```go
		Example: `  # Revoke a role assignment by id
  rocketvault vault-access revoke <assignment-id> --vault prod \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 3: Add Example to `cmd/vault-access/roles.go`**

```go
		Example: `  # List built-in vault roles and their permissions
  rocketvault vault-access roles \
    --username admin --password admin123 --totp-code <code>`,
```

(Note indentation: these commands are defined inside `Init*` functions with a
deeper tab level — match the surrounding struct literal indentation in each
file.)

- [ ] **Step 4: Optionally align grant.go**

Read `cmd/vault-access/grant.go:20`. Its single-line example is already correct
in spirit; rewrite to multi-line template for consistency with the batch.

- [ ] **Step 5: Build-verify**

Run: `go build ./cmd/...`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add cmd/vault-access/
git commit -S -m "docs(cli): add and normalize vault-access command examples"
```

---

## Task 8: top-level commands (`cmd/*.go`)

**Files:**
- Modify (blank → add): `cmd/root.go` (root command), `cmd/serve.go`, `cmd/migrate.go` (3 of its 4 commands), `cmd/vault_access.go` (group)
- Modify (normalize existing): `cmd/backup.go` (4), `cmd/certificate.go`, `cmd/health.go`, `cmd/keys.go`, `cmd/secrets.go`, `cmd/users.go`, `cmd/vaults.go`, `cmd/version.go` (4), `cmd/rotation.go` (already multi-line — leave), `cmd/migrate.go` migrate command (has example)

Verified flags/args:
- `serve` — `--listen`, `--api_base`, `--backend_url`, `--database_name`, `--log-timestamp`, `--log-level`.
- `migrate` (has example), `migrate:status` (no args), `migrate:to [version]` (ExactArgs 1), `migrate:create [description]` (MinimumNArgs 1).
- `root` (`rocketvault`) — top-level; example should point at common subcommands.
- `vault_access.go` — group, subcommands grant/revoke/list/roles.

- [ ] **Step 1: Add Example to root command `cmd/root.go`**

```go
	Example: `  # Log in
  rocketvault users login --username admin --password admin123 --totp-code <code>

  # Create and read a secret
  rocketvault secrets create <name> <value> --username admin --password admin123 --totp-code <code>
  rocketvault secrets get <id> --username admin --password admin123 --totp-code <code>

  # Start the API server
  rocketvault serve`,
```

- [ ] **Step 2: Add Example to `cmd/serve.go`**

```go
	Example: `  # Start the API server on the default address
  rocketvault serve

  # Start on a custom listen address with debug logging
  rocketvault serve --listen :9000 --log-level debug`,
```

- [ ] **Step 3: Add Examples to the three migrate subcommands in `cmd/migrate.go`**

`migrate:status`:
```go
	Example: `  # Show pending and applied migrations
  rocketvault migrate:status`,
```

`migrate:to`:
```go
	Example: `  # Migrate the database to a specific version
  rocketvault migrate:to <version>`,
```

`migrate:create`:
```go
	Example: `  # Create a new migration file
  rocketvault migrate:create "add purge_protection column"`,
```

- [ ] **Step 4: Add Example to the `vault-access` group in `cmd/vault_access.go`**

```go
	Example: `  # Grant a role to a principal in a vault
  rocketvault vault-access grant alice --role secrets-user --vault prod \
    --username admin --password admin123 --totp-code <code>

  # List built-in roles
  rocketvault vault-access roles \
    --username admin --password admin123 --totp-code <code>`,
```

- [ ] **Step 5: Normalize the existing top-level examples**

For `cmd/backup.go` (4), `cmd/certificate.go`, `cmd/health.go`, `cmd/keys.go`,
`cmd/secrets.go`, `cmd/users.go`, `cmd/vaults.go`, `cmd/version.go` (4): read
each command's flags and rewrite the existing `Example:` into the multi-line
template. Leave `cmd/rotation.go` as-is (already multi-line in the target
format).

- [ ] **Step 6: Build-verify and vet**

Run: `go build ./... && go vet ./...`
Expected: exit 0, no output.

- [ ] **Step 7: Spot-check help on a sample**

Run: `go run . serve --help` and `go run . migrate:status --help`
Expected: each shows the `Examples:` section.

- [ ] **Step 8: Commit**

```bash
git add cmd/*.go
git commit -S -m "docs(cli): add and normalize top-level command examples"
```

---

## Task 9: Final verification

- [ ] **Step 1: Confirm zero commands remain without an example**

Run:
```bash
for d in cmd cmd/secrets cmd/users cmd/vaults cmd/keys cmd/certificates cmd/audit cmd/vault-access; do
  for f in $d/*.go; do
    case $f in *_test.go|*/testutils/*) continue;; esac
    [ -f "$f" ] || continue
    u=$(grep -E "^[[:space:]]*Use:" "$f" | wc -l)
    e=$(grep -E "^[[:space:]]*Example:" "$f" | wc -l)
    [ "$u" -gt "$e" ] && echo "MISSING: $f (Use=$u Example=$e)"
  done
done
echo "scan done"
```
Expected: only `scan done` (no MISSING lines).

- [ ] **Step 2: Full build + vet + test**

Run: `./build.sh --test`
Expected: `[SUCCESS] All tests passed.` (examples are doc-only; tests must stay green).

- [ ] **Step 3: Confirm help output for one command per batch**

Run each and confirm an `Examples:` block renders:
```bash
go run . secrets list --help
go run . vaults get --help
go run . keys list --help
go run . certificates get --help
go run . users get --help
go run . audit logs --help
go run . vault-access roles --help
go run . serve --help
```

---

## Self-review notes

- **Spec coverage:** all 75 commands covered — 20 blanks filled (Tasks 1,2,6,7,8), 55 normalized (every batch). Group commands included (audit, vault-access, root). Auth flags included per spec decision.
- **No placeholders:** concrete example code given for every blank command; normalize steps direct the engineer to read real flags first (the only safe way — examples must match actual flags).
- **Type/flag consistency:** flag names (`--tags`, `--include-deleted`, `--length`, `--type`, `--listen`, `--log-level`, `--role`, `--vault`, `--bootstrap-token`) verified against source before listing.
- **Risk:** malformed backtick literals → caught by `go build` in each batch's verify step.
