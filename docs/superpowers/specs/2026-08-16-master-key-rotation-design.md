# Master Key Rotation — Startup Guard and Re-Encryption Migration Tool

**Date**: 2026-08-16
**Status**: Approved
**Severity of driving finding**: High (pentest 2026-08-16, confirmed by live exploitation)
**Scope**: `common/encrypt.go`, `common/masterkey.go` (new), `bootstrap/bootstrap.go`,
`internal/rekey` (new), `cmd/master_key.go` (new), `docs/runbooks/master-key-rotation.md` (new),
`scripts/docsgen/docs.go`, `.claude/known-bugs.md`

---

## Problem

Every secret value and every software (non-HSM) private key in a RocketVault deployment is sealed
with AES-256-GCM under a single master key read from `viper.GetString("master_key")`
(`common/encrypt.go:43` and `:86`). The AES-GCM construction itself is correct — a fresh 12-byte
`crypto/rand` nonce per seal, prepended to the ciphertext, real AEAD authentication on open. The
defect is the key *value*.

The committed `.rocketvault.yaml:5` ships:

```yaml
master_key: "***SECRET-REMOVED-2026-08-17***"
```

That base64 decodes to the ASCII string `0123456789abcdef0123456789abcdef` — a textbook
placeholder, committed to git, identical across every deployment that never changed it. Anyone
with a copy of the database file (a stolen backup, a snapshot, a decommissioned disk, the repo
itself) decrypts every secret offline in milliseconds. The pentest confirmed this by live
exploitation, not by inspection.

Two things must be true before that finding can be closed:

1. **The server must refuse to run on that key.** Today nothing checks key quality — a 32-byte
   decode is the only requirement, and even that check is inconsistent (`EncryptSecret` accepts
   `len(key) >= 32`, `DecryptSecret` requires `len(key) == 32`).
2. **Rotating the key must not destroy the data.** Changing `master_key` in the config with
   existing rows in the database makes every stored secret, key PEM, and certificate private key
   permanently undecryptable — AES-GCM authentication fails and the plaintext is gone. There is
   no re-encryption path in the codebase today, so "just change the key" is a data-loss operation.

The git/config side of the finding (removing the committed value, sourcing the key from the
environment or a secret store) is handled by a companion plan, **H4**. H4 performs the actual
rotation on the real dev/prod databases by invoking the tool this spec designs. This spec builds
the tool and the guard; it does not run either against a live database.

---

## Blast radius — what is actually sealed with `master_key`

Determined by reading every caller of `common.EncryptSecret`/`common.DecryptSecret`
(9 files, verified by full-repo grep), then mapping each to the column it writes:

| Table | Column | Written by | Notes |
|---|---|---|---|
| `secrets` | `value` | `secrets/cryptography_service.go` via `secret_service.go` | The obvious case. |
| `secret_versions` | `value` | `secrets/versioning_service.go:123` | Version history — same ciphertext format. |
| `keys` | `value` | `keys/key_service.go:210,298,716` | **Yes — key PEMs are master-key encrypted.** Software RSA/ECDSA/ES256K private keys are stored as AES-GCM-sealed PEM. |
| `key_versions` | `value` | `keys/key_service.go` (`CreateVersion` archives `existing.Value`) | Rotation history of the above; byte-identical ciphertext format. |
| `certificates` | `private_key` | `certificates/certificate_service.go:214,362,683` | Certificate private-key PEMs, including CA keys. |

So the answer to "does `master_key` also encrypt key PEMs?" is **yes** — and the migration tool
must cover all five columns, not just `secrets.value`. Two consequences that are easy to miss:

- **PKCS#11 / HSM keys are the exception.** When `hsm.enabled: true`, `keys.value` (and any
  archived `key_versions.value`) holds `pkcs11:<uuid-label>` — a token handle, not ciphertext
  (`key_service.go:207`, read back at `keys/crypto_service.go:183`). Those rows must be skipped,
  not "decrypted". The real key material never leaves the HSM, so it is unaffected by rotation.
- **The JWT signing key is one of these rows.** `SelfPKIProvider` stores its ECDSA signing key as
  an ordinary `keys` row named `_jwt_signing*`, sealed with the master key
  (`internal/signing/self_pki.go:122,203`, read at `:172`). It is migrated automatically as part
  of the `keys` table — but it also means that on a `jwt.key_source: self_pki` deployment, running
  the server with a mismatched master key makes `loadOrGenerate` fail to decrypt and **silently
  generate a brand-new signing key**, invalidating every live session. That is the strongest
  argument for the ordering constraints in the runbook below.

**Not** master-key encrypted, verified and explicitly out of scope:

- User passwords and OAuth2 client secrets — bcrypt hashes (`common.HashString`,
  `oauth2_service.go:135`). One-way; nothing to re-encrypt.
- TOTP secrets — stored as plaintext in `users.totp_secret` (`user_repository.go:122`). A separate
  finding, not this one; the rotation tool must not touch them.
- `certificates.certificate` — public PEM, not secret.
- Backup files written by `internal/backup/backup.go:340` — encrypted with the master key, but
  they are files on disk, not database rows. See "Backups" under Operational runbook.

---

## Goals

- The server refuses to start on the known-compromised default key, on any key that is not exactly
  32 raw bytes, or on any key that is obviously not CSPRNG output — with an error message that
  tells the operator exactly what to run.
- A first-class CLI tool re-encrypts all five columns from an old key to a new key, transactionally
  and reversibly-safe, with a dry-run mode.
- Interrupting the tool (crash, `Ctrl-C`, power loss) is safe: re-running it with the same key pair
  resumes and never double-encrypts a row.
- No plaintext secret value and no key material — old or new — ever reaches a log, an error
  message, the terminal, or the process argument list.
- The tool is genuinely operable: H4 will run exactly the invocation documented here against a real
  database, so the runbook has to be complete, not illustrative.

## Non-goals

- **No envelope encryption / KEK-DEK redesign.** Per-secret data keys wrapped by a KEK would make
  future rotations O(1) instead of O(rows), but that is a storage-format change touching every read
  path, migration of every existing row, and a new column. It is the right long-term answer and is
  explicitly deferred; this spec keeps the existing single-key format and makes rotating it safe.
- **No KMS/HSM master-key custody.** The key still comes from config/env. Moving custody is H4's
  and a later plan's problem.
- **No online rotation.** The tool requires the server to be stopped. Rotating under live writes is
  a distributed-consistency problem not worth solving for an operation run once a year.
- **No re-encryption of backup files.** Documented as a runbook step (keep the old key until old
  backups are re-created), not automated.
- **No override flag for the startup guard.** No `--allow-insecure-master-key`, no env bypass. A
  guard with a documented bypass is the same guard the pentest already walked through.

---

## Architecture

```
common/encrypt.go        ParseMasterKey / EncryptWithKey / DecryptWithKey  (key-parameterized core)
                         EncryptSecret / DecryptSecret  (unchanged signatures, now thin wrappers)
common/masterkey.go      ValidateMasterKey — structural + weak-key checks         (new)
        │
        ├── bootstrap/bootstrap.go
        │     ConfigurationValidator.ValidateMasterKey → called from setup() Step 1c
        │
        └── internal/rekey                                                        (new)
              Target / Targets()      — the five (table, column, key-columns) tuples
              classify()              — pure: skip-external | already-new-key | re-encrypt
              Rekeyer.Run()           — plan-then-apply per target, batched transactions
                    │
                    └── cmd/master_key.go   `rocketvault master-key rotate`       (new)
```

### 1. Key-parameterized crypto primitives (`common/encrypt.go`)

The rotation tool needs to decrypt under one key and encrypt under another in the same process.
Today the key is read from global Viper state inside the seal/open functions, so that is
impossible without mutating global config mid-run. The fix is a straight extraction, no behavior
change for existing callers:

```go
const masterKeySize = 32

func ParseMasterKey(encoded string) ([]byte, error)          // base64 decode + exact-length check
func EncryptWithKey(value string, key []byte) (string, error)
func DecryptWithKey(encryptedValue string, key []byte) (string, error)

func EncryptSecret(value string) (string, error)   // = EncryptWithKey(value, ParseMasterKey(viper...))
func DecryptSecret(value string) (string, error)   // = DecryptWithKey(value, ParseMasterKey(viper...))
```

This also settles the length inconsistency noted above: both directions now require exactly 32
bytes. That rejects no input that previously worked — `aes.NewCipher` only accepts 16/24/32-byte
keys, so a 33-or-more-byte key already failed one line later, just with a worse error message.

### 2. Startup guard (`common/masterkey.go` + `bootstrap`)

```go
func ValidateMasterKey(encoded string) error
```

Rejects, in this order (first match wins, so the most specific message is the one the operator
sees):

1. **Missing / not base64 / not exactly 32 bytes** — delegated to `ParseMasterKey`.
2. **The known-compromised committed default** — constant-time compare against
   `[]byte("0123456789abcdef0123456789abcdef")`. Error names the rotation command.
3. **All 32 bytes printable ASCII (0x20–0x7E)** — a key someone typed, not one a CSPRNG produced.
   A genuine random 32-byte key hits this with probability `(95/256)^32 ≈ 1.7e-14`.
4. **Fewer than 16 distinct byte values** — catches `AAAA…`-style filler. A random 32-byte key
   averages ~31 distinct values; the chance of it having fewer than 16 is around `3e-10`.

Rules 3 and 4 are deliberately cheap heuristics with negligible false-positive rates, not an
entropy estimator. They exist so that the *next* placeholder someone invents is also caught, not
just the one string the pentest found. (The committed default satisfies rule 3 and has exactly 16
distinct bytes — rule 2 catches it first and gives the better message.)

**Where the check runs matters.** It is a new `ConfigurationValidator.ValidateMasterKey` method
rather than a line inside the existing `Validate`, called from `bootstrap.setup` as **Step 1c** —
after Step 1b injects vault-sourced secrets into Viper, because that injection can itself supply
`master_key` (`bootstrap/secrets_initializer.go`); validating in Step 1 would read a value that is
about to be replaced. Keeping it a separate method also leaves the existing `Validate` test suite
(`bootstrap/bootstrap_test.go:99-155`) meaningful instead of forcing every one of its cases to
carry a valid master key.

**The CLI deliberately does not enforce this.** `cmd/root.go`'s `persistentPreRun` stays untouched:
at rotation time the config still holds the *old*, compromised key, and a CLI-wide guard would make
`rocketvault master-key rotate` — the one command that fixes the problem — impossible to run.
Server startup is the correct enforcement point; the CLI's job is to make rotation possible.

**Expected consequence, called out loudly:** once the guard lands, `go run main.go serve` against
this repo's committed `.rocketvault.yaml` fails to start until the key is rotated. That is
intended. It is also why the guard is the *last* code task in the plan — the branch stays bootable
until the tool that fixes it exists.

### 3. Re-encryption engine (`internal/rekey`)

```go
type Target struct {
    Table      string
    Column     string
    KeyColumns []string   // primary-key columns used to address a row
}
func Targets() []Target   // the five rows of the blast-radius table above

type Options struct {
    OldKey    []byte
    NewKey    []byte
    DryRun    bool
    BatchSize int          // rows per transaction, default 100
}

type TargetReport struct {
    Table, Column   string
    Total           int
    ReEncrypted     int
    AlreadyNewKey   int
    SkippedExternal int
}
type Report struct { Targets []TargetReport; DryRun bool }

type Rekeyer struct{ /* db, logger */ }
func New(database rvdb.DB, logger *logging.Logger) *Rekeyer
func (r *Rekeyer) Run(ctx context.Context, opts Options) (*Report, error)
```

**Why raw SQL instead of the repository layer.** Repositories are the codebase's normal data-access
path, and the instinct is to reuse them. They are wrong for this job on four counts: (a) reads are
scope-filtered (`model.Scope`) and soft-delete-filtered, but rotation must reach *every* row
including soft-deleted ones awaiting purge and rows owned by any user; (b) `secret_versions` and
`key_versions` have no update API at all — they are append-only from the service layer's point of
view; (c) repositories deal in domain objects whose `Value` field the service layer expects to
encrypt/decrypt on the way through, and rotation needs to write ciphertext verbatim; (d) rotation
is a storage-format maintenance operation, not a domain operation — the same category as
`internal/backup`, which for the same reasons also talks to `*sql.DB` directly. The package sits
next to `internal/backup`, not under `internal/services`.

Queries go through `rvdb.DB` (`internal/db/conn.go`), so `?` placeholders are rebound to `$n` on
Postgres automatically. Table and column names are interpolated into the SQL string, which is safe
here and only here: they come from the hardcoded `Targets()` list, never from user input.

**Per-row classification** — a pure function, the piece worth unit-testing hardest:

```
value has "pkcs11:" prefix          → SkipExternal    (HSM handle, no ciphertext)
DecryptWithKey(value, newKey) == ok → AlreadyNewKey   (already migrated; resume case)
DecryptWithKey(value, oldKey) == ok → ReEncrypt with newKey
otherwise                           → ErrUndecryptable (abort)
```

The "try the new key first" ordering is what makes the tool **idempotent under interruption**.
AES-GCM is authenticated: a wrong key fails to open with overwhelming probability, so a successful
open with the new key is a reliable "this row was already migrated" signal — no marker column, no
progress table, no state file. Re-running after a crash re-classifies everything and only touches
what is still on the old key. Running it twice in a row is a no-op that reports
`AlreadyNewKey == Total`.

**Plan-then-apply, per target.** Each table is fully read and classified before any write to it
happens. A row that decrypts with neither key therefore aborts that table with zero writes, rather
than half-migrating it — which matters because "wrong old key" is the most likely operator error.
Tables already completed before the failure stay migrated; that is safe precisely because of the
idempotent resume above, and the tool's final report plus the error message say which table failed.

Memory: the plan phase holds each row's key columns, old ciphertext, and new ciphertext for one
table at a time. Ciphertexts here are secret values and PEMs (single-digit KB at most), so a
100k-row `keys` table costs roughly 1 GB. That is the documented ceiling; deployments larger than
that should rotate table-by-table on a machine sized for it, or extend the plan phase to page by
primary key. Not solved now — `--batch-size` bounds transaction size, not plan memory.

**Concurrency guard.** Every `UPDATE` carries `AND <column> = <old ciphertext>` in its `WHERE`
clause and asserts `RowsAffected() == 1`. If anything rewrote the row between the plan and apply
phases — i.e. someone left the server running — the update matches zero rows and the tool aborts
with an error naming the row and telling the operator to stop the server and re-run. Cheap
optimistic concurrency control; it turns a silent "one secret is now unreadable" into a loud
failure.

Batches of `BatchSize` updates share one transaction (`rvdb.DB.BeginTx`), rolled back whole on any
error inside the batch. Progress is logged per batch as `table`, `column`, `updated`, `total`
counters only.

### 4. CLI surface (`cmd/master_key.go`)

```
rocketvault master-key rotate --new-key-env NEW_MASTER_KEY [--old-key-env OLD_MASTER_KEY]
                              [--dry-run] [--batch-size 100] [--yes]
```

A Cobra subcommand rather than a `scripts/` shell or Go script, because the CLI already has
everything this needs and a script would have to re-create all of it: `persistentPreRun`
(`cmd/root.go:220-260`) opens the database from the same config the server uses, builds the service
container, and resolves the admin session; `internal/db` gives dialect-correct SQL for both SQLite
and Postgres; `common` gives the crypto primitives. A standalone script would hand-roll DSN
parsing, dialect handling, and authentication, and would drift the moment the schema changes.

Command-group naming: `master-key rotate`, not `rotate-master-key` or a new `admin` group. The
codebase already has a top-level `rotation` command (scheduled *secret* rotation) and a
`keys rotate` subcommand (per-key material rotation); a `master-key` noun group keeps all three
unambiguous at the shell and leaves room for a later `master-key status`.

Flag semantics:

- `--new-key-env` (**required**) — *name of an environment variable* holding the new base64 key,
  never the key itself. Key material must not appear in argv, where `ps` and shell history can see
  it. The new key is run through the full `ValidateMasterKey` — rotating onto a second weak key is
  refused.
- `--old-key-env` (optional) — same, for the old key. Defaults to the running config's `master_key`,
  which is exactly where the old key lives at rotation time. Only structurally validated
  (`ParseMasterKey`) — the old key is by definition the weak one.
- `--dry-run` — plan phase only. Reports per-table counts of what would be re-encrypted, what is
  already on the new key, and what is skipped as HSM-external. Writes nothing, and skips the
  confirmation prompt.
- `--batch-size` (default 100) — rows per transaction.
- `--yes` — skip the interactive confirmation on a real run (for scripted maintenance windows).

Both key sources are echoed *by name* ("environment variable NEW_MASTER_KEY", "config file
(master_key)") so an operator can see which key came from where without any key bytes being
printed. Identical old and new keys are rejected up front with a message that names the most likely
cause: `viper.AutomaticEnv` makes `MASTER_KEY` in the environment take precedence over the config
file value, so exporting the new key as `MASTER_KEY` before rotating makes the "old key from
config" default silently resolve to the new key.

Authorization: the command is **not** in `persistentPreRun`'s `systemCmds` allowlist, so it
requires a logged-in session, and it additionally requires `model.RoleAdmin` — the same
`requireBackupAdmin` pattern `cmd/backup.go:45` uses, and for the same reason: the operation spans
every vault, so there is no vault to scope it to.

---

## Error handling

- **Wrong old key** → every row fails classification → `ErrUndecryptable` on the first row of the
  first table, before any write. Nothing changes; the operator fixes the key and re-runs.
- **Mixed-key database** (a previous run aborted mid-way) → rows already on the new key classify as
  `AlreadyNewKey`, the rest are re-encrypted. Normal, expected, reported.
- **Row changed during the run** → `RowsAffected() != 1` → batch rolled back, run aborts with
  "stop the RocketVault server before rotating and re-run".
- **New key fails `ValidateMasterKey`** → refuse before touching the database.
- **Old key == new key** → refuse before touching the database.
- **Startup guard failure** → `bootstrap.setup` returns an error and the process exits; the message
  names both `openssl rand -base64 32` and `rocketvault master-key rotate`.

## Logging discipline

Non-negotiable, and asserted by review rather than by test (a test cannot prove the absence of a
future log line):

- Neither key is ever logged, printed, or included in an error — only the *name* of its source.
- Decrypted plaintext exists only as a local variable inside `classify`, passed straight into
  `EncryptWithKey`. It is never logged, never returned, never included in an error.
- Row identity in logs and errors is the primary key (UUIDs, version integers) — never the secret
  name, never the value. Progress logs carry counters only.

---

## Testing

- **`common`** — `EncryptWithKey`/`DecryptWithKey` round-trip; ciphertext from key A fails to open
  with key B; `ParseMasterKey` rejects empty/non-base64/wrong-length; `ValidateMasterKey` accepts a
  CSPRNG key and rejects the committed default, an all-printable-ASCII key, a low-distinct-byte
  key, and a 16-byte key. The existing `common/encrypt_test.go` suite must keep passing unchanged —
  it is the proof that the refactor is behavior-preserving.
- **`bootstrap`** — `ValidateMasterKey` accepts a good key and rejects the compromised default; the
  existing `Validate` cases stay untouched.
- **`internal/rekey`** — `classify` table-driven unit tests for all four outcomes, then integration
  tests against a throwaway in-memory SQLite database (`sql.Open("sqlite3", ":memory:")` with
  `SetMaxOpenConns(1)`, matching the fixture style in
  `internal/services/softdelete/purge_scheduler_test.go:24` and
  `internal/repositories/audit_repository_test.go:18`) with fixture rows in all five tables:
  dry-run writes nothing but reports correct counts; a real run makes every row decrypt to its
  original plaintext under the new key; a second run reports `AlreadyNewKey == Total` and
  `ReEncrypted == 0` with byte-identical stored values; `pkcs11:` rows are untouched; a wrong old
  key aborts with no writes; a partially-migrated table completes correctly; identical keys are
  rejected. No test touches a real database file.
- **`cmd`** — the rotate command rejects a caller without admin claims; key resolution errors
  correctly when the env var is unset, when old and new match, and when the new key is weak.
- Standard bar before done: `go build ./...`, `go vet ./...`, `gofmt -l` clean on changed files,
  `go test ./...`, `golangci-lint run` on changed packages.

---

## Operational runbook

This is the procedure H4 will follow against the real dev and production databases. It is
reproduced verbatim in `docs/runbooks/master-key-rotation.md` for operators.

**Before you start:** rotation is offline. Budget a maintenance window sized by row count (the tool
does one AES-GCM open + one seal per row; tens of thousands of rows take seconds, the transaction
commits dominate).

1. **Generate the new key.**
   ```bash
   export NEW_MASTER_KEY="$(openssl rand -base64 32)"
   ```
   32 raw bytes, base64-encoded — exactly what `ValidateMasterKey` requires. Store it in the
   deployment's secret store *now*, before anything else: if it is lost after step 5, every secret
   in the vault is unrecoverable.
   Do **not** name this variable `MASTER_KEY`. Viper's `AutomaticEnv` gives `MASTER_KEY` precedence
   over the config file, which would make the tool's default "old key from config" resolve to the
   new key.
2. **Stop the RocketVault server.** Concurrent writes are detected and abort the run, but stopping
   first is the supported path.
3. **Back up the database.** File copy for SQLite, `pg_dump` for Postgres. This is the rollback:
   restoring it plus keeping the old `master_key` returns the deployment to its pre-rotation state.
4. **Log in as an admin and dry-run.**
   ```bash
   ./rocketvault users login --username admin --password '<password>' --totp-code <code>
   ./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
   ```
   Verify the report: per-table row counts look right, `already on new key` is 0 on a first run,
   `skipped (HSM)` is 0 unless the deployment uses PKCS#11, and there are no errors.
5. **Real run.**
   ```bash
   ./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
   ```
   Confirm at the prompt. If it is interrupted, just run it again — already-migrated rows are
   detected and skipped.
6. **Update the configuration to the new key.** Either set `master_key` in `.rocketvault.yaml` to
   the value of `$NEW_MASTER_KEY`, or (preferred, and H4's actual destination) export it as the
   `MASTER_KEY` environment variable of the server process and remove the key from the file
   entirely — `AutomaticEnv` means the environment value wins over the file.
7. **Restart the server.** It will now pass the startup guard. Verify by reading back one secret
   and one certificate:
   ```bash
   ./rocketvault secrets get <name> --vault default
   ./rocketvault certificates list --vault default
   ```
   A successful read is proof the rotation and the config update agree.
8. **Re-create backups.** Backup files written by `rocketvault backup create` before the rotation
   are encrypted with the **old** key and can only be restored with it. Either keep the old key
   archived (clearly labelled "restore-only, compromised") for their retention period, or take a
   fresh backup after the rotation and delete the old ones.

**Wrong-order warning.** If the config is updated to the new key *before* the rotation runs: on a
`jwt.key_source: self_pki` deployment, `SelfPKIProvider.loadOrGenerate` fails to decrypt the stored
signing key and silently generates a replacement, invalidating every live session; every secret and
key read fails with a decryption error; and the tool's own default old-key source now yields the
new key. Recovery is to put the old key back in the config and start again from step 4.

---

## Rollout ordering

1. `common` primitives and `ValidateMasterKey` (no behavior change to any running system).
2. `internal/rekey` engine plus its tests.
3. `rocketvault master-key rotate` CLI.
4. **Then** the bootstrap startup guard — landing it earlier would make the repo's own dev server
   unbootable before the tool that fixes it exists.
5. Runbook doc, docsgen registration, `.claude/known-bugs.md` entry.
6. (Separate plan, H4) Run the runbook against the real dev/prod databases and remove the committed
   key from `.rocketvault.yaml`.
