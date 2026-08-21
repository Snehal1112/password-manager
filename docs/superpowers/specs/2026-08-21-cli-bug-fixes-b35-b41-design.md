# CLI Bug Fixes B35–B41 — Design

**Date:** 2026-08-21
**Status:** Approved
**Scope:** `.claude/known-bugs.md` entries B35–B41

## Problem

The 2026-08-21 CLI help-text sweep read every `RunE` in `cmd/` to describe it
accurately. Doing so surfaced eleven defects, filed as B35–B41. Three are
serious: one destroys data, one gives a false security assurance, one silently
breaks certificate trust chains. The help text now documents actual behavior, so
the CLI is honest — but the defects remain.

This design covers all seven entries. Each gets its own implementation plan.

## Severity escalation discovered during design

B35 was filed as "a CLI command corrupts the secret it rotates". That
understates it.

`schedulerService.performAutomaticRotation`
(`internal/services/secrets/scheduler_service.go:240-247`) delegates to
`rotationSvc.PerformManualRotation` — the same corrupting function. So any
policy with `AutoRotate: true` corrupts its secrets **on a timer, unattended**,
not only when an operator runs the command.

One partially mitigating detail: the scheduler calls `versioningSvc.CreateVersion`
before rotating (`scheduler_service.go:224-236`), so the pre-rotation value
survives in a version row. `PerformManualRotation` does not version at all, so
the **manual** path loses the value outright. Both are fixed here.

**That mitigation is weaker than it looks.** The scheduler passes
`secret.Value` — the stored ciphertext — and `CreateVersion` encrypts what it
is given, so those version rows are **doubly encrypted**. The bytes survive,
but `secrets version get` returns ciphertext rather than the original value;
recovery requires a manual second decrypt outside any supported path. Recovery
guidance must say this plainly rather than claiming clean recoverability.

B35 should be re-rated High → Critical in `.claude/known-bugs.md` as part of its
plan.

## Decisions taken

| Question | Decision |
|---|---|
| B36: what key encrypts an export? | Passphrase-derived (argon2id), not the master key |
| B35: where does the new rotation value come from? | Caller-supplied; generation is opt-in |
| B39: how to fix `migrate:to` downward? | Refuse with a clear error; no down-migrations |
| B36: breaking change on `--encrypt` default? | Accepted — fail loudly rather than write plaintext |

Rejected, with reasons:

- **Master-key encryption for exports.** It is the smaller change and matches
  `internal/backup`, but it makes an export readable only by an instance holding
  that same master key, orphans every prior export on `master-key rotate`, and
  inherits the master-key exposure history (B12). An export exists to leave the
  instance; tying it to instance-local state defeats the purpose. Backup keeps
  master-key sealing, which is correct for same-instance disaster recovery.
- **Always generating a rotation value.** A random string is wrong whenever the
  secret must match an external system — a database password, a provider-minted
  API key. Azure's model has the application own the new value.
- **Implementing down-migrations.** Every existing migration would need a
  reverse written and tested, and some (dropped columns) cannot be reversed
  without data loss, so they would need an explicit refusal anyway. Refusing
  outright removes the false impression at a fraction of the cost.

## Global Constraints

Every plan derived from this spec inherits these. Copy them verbatim into the
plan's own `## Global Constraints` section.

- Go 1.24.2. Do not raise the version floor.
- **No new module dependencies.** `golang.org/x/crypto` v0.48.0 and
  `golang.org/x/term` are already present and were verified to compile and run
  offline on 2026-08-21.
- Comments are short, full sentences ending in a punctuation mark.
- Never log, print, or embed a passphrase or a plaintext secret in an error
  message.
- Argon2id parameters: `time=1`, `memory=65536`, `threads=4`, `keyLen=32`,
  `saltLen=16`.
- Any help-text change follows `.claude/cli-help-conventions.md`, and
  `cmd/help_examples_test.go` must stay green — every flag named in an
  `Example` must be registered on that command or inherited.
- `go build ./...`, `go test ./...`, `gofmt -l` and `go vet` must be clean at
  the end of every task.
- Fix the defect and nothing else. Adjacent problems get filed in
  `.claude/known-bugs.md`, not fixed opportunistically.

## Shared foundations

These land before the fixes that depend on them.

### `internal/pwgen`

`generatePassword(length int, useUpper, useLower, useNumbers, useSpecial bool)`
currently lives in `cmd/secrets/generate.go` (package `secrets`, under `cmd/`).
B35 needs it from `internal/services/secrets`, and a service must not import a
`cmd` package.

Move it to `internal/pwgen` as `pwgen.Generate(opts Options) (string, error)`.
`cmd/secrets/generate.go` becomes a thin caller. Behavior is preserved exactly,
including the guarantees the current implementation makes: at least one
character set enabled, at least one character from each enabled set, and no
three identical characters in a row.

### `common/export_envelope.go`

A self-describing, versioned envelope, reachable from both `cmd/` and the
service layer (as `common/encrypt.go` already is).

```json
{
  "rocketvault_export": 1,
  "kdf": "argon2id",
  "params": { "time": 1, "memory": 65536, "threads": 4 },
  "salt": "<base64, 16 bytes>",
  "ciphertext": "<base64>"
}
```

**Corrected 2026-08-21 to match the implementation.** An earlier draft showed a
top-level `nonce` field. There is none: `EncryptWithKey` already prepends its
own random GCM nonce to the ciphertext it returns, so the nonce travels inside
`ciphertext`. Adding a second one would have been redundant and a chance to get
nonce handling wrong. Release notes and any format documentation must describe
this shape, not the earlier draft's.

**Params are read from the file and must be validated.** `argon2.IDKey` panics
when `time` or `threads` is below 1, so an envelope that merely omits `params`
would crash the reader. The read path validates every parameter before use and
returns an error naming the bad one — never `ErrWrongPassphrase`, since a
malformed file is not a wrong passphrase.

- `argon2.IDKey` from `golang.org/x/crypto` — already a dependency at v0.48.0,
  currently unused in the tree. Verified 2026-08-21 that both
  `golang.org/x/crypto/argon2` and `golang.org/x/term` compile and run offline
  against the existing `go.mod`/`go.sum`, so **B36 adds no new dependency**.
- Derived key is 32 bytes, then AES-256-GCM through the existing
  `common.EncryptWithKey` / `DecryptWithKey`, so the symmetric layer is code
  that already exists and is already tested.
- `rocketvault_export` is both the format marker and the version number.
  Detection keys off its presence; a future format change bumps it and readers
  refuse an unknown version explicitly rather than misparsing.
- Params are stored in the file so a later change to argon2 cost does not
  strand existing exports.

API:

```go
func SealExport(plaintext []byte, passphrase string) ([]byte, error)
func OpenExport(data []byte, passphrase string) ([]byte, error)
func IsSealedExport(data []byte) bool
```

### Passphrase input

One helper, used by both export and import:

1. `--passphrase-file <path>` — first line, trimmed.
2. `ROCKETVAULT_EXPORT_PASSPHRASE` — for automation.
3. Interactive prompt via `golang.org/x/term` (already in `go.sum`), with
   confirmation on export only.

If none is available and stdin is not a terminal, fail with an explicit error.
Never fall through to writing plaintext.

## B35 — rotation writes a corrupted value

**Files:** `internal/services/secrets/rotation_service.go`,
`internal/services/secrets/scheduler_service.go`, `cmd/rotation.go`

`ManualRotationRequest` gains the value source:

```go
type ManualRotationRequest struct {
    SecretID uuid.UUID
    PolicyID uuid.UUID
    Scope    model.Scope
    Notes    string
    NewValue string        // explicit replacement value
    Generate bool          // generate one instead
    GenerateOpts pwgen.Options
}
```

`PerformManualRotation` becomes:

1. Reject if `NewValue` is empty and `Generate` is false — never invent a value.
2. Reject if both are set.
3. Resolve the plaintext: `NewValue`, or `pwgen.Generate(GenerateOpts)`.
4. `versioningSvc.CreateVersion` on the current value, **decrypted first**.
   `CreateVersion` encrypts whatever it is given
   (`versioning_service.go:127-128`), so passing the stored ciphertext would
   store it doubly encrypted. `SecretService.UpdateSecret`
   (`secret_service.go:299-317`) already does this correctly — decrypt, then
   pass plaintext — and this path must match it.

   `rotationService` has **no versioning dependency today**; only
   `schedulerService` holds one. Adding it means changing
   `NewRotationService`'s signature, the container wiring, and every test call
   site. The container already builds `versioningService` before
   `rotationService`, so there is no ordering problem or cycle.
5. `cryptoSvc.EncryptSecret(plaintext)` — the dependency is already injected at
   `rotation_service.go:100,115,126` and has never been called.
6. Assign the ciphertext, bump the version, `secretRepo.Update`.

`generateNewSecretValue` (`rotation_service.go:541`) is deleted.

The scheduler sets `Generate: true` with the policy's options and drops its own
`CreateVersion` call, since step 4 now covers it — leaving it would double-version.

CLI: `--value` and `--generate` (with `--length` and the character-set flags,
mirroring `secrets generate-password`). Neither supplied is an error that names
both options.

**Recovery guidance for already-corrupted secrets** belongs in the plan: values
rotated by the scheduler are recoverable from their version rows; values rotated
manually are not, and the plan should say so plainly rather than imply a clean
upgrade.

## B36 — export writes plaintext under a lying flag

**Files:** `cmd/secrets/export.go`, `cmd/secrets/import.go`,
`internal/services/secrets/secret_service.go`, `common/export_envelope.go`

`ExportSecretsRequest` gains **both** `Encrypt bool` and `Passphrase string`.
One field cannot express the invariant: with only a passphrase, the service
cannot distinguish "encryption not requested" from "requested with an empty
passphrase". `ExportSecrets` marshals as today and then `SealExport`s the
result; `Encrypt` set with an empty passphrase is an error, never a plaintext
write.

**Flag name correction.** `secrets export` registers `--file`/`-o` for its
output path (`cmd/secrets/export.go:141`), and `MarkFlagRequired("file")`.
`--output` is a *root persistent flag* selecting table/json/yaml rendering.
Earlier drafts of this spec and of `.claude/known-bugs.md` B36 wrote
`secrets export --output f.json`, which is wrong. The dead `exportEncrypt` binds
at `export.go:142`.

**CSV becomes a JSON envelope on disk.** Sealing happens after formatting, so a
sealed `--format csv` export is a JSON envelope whose payload is CSV — a file
named `payments.csv` containing JSON. Import detects the envelope independently
of `--format`, but the user still passes `--format csv` for the payload inside.
Both commands' help must say so; it is the one user-visible surprise here.

**Decryption belongs to the CLI, not the service.** Only the CLI can prompt.
`ImportSecrets` therefore refuses a sealed payload outright rather than
attempting to open it, so an API caller handed a sealed file gets a clear error
instead of "failed to parse JSON".

**The HTTP path has the same defect, and is fixed too.**
`model.ExportSecretsRequest.Encrypt` (`model/secret.go:228`) has no reader
anywhere in the tree, so `POST /secrets/export` with `{"encrypt": true}` returns
plaintext exactly as the CLI did. Fixing only the CLI would leave the API making
the same false claim.

**Decision (2026-08-21): the API accepts a passphrase in the request body.**
`model.ExportSecretsRequest` gains `Passphrase string \`json:"passphrase"\``,
and the handler passes it through to the same `ExportSecrets` path the CLI uses,
so there is one sealing implementation rather than two. Rules:

- `{"encrypt": true}` with no passphrase → `400`, naming the missing field.
  Never a plaintext body.
- `{"encrypt": false}` → plaintext, as today, deliberately requested.
- The passphrase is request-scoped: never logged, never audit-logged, never
  echoed in a response or an error. The audit entry records that an encrypted
  export happened, not what sealed it.
- Rejecting `{"encrypt": true}` outright with a 400 was considered and dropped:
  it would leave the API unable to produce an encrypted export at all, which is
  a capability regression against what the field already advertises.

This relies on transport security for the passphrase, which is the same
assumption every credential-bearing endpoint here already makes.

`--encrypt` keeps its `true` default and now means what it says. `--no-encrypt`
(or `--encrypt=false`) writes plaintext deliberately, and the CLI prints a
warning naming what is exposed.

Import auto-detects with `IsSealedExport` and prompts only when needed.
`--encrypted` is kept and marked deprecated via `Flags().MarkDeprecated`, since
detection makes it redundant — removing it outright would break existing
invocations for no benefit.

**Breaking change, accepted.** A scripted `secrets export --output f.json` with
no passphrase source will now fail instead of silently writing plaintext. This
is intended: the current behavior is the bug. Release notes must call it out,
along with the two non-interactive escape hatches.

## B37 — renewal drops the CA signature

**Files:** `internal/services/certificates/certificate_service.go`,
`cmd/certificates/renew.go`

`RenewCertificate` currently calls `crypto.CreateSelfSignedCertificatePEM(...,
IsCA: true)` unconditionally (l.743-746). Branch on the original's `CACertID`:

- Set → re-issue through the CA path, preserving issuer and chain.
- Unset → self-sign, as today.

`CreateCASignedCertificate` hardcodes the CA key type as `"RSA"` (l.381,
comment: "assume CA uses RSA for simplicity"). Derive it from the CA key's own
`Type` instead, so an ECDSA CA is signed correctly.

Also fix the output: `RenewCertificate` does `updated := *original` and
`certRepo.Update`, so "Old Certificate ID" and "New Certificate ID" are always
the same UUID. Print one ID.

## B38 — `import --overwrite` is a no-op

**File:** `internal/services/secrets/secret_service.go`

The import loop calls `CreateSecret` unconditionally. Add a name lookup within
the request's vault scope:

- Not found → create, as today.
- Found and `Overwrite` set → update, which versions the prior value.
- Found and `Overwrite` unset → skip and count.

The response already carries per-record counts; report skipped separately from
failed so the summary is meaningful.

## B39 — `migrate:to` downward is a silent no-op

**Files:** `internal/db/migrations/migration_runner.go`, `cmd/migrate.go`

`MigrateToVersion` only moves forward (`break` above target, `continue` on
applied, l.225-230). `GetCurrentVersion` already exists at l.248. Compare
target against current and refuse below it:

```
Error: cannot migrate down: current schema is at version 7, target 3 is lower; down-migrations are not supported
```

Exit non-zero. No interface change, no `Down()` method.

**Error text revised 2026-08-21.** The original wording ended in a period, which
`.golangci.yml`'s `staticcheck` ST1005 forbids in error strings — verified
empirically while planning, and no error string in this repo currently ends in
punctuation. Use the semicolon form above rather than adding a `//nolint`
exemption for a cosmetic reason.

**Comparison must be numeric, not lexicographic.** `GetCurrentVersion` returns a
string and `MigrateToVersion`'s existing loop compares versions with Go's
default string `>`, so `"10" < "9"` is true. This is dormant only by luck: every
migration version today is either a 3-digit (`001`) or 14-digit
(`YYYYMMDDNNNNNN`) all-digit string, and cross-shape comparisons happen to come
out right. The refusal check and that pre-existing `break` condition both need a
base-10 numeric comparison. Fixing the comparable shapes in `LoadMigrations` and
`MigrateUp` is out of scope here and is a follow-up.

## B40 — `backup list` hides encrypted backups

**Files:** `internal/backup/backup.go`, `cmd/backup.go`

`getBackupMetadata` (l.476) rejects any file not starting with `{`, and
`ListBackups` logs a warning and skips it — so a directory of default
(encrypted) backups lists as empty.

Detect by content rather than assuming JSON: attempt a plaintext parse, and on
failure treat the file as encrypted. An encrypted backup still lists as a row,
showing the filename, size and modification time from the filesystem, with the
columns that require reading the payload (record counts, backup timestamp)
rendered as `-`. A listing must never imply an empty directory that is not
empty. `ListBackups` stops discarding unreadable files; the warning log stays.

Separately, the `FILE` column is synthesized from each backup's timestamp
(`cmd/backup.go:227`). Use the actual filename.

## B41 — misleading output and help strings

Mechanical, no design decisions:

- `keys rotate` prints "New Key: ID=…" though the UUID is unchanged.
- `keys create --bits` help says "(2048 or 4096)"; `CreateRSAKey` accepts 3072.
- `cmd/vault-webhook/delete.go` has an unreachable `ErrWebhookNotFound` branch;
  `Delete` never returns that sentinel.
- `secrets create --purge-protection=false` is inert — `CreateSecret` writes the
  column only when true, while `UpdateSecret` honors both directions. Make
  create match update.
- `secrets generate-password` requires a session despite being pure local RNG
  that stores nothing. Add it to `persistentPreRun`'s `systemCmds` map.
- `vault-access list` passes `write=false`, the same value `revoke` passes, so
  listing needs revoke-level permission. Fail-closed, so this is a deliberate
  decision to revisit, not a hole: either add a read tier or document the
  intent. **Resolve before implementing** rather than changing an authorization
  check on assumption.

## Testing

Every fix starts with a failing test.

| Bug | The test that would have caught it |
|---|---|
| B35 | Rotate, then `GetSecret`, and assert the plaintext round-trips. Its absence is why this shipped. Plus: scheduler path, and version row created on manual rotation |
| B36 | Export with a passphrase, assert the file is not readable as JSON and contains no plaintext value; then import it back and compare. Plus: no passphrase source and non-interactive → error, never plaintext |
| B37 | Create a CA-signed cert, renew it, assert the issuer is unchanged and the chain still verifies. Plus an ECDSA CA |
| B38 | Import a name that exists, with and without `--overwrite`; assert update-and-version vs skip-and-count |
| B39 | `migrate:to` below current → non-zero exit and no schema change |
| B40 | A directory of encrypted backups lists non-empty |
| B41 | Assertions per item; the `systemCmds` one is a table entry |

`cmd/help_examples_test.go` already guards the help text, so any flag added here
must be registered or the build fails the validator.

## Sequencing

1. `internal/pwgen` extraction; `common/export_envelope.go` + passphrase helper.
2. B35 (Critical), B36 (High) — independent of each other, both depend on 1.
3. B37 (High).
4. B38, B39, B40.
5. B41, including the `vault-access list` decision.

## Non-goals

- No down-migration support (B39 decision).
- No change to `backup`'s master-key sealing, which is correct for
  same-instance disaster recovery.
- No re-encryption or repair tooling for already-corrupted secrets; the plan
  documents what is and is not recoverable.
- No changes to the prose docs (`docs/cli-guide.md` and friends), which are a
  separate outstanding pass.
