# `rocketvault keys verify` CLI Command

**Date**: 2026-08-18
**Status**: Approved
**Scope**: `cmd/keys/verify.go` (new), `cmd/keys.go`, `cmd/keys/keys_cmd_test.go`

---

## Problem

RocketVault has a REST endpoint (`POST /keys/{key_id}/verify`, `api/keys.go`'s `verifyKey`) that
verifies a signature against data using a vault key, but no CLI command for it. `rocketvault keys
sign` was added this session (commit `e83881c`); `verify` is its natural counterpart and was
explicitly called out as a remaining gap in that commit's message. A git-history search (all local
and remote branches, all commit messages) confirmed no prior CLI implementation of verify (or
encrypt/decrypt) ever existed to port forward — `feat/plan-b-crypto-routes` built the HTTP routes
for all four crypto operations but never followed through with CLI commands for any of them.

## Goals

- `rocketvault keys verify --key-id <id> --data <b64> --signature <b64> [--algorithm RS256]`
  verifies a signature the same way the REST endpoint does, reusing the same
  `CryptoService.Verify` call and authorization path (`vaultcli.RequireDataAction`) every other
  `cmd/keys` command already uses.
- Scriptable: exit code reflects whether the signature is valid, not just whether the command ran
  without a technical error — mirrors the standard Unix convention for verification tools (`gpg
  --verify`, `cosign verify`, `openssl dgst -verify`), all of which exit non-zero on a bad
  signature.
- Output goes through the shared table formatter (`formatter.Formatter`, already wired into every
  other `cmd/keys` command via `common.OutputFormatterKey`), not a bespoke `fmt.Println` — so
  `--output json`/`--output yaml` work for this command the same as `keys get`/`keys list`,
  without any extra code in `verify.go` itself.

## Non-goals

- No CLI commands for `encrypt`/`decrypt` — tracked as a separate, later gap (same audit finding,
  different command). This spec covers `verify` only.
- No change to the REST `verifyKey` handler or `CryptoService.Verify` — this is a CLI-only
  addition consuming an existing, unmodified service method.
- No new authorization action or policy — `ActionKeysVerify`/`OpVerify` already exist in
  `model/azure_roles.go` and `model/access_policy.go` and are already granted to the same
  built-in roles (Crypto Officer, Crypto User) that can already reach this via REST.

## Design

### Command shape

Mirrors `cmd/keys/sign.go` exactly for everything except the exit-code and output behavior
described below:

- Flags: `--key-id` (string), `--data` (string, base64), `--signature` (string, base64),
  `--algorithm` (string, default `"RS256"`) — viper-bound as `verify-key-id`, `verify-data`,
  `verify-signature`, `verify-algorithm`.
- Auth guard: `common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCryptoManager)`,
  logged via `log.LogAuditError`/`LogAuditInfo` with action name `verify_key` — identical pattern
  to `sign_key` in `sign.go`.
- Required-flag check: `--key-id` and `--data` and `--signature` must all be non-empty (three
  independent checks producing one combined error message, matching `sign.go`'s
  `--key-id and --data are required` style: `--key-id, --data, and --signature are required`).
- Two independent base64 decodes (`--data`, `--signature`) — each with its own error message
  (`failed to decode --data (must be standard base64)` / `failed to decode --signature (must be
  standard base64)`), since either can fail independently and a single generic message would hide
  which flag was wrong.
- `vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysVerify,
  model.OpVerify)` for vault authorization — identical call shape to `sign.go`, different
  action/op constants.
- `serviceContainer.GetCryptoService().Verify(ctx, keyServices.VerifyRequest{KeyID, Data,
  Signature, Algorithm, UserID, VaultID, Scope})`.

### Output and exit code

On a service error (bad key ID, key not found, forbidden, revoked, disabled/lifecycle-denied,
unsupported algorithm) — `RunE` returns the wrapped error, same as `sign.go`; non-zero exit, no
table printed. This is unchanged from `sign.go`'s behavior and mirrors every other `cmd/keys`
command.

On a successful call to `Verify` (no service error — the signature check itself completed,
regardless of its result):

1. Print one table row via the formatter: headers `Key ID`, `Algorithm`, `Valid`; values
   `result.KeyID.String()`, `string(result.Algorithm)`, `strconv.FormatBool(result.Valid)`
   (`VerifyResult.KeyID` is `uuid.UUID`, not a string — needs `.String()`). Printed via
   `fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})`, matching `keys get`'s pattern (not
   `sign.go`'s raw `fmt.Println`, since a boolean+metadata result is naturally tabular and this is
   the shape `--output json`/`yaml` expect to serialize).
2. Log the outcome via `log.LogAuditInfo`, message including the boolean result either way — an
   invalid-signature check is a meaningful security event worth its own audit row, not just a
   silent negative.
3. If `result.Valid` is `false`, return `fmt.Errorf("signature verification failed")` **after**
   the table has already been written to stdout — so the row is visible to the user before the
   command reports non-zero exit. (Cobra prints `RunE`'s returned error to stderr separately from
   whatever `RunE` already wrote to stdout, so this ordering is safe: the human-readable result and
   the machine-readable exit code don't race or overwrite each other.)
4. If `result.Valid` is `true`, return `nil` — exit 0, as normal.

### Registration

`InitKeysVerify(keysCmd *cobra.Command) *cobra.Command` in `verify.go`, called from `cmd/keys.go`'s
`init()` alongside the other `InitKeys*` calls — same wiring pattern `InitKeysSign` used.

### Testing

New tests in `cmd/keys/keys_cmd_test.go`, in a `// ========== verifyCmd tests ==========` block
mirroring the existing `signCmd` block:

- `TestVerifyCmd_NoClaims`
- `TestVerifyCmd_MissingRequiredFlags` (covers key-id, data, and signature each individually
  empty — table-driven, one subtest per missing flag)
- `TestVerifyCmd_InvalidKeyID`
- `TestVerifyCmd_InvalidDataBase64`
- `TestVerifyCmd_InvalidSignatureBase64`
- `TestVerifyCmd_NoServiceContainer`
- `TestVerifyCmd_Denied` (authz gate rejects; `cryptoSvc.AssertNotCalled(t, "Verify", ...)`)
- `TestVerifyCmd_Authorized` (authz gate allows via `RoleAssignmentService`/`AccessPolicyService`
  mocks, same shape as `TestSignCmd_Authorized`)
- `TestVerifyCmd_ServiceError` (`Verify` itself returns an error — e.g. `ErrKeyNotFound`)
- `TestVerifyCmd_ValidSignature_ExitsZero` — mock returns `{Valid: true}`; assert `cmd.Execute()`
  returns no error and stdout contains `true`.
- `TestVerifyCmd_InvalidSignature_ExitsNonZero` — mock returns `{Valid: false}`; assert
  `cmd.Execute()` returns an error AND stdout still contains the printed row (`false`) — pinning
  the "print first, then fail" ordering from the design above.
- `TestVerifyCmd_SetsResolvedVaultID` — mirrors `TestSignCmd_SetsResolvedVaultID`.

Confirmed during spec self-review: `keyCmdCryptoService.Verify` (`keys_cmd_test.go:159-161`) has
the identical silent-stub bug `Sign` had before this session's fix — `return nil, nil` without
routing through `m.Called()`. It must be fixed the same way, alongside adding the new tests:

```go
func (m *keyCmdCryptoService) Verify(ctx context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.VerifyResult), args.Error(1)
}
```

`TestMain` gains `InitKeysVerify(parent)` and `_ = NewVerifyCmd()` alongside the existing
registrations.

## Open questions

None — the two decisions with real design weight (exit-code semantics, output format) were made
explicitly above rather than left implicit, per the risk that motivated writing this spec instead
of skipping straight to implementation.
