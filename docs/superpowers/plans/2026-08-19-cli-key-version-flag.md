# CLI `--version` Flag for Key Crypto Commands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `rocketvault keys sign`, `verify`, `wrap`, and `unwrap` a `--version` flag so the CLI can address an archived key version, closing the REST-only gap left by the 2026-08-19 key-version-addressability work.

**Architecture:** Pure wiring. The service layer already accepts a version: `SignRequest`, `VerifyRequest`, `WrapKeyRequest`, and `UnwrapKeyRequest` each carry a `Version int // 0 = current` field (`internal/services/keys/crypto_service.go:29,50,90,127`), and `cryptoService.resolveVersionValue` (`:219`) already resolves it against `key_versions`. All four CLI commands construct their request literal with `Version` unset, so it defaults to 0. Each task adds one flag, one viper binding, and one struct field.

**Tech Stack:** Go 1.24, Cobra, Viper, testify/mock.

**Spec:** No separate design doc. The source finding is `.claude/azure-keyvault-parity.md` §2, the `Rotate (new version)` row (line 44): *"none of the four crypto CLI commands ... has a `--version` flag; each still calls its service method with `Version` unset, so all four only operate on the current version. REST is the only way to address an archived version today."* It is listed as a deliberate fast-follow in the "Not in scope" section of `docs/superpowers/specs/2026-08-19-key-version-addressability-design.md`.

## Global Constraints

- **`--version 0` means "current".** Do not treat 0 as an error or remap it. `resolveVersionValue` already special-cases it, and every existing scripted invocation omits the flag, which yields 0 — behavior must be identical to today when the flag is absent.
- **Do not change stdout.** `sign`, `wrap`, and `unwrap` each print exactly one base64 line; `verify` prints a formatter row of `key_id`/`algorithm`/`valid` and exits non-zero on an invalid signature. Adding a version column or line would break existing scripts. The resolved version is available on every result struct (`SignResult.Version`, etc.) but is deliberately not printed.
- **Do not change exit codes.** `verify`'s non-zero exit on an invalid signature (`cmd/keys/verify.go`, pinned by `TestVerifyCmd_InvalidSignature_ExitsNonZeroButPrintsResult`) is unchanged.
- **Viper key naming follows the existing per-command prefix convention** — `sign-version`, `verify-version`, `wrap-version`, `unwrap-version`. A bare `version` key would collide across commands, since all four bind into one global viper instance.
- **Flag type is `Int`, not `String`.** `viper.GetInt` on an unset key returns 0, which is exactly the "current version" sentinel; a string flag would need parsing and an error path for no benefit.
- **No authorization changes.** Each command's `vaultcli.RequireDataAction` call stays exactly as it is. Addressing an older version of a key the caller is already authorized for is the same data action.
- **Go 1.24, existing dependencies only.**

## File structure

| File | Responsibility |
|---|---|
| `cmd/keys/sign.go` (modify) | `--version` flag, `sign-version` binding, `Version` on `SignRequest` |
| `cmd/keys/verify.go` (modify) | same, for `verify-version` / `VerifyRequest` |
| `cmd/keys/wrap.go` (modify) | same, for `wrap-version` / `WrapKeyRequest` |
| `cmd/keys/unwrap.go` (modify) | same, for `unwrap-version` / `UnwrapKeyRequest` |
| `cmd/keys/keys_cmd_test.go` (modify) | One `*Cmd_PassesVersion` test per command |
| `docs/cli-guide.md` (modify) | Document the flag |
| `.claude/azure-keyvault-parity.md` (modify) | §2 row + Summary bullet |

Each task is one command, end to end, with its own test and commit. A reviewer can accept `sign` and reject `wrap` independently.

---

### Task 1: `--version` on `keys sign`

**Files:**
- Modify: `cmd/keys/sign.go:64-66` (flag reads), `:103-110` (request literal), `:132-137` (flag registration)
- Test: `cmd/keys/keys_cmd_test.go` (append after `TestSignCmd_SetsResolvedVaultID`, which ends around line 1922)

**Interfaces:**
- Consumes: `keyServices.SignRequest{KeyID, Data, Algorithm, UserID, VaultID, Scope, Version}` — the `Version int` field exists at `internal/services/keys/crypto_service.go:29`.
- Produces: viper key `sign-version` (int) and the `--version` flag on `signCmd`. Tasks 2-4 mirror this shape under their own prefixes but share nothing with it.

- [ ] **Step 1: Write the failing test**

Append to `cmd/keys/keys_cmd_test.go`:

```go
func TestSignCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	data := []byte("data-to-sign")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysSign).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpSign, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.KeyID == keyID && r.Version == 2
	})).Return(&keyServices.SignResult{Signature: []byte("sig")}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]any{
		"sign-key-id":    keyID.String(),
		"sign-data":      base64.StdEncoding.EncodeToString(data),
		"sign-algorithm": "RS256",
		"sign-version":   2,
	})
	defer cleanup()

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}

func TestSignCmd_OmittedVersionMeansCurrent(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysSign).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpSign, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.Version == 0
	})).Return(&keyServices.SignResult{Signature: []byte("sig")}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]any{
		"sign-key-id":    keyID.String(),
		"sign-data":      base64.StdEncoding.EncodeToString([]byte("d")),
		"sign-algorithm": "RS256",
	})
	defer cleanup()

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/keys/ -run 'TestSignCmd_PassesVersionToService|TestSignCmd_OmittedVersionMeansCurrent' -v`

Expected: `TestSignCmd_PassesVersionToService` FAILS — the mock's `MatchedBy` never matches because `r.Version` is 0, producing testify's `mock: I don't know what to return because the method call was unexpected`. `TestSignCmd_OmittedVersionMeansCurrent` passes already; it is the regression guard for the default.

- [ ] **Step 3: Read the flag in `RunE`**

In `cmd/keys/sign.go`, after the `algorithm := viper.GetString("sign-algorithm")` line (line 66):

```go
		// 0 means "the current version", matching the service-layer contract
		// on SignRequest.Version. An omitted flag yields 0.
		version := viper.GetInt("sign-version")
```

- [ ] **Step 4: Pass it into the request**

In the same file, add one field to the `keyServices.SignRequest` literal (lines 103-110):

```go
		result, err := cryptoService.Sign(ctx, keyServices.SignRequest{
			KeyID:     keyID,
			Data:      data,
			Algorithm: crypto.SignatureAlgorithm(algorithm),
			UserID:    claims.UserID,
			VaultID:   vaultID,
			Scope:     model.NewVaultScope(vaultID, claims.UserID),
			Version:   version,
		})
```

- [ ] **Step 5: Register the flag**

In `InitKeysSign` (line 129), after the `algorithm` flag line (134) and its binding (137):

```go
	signCmd.Flags().Int("version", 0, "Key version to sign with (0 = current version)")
	viper.BindPFlag("sign-version", signCmd.Flags().Lookup("version")) //nolint:errcheck,gosec
```

Also extend the command's `Example` block (line 47) with a second invocation:

```go
	Example: `  # Sign data with an RSA key
  rocketvault keys sign --key-id <uuid> --data <base64> --algorithm RS256 \
    --username admin --password admin123 --totp-code <code>

  # Sign with a specific archived key version
  rocketvault keys sign --key-id <uuid> --data <base64> --version 2`,
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./cmd/keys/ -run TestSignCmd -v`
Expected: PASS, including the pre-existing `TestSignCmd_*` cases.

- [ ] **Step 7: Commit**

```bash
git add cmd/keys/sign.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cli): add --version to keys sign"
```

---

### Task 2: `--version` on `keys verify`

**Files:**
- Modify: `cmd/keys/verify.go` (flag reads near line 73, request literal near line 116, `InitKeysVerify` at line 159)
- Test: `cmd/keys/keys_cmd_test.go`

**Interfaces:**
- Consumes: `keyServices.VerifyRequest{..., Version int}` (`crypto_service.go:50`).
- Produces: viper key `verify-version`, `--version` flag on `verifyCmd`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/keys/keys_cmd_test.go`:

```go
func TestVerifyCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysVerify).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpVerify, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("Verify", mock.Anything, mock.MatchedBy(func(r keyServices.VerifyRequest) bool {
		return r.KeyID == keyID && r.Version == 3
	})).Return(&keyServices.VerifyResult{
		KeyID:     keyID,
		Algorithm: crypto.SignatureAlgorithm("RS256"),
		Valid:     true,
	}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	// buildAdminCtx installs the output formatter verify needs (it writes a
	// formatter row, not a bare line); the ClaimsKey override then pins the
	// userID the mock expectations above were registered against, since
	// buildAdminCtx generates its own. This is the exact pattern
	// TestVerifyCmd_Authorized_ValidSignature uses at line 2075.
	ctx := buildAdminCtx(sc)
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)

	cleanup := viperSet(map[string]any{
		"verify-key-id":    keyID.String(),
		"verify-data":      base64.StdEncoding.EncodeToString([]byte("d")),
		"verify-signature": base64.StdEncoding.EncodeToString([]byte("sig")),
		"verify-algorithm": "RS256",
		"verify-version":   3,
	})
	defer cleanup()

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/keys/ -run TestVerifyCmd_PassesVersionToService -v`
Expected: FAIL — `mock: I don't know what to return because the method call was unexpected`, because `r.Version` is 0, not 3.

- [ ] **Step 3: Read the flag in `RunE`**

In `cmd/keys/verify.go`, after `algorithm := viper.GetString("verify-algorithm")`:

```go
		// 0 means "the current version", matching VerifyRequest.Version.
		version := viper.GetInt("verify-version")
```

- [ ] **Step 4: Pass it into the request**

Add `Version: version,` to the `keyServices.VerifyRequest` literal, alongside the existing `Scope:` field:

```go
		result, err := cryptoService.Verify(ctx, keyServices.VerifyRequest{
			KeyID:     keyID,
			Data:      data,
			Signature: signature,
			Algorithm: crypto.SignatureAlgorithm(algorithm),
			UserID:    claims.UserID,
			VaultID:   vaultID,
			Scope:     model.NewVaultScope(vaultID, claims.UserID),
			Version:   version,
		})
```

Keep the existing field names and order as they appear in the file; add only the `Version` line. If the literal's `Data`/`Signature` field names differ, leave them untouched.

- [ ] **Step 5: Register the flag**

In `InitKeysVerify` (line 159), after the `algorithm` binding (line 169):

```go
	verifyCmd.Flags().Int("version", 0, "Key version to verify against (0 = current version)")
	viper.BindPFlag("verify-version", verifyCmd.Flags().Lookup("version")) //nolint:errcheck,gosec
```

Extend the `Example` block (line 52) with:

```
  # Verify against a specific archived key version
  rocketvault keys verify --key-id <uuid> --data <base64> --signature <base64> --version 3
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./cmd/keys/ -run TestVerifyCmd -v`
Expected: PASS, including `TestVerifyCmd_InvalidSignature_ExitsNonZeroButPrintsResult` — the exit-code behavior must be unchanged.

- [ ] **Step 7: Commit**

```bash
git add cmd/keys/verify.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cli): add --version to keys verify"
```

---

### Task 3: `--version` on `keys wrap`

**Files:**
- Modify: `cmd/keys/wrap.go` (flag reads near line 65, request literal near lines 99-106, `InitKeysWrap` at line 124)
- Test: `cmd/keys/keys_cmd_test.go`

**Interfaces:**
- Consumes: `keyServices.WrapKeyRequest{KeyID, UserID, VaultID, Scope, PlaintextKey, Algorithm, Version}` — `Version int` at `crypto_service.go:90`.
- Produces: viper key `wrap-version`, `--version` flag on `wrapCmd`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/keys/keys_cmd_test.go`:

```go
func TestWrapCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysWrap).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.KeyID == keyID && r.Version == 4
	})).Return(&keyServices.WrapKeyResult{WrappedKey: []byte("wrapped"), Algorithm: "RSA-OAEP"}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]any{
		"wrap-key-id":       keyID.String(),
		"wrap-key-material": base64.StdEncoding.EncodeToString([]byte("material")),
		"wrap-version":      4,
	})
	defer cleanup()

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/keys/ -run TestWrapCmd_PassesVersionToService -v`
Expected: FAIL — unexpected `WrapKey` call, because `r.Version` is 0, not 4.

- [ ] **Step 3: Read the flag in `RunE`**

In `cmd/keys/wrap.go`, after `keyMaterialB64 := viper.GetString("wrap-key-material")`:

```go
		// 0 means "the current version", matching WrapKeyRequest.Version.
		version := viper.GetInt("wrap-version")
```

- [ ] **Step 4: Pass it into the request**

Add `Version: version,` to the `keyServices.WrapKeyRequest` literal:

```go
		result, err := cryptoService.WrapKey(ctx, keyServices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       claims.UserID,
			VaultID:      vaultID,
			Scope:        model.NewVaultScope(vaultID, claims.UserID),
			PlaintextKey: keyMaterial,
			Algorithm:    "RSA-OAEP",
			Version:      version,
		})
```

Use whatever local variable the file already assigns the decoded material to; add only the `Version` line.

- [ ] **Step 5: Register the flag**

In `InitKeysWrap` (line 124), after the `key-material` binding (line 130):

```go
	wrapCmd.Flags().Int("version", 0, "Key version to wrap with (0 = current version)")
	viper.BindPFlag("wrap-version", wrapCmd.Flags().Lookup("version")) //nolint:errcheck,gosec
```

Extend the `Example` block (line 46) with:

```
  # Wrap with a specific archived key version
  rocketvault keys wrap --key-id <uuid> --key-material <base64> --version 4
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./cmd/keys/ -run TestWrapCmd -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/keys/wrap.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cli): add --version to keys wrap"
```

---

### Task 4: `--version` on `keys unwrap`

**Files:**
- Modify: `cmd/keys/unwrap.go` (flag reads near line 65, request literal near lines 99-106, `InitKeysUnwrap` at line 124)
- Test: `cmd/keys/keys_cmd_test.go`

**Interfaces:**
- Consumes: `keyServices.UnwrapKeyRequest{KeyID, UserID, VaultID, Scope, WrappedKey, Algorithm, Version}` — `Version int` at `crypto_service.go:127`.
- Produces: viper key `unwrap-version`, `--version` flag on `unwrapCmd`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/keys/keys_cmd_test.go`:

```go
func TestUnwrapCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysUnwrap).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.KeyID == keyID && r.Version == 5
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: []byte("plain"), Algorithm: "RSA-OAEP"}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]any{
		"unwrap-key-id":      keyID.String(),
		"unwrap-wrapped-key": base64.StdEncoding.EncodeToString([]byte("wrapped")),
		"unwrap-version":     5,
	})
	defer cleanup()

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/keys/ -run TestUnwrapCmd_PassesVersionToService -v`
Expected: FAIL — unexpected `UnwrapKey` call, because `r.Version` is 0, not 5.

- [ ] **Step 3: Read the flag in `RunE`**

In `cmd/keys/unwrap.go`, after `wrappedKeyB64 := viper.GetString("unwrap-wrapped-key")`:

```go
		// 0 means "the current version", matching UnwrapKeyRequest.Version.
		// Unwrapping almost always needs an explicit version: material wrapped
		// before a rotation cannot be unwrapped by the current key.
		version := viper.GetInt("unwrap-version")
```

- [ ] **Step 4: Pass it into the request**

Add `Version: version,` to the `keyServices.UnwrapKeyRequest` literal:

```go
		result, err := cryptoService.UnwrapKey(ctx, keyServices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     claims.UserID,
			VaultID:    vaultID,
			Scope:      model.NewVaultScope(vaultID, claims.UserID),
			WrappedKey: wrappedKey,
			Algorithm:  "RSA-OAEP",
			Version:    version,
		})
```

- [ ] **Step 5: Register the flag**

In `InitKeysUnwrap` (line 124), after the `wrapped-key` binding (line 130):

```go
	unwrapCmd.Flags().Int("version", 0, "Key version to unwrap with (0 = current version)")
	viper.BindPFlag("unwrap-version", unwrapCmd.Flags().Lookup("version")) //nolint:errcheck,gosec
```

Extend the `Example` block (line 46) with:

```
  # Unwrap material that was wrapped before a rotation
  rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64> --version 5
```

- [ ] **Step 6: Run the full CLI suite**

Run: `go build ./... && go test ./cmd/keys/ -v 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/keys/unwrap.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cli): add --version to keys unwrap"
```

---

### Task 5: Document the flag and close the parity gap

**Files:**
- Modify: `docs/cli-guide.md` (the keys crypto-operations section)
- Modify: `.claude/azure-keyvault-parity.md` (§2 `Rotate (new version)` row at line 44; the §2 Summary bullet at lines 468-489)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Add a CLI-guide subsection**

Locate the section of `docs/cli-guide.md` covering `keys sign` / `verify` / `wrap` / `unwrap` (`grep -n "keys sign" docs/cli-guide.md`) and add, at the end of it:

````markdown
#### Addressing an older key version

Rotating a key archives the previous material and installs new material as the
current version. Data signed or wrapped before a rotation can only be verified
or unwrapped with the version that produced it, so all four crypto commands
take an optional `--version`:

```bash
# Unwrap material that was wrapped before two rotations
rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64> --version 1

# Verify a signature made by version 2
rocketvault keys verify --key-id <uuid> --data <base64> \
  --signature <base64> --version 2
```

Omit the flag (or pass `--version 0`) to use the key's current version — the
default, and the behavior of every invocation that predates this flag.

There is no `keys versions` CLI subcommand; list a key's versions over REST at
`GET /api/v1/keys/{key_id}/versions`, or read one version's metadata at
`GET /api/v1/keys/{key_id}/versions/{version}`.
````

- [ ] **Step 2: Update the parity row**

In `.claude/azure-keyvault-parity.md`, in the `Rotate (new version)` row (line 44), replace the sentence beginning *"The one gap left open: none of the four crypto CLI commands"* through *"REST is the only way to address an archived version today"* with:

```
All four crypto CLI commands (`rocketvault keys sign`/`verify`/`wrap`/`unwrap`)
now take a `--version` flag (0 or omitted = current version), so an archived
version is addressable from the CLI as well as over REST
```

and change that row's Status cell from `🟡 (full REST parity; CLI --version fast-follow not yet done)` to `✅`.

- [ ] **Step 3: Update the Summary bullet**

In the `**Partial (🟡):**` section's `Key operations beyond CRUD` bullet, delete the sentence *"Still open: none of the four crypto CLI commands (`rocketvault keys sign`/`verify`/`wrap`/`unwrap`) has a `--version` flag, so the fix is REST-only for now."* and append a dated note to §2's note block:

```
*Closed 2026-08-19: the CLI `--version` fast-follow this section flagged as
"not done as part of this pass" has landed. `rocketvault keys sign`, `verify`,
`wrap`, and `unwrap` each take `--version` (bound to the per-command viper keys
`sign-version`/`verify-version`/`wrap-version`/`unwrap-version`), passed
straight through to the `Version` field the four request structs already
carried. Omitting the flag yields 0, which `cryptoService.resolveVersionValue`
treats as the current version — so every pre-existing invocation behaves
identically. Command output and exit codes are unchanged; the resolved version
is available on each result struct but deliberately not printed, since three of
the four commands emit a single bare base64 line that scripts parse.*
```

- [ ] **Step 4: Verify and commit**

Run: `go build ./... && go test ./cmd/keys/ 2>&1 | tail -5`
Expected: PASS.

```bash
git add docs/cli-guide.md .claude/azure-keyvault-parity.md
git commit -m "docs: document keys --version and close the CLI half of the rotation parity gap"
```
