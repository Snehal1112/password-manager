# `rocketvault keys verify` CLI Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `rocketvault keys verify` as a working CLI command, calling the existing `CryptoService.Verify` the REST API already exposes, with an exit code that reflects the verification result.

**Architecture:** One new file, `cmd/keys/verify.go`, mirroring the existing `cmd/keys/sign.go` command exactly for auth/flag/error handling, registered from `cmd/keys.go` the same way every other `InitKeys*` function is. Output goes through the shared table `formatter.Formatter` (already used by `cmd/keys/get.go`) instead of `sign.go`'s raw `fmt.Println`, since the result (key ID + algorithm + boolean) is naturally tabular and this gets `--output json`/`--output yaml` for free. The command's `RunE` returns a non-nil error when the signature is invalid, *after* printing the result row, so both the human-readable output and the script-friendly exit code are available from a single invocation.

**Tech Stack:** Go, Cobra, Viper, testify (mock/assert), the project's existing `formatter.Formatter` abstraction.

**Spec:** `docs/superpowers/specs/2026-08-18-keys-verify-cli-design.md`

## Global Constraints

- Auth guard: `common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCryptoManager)` — exact same roles `sign.go` requires.
- Vault authorization: `vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysVerify, model.OpVerify)` — these two constants already exist (`model/azure_roles.go:68`, `model/access_policy.go:49`); do not add new ones.
- Every audit log call uses action name `"verify_key"` (matching `sign.go`'s `"sign_key"` convention), via `log.LogAuditInfo`/`log.LogAuditError` on the context's `*logging.Logger` (`common.LogKey`).
- Base64 encoding is always `encoding/base64`'s `StdEncoding` (standard, not URL-safe) — matches `sign.go` and the REST handler.
- Default algorithm when `--algorithm` is empty: `"RS256"`.

---

### Task 1: Fix the pre-existing `Verify` mock stub, implement `verify.go`, register it, and add full test coverage

**Files:**
- Create: `cmd/keys/verify.go`
- Modify: `cmd/keys.go` (register `InitKeysVerify`)
- Modify: `cmd/keys/keys_cmd_test.go` (fix `keyCmdCryptoService.Verify`, register in `TestMain`, add `verifyCmd` test block)

**Interfaces:**
- Consumes: `keyServices.CryptoService.Verify(ctx context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error)` (already exists, `internal/services/keys/crypto_service.go:355`+ implements it; `VerifyRequest{KeyID uuid.UUID, Data []byte, Signature []byte, Algorithm crypto.SignatureAlgorithm, UserID uuid.UUID, VaultID uuid.UUID, Scope model.Scope}`; `VerifyResult{Valid bool, Algorithm crypto.SignatureAlgorithm, KeyID uuid.UUID}` — both types at `internal/services/keys/crypto_service.go:40-55`). Also consumes `vaultcli.RequireDataAction` and `container.ServiceContainerInterface.GetCryptoService()`, both already used identically by `cmd/keys/sign.go`.
- Produces: `func InitKeysVerify(keysCmd *cobra.Command) *cobra.Command` and `func NewVerifyCmd() *cobra.Command`, exported from package `keys` — these are what `cmd/keys.go` and `keys_cmd_test.go`'s `TestMain` call.

- [ ] **Step 1: Write the failing tests for command-line validation (compile-fails first — this is expected and is this step's "red")**

Add this whole block to the end of `cmd/keys/keys_cmd_test.go`, immediately before the final `// ---- verify unused imports are gone ----` line:

```go
// ========== verifyCmd tests ==========

func TestVerifyCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cleanup := viperSet(map[string]any{
		"verify-key-id": uuid.New().String(), "verify-data": "dGVzdA==",
		"verify-signature": "c2ln", "verify-algorithm": "RS256",
	})
	defer cleanup()
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestVerifyCmd_MissingRequiredFlags(t *testing.T) {
	cases := []struct {
		name      string
		keyID     string
		data      string
		signature string
	}{
		{"missing key-id", "", "dGVzdA==", "c2ln"},
		{"missing data", uuid.New().String(), "", "c2ln"},
		{"missing signature", uuid.New().String(), "dGVzdA==", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cleanup := viperSet(map[string]any{
				"verify-key-id": tc.keyID, "verify-data": tc.data,
				"verify-signature": tc.signature, "verify-algorithm": "RS256",
			})
			defer cleanup()
			claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
			ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
			ctx = context.WithValue(ctx, common.LogKey, newLogger())
			cmd, _ := newTestCmd(verifyCmd.RunE, nil)
			cmd.SetContext(ctx)
			err := cmd.Execute()
			assert.ErrorContains(t, err, "--key-id, --data, and --signature are required")
		})
	}
}

func TestVerifyCmd_InvalidKeyID(t *testing.T) {
	cleanup := viperSet(map[string]any{
		"verify-key-id": "not-a-uuid", "verify-data": "dGVzdA==",
		"verify-signature": "c2ln", "verify-algorithm": "RS256",
	})
	defer cleanup()
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestVerifyCmd_InvalidDataBase64(t *testing.T) {
	cleanup := viperSet(map[string]any{
		"verify-key-id": uuid.New().String(), "verify-data": "not!!valid@@base64",
		"verify-signature": "c2ln", "verify-algorithm": "RS256",
	})
	defer cleanup()
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to decode --data")
}

func TestVerifyCmd_InvalidSignatureBase64(t *testing.T) {
	cleanup := viperSet(map[string]any{
		"verify-key-id": uuid.New().String(), "verify-data": "dGVzdA==",
		"verify-signature": "not!!valid@@base64", "verify-algorithm": "RS256",
	})
	defer cleanup()
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to decode --signature")
}

func TestVerifyCmd_NoServiceContainer(t *testing.T) {
	keyID := uuid.New()
	cleanup := viperSet(map[string]any{
		"verify-key-id": keyID.String(), "verify-data": "dGVzdA==",
		"verify-signature": "c2ln", "verify-algorithm": "RS256",
	})
	defer cleanup()
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}
```

- [ ] **Step 2: Run tests to confirm they fail (compile error — `verifyCmd` doesn't exist yet)**

Run: `go test ./cmd/keys/... -run TestVerifyCmd -v`
Expected: `# rocketvault/cmd/keys [rocketvault/cmd/keys.test]` compile error, `undefined: verifyCmd`.

- [ ] **Step 3: Fix the pre-existing mock bug in `keyCmdCryptoService.Verify`**

In `cmd/keys/keys_cmd_test.go`, find:

```go
func (m *keyCmdCryptoService) Verify(ctx context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
	return nil, nil
}
```

Replace with:

```go
func (m *keyCmdCryptoService) Verify(ctx context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.VerifyResult), args.Error(1)
}
```

(This is the same silent-stub bug `Sign` had before this session's earlier fix — it never routed through `m.Called()`, so any `.On("Verify", ...)` expectation would be silently ignored and the mock would always return `nil, nil`, which panics the caller on a nil-pointer dereference the moment real code reads `result.Valid`.)

- [ ] **Step 4: Register `InitKeysVerify`/`NewVerifyCmd` in `TestMain`**

In `cmd/keys/keys_cmd_test.go`'s `TestMain`, change:

```go
	InitKeysWrap(parent)
	InitKeysUnwrap(parent)
	InitKeysUpdate(parent)
	InitKeysSign(parent)
	_ = NewWrapCmd()
	_ = NewUnwrapCmd()
	_ = NewSignCmd()
	os.Exit(m.Run())
```

to:

```go
	InitKeysWrap(parent)
	InitKeysUnwrap(parent)
	InitKeysUpdate(parent)
	InitKeysSign(parent)
	InitKeysVerify(parent)
	_ = NewWrapCmd()
	_ = NewUnwrapCmd()
	_ = NewSignCmd()
	_ = NewVerifyCmd()
	os.Exit(m.Run())
```

- [ ] **Step 5: Create `cmd/keys/verify.go`**

```go
/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package keys

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/crypto"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// verifyCmd represents the verify subcommand.
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature using a vault key",
	Long: `Verify a base64-encoded signature against base64-encoded data using an
existing vault key. Prints the result and exits non-zero if the signature is
invalid, so the command composes directly in scripts (e.g. "if rocketvault
keys verify ...; then").`,
	Example: `  # Verify a signature produced by "keys sign"
  rocketvault keys verify --key-id <uuid> --data <base64> --signature <base64> --algorithm RS256 \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		keyIDStr := viper.GetString("verify-key-id")
		dataB64 := viper.GetString("verify-data")
		signatureB64 := viper.GetString("verify-signature")
		algorithm := viper.GetString("verify-algorithm")

		if keyIDStr == "" || dataB64 == "" || signatureB64 == "" {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "--key-id, --data, and --signature are required", nil)
			return fmt.Errorf("--key-id, --data, and --signature are required")
		}
		if algorithm == "" {
			algorithm = "RS256"
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "failed to decode data", err)
			return fmt.Errorf("failed to decode --data (must be standard base64): %w", err)
		}

		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "failed to decode signature", err)
			return fmt.Errorf("failed to decode --signature (must be standard base64): %w", err)
		}

		// Get service container from context.
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysVerify, model.OpVerify)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.Verify(ctx, keyServices.VerifyRequest{
			KeyID:     keyID,
			Data:      data,
			Signature: signature,
			Algorithm: crypto.SignatureAlgorithm(algorithm),
			UserID:    claims.UserID,
			VaultID:   vaultID,
			Scope:     model.NewVaultScope(vaultID, claims.UserID),
		})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", fmt.Sprintf("verify failed: %s", err), err)
			return fmt.Errorf("verify failed: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "verify_key", "success",
			fmt.Sprintf("signature check for vault key %s: valid=%v", keyID, result.Valid))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"Key ID", "Algorithm", "Valid"}
		row := []string{
			result.KeyID.String(),
			string(result.Algorithm),
			strconv.FormatBool(result.Valid),
		}
		if err := fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row}); err != nil {
			return err
		}

		if !result.Valid {
			return fmt.Errorf("signature verification failed")
		}
		return nil
	},
}

// NewVerifyCmd returns the verify cobra command (used in registration).
func NewVerifyCmd() *cobra.Command {
	return verifyCmd
}

// InitKeysVerify adds the verify subcommand to the keys command.
func InitKeysVerify(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().String("key-id", "", "UUID of the vault key used to verify")
	verifyCmd.Flags().String("data", "", "Base64-encoded original data")
	verifyCmd.Flags().String("signature", "", "Base64-encoded signature to verify")
	verifyCmd.Flags().String("algorithm", "RS256", "Signature algorithm (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)")
	viper.BindPFlag("verify-key-id", verifyCmd.Flags().Lookup("key-id"))       //nolint:errcheck,gosec
	viper.BindPFlag("verify-data", verifyCmd.Flags().Lookup("data"))           //nolint:errcheck,gosec
	viper.BindPFlag("verify-signature", verifyCmd.Flags().Lookup("signature")) //nolint:errcheck,gosec
	viper.BindPFlag("verify-algorithm", verifyCmd.Flags().Lookup("algorithm")) //nolint:errcheck,gosec

	return keysCmd
}
```

- [ ] **Step 6: Register in `cmd/keys.go`**

In `cmd/keys.go`, change:

```go
	keys.InitKeysWrap(keysCmd)
	keys.InitKeysUnwrap(keysCmd)
	keys.InitKeysSign(keysCmd)
```

to:

```go
	keys.InitKeysWrap(keysCmd)
	keys.InitKeysUnwrap(keysCmd)
	keys.InitKeysSign(keysCmd)
	keys.InitKeysVerify(keysCmd)
```

- [ ] **Step 7: Run the Step-1 tests to confirm they now pass**

Run: `go test ./cmd/keys/... -run TestVerifyCmd -v`
Expected: `TestVerifyCmd_NoClaims`, `TestVerifyCmd_MissingRequiredFlags` (all 3 subtests), `TestVerifyCmd_InvalidKeyID`, `TestVerifyCmd_InvalidDataBase64`, `TestVerifyCmd_InvalidSignatureBase64`, `TestVerifyCmd_NoServiceContainer` all `PASS`.

- [ ] **Step 8: Add the success/authz/error test cases**

Append to the same `// ========== verifyCmd tests ==========` block:

```go
func TestVerifyCmd_Denied(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(nil, cryptoSvc)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]any{
		"verify-key-id": keyID.String(), "verify-data": base64.StdEncoding.EncodeToString([]byte("data")),
		"verify-signature": base64.StdEncoding.EncodeToString([]byte("sig")), "verify-algorithm": "RS256",
	})
	defer cleanup()

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "Verify", mock.Anything, mock.Anything)
}

func TestVerifyCmd_Authorized_ValidSignature(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	data := []byte("data-to-verify")
	signature := []byte("signature-bytes")
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
		return r.KeyID == keyID && r.UserID == userID && r.VaultID == vaultID &&
			r.Scope == model.NewVaultScope(vaultID, userID) &&
			r.Algorithm == crypto.SignatureAlgorithm("RS256")
	})).Return(&keyServices.VerifyResult{KeyID: keyID, Algorithm: crypto.SignatureAlgorithm("RS256"), Valid: true}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := buildAdminCtx(sc)
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)

	cleanup := viperSet(map[string]any{
		"verify-key-id": keyID.String(), "verify-data": base64.StdEncoding.EncodeToString(data),
		"verify-signature": base64.StdEncoding.EncodeToString(signature), "verify-algorithm": "RS256",
	})
	defer cleanup()

	cmd, out := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err, "a valid signature must exit 0")
	assert.Contains(t, out.String(), "true")
	cryptoSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestVerifyCmd_InvalidSignature_ExitsNonZeroButPrintsResult(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Verify", mock.Anything, mock.Anything).
		Return(&keyServices.VerifyResult{KeyID: keyID, Algorithm: crypto.SignatureAlgorithm("RS256"), Valid: false}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := buildAdminCtx(sc)
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)

	cleanup := viperSet(map[string]any{
		"verify-key-id": keyID.String(), "verify-data": base64.StdEncoding.EncodeToString([]byte("data")),
		"verify-signature": base64.StdEncoding.EncodeToString([]byte("bad-sig")), "verify-algorithm": "RS256",
	})
	defer cleanup()

	cmd, out := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.Error(t, err, "an invalid signature must exit non-zero")
	assert.ErrorContains(t, err, "signature verification failed")
	assert.Contains(t, out.String(), "false", "the result row must still be printed even though the command fails")
}

func TestVerifyCmd_ServiceError(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Verify", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("verify error"))

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]any{
		"verify-key-id": keyID.String(), "verify-data": base64.StdEncoding.EncodeToString([]byte("data")),
		"verify-signature": base64.StdEncoding.EncodeToString([]byte("sig")), "verify-algorithm": "RS256",
	})
	defer cleanup()

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "verify failed")
}

func TestVerifyCmd_SetsResolvedVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Verify", mock.Anything, mock.MatchedBy(func(r keyServices.VerifyRequest) bool {
		return r.VaultID == vaultID && r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.VerifyResult{KeyID: keyID, Algorithm: crypto.SignatureAlgorithm("RS256"), Valid: true}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := buildAdminCtx(sc)
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)

	cleanup := viperSet(map[string]any{
		"verify-key-id": keyID.String(), "verify-data": base64.StdEncoding.EncodeToString([]byte("data")),
		"verify-signature": base64.StdEncoding.EncodeToString([]byte("sig")), "verify-algorithm": "RS256",
	})
	defer cleanup()

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}
```

Note: `TestVerifyCmd_Denied` and `TestVerifyCmd_ServiceError` deliberately build their context manually (not via `buildAdminCtx`) to match the exact style of the equivalent `TestSignCmd_Denied`/`TestSignCmd_ServiceError` — those two don't need the formatter in context since they never reach the point where `verify.go` reads `common.OutputFormatterKey` (both fail earlier: the authz gate, and the `cryptoService.Verify` error branch, respectively). The three tests that need the printed table (`Authorized_ValidSignature`, `InvalidSignature_ExitsNonZeroButPrintsResult`, `SetsResolvedVaultID`) use `buildAdminCtx`, which already sets `common.OutputFormatterKey`.

- [ ] **Step 9: Run the full `verifyCmd` test suite**

Run: `go test ./cmd/keys/... -run TestVerifyCmd -v`
Expected: every `TestVerifyCmd_*` test `PASS`.

- [ ] **Step 10: Run the full `cmd/keys` package and the whole repo test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: clean build, clean vet, and every package `ok` — no `FAIL` anywhere. (If `api/key_rotation_policy_test.go`'s `TestUpsertKeyRotationPolicy_*` tests are failing at the time this task runs, that is unrelated pre-existing/parallel work, not something this task touches — confirm the *only* delta versus a baseline run is `cmd/keys` gaining passing tests, nothing regressing elsewhere.)

- [ ] **Step 11: Commit**

```bash
git add cmd/keys/verify.go cmd/keys.go cmd/keys/keys_cmd_test.go
git commit -m "$(cat <<'EOF'
feat(keys): add the CLI verify command

rocketvault keys verify calls the same CryptoService.Verify the REST
POST /keys/{id}/verify endpoint already exposes, using the same
authz/flag/error-handling pattern as the existing sign command
(vaultcli.RequireDataAction, viper-bound flags, LogAuditInfo/Error).

Unlike the REST endpoint (which always returns 200 with a valid: bool
field), the CLI exits non-zero when the signature is invalid, in
addition to printing the result row -- matching the standard
convention for verification tools (gpg --verify, cosign verify,
openssl dgst -verify all do the same) and letting the command compose
directly in scripts without parsing output.

Also fixes a pre-existing bug in the keyCmdCryptoService test mock's
Verify method: it returned (nil, nil) unconditionally instead of
routing through m.Called(), the same silent-stub bug Sign had before
this session's earlier fix -- any .On("Verify", ...) expectation was
being silently ignored.

Spec: docs/superpowers/specs/2026-08-18-keys-verify-cli-design.md
EOF
)"
```

---

## Self-Review

**1. Spec coverage:**
- Command shape (flags, auth guard, required-flag check, two independent base64 decodes, `RequireDataAction`, `Verify` call) — Step 5.
- Output/exit-code behavior (table row via formatter, log outcome either way, non-zero exit on `Valid: false` *after* printing) — Step 5's `RunE` body, tail end.
- Registration (`InitKeysVerify` from `cmd/keys.go`) — Step 6.
- Testing list from the spec — every named test in the spec's Testing section has a corresponding test in Steps 1 and 8, except the spec's `TestVerifyCmd_ValidSignature_ExitsZero` and `TestVerifyCmd_InvalidSignature_ExitsNonZero` names, which this plan implements as `TestVerifyCmd_Authorized_ValidSignature` (folds in the authz-allowed assertion, since a separate bare "valid signature" test with no authz mocks would either need `newAllowedContainer`'s bypass — already covered by `TestVerifyCmd_SetsResolvedVaultID` — making a third redundant) and `TestVerifyCmd_InvalidSignature_ExitsNonZeroButPrintsResult` (same test, clearer name pinning the print-then-fail ordering the spec calls out explicitly).
- Mock fix — Step 3.

**2. Placeholder scan:** none found — every step has real, complete code.

**3. Type consistency:** `VerifyRequest`/`VerifyResult` field names (`KeyID`, `Data`, `Signature`, `Algorithm`, `UserID`, `VaultID`, `Scope`; `Valid`, `Algorithm`, `KeyID`) verified against `internal/services/keys/crypto_service.go:40-55` and used identically in both the implementation (Step 5) and every test (Steps 1, 8). `model.ActionKeysVerify`/`model.OpVerify` verified to exist in `model/azure_roles.go:68` and `model/access_policy.go:49`. `buildAdminCtx`, `newAllowedContainer`, `newDeniedContainer`, `viperSet`, `newTestCmd`, `newLogger`, `keyCmdCryptoService` all verified present in the current `cmd/keys/keys_cmd_test.go` before this plan was written.
