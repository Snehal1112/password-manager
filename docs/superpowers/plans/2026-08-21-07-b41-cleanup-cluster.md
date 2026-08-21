# B41 Cleanup Cluster Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the six independently-actionable defects in known-bugs.md's B41
cluster (misleading key-rotation/purge-protection output, a stale `--bits`
help string, a dead error branch, an unauthenticated-by-mistake command, and
an under-documented authorization tier), each as its own acceptable/rejectable
task, without touching any authorization check.

**Architecture:** Five of the six items are self-contained edits inside a
single `cmd/` or `internal/services/` file (a print statement, a flag help
string, a dead `errors.Is` branch, one conditional in `CreateSecret`). The
sixth (`cmd/root.go`'s `systemCmds` map) is extracted into a small testable
`isSystemCommand(cmd *cobra.Command) bool` helper, mirroring the existing
`isCobraBuiltinCommand`/`isContextCommandArgs` pattern in the same file, so
the new session-exemption entry has a direct unit test instead of requiring a
full CLI run. The seventh cluster item (`certificates renew`'s ID output) is
owned by B37's plan and is not touched here.

**Tech Stack:** Go 1.24.2, Cobra, testify (`assert`/`require`/`mock`).

**Spec:** docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md

## Global Constraints

- Go 1.24.2. Do not raise the version floor.
- Comments are short, full sentences ending in a punctuation mark.
- Every fix starts with a failing test ("Testing" section of the spec);
  for a pure string change, the "failing test" is an assertion on the new
  string that fails against the current string.
- `cmd/help_examples_test.go` already guards `Example` blocks — any Long/
  Example text touched here must keep it passing, and must follow
  `.claude/cli-help-conventions.md`.
- Each of the six items below is its own task with its own commit(s), so a
  reviewer can accept or reject them independently. Do not combine tasks
  into one commit.
- Item 6 (`vault-access list`) is documentation- and known-bugs.md-only.
  **Do not change `requireCanManageRoleAssignments` or the `write` argument
  it is called with.** The spec explicitly marks the permission-tier
  question "resolve before implementing" — changing an authorization check
  on assumption is out of scope for a cosmetic cluster like B41.
- Item 7 (`cmd/certificates/renew.go`'s "Old/New Certificate ID" output) is
  owned by `docs/superpowers/plans/2026-08-21-03-b37-ca-renewal.md`. Do not
  duplicate it here.
- No changes to the prose docs (`docs/cli-guide.md` and friends) — a
  separate outstanding pass per the spec's Non-goals.
- `go build ./...`, `go vet ./...`, and `go test ./...` must be clean before
  this work is considered mergeable.

---

### Task 1: `keys rotate` no longer claims a new key ID

**Files:**
- Modify: `cmd/keys/rotate.go` (lines 105–107)
- Modify: `cmd/keys/keys_cmd_test.go` (`TestRotateCmd_Success`, lines 1138–1159)

`RotateKey` (`internal/services/keys/key_service.go:875-999`) always returns
`KeyID: keyID` — the same UUID it was called with (confirmed by reading the
function body: `existing, err := s.keyRepo.Read(ctx, keyID, scope)` ...
`return &CreateKeyResult{KeyID: keyID, ...}`). `cmd/keys/rotate.go` prints
`"Key rotated successfully, New Key: ID=%s, ..."` and audit-logs `"key
rotated, new ID: %s"`, both implying a new identifier. Fix the wording and,
since the command currently writes via raw `fmt.Printf` (bypassing
`cmd.OutOrStdout()`, unlike every sibling command), switch it to
`cmd.OutOrStdout()` so the output is testable and consistent with the rest of
the CLI.

- [ ] **Step 1: Write a failing test asserting the new output text**

  In `cmd/keys/keys_cmd_test.go`, replace `TestRotateCmd_Success` (currently
  discards the output buffer with `cmd, _ := newTestCmd(...)` and stubs a
  `RotateKey` result with a fabricated *different* `KeyID: uuid.New()`, which
  does not match what the real service does) with:

  ```go
  func TestRotateCmd_Success(t *testing.T) {
  	keySvc := &keyCmdKeyService{}
  	userID := uuid.New()
  	keyID := uuid.New()
  	sc, vaultID := newAllowedContainer(keySvc, nil)
  	result := &keyServices.CreateKeyResult{
  		KeyID: keyID, Name: "rotated", Type: "RSA", CreatedAt: time.Now(),
  	}
  	keySvc.On("RotateKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(result, nil)

  	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
  	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
  	ctx = context.WithValue(ctx, common.LogKey, newLogger())
  	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

  	cmd, buf := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
  	cmd.Args = cobra.ExactArgs(1)
  	cmd.SetContext(ctx)
  	err := cmd.Execute()
  	assert.NoError(t, err)
  	keySvc.AssertExpectations(t)
  	assert.Contains(t, buf.String(), "Key rotated successfully: ID="+keyID.String())
  	assert.NotContains(t, buf.String(), "New Key", "the rotated key keeps its UUID; the output must not imply a new one")
  }
  ```

  Run: `go test ./cmd/keys/... -run TestRotateCmd_Success -v`

  Expected failure: `buf.String()` is empty (today's `rotate.go` writes with
  raw `fmt.Printf`, not `cmd.OutOrStdout()`), so
  `assert.Contains(t, buf.String(), "Key rotated successfully: ID=...")` fails.

- [ ] **Step 2: Fix the output in `cmd/keys/rotate.go`**

  Replace lines 105–107:

  ```go
  		log.LogAuditInfo(claims.UserID.String(), "rotate_key", "success", fmt.Sprintf("key rotated, new ID: %s", newKey.KeyID))
  		fmt.Printf("Key rotated successfully, New Key: ID=%s, Name=%s, Type=%s, CreatedAt=%s, Tags=%v\n",
  			newKey.KeyID, newKey.Name, newKey.Type, newKey.CreatedAt.Format(time.RFC3339), newKey.Tags)
  		return nil
  ```

  with:

  ```go
  		log.LogAuditInfo(claims.UserID.String(), "rotate_key", "success", fmt.Sprintf("key rotated: %s", newKey.KeyID))
  		fmt.Fprintf(cmd.OutOrStdout(), "Key rotated successfully: ID=%s, Name=%s, Type=%s, CreatedAt=%s, Tags=%v\n", //nolint:errcheck
  			newKey.KeyID, newKey.Name, newKey.Type, newKey.CreatedAt.Format(time.RFC3339), newKey.Tags)
  		return nil
  ```

- [ ] **Step 3: Run the test and see it pass**

  Run: `go test ./cmd/keys/... -run TestRotateCmd_Success -v`

  Expected: PASS.

- [ ] **Step 4: Commit**

  ```
  git add cmd/keys/rotate.go cmd/keys/keys_cmd_test.go
  git commit -m "fix(keys): stop claiming key rotation mints a new key ID"
  ```

---

### Task 2: `keys create --bits` help lists all three accepted sizes

**Files:**
- Modify: `cmd/keys/create.go` (line 191)
- Modify: `cmd/keys/keys_cmd_test.go` (new test, near the `createCmd` tests section)

`CreateRSAKey` (`internal/services/keys/key_service.go:232-235`) validates
`req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096` — 3072 is
accepted. `createCmd.Long` already says "RSA keys must be 2048, 3072 or 4096
bits" (line 55) correctly; only the `--bits` flag's own help string at line
191 is stale: `"RSA key size in bits (2048 or 4096)"`.

- [ ] **Step 1: Write a failing test asserting the new flag help string**

  Add to `cmd/keys/keys_cmd_test.go` (e.g. directly after `TestCreateCmd_RSASuccess`):

  ```go
  func TestKeysCreateBitsFlagDocumentsAllAcceptedSizes(t *testing.T) {
  	flag := createCmd.Flags().Lookup("bits")
  	if flag == nil {
  		t.Fatal("--bits flag not registered on keys create")
  	}
  	assert.Equal(t, "RSA key size in bits (2048, 3072 or 4096)", flag.Usage)
  }
  ```

  Run: `go test ./cmd/keys/... -run TestKeysCreateBitsFlagDocumentsAllAcceptedSizes -v`

  Expected failure: actual Usage is `"RSA key size in bits (2048 or 4096)"`,
  not the expected string.

- [ ] **Step 2: Fix the flag help string in `cmd/keys/create.go`**

  Replace line 191:

  ```go
  	createCmd.Flags().Int("bits", 2048, "RSA key size in bits (2048 or 4096)")
  ```

  with:

  ```go
  	createCmd.Flags().Int("bits", 2048, "RSA key size in bits (2048, 3072 or 4096)")
  ```

- [ ] **Step 3: Run the test and see it pass**

  Run: `go test ./cmd/keys/... -run TestKeysCreateBitsFlagDocumentsAllAcceptedSizes -v`

  Expected: PASS.

- [ ] **Step 4: Commit**

  ```
  git add cmd/keys/create.go cmd/keys/keys_cmd_test.go
  git commit -m "fix(keys): document all three accepted RSA bit sizes in --bits help"
  ```

---

### Task 3: Remove the unreachable `ErrWebhookNotFound` branch from `vault-webhook delete`

**Files:**
- Modify: `cmd/vault-webhook/delete.go` (imports, lines 3–12; dead branch, lines 48–53)
- Create: `cmd/vault-webhook/delete_test.go`

`VaultWebhookService.Delete` (`internal/services/vaults/webhook_service.go:232-241`)
calls `s.repo.DeleteByVaultID(ctx, vaultID)` and returns whatever that
returns — it never returns `ErrWebhookNotFound`, and deleting an absent
webhook config is a silent success (per the command's own `Long` text and
doc comment, which are correct and unaffected by this change). The
`errors.Is(err, vaultServices.ErrWebhookNotFound)` branch in `delete.go` is
dead code that can never execute. Remove it and the two imports it alone
uses (`errors`, `vaultServices`).

- [ ] **Step 1: Write a failing test proving the branch is dead code that miscategorizes a real error**

  Create `cmd/vault-webhook/delete_test.go`, reusing the `fakeWebhookSvc` and
  `newVaultWebhookCmd` helpers already defined in `cmd/vault-webhook/set_test.go`
  (same package):

  ```go
  package vaultwebhook

  import (
  	"testing"

  	"github.com/stretchr/testify/assert"
  	"github.com/stretchr/testify/require"

  	"rocketvault/cmd/testutils"
  	vaultServices "rocketvault/internal/services/vaults"
  )

  // TestVaultWebhookDelete_ServiceErrorNotSpecialCased proves the removed
  // errors.Is(err, ErrWebhookNotFound) branch is gone: VaultWebhookService.Delete
  // is idempotent on an absent config (it calls repo.DeleteByVaultID and treats
  // deleting nothing as success -- see webhook_service.go's Delete), so the CLI
  // never legitimately observes that sentinel from a real call. Any error the
  // service does return -- including, artificially, this sentinel itself --
  // must surface as the generic failure message, not be re-interpreted as
  // "not configured".
  func TestVaultWebhookDelete_ServiceErrorNotSpecialCased(t *testing.T) {
  	tc := testutils.NewTestContext(t)
  	fake := &fakeWebhookSvc{deleteErr: vaultServices.ErrWebhookNotFound}
  	tc.MockContainer.VaultWebhookService = fake

  	cmd, _ := newVaultWebhookCmd(tc.Ctx)
  	cmd.SetArgs([]string{"delete"})

  	err := cmd.Execute()
  	require.Error(t, err)
  	assert.Contains(t, err.Error(), "delete webhook failed")
  	assert.NotContains(t, err.Error(), "no webhook configured for vault")
  }
  ```

  Run: `go test ./cmd/vault-webhook/... -run TestVaultWebhookDelete_ServiceErrorNotSpecialCased -v`

  Expected failure: today's `delete.go` intercepts the sentinel and returns
  `no webhook configured for vault "default"`, so
  `assert.Contains(t, err.Error(), "delete webhook failed")` fails.

- [ ] **Step 2: Remove the dead branch and its now-unused imports in `cmd/vault-webhook/delete.go`**

  Replace:

  ```go
  import (
  	"errors"
  	"fmt"

  	"github.com/spf13/cobra"

  	"rocketvault/common"
  	"rocketvault/internal/container"
  	vaultServices "rocketvault/internal/services/vaults"
  )
  ```

  with:

  ```go
  import (
  	"fmt"

  	"github.com/spf13/cobra"

  	"rocketvault/common"
  	"rocketvault/internal/container"
  )
  ```

  and replace:

  ```go
  			if err := sc.GetVaultWebhookService().Delete(ctx, vaultID, actor); err != nil {
  				if errors.Is(err, vaultServices.ErrWebhookNotFound) {
  					return fmt.Errorf("no webhook configured for vault %q", vaultName)
  				}
  				return fmt.Errorf("delete webhook failed: %w", err)
  			}
  ```

  with:

  ```go
  			if err := sc.GetVaultWebhookService().Delete(ctx, vaultID, actor); err != nil {
  				return fmt.Errorf("delete webhook failed: %w", err)
  			}
  ```

  (`vaultName` is still used by the success-message `fmt.Fprintf` below it, so
  it stays a live local variable.)

- [ ] **Step 3: Run the test and see it pass**

  Run: `go test ./cmd/vault-webhook/... -run TestVaultWebhookDelete_ServiceErrorNotSpecialCased -v`

  Expected: PASS. Also run the full package to confirm no regression:
  `go test ./cmd/vault-webhook/... -v`

- [ ] **Step 4: Commit**

  ```
  git add cmd/vault-webhook/delete.go cmd/vault-webhook/delete_test.go
  git commit -m "fix(vault-webhook): remove unreachable ErrWebhookNotFound branch from delete"
  ```

---

### Task 4: `secrets create --purge-protection=false` is no longer inert

**Files:**
- Modify: `internal/services/secrets/secret_service.go` (`CreateSecret`, lines 259–266)
- Modify: `internal/services/secrets/secret_scope_service_test.go` (new test, after line 385)
- Modify: `cmd/secrets/create.go` (`Long` text, line 58)
- Modify: `cmd/secrets/create_test.go` (new test)

`CreateSecret` only calls `SetPurgeProtection` when
`req.PurgeProtection != nil && *req.PurgeProtection` (i.e. only for an
explicit `true`), while `UpdateSecret` calls it whenever
`req.PurgeProtection != nil`, honoring both `true` and `false` (lines
333–338). An explicit `--purge-protection=false` on `secrets create` is
therefore silently dropped — no-op, not "explicitly disabled". Make
`CreateSecret` match `UpdateSecret`'s nil-check.

- [ ] **Step 1: Write a failing test for explicit `false` at creation time**

  Add to `internal/services/secrets/secret_scope_service_test.go`, directly
  after `TestCreateSecretLeavesPurgeProtectionAloneByDefault` (line 385):

  ```go
  func TestCreateSecretSetsPurgeProtectionFalseWhenExplicitlyRequested(t *testing.T) {
  	repo, svc := newScopeServiceFixture(t)
  	ctx := context.Background()

  	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil).Once()
  	repo.On("SetPurgeProtection", ctx, mock.AnythingOfType("uuid.UUID"), false).Return(nil).Once()

  	protect := false
  	secret, err := svc.CreateSecret(ctx, CreateSecretRequest{
  		UserID: uuid.New(), Name: "s1", Value: "v1", PurgeProtection: &protect,
  	})
  	require.NoError(t, err)
  	repo.AssertCalled(t, "SetPurgeProtection", ctx, secret.ID, false)
  	repo.AssertExpectations(t)
  }
  ```

  Run: `go test ./internal/services/secrets/... -run TestCreateSecretSetsPurgeProtectionFalseWhenExplicitlyRequested -v`

  Expected failure: today's `CreateSecret` never calls `SetPurgeProtection`
  for an explicit `false`, so `repo.AssertExpectations(t)` fails with
  something like "0 out of 1 expectation(s) were met" for `SetPurgeProtection`.

- [ ] **Step 2: Fix `CreateSecret` in `internal/services/secrets/secret_service.go`**

  Replace lines 259–266:

  ```go
  	// Purge protection lives in its own column, so it is set as a follow-up
  	// write rather than through Create's insert.
  	if req.PurgeProtection != nil && *req.PurgeProtection {
  		if err = s.secretRepo.SetPurgeProtection(ctx, secret.ID, true); err != nil {
  			s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to set purge protection", err)
  			return nil, fmt.Errorf("failed to set purge protection: %w", err)
  		}
  	}
  ```

  with:

  ```go
  	// Purge protection lives in its own column, so it is set as a follow-up
  	// write rather than through Create's insert. Honor an explicit false the
  	// same way UpdateSecret does, so "--purge-protection=false" is not
  	// silently inert (B41).
  	if req.PurgeProtection != nil {
  		if err = s.secretRepo.SetPurgeProtection(ctx, secret.ID, *req.PurgeProtection); err != nil {
  			s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to set purge protection", err)
  			return nil, fmt.Errorf("failed to set purge protection: %w", err)
  		}
  	}
  ```

- [ ] **Step 3: Run the tests and see them pass**

  Run: `go test ./internal/services/secrets/... -run TestCreateSecretSetsPurgeProtection -v`

  Expected: both `TestCreateSecretSetsPurgeProtectionWhenRequested` and
  `TestCreateSecretSetsPurgeProtectionFalseWhenExplicitlyRequested` PASS.
  Also confirm the nil-default case is untouched:
  `go test ./internal/services/secrets/... -run TestCreateSecretLeavesPurgeProtectionAloneByDefault -v`

- [ ] **Step 4: Commit the behavior fix**

  ```
  git add internal/services/secrets/secret_service.go internal/services/secrets/secret_scope_service_test.go
  git commit -m "fix(secrets): make --purge-protection=false stick on create, matching update"
  ```

- [ ] **Step 5: Write a failing test for the now-stale CLI help text**

  `cmd/secrets/create.go`'s `Long` text (line 58) says "--purge-protection is
  only written when it is true" — accurate before Step 2, wrong after it.
  Add to `cmd/secrets/create_test.go`:

  ```go
  // TestCreateCmdLongTextMatchesPurgeProtectionBehavior pins the help text to
  // the fix in secret_service.go's CreateSecret (B41): --purge-protection is
  // now written whenever the flag is explicitly passed, true or false,
  // matching UpdateSecret -- not "only when it is true" as the text used to
  // claim.
  func TestCreateCmdLongTextMatchesPurgeProtectionBehavior(t *testing.T) {
  	assert.NotContains(t, createCmd.Long, "only written when it is true")
  	assert.Contains(t, createCmd.Long, "whenever the flag is explicitly passed")
  }
  ```

  Run: `go test ./cmd/secrets/... -run TestCreateCmdLongTextMatchesPurgeProtectionBehavior -v`

  Expected failure: the current `Long` text still contains "only written
  when it is true", so `assert.NotContains` fails.

- [ ] **Step 6: Fix the `Long` text in `cmd/secrets/create.go`**

  Replace line 58 (the final sentence of the `Long` string):

  ```go
  stored. --purge-protection is only written when it is true, and it blocks
  the later permanent purge of the secret once it has been soft-deleted.`,
  ```

  with:

  ```go
  stored. --purge-protection is written whenever the flag is explicitly
  passed (true or false), and it blocks the later permanent purge of the
  secret once it has been soft-deleted.`,
  ```

- [ ] **Step 7: Run the test and see it pass, then run the help-text guard**

  Run: `go test ./cmd/secrets/... -run TestCreateCmdLongTextMatchesPurgeProtectionBehavior -v`

  Expected: PASS. Then run the repo-wide help guard to confirm no flag/example
  drift: `go test ./cmd/ -run TestExampleFlagsAreRegistered -v`

- [ ] **Step 8: Commit the help-text fix**

  ```
  git add cmd/secrets/create.go cmd/secrets/create_test.go
  git commit -m "docs(secrets): fix purge-protection help text to match create's new behavior"
  ```

---

### Task 5: `secrets generate-password` no longer requires a session

**Files:**
- Modify: `cmd/root.go` (extract `isSystemCommand`, lines ~154–168 for placement, ~296–335 for the call site; `rootCmd.Long`, lines 67–69)
- Modify: `cmd/root_test.go` (new tests, near `TestIsCobraBuiltinCommand`, lines ~317–347)
- Modify: `cmd/secrets/generate.go` (`Long` text, lines 47–49)
- Modify: `cmd/secrets/generate_test.go` (new test)
- Modify: `.claude/cli-help-conventions.md` (lines 115–120)

`generateCmd`'s `RunE` (`cmd/secrets/generate.go`) does pure local RNG via
`crypto/rand` and stores nothing — no DB, no vault, no data action, no role
check (confirmed by reading the whole file). `persistentPreRun`'s
`systemCmds` map (`cmd/root.go:312-329`) does not include it, so it goes
through `resolveAuthentication` like every data-plane command. Cobra's
`cmd.Name()` for this command is **`"generate-password"`** (from
`Use: "generate-password"` in `cmd/secrets/generate.go:36` — no space in
`Use`, so `Name()` returns the whole string), and `systemCmds` is keyed by
`cmd.Name()` for a leaf command (see the existing `"roles"`, `"login"`,
`"logout"` entries, which are leaves under `vault-access`/`users` the same
way). Add `"generate-password": true` under that exact key.

This task also extracts the inline `systemCmds` map + lookup in
`persistentPreRun` into a package-level `isSystemCommand(cmd *cobra.Command)
bool` function, mirroring the existing `isCobraBuiltinCommand` and
`isContextCommandArgs` helpers already in this file — this is what makes the
new entry unit-testable without executing the full CLI pipeline (DB init,
service container, etc.), the same way `TestIsCobraBuiltinCommand` tests
`isCobraBuiltinCommand` directly.

This task changes only the **authentication** exemption. It does not touch
the separate DB-initialization requirement in `persistentPreRun` (the
`isContextGroup`/`isCobraBuiltinCommand` check around `database.InitializeDB()`)
— every other `systemCmds` entry (`"roles"`, `"login"`, etc.) is subject to
that same pre-existing requirement, so this is not a new gap and is out of
scope for B41.

- [ ] **Step 1: Write a failing test for the new classifier function**

  Add to `cmd/root_test.go`, directly after `TestIsCobraBuiltinCommand`:

  ```go
  // TestIsSystemCommand pins persistentPreRun's authentication-exemption
  // list at the unit level, the same way TestIsCobraBuiltinCommand pins the
  // cobra-builtin classification -- see isSystemCommand in cmd/root.go.
  func TestIsSystemCommand(t *testing.T) {
  	secretsCmd := &cobra.Command{Use: "secrets"}
  	generatePasswordCmd := &cobra.Command{Use: "generate-password"}
  	secretsCmd.AddCommand(generatePasswordCmd)

  	usersCmd := &cobra.Command{Use: "users"}
  	loginCmd := &cobra.Command{Use: "login"}
  	usersCmd.AddCommand(loginCmd)

  	cases := []struct {
  		name string
  		cmd  *cobra.Command
  		want bool
  	}{
  		{"generate-password (leaf, pure local RNG, no session needed)", generatePasswordCmd, true},
  		{"secrets (parent; not itself a system command)", secretsCmd, false},
  		{"login (pre-existing exemption, still works)", loginCmd, true},
  		{"health (top-level system command)", &cobra.Command{Use: "health"}, true},
  		{"create (not a system command)", &cobra.Command{Use: "create"}, false},
  	}
  	for _, tc := range cases {
  		t.Run(tc.name, func(t *testing.T) {
  			assert.Equal(t, tc.want, isSystemCommand(tc.cmd))
  		})
  	}
  }
  ```

  Run: `go test ./cmd/ -run TestIsSystemCommand -v`

  Expected failure: build failure — `isSystemCommand` does not exist yet
  (`undefined: isSystemCommand`).

- [ ] **Step 2: Extract `isSystemCommand` in `cmd/root.go` and add the new entry**

  Add this function directly after `isCobraBuiltinCommand` (after line 168):

  ```go
  // isSystemCommand reports whether cmd is exempt from persistentPreRun's
  // authentication requirement -- either because it performs no vault/data
  // operation at all (e.g. "health", "roles", "generate-password"), or
  // because it is itself part of bootstrapping or clearing a session (e.g.
  // "login", "logout"). Checked against both cmd.Name() and, for a leaf
  // command, its parent's name, so a whole command group (e.g. "context")
  // can be exempted at once.
  func isSystemCommand(cmd *cobra.Command) bool {
  	systemCmds := map[string]bool{
  		"health":                        true,
  		"serve":                         true, // Server startup doesn't require prior authentication
  		"admin":                         true, // Allow admin registration without prior authentication
  		"migrate":                       true, // Database migrations don't require authentication
  		"migrate:status":                true, // Migration status check
  		"migrate:to":                    true, // Targeted migrations
  		"migrate:create":                true, // Migration file creation
  		"roles":                         true, // Lists built-in vault roles; pure client-side, no auth needed
  		"preview-migration":             true, // Reads ownership to plan role assignments; no auth, no writes
  		"login":                         true, // Bootstraps a session (password or --oidc); cannot itself require one
  		"logout":                        true, // Clears a cached session; must work even if that session is broken
  		"context":                       true, // Local-only config (add/list/use/current/remove); no DB, no auth
  		"help":                          true, // Cobra built-in; must never require login (see isCobraBuiltinCommand)
  		"completion":                    true, // Cobra built-in; ditto, for the per-shell completion-script commands
  		"generate-password":             true, // Pure local RNG; stores nothing, touches no vault -- see B41
  		cobra.ShellCompRequestCmd:       true, // "__complete" -- invoked by live shell tab-completion
  		cobra.ShellCompNoDescRequestCmd: true, // "__completeNoDesc" -- ditto, no-description variant
  	}

  	if systemCmds[cmd.Name()] {
  		return true
  	}
  	return cmd.Parent() != nil && systemCmds[cmd.Parent().Name()]
  }
  ```

  Then in `persistentPreRun`, replace lines 311–335:

  ```go
  	// System commands that don't require authentication
  	systemCmds := map[string]bool{
  		"health":                        true,
  		"serve":                         true, // Server startup doesn't require prior authentication
  		"admin":                         true, // Allow admin registration without prior authentication
  		"migrate":                       true, // Database migrations don't require authentication
  		"migrate:status":                true, // Migration status check
  		"migrate:to":                    true, // Targeted migrations
  		"migrate:create":                true, // Migration file creation
  		"roles":                         true, // Lists built-in vault roles; pure client-side, no auth needed
  		"preview-migration":             true, // Reads ownership to plan role assignments; no auth, no writes
  		"login":                         true, // Bootstraps a session (password or --oidc); cannot itself require one
  		"logout":                        true, // Clears a cached session; must work even if that session is broken
  		"context":                       true, // Local-only config (add/list/use/current/remove); no DB, no auth
  		"help":                          true, // Cobra built-in; must never require login (see isCobraBuiltinCommand)
  		"completion":                    true, // Cobra built-in; ditto, for the per-shell completion-script commands
  		cobra.ShellCompRequestCmd:       true, // "__complete" — invoked by live shell tab-completion
  		cobra.ShellCompNoDescRequestCmd: true, // "__completeNoDesc" — ditto, no-description variant
  	}

  	// Check if this is a system command (either the command itself or its parent)
  	isSystemCmd := systemCmds[cmd.Name()]
  	if !isSystemCmd && cmd.Parent() != nil {
  		isSystemCmd = systemCmds[cmd.Parent().Name()]
  	}
  ```

  with:

  ```go
  	// System commands that don't require authentication -- see isSystemCommand.
  	isSystemCmd := isSystemCommand(cmd)
  ```

- [ ] **Step 3: Run the test and see it pass**

  Run: `go test ./cmd/ -run TestIsSystemCommand -v`

  Expected: PASS. Then run the full `cmd` package to confirm no regression
  (the extraction must be behavior-preserving for every pre-existing entry):
  `go test ./cmd/... -v -run 'TestIsSystemCommand|TestIsCobraBuiltinCommand|TestPersistentPreRun'`

- [ ] **Step 4: Commit**

  ```
  git add cmd/root.go cmd/root_test.go
  git commit -m "fix(cli): exempt secrets generate-password from the session requirement"
  ```

- [ ] **Step 5: Write failing tests for the now-stale help text in two places**

  `rootCmd.Long` (`cmd/root.go:67-69`) lists the session-exempt commands and
  is missing `secrets generate-password`. `generateCmd.Long`
  (`cmd/secrets/generate.go:47-49`) explicitly says the opposite of the new
  behavior: "The command is not on the CLI's list of session-exempt
  commands... an active session is still required to run it."

  Add to `cmd/root_test.go`:

  ```go
  // TestRootLongTextListsGeneratePasswordAsSessionExempt pins rootCmd.Long's
  // session-exempt command list against the isSystemCommand fix (B41).
  func TestRootLongTextListsGeneratePasswordAsSessionExempt(t *testing.T) {
  	assert.Contains(t, rootCmd.Long, "secrets generate-password")
  }
  ```

  Add to `cmd/secrets/generate_test.go`:

  ```go
  // TestGenerateCmdLongTextReflectsSessionExemption pins the help text
  // against the isSystemCommand fix (B41): the command no longer requires an
  // active session, so its Long text must not claim otherwise.
  func TestGenerateCmdLongTextReflectsSessionExemption(t *testing.T) {
  	assert.NotContains(t, generateCmd.Long, "is still required to run it")
  	assert.Contains(t, generateCmd.Long, "needs no active session")
  }
  ```

  Run: `go test ./cmd/ -run TestRootLongTextListsGeneratePasswordAsSessionExempt -v`
  and `go test ./cmd/secrets/... -run TestGenerateCmdLongTextReflectsSessionExemption -v`

  Expected failure: both fail against the current text (missing phrase /
  still-present old sentence, respectively).

- [ ] **Step 6: Fix both `Long` texts**

  In `cmd/root.go`, replace (within `rootCmd.Long`):

  ```go
  no credential flags. These commands need no session at all: health, serve,
  users admin, users login, users logout, the migrate commands, vaults
  preview-migration, vault-access roles, and the whole context group.
  ```

  with:

  ```go
  no credential flags. These commands need no session at all: health, serve,
  users admin, users login, users logout, the migrate commands, vaults
  preview-migration, vault-access roles, secrets generate-password, and the
  whole context group.
  ```

  In `cmd/secrets/generate.go`, replace lines 47–49:

  ```go
  No role and no data action is checked, and no vault is touched. The command
  is not on the CLI's list of session-exempt commands, so an active session
  is still required to run it.`,
  ```

  with:

  ```go
  No role and no data action is checked, and no vault is touched. The command
  needs no active session or credential flags to run it, since it performs no
  server or vault operation at all.`,
  ```

- [ ] **Step 7: Run both tests and see them pass, then run the help-text guard**

  Run: `go test ./cmd/ -run TestRootLongTextListsGeneratePasswordAsSessionExempt -v`
  and `go test ./cmd/secrets/... -run TestGenerateCmdLongTextReflectsSessionExemption -v`

  Expected: both PASS. Then: `go test ./cmd/ -run TestExampleFlagsAreRegistered -v`

- [ ] **Step 8: Update `.claude/cli-help-conventions.md`'s own list**

  This is a repository convention doc, not CLI-visible text, so no Go test
  applies to it — it is a documentation-consistency edit only. Replace lines
  115–120:

  ```
  `persistentPreRun` treats these as system commands, so their examples must not
  imply a login: `health`, `serve`, `admin`, `migrate`, `migrate:status`,
  `migrate:to`, `migrate:create`, `roles`, `preview-migration`, `login`,
  `logout`, and the whole `context` group.
  ```

  with:

  ```
  `persistentPreRun` treats these as system commands, so their examples must not
  imply a login: `health`, `serve`, `admin`, `migrate`, `migrate:status`,
  `migrate:to`, `migrate:create`, `roles`, `preview-migration`, `login`,
  `logout`, `secrets generate-password`, and the whole `context` group.
  ```

- [ ] **Step 9: Commit the help-text fixes**

  ```
  git add cmd/root.go cmd/root_test.go cmd/secrets/generate.go cmd/secrets/generate_test.go .claude/cli-help-conventions.md
  git commit -m "docs(cli): document generate-password's session exemption"
  ```

---

### Task 6: `vault-access list`'s permission tier — document and defer, do not change

**Files:**
- Verify only (no code change): `cmd/vault-access/list.go`
- Modify: `.claude/known-bugs.md` (B41 entry, after the `vault-access list` bullet, before the "Provenance" paragraph — currently around line 1925/1927)

`cmd/vault-access/list.go` calls
`requireCanManageRoleAssignments(ctx, sc, vaultID, false)` — the identical
`write=false` argument `cmd/vault-access/revoke.go` passes (confirmed by
reading both files), which is stricter than `grant.go`'s `write=true`. This
is fail-closed (listing requires at least revoke-level permission, never
less), so it is a deliberate-but-underdocumented tightness, not a security
hole. The spec explicitly marks the question of whether to add a narrower
read-only tier as **"resolve before implementing"** — a product decision,
not a mechanical fix, and out of scope for a cosmetic cluster.

Reading `cmd/vault-access/list.go`'s current `Long` text (lines 17–27) shows
this was already fixed in commit `dd5fb83` ("fix(authz): gate CLI
role-assignment list, complete Azure-role-count sweep"): it already states
"That is the same check vault-access revoke uses — there is no separate,
narrower permission tier for listing." So the CLI-visible documentation part
of this item is **already done**; the only remaining action is recording the
deferred product decision in `known-bugs.md` so it isn't lost.

- [ ] **Step 1: Verify the `Long` text is still accurate**

  Read `cmd/vault-access/list.go` lines 17–27 and confirm it still says the
  command "Requires ... a Key Vault Data Access Administrator role
  assignment holding Microsoft.Authorization/roleAssignments/delete in this
  vault. That is the same check vault-access revoke uses — there is no
  separate, narrower permission tier for listing." If it has drifted (e.g. a
  later change re-introduced a narrower claim), correct it to match
  `requireCanManageRoleAssignments(ctx, sc, vaultID, false)`'s actual
  behavior; otherwise make no code change. **Do not touch the `false`
  argument itself or `requireCanManageRoleAssignments`.**

- [ ] **Step 2: Record the deferred decision in `.claude/known-bugs.md`**

  In the B41 entry, immediately after the existing `vault-access list`
  bullet (the one ending "...stricter than the parameter name suggests.")
  and before the `**Provenance for B35–B41**` paragraph, add:

  ```markdown

  **`vault-access list`'s permission tier is a deferred product decision, not
  a bug fix.** `cmd/vault-access/list.go`'s `Long` text (as of commit
  `dd5fb83`) already documents the current behavior accurately: listing
  requires the same permission as `vault-access revoke`. The spec for this
  cluster (`docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`,
  § B41) marks "add a narrower read tier vs. keep the shared check" as
  "resolve before implementing" rather than a mechanical fix, so B41's plan
  (`docs/superpowers/plans/2026-08-21-07-b41-cleanup-cluster.md`) deliberately
  left the authorization check untouched. Whoever owns the product call
  should update this note when a decision is made.
  ```

- [ ] **Step 3: Confirm no test regressions**

  Run: `go test ./cmd/vault-access/... -v`

  Expected: all pre-existing tests PASS unchanged (no behavior was touched).

- [ ] **Step 4: Commit**

  ```
  git add .claude/known-bugs.md
  git commit -m "docs(known-bugs): record the vault-access list permission-tier decision as deferred"
  ```

---

### Task 7: `certificates renew` ID output — owned by B37, not implemented here

`cmd/certificates/renew.go`'s "Old Certificate ID"/"New Certificate ID"
output (always the same UUID, since `RenewCertificate` does `updated :=
*original` and updates in place) is the seventh item in known-bugs.md's B41
cluster, but it is already covered by
`docs/superpowers/plans/2026-08-21-03-b37-ca-renewal.md`. It is intentionally
**not** duplicated in this plan — see that plan for its implementation.

---

## Definition of Done

- All six items have their own commit(s); none touch
  `requireCanManageRoleAssignments` or any other authorization check.
- `keys rotate` prints and audit-logs the key's (unchanged) ID without
  implying a new one.
- `keys create --bits`'s help string lists 2048, 3072, and 4096.
- `cmd/vault-webhook/delete.go` has no `errors.Is(err, ErrWebhookNotFound)`
  branch and no unused imports.
- `secrets create --purge-protection=false` writes `false` to the column
  (proven by `TestCreateSecretSetsPurgeProtectionFalseWhenExplicitlyRequested`),
  matching `UpdateSecret`.
- `secrets generate-password` runs with no cached session and no credential
  flags (proven by `TestIsSystemCommand`); `rootCmd.Long` and
  `generateCmd.Long` reflect it.
- `.claude/known-bugs.md`'s B41 entry records the `vault-access list`
  permission-tier question as an explicitly deferred product decision.
- `go build ./...`, `go vet ./...`, `go test ./...` all clean.
- `go test ./cmd/ -run TestExampleFlagsAreRegistered -v` passes.
