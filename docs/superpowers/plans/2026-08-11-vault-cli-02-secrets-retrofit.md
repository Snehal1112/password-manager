# Vault CLI Extension — Plan 02: `cmd/secrets` Authorization Retrofit

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retrofit all 7 vault-aware `cmd/secrets` commands (`create`, `list`, `get`, `delete`, `update`, `export`, `import`) to call `vaultcli.RequireDataAction` before touching the service layer, closing the CLI authorization gap the whole 5-plan series exists to fix. Delete `cmd/secrets/vault.go`. Fix the `uuid.Nil` actor-ID bug in `get.go`/`delete.go`. Fix the stale "owner-scoped, matches HTTP" comments in `update.go`/`export.go` — that claim is false today — by switching both to `model.NewVaultScope`, genuinely matching current HTTP behavior.

**Architecture:** Every command already extracts (or gains an extraction of) the caller's `userID` from `ctx.Value(common.UserIDKey)`. Each command's existing `resolveVaultID(ctx, cmd, sc)` call is replaced by `vaultcli.RequireDataAction(ctx, cmd, sc, userID, <action>)`, which resolves the vault by name AND checks the role assignment in one call, returning the vault ID on success and an error (vault-not-found or forbidden) otherwise — before any service/repository call. No other control flow changes.

**Tech Stack:** Go, `github.com/google/uuid`, `github.com/spf13/cobra`, `github.com/stretchr/testify/{assert,require,mock}`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-11-vault-cli-extension-design.md` — read in full before starting.
- Depends on Plan 01 (`docs/superpowers/plans/2026-08-11-vault-cli-01-shared-primitives.md`), already merged, which produced:
  - `authorization.RequireDataAction(ctx context.Context, roles RoleAssignmentService, principalID, vaultID uuid.UUID, action model.DataAction) error` — package `rocketvault/internal/services/authorization`.
  - `vaultcli.ResolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error)` and `vaultcli.RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction, op model.PolicyOperation) (vaultID uuid.UUID, err error)` — package `rocketvault/cmd/vaultcli`.
  - `testutils.MockRoleAssignmentService` (testify-mock) and a `MockRoleAssignmentService` field on `testutils.TestContext`. `testutils.NewTestContext(t)` wires `tc.MockContainer.RoleAssignmentService` to a default instance whose `HasDataAction` returns `(true, nil)` for every call (`.Maybe()`), so every pre-existing test in this package keeps passing once these commands gain the new authz call. A test that wants the deny path replaces the whole field with a fresh instance:
    ```go
    denyRoles := &testutils.MockRoleAssignmentService{}
    denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
    tc.MockContainer.RoleAssignmentService = denyRoles
    ```
    Never add `.On()` expectations to the shared default instance for a deny case — swap the field.
- `vaultcli.RequireDataAction` gained a `op model.PolicyOperation` parameter after Plan 01's final review found it needed to also check the `access_policies` explicit-deny override — see `docs/superpowers/specs/2026-08-11-vault-cli-extension-design.md`'s "Access-policy explicit-deny in the CLI adapter" section for the full per-command mapping table (reproduced above for this plan's commands).
- **User-visible behavior change, ship this deliberately:** after this plan, any vault member holding a role that grants `ActionSecretsSet` (e.g. `Key Vault Secrets Officer`) can update or export another member's secret via the CLI, not just the object's own creator. This matches what the HTTP API's vault-scoped route (`/vaults/{name}/secrets/...`) already does today via `scopeFromRequest` → `model.NewVaultScope`; it is CLI catch-up to existing HTTP behavior, not a new capability HTTP doesn't already have.
- **Known pre-existing test trap, do not use as a template:** `cmd/secrets/list_test.go`'s `TestListSecretsCommand` builds its own inline fake `RunE` closure that reimplements list logic independently of the real `listCmd` (hardcodes `model.NewOwnerScope`, calls `secretService.ListSecrets` directly). It does not exercise production code and is out of scope for this plan — leave it untouched. The REAL list command test in that file is `TestListSecretsOutputFormat`, which calls `listCmd.RunE` directly and already expects `model.NewVaultScope(tc.TestVaultID, uuid.Nil)`. `cmd/secrets/service_test.go` has the same kind of fully-synthetic, non-production-RunE tests throughout (`TestSecretsCreateCommand`, `TestSecretsListCommand`, `TestSecretsGetCommand`, `TestSecretsIntegration`) — also untouched, also not a template.
- `go build ./... && go vet ./...` must pass after every task.
- This plan touches only `cmd/secrets/*.go` and its test files. It does not touch `cmd/keys`, `cmd/certificates`, `cmd/vaultcli`, or `internal/services/authorization` — those are Plans 01, 03, and 05.

---

### Task 1: `create.go` and `list.go`

**Files:**
- Modify: `cmd/secrets/create.go`
- Modify: `cmd/secrets/list.go`
- Modify: `cmd/secrets/create_test.go`
- Modify: `cmd/secrets/list_test.go`

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction` and `testutils.MockRoleAssignmentService` (both from Plan 01, see Global Constraints).
- Produces: nothing new consumed by later tasks — `create.go` and `list.go` are independent of `get.go`/`delete.go`/`update.go`/`export.go`/`import.go`.

- [ ] **Step 1: Write the failing tests**

Add to `cmd/secrets/create_test.go` (existing imports already cover `bytes`, `context`, `testing`, `uuid`, `assert`, `mock`, `require`, `cobra`, `testutils`, `common`, `formatter`, `secretServices`, `model` — no new imports needed):

```go
func TestCreateSecretCommand_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)
	tc.MockSecretService.On("CreateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.CreateSecretRequest) bool {
		return r.VaultID == tc.TestVaultID
	})).Return(&model.Secret{ID: uuid.New(), Name: "test-secret", Version: 1, Enabled: true}, nil)

	ctx := ctxWithFormatter(tc.Ctx)
	var out bytes.Buffer
	createCmd.SetContext(ctx)
	createCmd.SetOut(&out)
	createCmd.SetErr(&out)

	err := createCmd.RunE(createCmd, []string{"test-secret", "secret-value"})
	require.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

func TestCreateSecretCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	ctx := ctxWithFormatter(tc.Ctx)
	var out bytes.Buffer
	createCmd.SetContext(ctx)
	createCmd.SetOut(&out)
	createCmd.SetErr(&out)

	err := createCmd.RunE(createCmd, []string{"test-secret", "secret-value"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "CreateSecret", mock.Anything, mock.Anything)
}
```

Add to `cmd/secrets/list_test.go` (existing imports already cover `bytes`, `context`, `testing`, `uuid`, `cobra`, `assert`, `mock`, `testutils`, `common`, `formatter`, `model` — no new imports needed):

```go
func TestListCmd_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)
	tc.MockSecretService.On("ListSecrets", mock.Anything, model.NewVaultScope(tc.TestVaultID, uuid.Nil), []string{}).
		Return([]model.Secret{}, nil)

	fmtr, ferr := formatter.New(formatter.FormatTable)
	assert.NoError(t, ferr)
	ctx := context.WithValue(tc.Ctx, common.OutputFormatterKey, fmtr)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

func TestListCmd_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "ListSecrets", mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/secrets/... -run 'TestCreateSecretCommand_Authorized|TestCreateSecretCommand_Forbidden|TestListCmd_Authorized|TestListCmd_Forbidden' -v`
Expected: FAIL. `TestCreateSecretCommand_Forbidden` and `TestListCmd_Forbidden` fail because `create.go`/`list.go` still call the old `resolveVaultID`, which ignores `tc.MockContainer.RoleAssignmentService` entirely, so the command succeeds instead of returning "forbidden". `TestCreateSecretCommand_Authorized` may pass already (default-allow), but the `r.VaultID == tc.TestVaultID` assertion is not yet exercised by the real authorization path — keep it as a pin.

- [ ] **Step 3: Rewrite `cmd/secrets/create.go`**

Replace the import block:

```go
import (
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	secretsServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)
```

Replace the `RunE` function body:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("requires <name> and <value> arguments")
		}
		name := args[0]
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")
		contentType, _ := cmd.Flags().GetString("content-type")

		ctx := cmd.Context()
		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsSet, model.OpCreate)
		if err != nil {
			return err
		}

		req := secretsServices.CreateSecretRequest{
			UserID:      userID,
			VaultID:     vaultID,
			Name:        name,
			Value:       value,
			Tags:        tags,
			ContentType: contentType,
		}

		secret, err := secretService.CreateSecret(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Version", "Enabled", "Created"}
		row := []string{
			secret.ID.String(),
			secret.Name,
			strconv.Itoa(secret.Version),
			strconv.FormatBool(secret.Enabled),
			secret.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
```

- [ ] **Step 4: Rewrite `cmd/secrets/list.go`**

Replace the import block:

```go
import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)
```

Replace the `RunE` function body:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		tags, _ := cmd.Flags().GetStringSlice("tags")

		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsReadMetadata, model.OpGet)
		if err != nil {
			return err
		}

		secretsList, err := secretService.ListSecrets(ctx, model.NewVaultScope(vaultID, uuid.Nil), tags)
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Version", "Enabled", "Tags", "Created"}
		rows := make([][]string, len(secretsList))
		for i, s := range secretsList {
			rows[i] = []string{
				s.ID.String(),
				s.Name,
				strconv.Itoa(s.Version),
				strconv.FormatBool(s.Enabled),
				strings.Join(s.Tags, ","),
				s.CreatedAt.Format(time.RFC3339),
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
	},
```

Note: `list.go`'s `ListSecrets` call keeps `uuid.Nil` as the scope's actor — only `get.go` and `delete.go` have the actor-ID bug fixed in Task 2; `list` never had an owner-identifying actor to begin with.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/secrets/... -run 'TestCreateSecretCommand|TestCreateSecretWithTags|TestListCmd|TestListSecrets' -v`
Expected: PASS. This includes the pre-existing `TestCreateSecretCommand`, `TestCreateSecretWithTags`, `TestListSecretsOutputFormat` (still expects `model.NewVaultScope(tc.TestVaultID, uuid.Nil)`, unchanged), and the four new tests from Step 1. `TestListSecretsCommand` (the fake-reimplementation test) is unaffected either way since it never calls the real `listCmd.RunE`.

- [ ] **Step 6: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add cmd/secrets/create.go cmd/secrets/list.go cmd/secrets/create_test.go cmd/secrets/list_test.go
git commit -m "feat(cmd/secrets): require vault role assignment before create and list"
```

---

### Task 2: `get.go` and `delete.go` (+ actor-ID fix)

**Files:**
- Modify: `cmd/secrets/get.go`
- Modify: `cmd/secrets/delete.go`
- Modify: `cmd/secrets/secrets_cmd_test.go`
- Modify: `cmd/secrets/scope_test.go`

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction`, `testutils.MockRoleAssignmentService` (Plan 01).
- Produces: nothing consumed by later tasks.

**Behavior fix in this task:** `get.go` and `delete.go` currently build `model.NewVaultScope(vaultID, uuid.Nil)` — the scope's actor (used only for audit attribution, never as an access predicate) is always the nil UUID instead of the real caller. Both commands gain a `userID` extraction (matching the existing pattern in `create.go`) and use `model.NewVaultScope(vaultID, userID)`.

- [ ] **Step 1: Write the failing tests**

Modify `cmd/secrets/secrets_cmd_test.go`. Change the `NewVaultScope` actor argument from `uuid.Nil` to `tc.TestUserID` in these five existing tests (find-and-replace `model.NewVaultScope(tc.TestVaultID, uuid.Nil)` with `model.NewVaultScope(tc.TestVaultID, tc.TestUserID)` — seven occurrences total, across the functions below):

```go
func TestGetCmd_Success_WithFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()
	now := time.Now()
	secret := &model.Secret{
		ID:        secretID,
		Name:      "my-get-secret",
		Value:     "s3cr3t",
		Version:   1,
		Enabled:   true,
		CreatedAt: now,
		Tags:      []string{"env:prod"},
	}

	tc.MockSecretService.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(secret, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd, buf := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "my-get-secret")
	tc.MockSecretService.AssertExpectations(t)
}

func TestGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(nil, fmt.Errorf("not found"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to retrieve secret")
	tc.MockSecretService.AssertExpectations(t)
}

func TestGetCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()
	now := time.Now()
	secret := &model.Secret{
		ID:        secretID,
		Name:      "fmt-missing",
		Value:     "val",
		Version:   1,
		Enabled:   true,
		CreatedAt: now,
	}

	tc.MockSecretService.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(secret, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtxNoFormatter(tc.MockContainer, tc.TestUserID)

	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockSecretService.AssertExpectations(t)
}

func TestDeleteCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

func TestDeleteCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(fmt.Errorf("delete failed"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete secret")
	tc.MockSecretService.AssertExpectations(t)
}

func TestDeleteCmd_ServiceContract_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)

	err := tc.MockSecretService.DeleteSecret(context.Background(), secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID))
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

func TestDeleteCmd_ServiceContract_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(fmt.Errorf("delete failed"))

	err := tc.MockSecretService.DeleteSecret(context.Background(), secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
	tc.MockSecretService.AssertExpectations(t)
}
```

`TestDeleteCmd_NoServiceContainer` currently builds a context with no `UserIDKey`, relying on the service-container check being the first thing `deleteCmd.RunE` does. After this task, `deleteCmd.RunE` checks `userID` first, so this test needs a `UserIDKey` added to keep testing what it says it tests:

```go
func TestDeleteCmd_NoServiceContainer(t *testing.T) {
	secretID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ServiceContainerKey.

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}
```

Add two new tests to the same file, right after `TestGetCmd_NoFormatter` and `TestDeleteCmd_ServiceContract_Error` respectively:

```go
func TestGetCmd_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	secretID := uuid.New()
	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "GetSecret", mock.Anything, mock.Anything, mock.Anything)
}

func TestDeleteCmd_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	secretID := uuid.New()

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "DeleteSecret", mock.Anything, mock.Anything, mock.Anything)
}
```

Modify `cmd/secrets/scope_test.go` — the helper `newCLIScopeFixture` must also return the test user ID, since `get`/`delete` now need it for the scope assertion:

```go
// TestSecretsGetBuildsAVaultScope pins that the CLI resolves --vault into a
// vault scope rather than calling a *InVault method.
func TestSecretsGetBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID, userID := newCLIScopeFixture(t, func() *cobra.Command {
		return &cobra.Command{Use: "get [id]", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	})
	secretID := uuid.New()

	svc.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(vaultID, userID)).
		Return(&model.Secret{ID: secretID, Name: "s", Value: "v", Version: 1}, nil).Once()

	cmd.SetArgs([]string{secretID.String()})
	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

func TestSecretsListBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID, _ := newCLIScopeFixture(t, func() *cobra.Command {
		c := &cobra.Command{Use: "list", RunE: listCmd.RunE}
		c.Flags().StringSlice("tags", []string{}, "Tags to filter secrets (comma-separated)")
		return c
	})

	svc.On("ListSecrets", mock.Anything, model.NewVaultScope(vaultID, uuid.Nil), mock.Anything).
		Return([]model.Secret{{ID: uuid.New(), Name: "a"}}, nil).Once()

	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

func TestSecretsDeleteBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID, userID := newCLIScopeFixture(t, func() *cobra.Command {
		return &cobra.Command{Use: "delete [id]", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	})
	secretID := uuid.New()

	svc.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(vaultID, userID)).
		Return(nil).Once()

	cmd.SetArgs([]string{secretID.String()})
	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

// newCLIScopeFixture returns the mock secret service, a command wired to the
// test context, the vault id resolveVaultID/vaultcli.RequireDataAction will
// produce, and the authenticated test user id. buildCmd constructs a fresh
// cobra.Command per test, registering only the flags that command reads, so
// flag registration cannot collide across the three commands exercised in
// this file (get and delete take none, list takes --tags).
//
// It reuses testutils.NewTestContext(t), which wires a MockServiceContainer
// into the context under common.ServiceContainerKey and pre-registers a
// GetVault(ctx, "default") expectation returning the default vault, plus a
// default-allow RoleAssignmentService, so both vault resolution and the
// authorization check succeed without extra setup. It also attaches an
// output formatter, since the get/list RunE paths require one to reach the
// point where the scoped service call happens.
func newCLIScopeFixture(t *testing.T, buildCmd func() *cobra.Command) (*testutils.MockSecretService, *cobra.Command, uuid.UUID, uuid.UUID) {
	t.Helper()

	tc := testutils.NewTestContext(t)
	t.Cleanup(func() { tc.MockSecretService.AssertExpectations(t) })

	fmtr, err := formatter.New(formatter.FormatTable)
	require.NoError(t, err)
	ctx := context.WithValue(tc.Ctx, common.OutputFormatterKey, fmtr)

	cmd := buildCmd()
	cmd.SetContext(ctx)

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	return tc.MockSecretService, cmd, tc.TestVaultID, tc.TestUserID
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/secrets/... -run 'TestGetCmd|TestDeleteCmd|TestSecretsGetBuildsAVaultScope|TestSecretsDeleteBuildsAVaultScope|TestSecretsListBuildsAVaultScope' -v`
Expected: FAIL. The scope-assertion tests fail because `get.go`/`delete.go` still build `model.NewVaultScope(vaultID, uuid.Nil)`, not `..., userID)`. `TestGetCmd_Forbidden`/`TestDeleteCmd_Forbidden` fail because the commands don't call `vaultcli.RequireDataAction` yet, so the deny-mock is never consulted. `scope_test.go` fails to compile (`newCLIScopeFixture` signature mismatch — 4 return values expected, 3 produced) until Step 3.

- [ ] **Step 3: Rewrite `cmd/secrets/get.go`**

Replace the import block:

```go
import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)
```

Replace the `RunE` function body:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID: %w", err)
		}

		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsGet, model.OpGet)
		if err != nil {
			return err
		}

		// The scope's actor is the real authenticated caller, not uuid.Nil, so
		// the audit row for this read is attributed to the person who made it.
		secret, err := secretService.GetSecret(ctx, secretID, model.NewVaultScope(vaultID, userID))
		if err != nil {
			return fmt.Errorf("failed to retrieve secret: %w", err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Value", "Version", "Enabled", "ContentType", "Tags", "Expires", "NotBefore", "Created"}
		row := []string{
			secret.ID.String(),
			secret.Name,
			secret.Value,
			strconv.Itoa(secret.Version),
			strconv.FormatBool(secret.Enabled),
			secret.ContentType,
			strings.Join(secret.Tags, ","),
			formatOptionalTime(secret.ExpiresAt),
			formatOptionalTime(secret.NotBefore),
			secret.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
```

`InitSecretsGet` and `formatOptionalTime` are unchanged — leave them as-is.

- [ ] **Step 4: Rewrite `cmd/secrets/delete.go`**

Replace the import block:

```go
import (
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/model"
)
```

Replace the `RunE` function body:

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID: %w", err)
		}

		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		// Get service container and secret service
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsDelete.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsDelete, model.OpDelete)
		if err != nil {
			return err
		}

		// Delete secret via service (includes access control). The scope's
		// actor is the real authenticated caller, not uuid.Nil, so the audit
		// row for this delete is attributed to the person who made it.
		err = secretService.DeleteSecret(ctx, secretID, model.NewVaultScope(vaultID, userID))
		if err != nil {
			return fmt.Errorf("failed to delete secret: %w", err)
		}

		logrus.WithFields(logrus.Fields{
			"secret_id": secretID.String(),
			"vault_id":  vaultID.String(),
		}).Info("Secret deleted successfully")
		return nil
	},
```

Note the old code wrapped the vault-resolution error as `"failed to resolve vault: %w"`; that wrapping is dropped here because `vaultcli.RequireDataAction` can also fail with a `forbidden` error, and labelling a permission denial as a "vault resolution" failure would be misleading. Every other command in this package (`create`, `list`, `get`, `update`, `export`, `import`) already returns the `vaultcli.RequireDataAction` error unwrapped — this makes `delete.go` consistent with the rest of the package. No test asserts on the old `"failed to resolve vault"` string (confirmed by repo-wide grep before writing this plan).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/secrets/... -run 'TestGetCmd|TestDeleteCmd|TestSecretsGetBuildsAVaultScope|TestSecretsDeleteBuildsAVaultScope|TestSecretsListBuildsAVaultScope' -v`
Expected: PASS.

Then run the full package to confirm nothing else regressed:

Run: `go test ./cmd/secrets/... -v`
Expected: PASS (including `TestListSecretsCommand`'s fake reimplementation and `service_test.go`'s synthetic tests, both untouched and unaffected).

- [ ] **Step 6: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add cmd/secrets/get.go cmd/secrets/delete.go cmd/secrets/secrets_cmd_test.go cmd/secrets/scope_test.go
git commit -m "fix(cmd/secrets): authorize get/delete and attribute their scope actor to the real caller"
```

---

### Task 3: `update.go`, `export.go`, `import.go` — scope-kind fix, authorization, delete `vault.go`

**Files:**
- Modify: `cmd/secrets/update.go`
- Modify: `cmd/secrets/export.go`
- Modify: `cmd/secrets/import.go`
- Modify: `cmd/secrets/update_test.go`
- Modify: `cmd/secrets/export_test.go`
- Modify: `cmd/secrets/import_cmd_test.go`
- Delete: `cmd/secrets/vault.go`

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction`, `testutils.MockRoleAssignmentService` (Plan 01).
- Produces: nothing — this is the last task in the plan.

**Behavior fix in this task:** `update.go` and `export.go` currently build `model.NewOwnerScope(vaultID, userID)` behind a comment claiming this "matches the HTTP export handler" (and, for update, "Update stays owner-scoped: a vault scope would let any co-member overwrite another member's secret"). That claim is false today: `api/secrets.go`'s `updateSecret` and `exportSecrets` handlers both call `scopeFromRequest(c, r)` (`api/context.go:64`), which returns `model.NewVaultScope(vaultID, userID)` whenever `mux.Vars(r)["vault_name"]` is set — true for every request on the `/vaults/{name}/secrets/...` route both handlers are registered on. Both commands switch to `model.NewVaultScope` to genuinely match current HTTP behavior; see the Global Constraints section for the resulting user-visible capability change. `import.go` already uses `model.NewVaultScope` — no scope change there, only the authorization call is added.

- [ ] **Step 1: Write the failing tests**

Modify `cmd/secrets/update_test.go`'s `TestUpdateCommand_CallsServiceUpdate`:

```go
func TestUpdateCommand_CallsServiceUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()
	newValue := "new-secret-value"

	// The request must carry a vault scope built from the real authenticated
	// user, matching api/secrets.go's updateSecret handler on the
	// /vaults/{name}/secrets/... route (scopeFromRequest returns a vault
	// scope there). Any vault member holding a role that grants
	// ActionSecretsSet can update the secret; the actor is still the real
	// authenticated user so the audit row is attributed correctly.
	tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.UpdateSecretRequest) bool {
		return r.SecretID == secretID &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) &&
			r.Value != nil && *r.Value == newValue
	})).Return(nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetArgs([]string{secretID.String(), newValue})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}
```

Add to the end of `cmd/secrets/update_test.go`:

```go
func TestUpdateCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetArgs([]string{secretID.String(), "value"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "UpdateSecret", mock.Anything, mock.Anything)
}
```

Modify `cmd/secrets/export_test.go`'s `TestExportCommand_CallsServiceExport`:

```go
func TestExportCommand_CallsServiceExport(t *testing.T) {
	tc := testutils.NewTestContext(t)

	// The request must carry a vault scope built from the real authenticated
	// user, matching api/secrets.go's exportSecrets handler on the
	// /vaults/{name}/secrets/... route (scopeFromRequest returns a vault
	// scope there): any vault member holding a role that grants
	// ActionSecretsGet can export the vault's secrets, not just their own. A
	// zero Scope has kind ScopeInvalid and every repository query rejects
	// it, so this assertion also catches a "Scope never set" regression.
	wantScope := model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return r.Format == "json" && r.Scope == wantScope
	})).Return([]byte(`{"secrets":[]}`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	tmpFile := t.TempDir() + "/export.json"

	// Reset package-level vars before test.
	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = false
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", tmpFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}
```

Add to the end of `cmd/secrets/export_test.go`:

```go
func TestExportCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	tmpFile := t.TempDir() + "/export.json"
	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = false
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", tmpFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "ExportSecrets", mock.Anything, mock.Anything)
}
```

Add to the end of `cmd/secrets/import_cmd_test.go`:

```go
func TestImportCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600)

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/secrets/... -run 'TestUpdateCommand|TestExportCommand|TestImportCommand_Forbidden' -v`
Expected: FAIL. `TestUpdateCommand_CallsServiceUpdate` and `TestExportCommand_CallsServiceExport` fail because `update.go`/`export.go` still build `model.NewOwnerScope`, not `model.NewVaultScope`. The three new `*_Forbidden` tests fail because none of the three commands call `vaultcli.RequireDataAction` yet, so the deny-mock is never consulted and each command succeeds instead of erroring.

- [ ] **Step 3: Rewrite `cmd/secrets/update.go`**

Replace the import block:

```go
import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)
```

Replace the `Long` field and the `RunE` function body:

```go
// updateCmd represents the update command.
var updateCmd = &cobra.Command{
	Use:   "update [id] [value]",
	Short: "Update a secret",
	Long: `Update a secret's value and tags by its ID.
Any member of the target vault holding a role that grants ActionSecretsSet
(e.g. Key Vault Secrets Officer) can update the secret, matching the HTTP
API's vault-scoped update route.`,
	Example: `  # Update a secret's value
  rocketvault secrets update <id> <new-value> \
    --username admin --password admin123 --totp-code <code>

  # Update value, tags and content type
  rocketvault secrets update <id> <new-value> --tags prod,db --content-type text/plain \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID: %w", err)
		}
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")
		contentType, _ := cmd.Flags().GetString("content-type")

		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user not authenticated")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsSet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsSet, model.OpSet)
		if err != nil {
			return err
		}

		// Vault-scoped: this matches api/secrets.go's updateSecret handler,
		// which calls scopeFromRequest and gets a vault scope back on the
		// /vaults/{name}/secrets/... route. Any vault member holding a role
		// that grants ActionSecretsSet can update another member's secret,
		// not just the secret's creator.
		req := secretServices.UpdateSecretRequest{
			SecretID: secretID,
			Scope:    model.NewVaultScope(vaultID, userID),
			Value:    &value,
		}
		if len(tags) > 0 {
			req.Tags = &tags
		}
		// Only set ContentType when the flag was explicitly passed.
		var contentTypePtr *string
		if cmd.Flags().Changed("content-type") {
			contentTypePtr = &contentType
		}
		req.ContentType = contentTypePtr

		if err := sc.GetSecretService().UpdateSecret(ctx, req); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		fmt.Printf("Secret %s updated successfully\n", secretID)
		return nil
	},
}
```

- [ ] **Step 4: Rewrite `cmd/secrets/export.go`**

Replace the import block:

```go
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)
```

Replace the `Long` field and the `RunE` function body:

```go
var secretsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets to a file",
	Long: `Export secrets to an encrypted JSON or CSV file.
Any member of the target vault holding a role that grants ActionSecretsGet
can export the vault's secrets, including those created by other members,
matching the HTTP API's vault-scoped export route.`,
	Example: `  # Export all secrets to JSON
  rocketvault secrets export --format json --file secrets.json \
    --username admin --password admin123 --totp-code <code>

  # Export secrets filtered by tags to CSV
  rocketvault secrets export --format csv --file secrets.csv --tags production \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user not authenticated")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		format := strings.ToLower(exportFormat)
		if format != "json" && format != "csv" {
			return fmt.Errorf("unsupported format: %s (supported: json, csv)", exportFormat)
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsGet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsGet, model.OpCreate)
		if err != nil {
			return err
		}

		allTags := append(exportTags, exportFilterTags...)

		// Vault-scoped: this matches api/secrets.go's exportSecrets handler,
		// which calls scopeFromRequest and gets a vault scope back on the
		// /vaults/{name}/secrets/... route. Any vault member holding a role
		// that grants ActionSecretsGet can export another member's plaintext
		// secret values into their own local file.
		data, err := sc.GetSecretService().ExportSecrets(ctx, secretServices.ExportSecretsRequest{
			Scope:       model.NewVaultScope(vaultID, userID),
			Format:      format,
			FilterTags:  allTags,
			IncludeTags: true,
		})
		if err != nil {
			return fmt.Errorf("failed to export secrets: %w", err)
		}

		dir := filepath.Dir(exportFile)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
		}
		if err := os.WriteFile(exportFile, data, 0o600); err != nil {
			return fmt.Errorf("failed to write export file: %w", err)
		}

		fmt.Printf("Secrets exported successfully\nFormat: %s\nFile: %s\n", format, exportFile)
		return nil
	},
}
```

- [ ] **Step 5: Rewrite `cmd/secrets/import.go`**

Replace the import block:

```go
import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)
```

Replace the `RunE` function body (`Scope` construction is unchanged — only the vault-resolution call changes):

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user not authenticated")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		format := strings.ToLower(importFormat)
		if format != "json" && format != "csv" {
			return fmt.Errorf("unsupported format: %s (supported: json, csv)", importFormat)
		}

		if _, err := os.Stat(importFile); os.IsNotExist(err) {
			return fmt.Errorf("import file does not exist: %s", importFile)
		}

		data, err := os.ReadFile(importFile)
		if err != nil {
			return fmt.Errorf("failed to read import file: %w", err)
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsSet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsSet, model.OpImport)
		if err != nil {
			return err
		}

		// The scope's actor becomes the owner of every imported secret, so it
		// must carry the real authenticated user; uuid.Nil would orphan every
		// row (and fail the PostgreSQL foreign key outright).
		result, err := sc.GetSecretService().ImportSecrets(ctx, secretServices.ImportSecretsRequest{
			Scope:     model.NewVaultScope(vaultID, userID),
			Data:      data,
			Format:    format,
			Overwrite: importOverwrite,
		})
		if err != nil {
			return fmt.Errorf("failed to import secrets: %w", err)
		}

		fmt.Printf("Secrets imported successfully\nImported: %d\nSkipped: %d\n",
			result.ImportedCount, result.SkippedCount)
		return nil
	},
```

- [ ] **Step 6: Delete `cmd/secrets/vault.go`**

Every call site in `cmd/secrets` has now been migrated from the package-private `resolveVaultID` to `vaultcli.ResolveVaultID`/`vaultcli.RequireDataAction`. Confirm no remaining references, then delete the file:

Run: `grep -rn 'resolveVaultID' cmd/secrets/`
Expected: no output (only the definition in `vault.go` itself would show up if any call site were missed; if it shows anything besides `vault.go`, stop and fix that call site before deleting).

```bash
rm cmd/secrets/vault.go
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./cmd/secrets/... -v`
Expected: PASS for the entire package, including all tests touched across Tasks 1–3 and the untouched fake-reimplementation tests in `list_test.go` and `service_test.go`.

- [ ] **Step 8: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean. This is also the first point at which `cmd/secrets/vault.go`'s removal is verified not to break any other package (none do — `resolveVaultID` was unexported and only ever called from within `cmd/secrets`).

- [ ] **Step 9: Commit**

```bash
git add cmd/secrets/update.go cmd/secrets/export.go cmd/secrets/import.go \
        cmd/secrets/update_test.go cmd/secrets/export_test.go cmd/secrets/import_cmd_test.go \
        cmd/secrets/vault.go
git commit -m "fix(cmd/secrets): vault-scope update/export to match HTTP, authorize update/export/import, drop legacy vault.go"
```
