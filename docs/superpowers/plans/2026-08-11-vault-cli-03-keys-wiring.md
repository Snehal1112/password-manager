# Vault CLI Extension — Plan 03: `cmd/keys` Vault Wiring + Authorization

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `--vault` resolution (via `cmd/vaultcli.ResolveVaultID`) and the new per-vault authorization check (via `cmd/vaultcli.RequireDataAction`) into all 8 `cmd/keys` commands — `create`, `get`, `list`, `update`, `delete`, `rotate`, `wrap`, `unwrap` — replacing every hardcoded `model.NewOwnerScope(uuid.Nil, claims.UserID)` (and, in `wrap`/`unwrap`, the hardcoded `uuid.MustParse(model.DefaultVaultID)`) with a resolved, authorization-checked `model.NewVaultScope(vaultID, claims.UserID)`.

**Architecture:** Each command already fetches `claims` (via `common.ClaimsKey`) and the service container (via `common.ServiceContainerKey`). This plan inserts one call — `vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.Action...)` — right after the service container is obtained and before the first service-layer call that uses a scope, in every command. The returned `vaultID` replaces the hardcoded owner scope (and, for `wrap`/`unwrap`, the hardcoded default-vault ID) everywhere it appears. No new CLI flags: `--vault` is already a persistent root flag (`cmd/root.go:93`) that `vaultcli.ResolveVaultID` (via `common.ResolveVaultName`) already reads.

**Tech Stack:** Go, `github.com/google/uuid`, `github.com/spf13/cobra`, `github.com/stretchr/testify/mock`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-vault-cli-extension-design.md` — read in full before starting.
- Depends on Plan 01 (`docs/superpowers/plans/2026-08-11-vault-cli-01-shared-primitives.md`), already merged. This plan consumes, unmodified:
  - `cmd/vaultcli.ResolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error)`
  - `cmd/vaultcli.RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction) (vaultID uuid.UUID, err error)`
  - `cmd/testutils.MockRoleAssignmentService` (testify-mock), `cmd/testutils.MockServiceContainer.RoleAssignmentService` field (defaults to an instance that allows every `HasDataAction` call via `testutils.NewTestContext`), and `cmd/testutils.TestContext.MockRoleAssignmentService`.
- **Deliberate behavior change #1 — uniform `VaultScope`, no narrower scope anywhere in `keys`:** unlike `cmd/secrets` (whose `update`/`export` stay owner-narrowed by design, for value-exposing operations), every `cmd/keys` command in this plan — including `update`, `delete`, `rotate`, `wrap`, `unwrap` — moves to `model.NewVaultScope(vaultID, claims.UserID)`. This matches `api/keys.go`'s HTTP handlers, which all use `scopeFromRequest` uniformly; per commit `da6fb9b` (2026-08-02) even key delete and every crypto operation are vault-wide-scoped over HTTP, with no owner restriction. `keys` has no HTTP-side narrowing to preserve, so none is introduced here.
- **Deliberate behavior change #2 — `keys list` loses its admin global-visibility bypass:** `cmd/keys/list.go` currently special-cases `claims.Role == model.RoleAdmin` to `model.NewAdminScope(claims.UserID)`, letting any global-`admin`-role CLI user see every key in every vault, system-wide. The HTTP `GET /keys` endpoint (via `scopeFromRequest`) has no such role-based special case. This plan deletes the admin branch entirely; `keys list` becomes uniformly vault-scoped, matching HTTP and matching every other command touched by this plan. This is a breaking CLI behavior change: an admin-role user who previously saw all keys via `rocketvault keys list` will now see only keys in the resolved `--vault`, and only if they hold a role assignment there.
- `go build ./...` and `go vet ./...` must pass after every task.
- Every touched command gets a `*_Denied` test proving: role-assignment mock returns `(false, nil)` → the command returns an error containing `"forbidden"` (from `authorization.RequireDataAction`, via `vaultcli.RequireDataAction`) **and** the underlying `KeyService`/`CryptoService` method is never called (`mock.AssertNotCalled`) — not just "returned an error", per the design's testing section.
- This plan does not touch `cmd/secrets/*`, `cmd/certificates/*`, `internal/services/authorization/*`, or `cmd/vaultcli/*` — those are covered by Plans 01, 02, 04, and 05.

---

### Task 1: `create`, `get`, `list`

**Files:**
- Modify: `cmd/keys/create.go`
- Modify: `cmd/keys/get.go`
- Modify: `cmd/keys/list.go`
- Modify: `cmd/keys/keys_cmd_test.go` (add a shared test helper; update `TestCreateCmd_*`, `TestGetCmd_*`, `TestListCmd_*` groups)

**Interfaces:**
- Consumes: `vaultcli.ResolveVaultID`, `vaultcli.RequireDataAction` (Plan 01, `cmd/vaultcli/vault.go`); `testutils.MockRoleAssignmentService`, `testutils.MockVaultService` (Plan 01, `cmd/testutils/test_utils.go`); `keyServices.CreateKeyRequest.VaultID uuid.UUID` (existing, `internal/services/keys/key_service.go:49`); `keyServices.KeyService.GetKey`/`ListKeys` (existing, same file); `model.NewVaultScope(vaultID, actorID uuid.UUID) model.Scope` (existing, `model/scope.go:39`).
- Produces: `newAllowedContainer(keySvc keyServices.KeyService, cryptoSvc keyServices.CryptoService) (*keysTestContainer, uuid.UUID)` in `cmd/keys/keys_cmd_test.go` — a shared test helper wiring a default-allow `MockVaultService` + `MockRoleAssignmentService` into a `keysTestContainer`, returning the resolved default vault ID. Reused by Tasks 2 and 3.

- [ ] **Step 1: Write the failing tests**

In `cmd/keys/keys_cmd_test.go`, add this helper immediately after the `keysTestContainer` type definition (after line 140, before the `// ---- context helpers ----` comment at line 142):

```go
// newAllowedContainer returns a keysTestContainer pre-wired with a
// default-allow vault resolution (the "default" vault) and a default-allow
// role-assignment mock, mirroring testutils.NewTestContext's wiring. Tests
// in this file build their service container by hand instead of using
// testutils.NewTestContext, so this helper gives them the same defaults.
// Returns the container and the id of the resolved default vault, for
// scope/VaultID assertions.
func newAllowedContainer(keySvc keyServices.KeyService, cryptoSvc keyServices.CryptoService) (*keysTestContainer, uuid.UUID) {
	vaultID := uuid.MustParse(model.DefaultVaultID)

	mockVaultSvc := &testutils.MockVaultService{}
	mockVaultSvc.On("GetVault", mock.Anything, model.DefaultVaultName).
		Return(&model.Vault{ID: vaultID, Name: model.DefaultVaultName, Enabled: true}, nil).Maybe()

	mockRoleSvc := &testutils.MockRoleAssignmentService{}
	mockRoleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	base := &testutils.MockServiceContainer{}
	base.VaultService = mockVaultSvc
	base.RoleAssignmentService = mockRoleSvc

	return &keysTestContainer{
		MockServiceContainer: base,
		keySvc:                keySvc,
		cryptoSvc:             cryptoSvc,
	}, vaultID
}

// newDeniedContainer is identical to newAllowedContainer except the
// role-assignment mock denies every HasDataAction call, simulating a caller
// with no role assignment in the resolved vault.
func newDeniedContainer(keySvc keyServices.KeyService, cryptoSvc keyServices.CryptoService) *keysTestContainer {
	vaultID := uuid.MustParse(model.DefaultVaultID)

	mockVaultSvc := &testutils.MockVaultService{}
	mockVaultSvc.On("GetVault", mock.Anything, model.DefaultVaultName).
		Return(&model.Vault{ID: vaultID, Name: model.DefaultVaultName, Enabled: true}, nil).Maybe()

	mockRoleSvc := &testutils.MockRoleAssignmentService{}
	mockRoleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()

	base := &testutils.MockServiceContainer{}
	base.VaultService = mockVaultSvc
	base.RoleAssignmentService = mockRoleSvc

	return &keysTestContainer{
		MockServiceContainer: base,
		keySvc:                keySvc,
		cryptoSvc:             cryptoSvc,
	}
}
```

Replace `TestCreateCmd_RSASuccess` (lines 285-316) with:

```go
func TestCreateCmd_RSASuccess(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "mykey", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "mykey" && r.Type == "RSA" && r.Bits == 2048 && r.VaultID == vaultID
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{
		"key-name": "mykey", "key-type": "RSA", "key-bits": 2048, "key-curve": "P-256", "key-tags": "",
	})
	defer cleanup()

	cmd, buf := newTestCmd(createCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestCreateCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{
		"key-name": "mykey", "key-type": "RSA", "key-bits": 2048, "key-curve": "P-256", "key-tags": "",
	})
	defer cleanup()

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "CreateRSAKey", mock.Anything, mock.Anything)
	keySvc.AssertNotCalled(t, "CreateECDSAKey", mock.Anything, mock.Anything)
}
```

Replace `TestCreateCmd_RSAWithTags` (lines 318-348) with:

```go
func TestCreateCmd_RSAWithTags(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "tagged-key", Type: "RSA", Tags: []string{"prod", "infra"}, CreatedAt: time.Now(),
	}
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "tagged-key" && len(r.Tags) == 2 && r.VaultID == vaultID
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{
		"key-name": "tagged-key", "key-type": "rsa", "key-bits": 2048, "key-curve": "P-256", "key-tags": "prod,infra",
	})
	defer cleanup()

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}
```

Replace `TestCreateCmd_ECDSASuccess` (lines 350-380) with:

```go
func TestCreateCmd_ECDSASuccess(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "eckey", Type: "ECDSA", CreatedAt: time.Now(),
	}
	keySvc.On("CreateECDSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "eckey" && r.Type == "ECDSA" && r.Curve == "P-256" && r.VaultID == vaultID
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleSecretsManager}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{
		"key-name": "eckey", "key-type": "ECDSA", "key-bits": 2048, "key-curve": "P-256", "key-tags": "",
	})
	defer cleanup()

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}
```

Replace `TestCreateCmd_ServiceError` (lines 382-406) with:

```go
func TestCreateCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, _ := newAllowedContainer(keySvc, nil)
	keySvc.On("CreateRSAKey", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("db error"))

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{
		"key-name": "failkey", "key-type": "RSA", "key-bits": 2048, "key-curve": "", "key-tags": "",
	})
	defer cleanup()

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create key")
}
```

Replace `TestCreateCmd_NoFormatter` (lines 408-433) with:

```go
func TestCreateCmd_NoFormatter(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, _ := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "k", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("CreateRSAKey", mock.Anything, mock.Anything).Return(result, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No OutputFormatterKey.

	cleanup := viperSet(map[string]interface{}{
		"key-name": "k", "key-type": "RSA", "key-bits": 2048, "key-curve": "", "key-tags": "",
	})
	defer cleanup()

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}
```

Replace `TestGetCmd_Success` (lines 626-650) with:

```go
func TestGetCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	key := &model.Key{ID: keyID, UserID: userID, Name: "my-key", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("GetKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(key, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, buf := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestGetCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "GetKey", mock.Anything, mock.Anything, mock.Anything)
}
```

Replace `TestGetCmd_ServiceError` (lines 652-673) with:

```go
func TestGetCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("GetKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, fmt.Errorf("not found"))

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get key")
}
```

Replace `TestGetCmd_NoFormatter` (lines 675-697) with:

```go
func TestGetCmd_NoFormatter(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	key := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("GetKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(key, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}
```

Replace `TestListCmd_NonAdminSuccess` (lines 457-486) with:

```go
func TestListCmd_NonAdminSuccess(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keys := []model.Key{
		{ID: uuid.New(), UserID: userID, Name: "k1", Type: "RSA"},
		{ID: uuid.New(), UserID: userID, Name: "k2", Type: "ECDSA"},
	}
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "", Tags: nil}).
		Return(keys, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleSecretsManager}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{"type": "", "tags": ""})
	defer cleanup()

	cmd, buf := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestListCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleSecretsManager}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{"type": "", "tags": ""})
	defer cleanup()

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "ListKeys", mock.Anything, mock.Anything, mock.Anything)
}
```

Replace `TestListCmd_NonAdminWithTags` (lines 488-512) with:

```go
func TestListCmd_NonAdminWithTags(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "RSA", Tags: []string{"prod", "secure"}}).
		Return([]model.Key{}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleUser}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{"type": "RSA", "tags": "prod,secure"})
	defer cleanup()

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}
```

Replace `TestListCmd_AdminPath` (lines 514-541) — this behavior no longer exists — with a test proving the opposite: an `admin`-role caller with no vault role assignment is now denied, exactly like any other role:

```go
func TestListCmd_AdminRoleAloneDoesNotBypassVaultAuthorization(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	// A global admin role with NO vault role assignment: the legacy
	// list.go admin bypass (model.NewAdminScope) has been removed, so this
	// must be denied exactly like TestListCmd_Denied, matching HTTP's
	// GET /keys (scopeFromRequest has no role-based special case).
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{"type": "", "tags": ""})
	defer cleanup()

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "ListKeys", mock.Anything, mock.Anything, mock.Anything)
	// In particular, ListKeys must never be called with model.NewAdminScope:
	// that call pattern must not exist anywhere in list.go anymore.
	keySvc.AssertNotCalled(t, "ListKeys", mock.Anything, model.NewAdminScope(userID), mock.Anything)
}
```

Replace `TestListCmd_ServiceError` (lines 543-566) with:

```go
func TestListCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "", Tags: nil}).
		Return(nil, fmt.Errorf("db error"))

	claims := &model.Claims{UserID: userID, Role: model.RoleSecretsManager}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cleanup := viperSet(map[string]interface{}{"type": "", "tags": ""})
	defer cleanup()

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list keys")
}
```

Replace `TestListCmd_NoFormatter` (lines 568-591) with:

```go
func TestListCmd_NoFormatter(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "", Tags: nil}).
		Return([]model.Key{}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleUser}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No OutputFormatterKey.

	cleanup := viperSet(map[string]interface{}{"type": "", "tags": ""})
	defer cleanup()

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/keys/... -run 'TestCreateCmd|TestGetCmd|TestListCmd' -v`

Expected: FAIL. `TestCreateCmd_RSASuccess` et al. fail because `create.go` never sets `req.VaultID`, so the `mock.MatchedBy` predicate (`r.VaultID == vaultID`) never matches and testify reports an unexpected call. `TestGetCmd_Success`/`ServiceError`/`NoFormatter` fail because `get.go` still calls `GetKey` with `model.NewOwnerScope(uuid.Nil, userID)`, not the mocked `model.NewVaultScope(vaultID, userID)` expectation. `TestListCmd_NonAdminSuccess` etc. fail for the same reason. `TestCreateCmd_Denied`, `TestGetCmd_Denied`, `TestListCmd_Denied`, `TestListCmd_AdminRoleAloneDoesNotBypassVaultAuthorization` fail because there is no authorization check yet — the commands proceed straight to the (unmocked-for-denial) service call, which panics via testify's mock "unexpected call" behavior instead of returning a `"forbidden"` error.

- [ ] **Step 3: Implement `create.go`**

Add the import and insert the authorization check. In `cmd/keys/create.go`, change the import block:

```go
import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)
```

Replace the request-building block:

```go
		// Create key request
		req := keyServices.CreateKeyRequest{
			Name:   name,
			Type:   keyType,
			Bits:   bits,
			Curve:  curve,
			Tags:   tags,
			UserID: claims.UserID,
		}

		var result *keyServices.CreateKeyResult
		var err error

		if keyType == "RSA" {
			result, err = keyService.CreateRSAKey(ctx, req)
		} else {
			result, err = keyService.CreateECDSAKey(ctx, req)
		}
```

with:

```go
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		// Create key request
		req := keyServices.CreateKeyRequest{
			Name:    name,
			Type:    keyType,
			Bits:    bits,
			Curve:   curve,
			Tags:    tags,
			UserID:  claims.UserID,
			VaultID: vaultID,
		}

		var result *keyServices.CreateKeyResult

		if keyType == "RSA" {
			result, err = keyService.CreateRSAKey(ctx, req)
		} else {
			result, err = keyService.CreateECDSAKey(ctx, req)
		}
```

This leaves the pre-existing `common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleSecretsManager)` global-role check untouched, above this block — both checks apply; the legacy check gates who can create keys at all, the new one gates whether they hold a role in the resolved vault.

- [ ] **Step 4: Implement `get.go`**

Add the import:

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
	"rocketvault/internal/logging"
	"rocketvault/model"
)
```

Replace:

```go
		key, err := keyService.GetKey(ctx, keyID, model.NewOwnerScope(uuid.Nil, claims.UserID))
```

with:

```go
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysRead)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		key, err := keyService.GetKey(ctx, keyID, model.NewVaultScope(vaultID, claims.UserID))
```

- [ ] **Step 5: Implement `list.go`**

Change the import block, removing `"github.com/google/uuid"` (no longer used once `uuid.Nil` is gone) and adding `vaultcli`:

```go
import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)
```

Replace:

```go
		scope := model.NewOwnerScope(uuid.Nil, claims.UserID)
		if claims.Role == model.RoleAdmin {
			scope = model.NewAdminScope(claims.UserID)
		}

		keys, err := keyService.ListKeys(ctx, scope, repositories.KeyFilter{Type: keyType, Tags: tags})
```

with:

```go
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysRead)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_keys", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		keys, err := keyService.ListKeys(ctx, model.NewVaultScope(vaultID, claims.UserID), repositories.KeyFilter{Type: keyType, Tags: tags})
```

Note: this deletes the `admin`-role bypass entirely, per this plan's Global Constraints — `keys list` is now uniformly vault-scoped for every caller.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./cmd/keys/... -run 'TestCreateCmd|TestGetCmd|TestListCmd' -v`
Expected: PASS.

- [ ] **Step 7: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add cmd/keys/create.go cmd/keys/get.go cmd/keys/list.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cmd/keys): wire --vault + authorization into create, get, list"
```

---

### Task 2: `update`, `delete`, `rotate`

**Files:**
- Modify: `cmd/keys/update.go`
- Modify: `cmd/keys/delete.go`
- Modify: `cmd/keys/rotate.go`
- Modify: `cmd/keys/update_test.go`
- Modify: `cmd/keys/keys_cmd_test.go` (update `TestDeleteCmd_*`, `TestRotateCmd_*` groups)

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction` (Plan 01); `newAllowedContainer`, `newDeniedContainer` (Task 1, `cmd/keys/keys_cmd_test.go`); `keyServices.UpdateKeyRequest.Scope model.Scope` (existing, `internal/services/keys/key_service.go:76`); `model.NewVaultScope` (existing).
- Produces: nothing new consumed by later tasks — `wrap`/`unwrap` (Task 3) touch different files.

- [ ] **Step 1: Write the failing tests**

In `cmd/keys/update_test.go`, replace `TestUpdateKeyCommand_CallsServiceUpdate` (lines 46-72) with:

```go
func TestUpdateKeyCommand_CallsServiceUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
		return r.KeyID == keyID &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) &&
			r.Name != nil && *r.Name == "new-name"
	})).Return(nil)
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--name=new-name"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	mockKeySvc.AssertExpectations(t)
}

func TestUpdateKeyCommand_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--name=new-name"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	mockKeySvc.AssertNotCalled(t, "UpdateKey", mock.Anything, mock.Anything)
}
```

Replace `TestUpdateKeyCommand_SetsRevoked` (lines 74-98) with:

```go
func TestUpdateKeyCommand_SetsRevoked(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
		return r.Revoked != nil && *r.Revoked == true &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	})).Return(nil)
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--revoked=true"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	mockKeySvc.AssertExpectations(t)
}
```

`TestUpdateKeyCommand_NoFieldsProvided` (lines 100-118) is unaffected — it returns its error from the `hasUpdate` check, and `tc` (via `testutils.NewTestContext`) already wires a default-allow `MockVaultService`/`MockRoleAssignmentService`, so no source-file ordering choice can break it; leave it unchanged.

In `cmd/keys/keys_cmd_test.go`, replace `TestDeleteCmd_Success` (lines 732-753) with:

```go
func TestDeleteCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("DeleteKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(deleteCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestDeleteCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(deleteCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "DeleteKey", mock.Anything, mock.Anything, mock.Anything)
}
```

Replace `TestDeleteCmd_ServiceError` (lines 755-775) with:

```go
func TestDeleteCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("DeleteKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, fmt.Errorf("delete failed"))

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(deleteCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete key")
}
```

Replace `TestRotateCmd_Success` (lines 810-834) with:

```go
func TestRotateCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "rotated", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("RotateKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(result, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestRotateCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "RotateKey", mock.Anything, mock.Anything, mock.Anything)
}
```

Replace `TestRotateCmd_ServiceError` (lines 836-856) with:

```go
func TestRotateCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("RotateKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, fmt.Errorf("rotation failed"))

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to rotate key")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/keys/... -run 'TestUpdateKeyCommand|TestDeleteCmd|TestRotateCmd' -v`
Expected: FAIL — `update.go`/`delete.go`/`rotate.go` still build `model.NewOwnerScope(uuid.Nil, ...)`, which does not match the `model.NewVaultScope(...)` expectations now set on the mocks; the `*_Denied` tests fail because there is no authorization check yet.

- [ ] **Step 3: Implement `update.go`**

Add the import:

```go
import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)
```

Replace:

```go
		req := keyServices.UpdateKeyRequest{
			KeyID: keyID,
			Scope: model.NewOwnerScope(uuid.Nil, claims.UserID),
		}
```

with:

```go
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionKeysUpdate)
		if err != nil {
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		req := keyServices.UpdateKeyRequest{
			KeyID: keyID,
			Scope: model.NewVaultScope(vaultID, claims.UserID),
		}
```

- [ ] **Step 4: Implement `delete.go`**

Add the import:

```go
import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/model"
)
```

Replace:

```go
		// Service layer handles ownership validation and deletion.
		_, err = keyService.DeleteKey(ctx, keyID, model.NewOwnerScope(uuid.Nil, claims.UserID))
```

with:

```go
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysDelete)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		// Service layer handles ownership validation and deletion.
		_, err = keyService.DeleteKey(ctx, keyID, model.NewVaultScope(vaultID, claims.UserID))
```

- [ ] **Step 5: Implement `rotate.go`**

Add the import:

```go
import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/model"
)
```

Replace:

```go
			// Rotate key using service. The keys CLI has no --vault flag yet, so
			// the scope carries no vault id, matching the get/delete commands.
			newKey, err := keyService.RotateKey(ctx, keyID, model.NewOwnerScope(uuid.Nil, claims.UserID))
```

with:

```go
			vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysRotate)
			if err != nil {
				log.LogAuditError(claims.UserID.String(), "rotate_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
				return fmt.Errorf("vault authorization failed: %w", err)
			}

			// Rotate key using service, scoped to the resolved --vault.
			newKey, err := keyService.RotateKey(ctx, keyID, model.NewVaultScope(vaultID, claims.UserID))
```

(Note: `rotateCmd`'s `RunE` body is indented one level further than `updateCmd`'s/`deleteCmd`'s in the current file — keep whatever indentation `gofmt` produces; this is shown at the source's existing indent level.)

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./cmd/keys/... -run 'TestUpdateKeyCommand|TestDeleteCmd|TestRotateCmd' -v`
Expected: PASS.

- [ ] **Step 7: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add cmd/keys/update.go cmd/keys/delete.go cmd/keys/rotate.go cmd/keys/update_test.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cmd/keys): wire --vault + authorization into update, delete, rotate"
```

---

### Task 3: `wrap`, `unwrap`

**Files:**
- Modify: `cmd/keys/wrap.go`
- Modify: `cmd/keys/unwrap.go`
- Modify: `cmd/keys/keys_cmd_test.go` (update `TestWrapCmd_*`, `TestUnwrapCmd_*` groups)

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction` (Plan 01); `newAllowedContainer`, `newDeniedContainer` (Task 1); `keyServices.WrapKeyRequest{KeyID, UserID, VaultID, Scope, PlaintextKey, Algorithm}` / `keyServices.UnwrapKeyRequest{KeyID, UserID, VaultID, Scope, WrappedKey, Algorithm}` (existing, `internal/services/keys/crypto_service.go:94-117`).
- Produces: nothing consumed by later plans.

- [ ] **Step 1: Write the failing tests**

In `cmd/keys/keys_cmd_test.go`, replace `TestWrapCmd_Success` (lines 932-963) with:

```go
func TestWrapCmd_Success(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	plaintext := []byte("my-secret-key-material")
	wrapped := []byte("wrapped-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.KeyID == keyID && r.UserID == userID &&
			r.VaultID == vaultID && r.Scope == model.NewVaultScope(vaultID, userID)
	})).Return(&keyServices.WrapKeyResult{WrappedKey: wrapped}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"wrap-key-id":       keyID.String(),
		"wrap-key-material": base64.StdEncoding.EncodeToString(plaintext),
	})
	defer cleanup()

	// wrapCmd uses fmt.Println (writes to os.Stdout), not cmd.OutOrStdout().
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestWrapCmd_Denied(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(nil, cryptoSvc)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"wrap-key-id":       keyID.String(),
		"wrap-key-material": base64.StdEncoding.EncodeToString([]byte("plaintext")),
	})
	defer cleanup()

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "WrapKey", mock.Anything, mock.Anything)
}
```

Replace `TestWrapCmd_ServiceError` (lines 965-990) with:

```go
func TestWrapCmd_ServiceError(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("WrapKey", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("wrap error"))

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"wrap-key-id":       keyID.String(),
		"wrap-key-material": base64.StdEncoding.EncodeToString([]byte("plaintext")),
	})
	defer cleanup()

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "wrap failed")
}
```

Replace `TestWrapCmd_SetsDefaultVaultID` (lines 1125-1155) — renamed to reflect that the vault id now comes from `vaultcli` resolution, not a hardcoded constant, though it still resolves to the same well-known default vault id when no `--vault` flag is given:

```go
func TestWrapCmd_SetsResolvedVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	plaintext := []byte("my-secret-key-material")
	wrapped := []byte("wrapped-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.VaultID == vaultID && r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.WrapKeyResult{WrappedKey: wrapped}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"wrap-key-id":       keyID.String(),
		"wrap-key-material": base64.StdEncoding.EncodeToString(plaintext),
	})
	defer cleanup()

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}
```

Replace `TestUnwrapCmd_Success` (lines 1065-1096) with:

```go
func TestUnwrapCmd_Success(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	wrappedBytes := []byte("wrapped-material")
	plaintext := []byte("recovered-key")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.KeyID == keyID && r.UserID == userID &&
			r.VaultID == vaultID && r.Scope == model.NewVaultScope(vaultID, userID)
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: plaintext}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"unwrap-key-id":      keyID.String(),
		"unwrap-wrapped-key": base64.StdEncoding.EncodeToString(wrappedBytes),
	})
	defer cleanup()

	// unwrapCmd uses fmt.Println (writes to os.Stdout), not cmd.OutOrStdout().
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestUnwrapCmd_Denied(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(nil, cryptoSvc)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"unwrap-key-id":      keyID.String(),
		"unwrap-wrapped-key": base64.StdEncoding.EncodeToString([]byte("wrapped")),
	})
	defer cleanup()

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "UnwrapKey", mock.Anything, mock.Anything)
}
```

Replace `TestUnwrapCmd_ServiceError` (lines 1098-1123) with:

```go
func TestUnwrapCmd_ServiceError(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("unwrap error"))

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"unwrap-key-id":      keyID.String(),
		"unwrap-wrapped-key": base64.StdEncoding.EncodeToString([]byte("wrapped")),
	})
	defer cleanup()

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unwrap failed")
}
```

Replace `TestUnwrapCmd_SetsDefaultVaultID` (lines 1157-1187) with:

```go
func TestUnwrapCmd_SetsResolvedVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	wrapped := []byte("wrapped-bytes")
	plaintext := []byte("recovered-key-material")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.VaultID == vaultID && r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: plaintext}, nil)

	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"unwrap-key-id":      keyID.String(),
		"unwrap-wrapped-key": base64.StdEncoding.EncodeToString(wrapped),
	})
	defer cleanup()

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/keys/... -run 'TestWrapCmd|TestUnwrapCmd' -v`
Expected: FAIL — `wrap.go`/`unwrap.go` still hardcode `VaultID: uuid.MustParse(model.DefaultVaultID)` and `Scope: model.NewOwnerScope(uuid.Nil, claims.UserID)`; the `mock.MatchedBy` predicates checking `r.Scope == model.NewVaultScope(vaultID, userID)` never match. `TestWrapCmd_Denied`/`TestUnwrapCmd_Denied` fail because there is no authorization check yet.

- [ ] **Step 3: Implement `wrap.go`**

Add the import:

```go
import (
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)
```

Replace:

```go
		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.WrapKey(ctx, keyServices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       claims.UserID,
			VaultID:      uuid.MustParse(model.DefaultVaultID),
			Scope:        model.NewOwnerScope(uuid.Nil, claims.UserID),
			PlaintextKey: plaintext,
			Algorithm:    "RSA-OAEP",
		})
```

with:

```go
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysWrap)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "wrap_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.WrapKey(ctx, keyServices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       claims.UserID,
			VaultID:      vaultID,
			Scope:        model.NewVaultScope(vaultID, claims.UserID),
			PlaintextKey: plaintext,
			Algorithm:    "RSA-OAEP",
		})
```

- [ ] **Step 4: Implement `unwrap.go`**

Add the import:

```go
import (
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)
```

Replace:

```go
		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.UnwrapKey(ctx, keyServices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     claims.UserID,
			VaultID:    uuid.MustParse(model.DefaultVaultID),
			Scope:      model.NewOwnerScope(uuid.Nil, claims.UserID),
			WrappedKey: wrappedKey,
			Algorithm:  "RSA-OAEP",
		})
```

with:

```go
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysUnwrap)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "unwrap_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.UnwrapKey(ctx, keyServices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     claims.UserID,
			VaultID:    vaultID,
			Scope:      model.NewVaultScope(vaultID, claims.UserID),
			WrappedKey: wrappedKey,
			Algorithm:  "RSA-OAEP",
		})
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/keys/... -run 'TestWrapCmd|TestUnwrapCmd' -v`
Expected: PASS.

- [ ] **Step 6: Run the full `cmd/keys` suite**

Run: `go test ./cmd/keys/... -v`
Expected: PASS — every test in the package, including the untouched `service_test.go` tests (which build their own standalone commands and don't exercise `create.go`/`get.go`/etc.'s real `RunE`, so they're unaffected by this plan).

- [ ] **Step 7: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add cmd/keys/wrap.go cmd/keys/unwrap.go cmd/keys/keys_cmd_test.go
git commit -m "feat(cmd/keys): wire --vault + authorization into wrap, unwrap"
```
