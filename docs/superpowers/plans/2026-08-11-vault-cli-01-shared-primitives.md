# Vault CLI Extension — Plan 01: Shared Authorization + Vault-Resolution Primitives

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `RequireDataAction` (the CLI-callable authorization decision, in `internal/services/authorization`) and the `cmd/vaultcli` package (`ResolveVaultID` + a thin adapter combining both), plus the test infrastructure (`MockRoleAssignmentService`, a default "allow" wiring in `NewTestContext`) every later plan in this series depends on.

**Architecture:** `internal/services/authorization/data_action_authz.go` gets one new function, `RequireDataAction`, a pure pass-through to the existing `RoleAssignmentService.HasDataAction` — no admin short-circuit. `cmd/vaultcli` (new package) provides `ResolveVaultID` (ported from `cmd/secrets/vault.go`) and `RequireDataAction` (adapter: resolve vault, then call the authorization package's function). `cmd/testutils` gets a `MockRoleAssignmentService` (testify-mock, mirroring the existing `MockVaultService` pattern exactly) wired to default-allow so every pre-existing CLI test keeps passing once later plans add the new check to commands.

**Tech Stack:** Go, `github.com/google/uuid`, `github.com/stretchr/testify/mock`, standard library `testing`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-vault-cli-extension-design.md` — read in full before starting.
- No admin short-circuit in `RequireDataAction` (either the service-package function or the `vaultcli` adapter) — data-plane access has none today, even over HTTP (`PolicyMiddleware`'s vault-data-plane branch calls `HasDataAction` with no role special-case). Do not copy the `CanManageVault`/`CanPurgeVault` admin-shortcut idiom from `docs/superpowers/plans/2026-08-11-02-shared-vault-authz-functions.md` — that's for vault-*management*, a different decision.
- `go build ./...` and `go vet ./...` must pass after every task.
- This plan does not touch any `cmd/secrets`, `cmd/keys`, or `cmd/certificates` command file — that's Plans 02, 03, 05.

---

### Task 1: `RequireDataAction` in `internal/services/authorization`

**Files:**
- Create: `internal/services/authorization/data_action_authz.go`
- Create: `internal/services/authorization/data_action_authz_test.go`

**Interfaces:**
- Consumes: `RoleAssignmentService.HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error)` (existing, `internal/services/authorization/role_assignment_service.go:61`).
- Produces: `func RequireDataAction(ctx context.Context, roles RoleAssignmentService, principalID, vaultID uuid.UUID, action model.DataAction) error` — package `authorization`. Used by Task 2's `cmd/vaultcli.RequireDataAction` adapter.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/authorization/data_action_authz_test.go`:

```go
package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// fakeRoleAssignmentService is a minimal test double for RoleAssignmentService,
// returning a fixed decision/error for HasDataAction. The remaining interface
// methods are no-ops; no test in this file exercises them.
type fakeRoleAssignmentService struct {
	hasAction bool
	err       error
}

func (f *fakeRoleAssignmentService) AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error) {
	return nil, nil
}

func (f *fakeRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error {
	return nil
}

func (f *fakeRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, nil
}

func (f *fakeRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	return f.hasAction, f.err
}

func TestRequireDataAction_Grants(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: true}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRequireDataAction_Denies(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil {
		t.Fatal("expected a forbidden error, got nil")
	}
}

func TestRequireDataAction_PropagatesLookupError(t *testing.T) {
	wantErr := errors.New("db exploded")
	roles := &fakeRoleAssignmentService{err: wantErr}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v, got %v", wantErr, err)
	}
}

func TestRequireDataAction_DenyNotConflatedWithLookupError(t *testing.T) {
	// A plain deny (false, nil) must not satisfy errors.Is against some
	// sentinel lookup error — they're different failure classes with
	// different messages, per the design's error-handling section.
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionKeysWrap)
	if errors.Is(err, errors.New("db exploded")) {
		t.Fatal("a plain deny must not resemble a lookup error")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/authorization/... -run TestRequireDataAction -v`
Expected: FAIL — `undefined: RequireDataAction` (compile error).

- [ ] **Step 3: Write the implementation**

Create `internal/services/authorization/data_action_authz.go`:

```go
package authorization

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/model"
)

// RequireDataAction returns nil if principalID holds a role assignment in
// vaultID granting action, and an error otherwise. It is the CLI-callable
// equivalent of PolicyMiddleware's HasDataAction check and must stay
// behaviorally identical to it: no admin short-circuit. Data-plane access has
// none today, even over HTTP (unlike CanManageVault/CanPurgeVault, which do
// short-circuit for the global admin role) — copying that idiom here would
// grant the CLI a bypass the HTTP API doesn't have.
func RequireDataAction(ctx context.Context, roles RoleAssignmentService, principalID, vaultID uuid.UUID, action model.DataAction) error {
	ok, err := roles.HasDataAction(ctx, principalID, vaultID, action)
	if err != nil {
		return fmt.Errorf("checking vault authorization: %w", err)
	}
	if !ok {
		return fmt.Errorf("forbidden: no role grants %s in this vault", action)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/services/authorization/... -run TestRequireDataAction -v`
Expected: PASS (all 4 subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/data_action_authz.go internal/services/authorization/data_action_authz_test.go
git commit -m "feat(authorization): add RequireDataAction, the CLI-callable HasDataAction gate"
```

---

### Task 2: `cmd/vaultcli` package + test infrastructure

**Files:**
- Create: `cmd/vaultcli/vault.go`
- Create: `cmd/vaultcli/vault_test.go`
- Modify: `cmd/testutils/test_utils.go` — add `MockRoleAssignmentService`, wire a default-allow instance into `NewTestContext`, add `RoleAssignmentService` field to `MockServiceContainer`, add `MockRoleAssignmentService` field to `TestContext`.

**Interfaces:**
- Consumes: `authorization.RequireDataAction` (Task 1); `common.ResolveVaultName(cmd *cobra.Command) string` (existing, `common/vault_selector.go:15`); `container.ServiceContainerInterface.GetVaultService()` / `.GetRoleAssignmentService()` (existing).
- Produces: `func vaultcli.ResolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error)`, `func vaultcli.RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction) (vaultID uuid.UUID, err error)` — both consumed by every command touched in Plans 02, 03, 05. Also produces `testutils.MockRoleAssignmentService` (testify-mock struct), consumed by every test file touched in Plans 02, 03, 05.

- [ ] **Step 1: Write the failing tests**

Create `cmd/vaultcli/vault_test.go`:

```go
package vaultcli

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/model"
)

func newTestCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("vault", "", "")
	return cmd
}

func TestResolveVaultID_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	id, err := ResolveVaultID(context.Background(), cmd, tc.MockContainer)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if id != tc.TestVaultID {
		t.Fatalf("expected default vault id %s, got %s", tc.TestVaultID, id)
	}
}

func TestResolveVaultID_UnknownVault(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()
	if err := cmd.Flags().Set("vault", "does-not-exist"); err != nil {
		t.Fatal(err)
	}
	tc.MockVaultService.On("GetVault", mock.Anything, "does-not-exist").
		Return(nil, testutils.ErrVaultNotFoundForTest).Maybe()

	_, err := ResolveVaultID(context.Background(), cmd, tc.MockContainer)
	if err == nil {
		t.Fatal("expected an error for an unknown vault")
	}
}

func TestRequireDataAction_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	vaultID, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet)
	if err != nil {
		t.Fatalf("expected no error (default mock allows), got %v", err)
	}
	if vaultID != tc.TestVaultID {
		t.Fatalf("expected default vault id %s, got %s", tc.TestVaultID, vaultID)
	}
}

func TestRequireDataAction_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	// Replace the default-allow instance with a fresh, deny-everything one.
	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	_, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/vaultcli/... -v`
Expected: FAIL — package `vaultcli` doesn't exist yet, and `testutils.MockRoleAssignmentService`/`testutils.ErrVaultNotFoundForTest` are undefined.

- [ ] **Step 3: Add `MockRoleAssignmentService` and default wiring to `cmd/testutils/test_utils.go`**

Add near `MockVaultService` (after its last method, before the next type):

```go
// ErrVaultNotFoundForTest is returned by test doubles standing in for a
// vault-lookup failure; production code never checks for this sentinel.
var ErrVaultNotFoundForTest = errors.New("test: vault not found")

// MockRoleAssignmentService implements authzServices.RoleAssignmentService for testing.
type MockRoleAssignmentService struct {
	mock.Mock
}

func (m *MockRoleAssignmentService) AssignRole(ctx context.Context, in authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error {
	args := m.Called(ctx, assignmentID, vaultID)
	return args.Error(0)
}

func (m *MockRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	args := m.Called(ctx, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	args := m.Called(ctx, principalID, vaultID, action)
	return args.Bool(0), args.Error(1)
}
```

Add `"errors"` to the import block if not already present.

Add a field to `MockServiceContainer` (next to the existing `VaultService` field):

```go
type MockServiceContainer struct {
	mock.Mock
	// VaultService is returned by GetVaultService. It defaults to a MockVaultService
	// that resolves the "default" vault so vault-aware resource commands work in tests.
	VaultService vaultServices.VaultService
	// RoleAssignmentService is returned by GetRoleAssignmentService. It defaults to a
	// MockRoleAssignmentService that allows every action, so vault-authorization checks
	// added to CLI commands don't break every pre-existing test that doesn't care about
	// them. Tests exercising the deny path replace this field with a fresh instance.
	RoleAssignmentService authzServices.RoleAssignmentService
}
```

Change the existing `GetRoleAssignmentService` method (currently returns `nil` unconditionally):

```go
func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return m.RoleAssignmentService
}
```

Add a `MockRoleAssignmentService *MockRoleAssignmentService` field to `TestContext` (next to `MockVaultService`), and in `NewTestContext`, after the existing `mockVaultService.On("GetVault", ...)` block:

```go
mockRoleAssignmentService := &MockRoleAssignmentService{}
mockRoleAssignmentService.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
	Return(true, nil).Maybe()
```

and after `mockContainer.VaultService = mockVaultService`:

```go
mockContainer.RoleAssignmentService = mockRoleAssignmentService
```

and in the `TestContext{...}` struct literal returned at the end of `NewTestContext`, add:

```go
MockRoleAssignmentService: mockRoleAssignmentService,
```

- [ ] **Step 4: Write `cmd/vaultcli/vault.go`**

```go
package vaultcli

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// ResolveVaultID resolves the --vault selection to a vault id via the service container.
func ResolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error) {
	name := common.ResolveVaultName(cmd)
	v, err := sc.GetVaultService().GetVault(ctx, name)
	if err != nil {
		return uuid.Nil, fmt.Errorf("vault %q not found: %w", name, err)
	}
	return v.ID, nil
}

// RequireDataAction resolves the vault, then checks principalID holds a role
// assignment in it granting action. Returns the resolved vault ID on success
// so callers don't have to resolve twice.
func RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction) (uuid.UUID, error) {
	vaultID, err := ResolveVaultID(ctx, cmd, sc)
	if err != nil {
		return uuid.Nil, err
	}
	if err := authorization.RequireDataAction(ctx, sc.GetRoleAssignmentService(), principalID, vaultID, action); err != nil {
		return uuid.Nil, err
	}
	return vaultID, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/vaultcli/... ./cmd/testutils/... -v`
Expected: PASS.

- [ ] **Step 6: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean (the `MockServiceContainer.GetRoleAssignmentService` signature didn't change, so no other package breaks).

- [ ] **Step 7: Commit**

```bash
git add cmd/vaultcli/ cmd/testutils/test_utils.go
git commit -m "feat(cmd): add vaultcli package (ResolveVaultID, RequireDataAction) + test double"
```
