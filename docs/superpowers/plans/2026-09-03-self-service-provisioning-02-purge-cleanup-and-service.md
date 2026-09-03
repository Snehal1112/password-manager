# Purge Cleanup and Grant Service — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the pre-existing `role_assignments` leak on vault purge, then add the grant service and wire it into the DI container.

**Architecture:** `PurgeVault` already cleans `access_policies` and `vault_webhook_configs` explicitly because neither FK cascade fires on SQLite; `role_assignments` was missed. Every provisioned vault will carry a creator assignment, so that leak must close before plan 04 starts creating them. The grant service then follows the thin `accessPolicyService` shape, wired by setter injection to avoid the container's construction-order trap.

**Tech Stack:** Go 1.24, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §8, §4

**Depends on:** `…-01-grant-storage.md` — the grant repository and `model.VaultProvisioningGrant` must exist.
**Followed by:** `…-03-can-create-vault.md`.

## Global Constraints

- **Release 1 is additive only.** No existing authorization decision may change behaviour. Narrowing the global `vaults:manage` grant is release 2, out of scope here.
- SQLite runs with the `foreign_keys` pragma **off**, so every `ON DELETE CASCADE` in the schema is inert. Child rows must be deleted explicitly. This is why `PurgeVault` already has two cleaners.
- Repositories do data access only; business rules live in services (`CLAUDE.md`).
- New service dependencies on `vaultService` are **setter-injected**, never constructor-injected — `NewVaultService` runs at `internal/container/service_container.go:297`, before the policy and role repositories exist at `:429`/`:434`.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Close the role_assignments leak on purge

**Files:**
- Modify: `internal/repositories/role_assignment_repository.go` (add `DeleteByVault` to the interface and implementation)
- Modify: `internal/services/vaults/vault_service.go` (new `RoleAssignmentCleaner` interface near `PolicyCleaner` at line 61; new field and setter beside `SetPolicyCleaner` at line 157; new call in `PurgeVault` beside the existing cleaners at lines 503-516)
- Modify: `internal/container/service_container.go` (wire the cleaner beside `SetPolicyCleaner` at line 433)
- Test: `internal/services/vaults/vault_service_test.go`

**Interfaces:**
- Produces:
  - `RoleAssignmentRepositoryInterface.DeleteByVault(ctx context.Context, vaultID uuid.UUID) error`
  - `type RoleAssignmentCleaner interface { DeleteByVault(ctx context.Context, vaultID uuid.UUID) error }` in `internal/services/vaults`
  - `func (s *vaultService) SetRoleAssignmentCleaner(c RoleAssignmentCleaner)`
  - Plan 04 relies on this leak being closed before it starts writing creator assignments.

This is a standalone bug fix and is worth reviewing on its own merits: it is already wrong today, independent of provisioning.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/vaults/vault_service_test.go`:

```go
// fakeRoleAssignmentCleaner records the vault IDs it was asked to clean.
type fakeRoleAssignmentCleaner struct {
	cleaned []uuid.UUID
	err     error
}

func (f *fakeRoleAssignmentCleaner) DeleteByVault(_ context.Context, vaultID uuid.UUID) error {
	if f.err != nil {
		return f.err
	}
	f.cleaned = append(f.cleaned, vaultID)
	return nil
}

func TestPurgeVault_RemovesRoleAssignments(t *testing.T) {
	svc, repo := newTestVaultService(t) // existing helper in this file
	cleaner := &fakeRoleAssignmentCleaner{}
	svc.(interface {
		SetRoleAssignmentCleaner(vaults.RoleAssignmentCleaner)
	}).SetRoleAssignmentCleaner(cleaner)

	v := seedSoftDeletedVault(t, repo, "doomed") // existing helper in this file

	require.NoError(t, svc.PurgeVault(context.Background(), "doomed"))
	require.Equal(t, []uuid.UUID{v.ID}, cleaner.cleaned,
		"purging a vault must delete its role assignments: the FK cascade is inert on SQLite")
}
```

Use the package's existing service-construction and seeding helpers rather than adding new ones. If `newTestVaultService` / `seedSoftDeletedVault` are named differently in that file, use the real names and keep the assertions identical.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestPurgeVault_RemovesRoleAssignments -v`
Expected: FAIL — `RoleAssignmentCleaner` undefined.

- [ ] **Step 3: Add DeleteByVault to the role-assignment repository**

In `internal/repositories/role_assignment_repository.go`, add to `RoleAssignmentRepositoryInterface` and implement beside `ListByVault`:

```go
// DeleteByVault removes every role assignment scoped to vaultID. Called when
// a vault is purged: role_assignments declares ON DELETE CASCADE on vault_id,
// but SQLite runs with the foreign_keys pragma off, so that cascade never
// fires and the rows would be stranded -- unreachable but never removed.
func (r *roleAssignmentRepository) DeleteByVault(ctx context.Context, vaultID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM role_assignments WHERE vault_id = ?", vaultID.String())
	if err != nil {
		return fmt.Errorf("delete role assignments for vault %s: %w", vaultID, err)
	}
	return nil
}
```

- [ ] **Step 4: Add the cleaner to the vault service**

In `internal/services/vaults/vault_service.go`, beside `PolicyCleaner` (line 61):

```go
// RoleAssignmentCleaner removes role assignments scoped to a vault (used on
// purge). Separate from PolicyCleaner because the two are different tables
// with different repositories, and either may be absent in a unit test.
type RoleAssignmentCleaner interface {
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
}
```

Add `roleAssignments RoleAssignmentCleaner` to the `vaultService` struct (line 139), declare `SetRoleAssignmentCleaner(c RoleAssignmentCleaner)` on the `VaultService` interface beside `SetPolicyCleaner` (line 128), and add the setter beside line 157:

```go
// SetRoleAssignmentCleaner attaches an optional cleaner that removes
// vault-scoped role assignments on purge.
func (s *vaultService) SetRoleAssignmentCleaner(c RoleAssignmentCleaner) { s.roleAssignments = c }
```

- [ ] **Step 5: Call it from PurgeVault**

In `PurgeVault`, directly after the existing `s.policies` block and before the `s.webhooks` block (around line 509):

```go
	// role_assignments declares ON DELETE CASCADE on vault_id, but the SQLite
	// foreign_keys pragma is off here, so the cascade is inert and the rows
	// must be removed explicitly -- same reason as the access_policies block
	// above.
	if s.roleAssignments != nil {
		if err := s.roleAssignments.DeleteByVault(ctx, v.ID); err != nil {
			return fmt.Errorf("delete vault role assignments: %w", err)
		}
	}
```

The `!= nil` guard matches the two neighbouring cleaners: unit tests construct a `vaultService` without them.

- [ ] **Step 6: Wire it in the container**

In `internal/container/service_container.go`, directly after `c.roleAssignmentRepository = repositories.NewRoleAssignmentRepository(c.conn)` (line 434):

```go
	// Wire the role-assignment cleaner now that its repository exists; the
	// vault service deletes vault-scoped assignments on purge because the FK
	// cascade is inert on SQLite.
	c.vaultService.SetRoleAssignmentCleaner(c.roleAssignmentRepository)
```

- [ ] **Step 7: Run the tests**

Run: `go test ./internal/services/vaults/ ./internal/repositories/ ./internal/container/`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/repositories/role_assignment_repository.go \
        internal/services/vaults/vault_service.go \
        internal/services/vaults/vault_service_test.go \
        internal/container/service_container.go
git commit -S -m "fix(vaults): delete role assignments when purging a vault"
```

---

### Task 2: Grant service

**Files:**
- Create: `internal/services/provisioning/grant_service.go`
- Create: `internal/services/provisioning/grant_service_test.go`

**Interfaces:**
- Consumes: `repositories.VaultProvisioningGrantRepositoryInterface`, `model.VaultProvisioningGrant`, `model.ErrInvalidQuota` from plan 01.
- Produces:
  - `type GrantService interface { IssueGrant(ctx, principalID uuid.UUID, quota int, issuedBy uuid.UUID) (*model.VaultProvisioningGrant, error); GetGrant(ctx, principalID uuid.UUID) (*model.VaultProvisioningGrant, error); RevokeGrant(ctx, principalID uuid.UUID) error; ListGrants(ctx) ([]*model.VaultProvisioningGrant, error) }`
  - `func NewGrantService(repo repositories.VaultProvisioningGrantRepositoryInterface, log *logging.Logger) GrantService`
  - `var ErrGrantNotFound = errors.New("no provisioning grant for principal")`
  - Plans 03, 04, 06 and 07 consume these.

Keep this as thin as `accessPolicyService` (`internal/services/authorization/access_policy_service.go:68-96`): validation, audit logging, and delegation. The quota *decision* is not here — it belongs inside plan 04's transaction, because a decision made outside the transaction races with the insert.

- [ ] **Step 1: Write the failing test**

Create `internal/services/provisioning/grant_service_test.go`:

```go
package provisioning_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/provisioning"
	"rocketvault/model"
)

// fakeGrantRepo is an in-memory VaultProvisioningGrantRepositoryInterface.
type fakeGrantRepo struct {
	grants map[uuid.UUID]*model.VaultProvisioningGrant
}

func newFakeGrantRepo() *fakeGrantRepo {
	return &fakeGrantRepo{grants: map[uuid.UUID]*model.VaultProvisioningGrant{}}
}

func (f *fakeGrantRepo) Upsert(_ context.Context, g *model.VaultProvisioningGrant) error {
	f.grants[g.PrincipalID] = g
	return nil
}

func (f *fakeGrantRepo) GetByPrincipal(_ context.Context, id uuid.UUID) (*model.VaultProvisioningGrant, error) {
	g, ok := f.grants[id]
	if !ok {
		return nil, repositories.ErrNotFound
	}
	return g, nil
}

func (f *fakeGrantRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.grants, id)
	return nil
}

func (f *fakeGrantRepo) List(_ context.Context) ([]*model.VaultProvisioningGrant, error) {
	out := make([]*model.VaultProvisioningGrant, 0, len(f.grants))
	for _, g := range f.grants {
		out = append(out, g)
	}
	return out, nil
}

func TestIssueGrant_StoresAndReturns(t *testing.T) {
	repo := newFakeGrantRepo()
	svc := provisioning.NewGrantService(repo, nil)
	principal, issuer := uuid.New(), uuid.New()

	g, err := svc.IssueGrant(context.Background(), principal, 5, issuer)
	require.NoError(t, err)
	require.Equal(t, 5, g.Quota)
	require.Equal(t, issuer, g.CreatedBy)
	require.NotEqual(t, uuid.Nil, g.ID)
}

func TestIssueGrant_RejectsNonPositiveQuota(t *testing.T) {
	svc := provisioning.NewGrantService(newFakeGrantRepo(), nil)

	for _, quota := range []int{0, -1} {
		_, err := svc.IssueGrant(context.Background(), uuid.New(), quota, uuid.New())
		require.True(t, errors.Is(err, model.ErrInvalidQuota),
			"quota %d must be rejected: a zero-quota grant is indistinguishable from no grant", quota)
	}
}

func TestIssueGrant_IsUpsert(t *testing.T) {
	repo := newFakeGrantRepo()
	svc := provisioning.NewGrantService(repo, nil)
	principal := uuid.New()

	_, err := svc.IssueGrant(context.Background(), principal, 5, uuid.New())
	require.NoError(t, err)
	_, err = svc.IssueGrant(context.Background(), principal, 9, uuid.New())
	require.NoError(t, err)

	all, err := svc.ListGrants(context.Background())
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.Equal(t, 9, all[0].Quota)
}

func TestGetGrant_MissingReturnsErrGrantNotFound(t *testing.T) {
	svc := provisioning.NewGrantService(newFakeGrantRepo(), nil)

	_, err := svc.GetGrant(context.Background(), uuid.New())
	require.True(t, errors.Is(err, provisioning.ErrGrantNotFound),
		"callers branch on this sentinel to mean 'no provisioning right', not 'lookup failed'")
}

func TestRevokeGrant(t *testing.T) {
	repo := newFakeGrantRepo()
	svc := provisioning.NewGrantService(repo, nil)
	principal := uuid.New()

	_, err := svc.IssueGrant(context.Background(), principal, 5, uuid.New())
	require.NoError(t, err)
	require.NoError(t, svc.RevokeGrant(context.Background(), principal))

	_, err = svc.GetGrant(context.Background(), principal)
	require.True(t, errors.Is(err, provisioning.ErrGrantNotFound))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/provisioning/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Write the service**

Create `internal/services/provisioning/grant_service.go`:

```go
// Package provisioning manages bounded vault-creation rights. A grant is the
// delegated alternative to a global vaults:manage policy, which additionally
// confers authority over every vault that already exists.
//
// Issuing a grant is a global-admin operation and is deliberately not
// delegable: a principal able to amend grants could raise its own quota, and
// the bound would be decorative.
package provisioning

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrGrantNotFound means the principal holds no provisioning grant. Callers
// branch on it to mean "no provisioning right", distinct from a lookup that
// itself failed.
var ErrGrantNotFound = errors.New("no provisioning grant for principal")

// GrantService is CRUD over provisioning grants. It does NOT decide whether a
// given create is within quota: that decision must run inside the vault
// creation transaction, or it races with the insert it is guarding.
type GrantService interface {
	IssueGrant(ctx context.Context, principalID uuid.UUID, quota int, issuedBy uuid.UUID) (*model.VaultProvisioningGrant, error)
	GetGrant(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error)
	RevokeGrant(ctx context.Context, principalID uuid.UUID) error
	ListGrants(ctx context.Context) ([]*model.VaultProvisioningGrant, error)
}

type grantService struct {
	repo repositories.VaultProvisioningGrantRepositoryInterface
	log  *logging.Logger
}

// NewGrantService constructs a GrantService. log may be nil, matching the
// optional-logger convention used elsewhere in the services packages.
func NewGrantService(repo repositories.VaultProvisioningGrantRepositoryInterface, log *logging.Logger) GrantService {
	return &grantService{repo: repo, log: log}
}

// IssueGrant creates or replaces the grant for principalID. principal_id is
// UNIQUE, so re-issuing is a quota change rather than a second right.
func (s *grantService) IssueGrant(ctx context.Context, principalID uuid.UUID, quota int, issuedBy uuid.UUID) (*model.VaultProvisioningGrant, error) {
	g := &model.VaultProvisioningGrant{
		ID:          uuid.New(),
		PrincipalID: principalID,
		Quota:       quota,
		CreatedBy:   issuedBy,
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.Upsert(ctx, g); err != nil {
		return nil, fmt.Errorf("issue provisioning grant: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo(issuedBy.String(), "issue_provisioning_grant", "success",
			fmt.Sprintf("Provisioning grant issued: principal=%s quota=%d", principalID, quota))
	}
	return g, nil
}

func (s *grantService) GetGrant(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error) {
	g, err := s.repo.GetByPrincipal(ctx, principalID)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, ErrGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read provisioning grant: %w", err)
	}
	return g, nil
}

func (s *grantService) RevokeGrant(ctx context.Context, principalID uuid.UUID) error {
	if err := s.repo.Delete(ctx, principalID); err != nil {
		return fmt.Errorf("revoke provisioning grant: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo("", "revoke_provisioning_grant", "success",
			fmt.Sprintf("Provisioning grant revoked: principal=%s", principalID))
	}
	return nil
}

func (s *grantService) ListGrants(ctx context.Context) ([]*model.VaultProvisioningGrant, error) {
	return s.repo.List(ctx)
}
```

Revoking a grant deliberately leaves the principal's existing vaults and their rights over them untouched. Cascading revocation would let one `DELETE` strip a customer's access to live vaults; removing those is a separate operator action.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/provisioning/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/provisioning/
git commit -S -m "feat(provisioning): add grant service"
```

---

### Task 3: Container wiring

**Files:**
- Modify: `internal/container/service_container.go` (field declarations; construction beside the authorization services around line 429-440; a new accessor)
- Modify: `internal/container/service_container_interface.go` (add the accessor to `ServiceContainerInterface`)
- Test: `internal/container/service_container_test.go`

**Interfaces:**
- Consumes: `provisioning.NewGrantService` from task 2, `repositories.NewVaultProvisioningGrantRepository` from plan 01.
- Produces: `func (c *ServiceContainer) GetGrantService() provisioning.GrantService`, declared on `ServiceContainerInterface`. Plans 03, 04, 06 and 07 reach the service through this accessor.

The accessor must go on `ServiceContainerInterface`, not only the concrete type: CLI commands type-assert to the interface, a pattern introduced specifically to stop type-assertion panics in tests (`CLAUDE.md`, CLI Type Safety Fix).

- [ ] **Step 1: Write the failing test**

Add to `internal/container/service_container_test.go`:

```go
func TestServiceContainer_GetGrantService(t *testing.T) {
	c := newTestServiceContainer(t) // existing helper in this file

	svc := c.GetGrantService()
	require.NotNil(t, svc, "grant service must be constructed during container initialization")

	var iface container.ServiceContainerInterface = c
	require.NotNil(t, iface.GetGrantService(),
		"accessor must be reachable through ServiceContainerInterface: CLI commands assert to the interface")
}
```

If `newTestServiceContainer` is named differently in that file, use the real helper.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/container/ -run TestServiceContainer_GetGrantService -v`
Expected: FAIL — `c.GetGrantService` undefined.

- [ ] **Step 3: Add the fields and construction**

In `internal/container/service_container.go`, add to the struct:

```go
	vaultProvisioningGrantRepository repositories.VaultProvisioningGrantRepositoryInterface
	grantService                     provisioning.GrantService
```

Then, immediately after `c.roleAssignmentService = ...` (around line 436-440), add:

```go
	c.vaultProvisioningGrantRepository = repositories.NewVaultProvisioningGrantRepository(c.conn)
	c.grantService = provisioning.NewGrantService(c.vaultProvisioningGrantRepository, c.logger)
```

Add the import `"rocketvault/internal/services/provisioning"`.

- [ ] **Step 4: Add the accessor**

In `internal/container/service_container.go`:

```go
// GetGrantService returns the vault-provisioning grant service.
func (c *ServiceContainer) GetGrantService() provisioning.GrantService {
	return c.grantService
}
```

And add `GetGrantService() provisioning.GrantService` to `ServiceContainerInterface` in `internal/container/service_container_interface.go`.

- [ ] **Step 5: Update any interface implementations**

Adding a method to `ServiceContainerInterface` breaks every mock that implements it. Run:

```bash
go build ./... 2>&1 | head -30
```

Add `GetGrantService()` to each reported implementation — check `cmd/testutils/test_utils.go` first, which carries the CLI mocks. Return `nil` in the mocks unless a test needs a real value.

- [ ] **Step 6: Run tests**

Run: `go build ./... && go vet ./... && go test ./internal/container/ ./cmd/...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/container/ cmd/testutils/
git commit -S -m "feat(container): wire the provisioning grant service"
```
