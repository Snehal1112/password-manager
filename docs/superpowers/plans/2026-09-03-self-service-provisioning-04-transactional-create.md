# Transactional Provisioned Create — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce the quota and grant the creator their rights, both inside one transaction, so a provisioned create is atomic and cannot exceed its bound under concurrency.

**Architecture:** `CreateVault` gains a provisioned path. It opens a transaction, takes a row lock on the grant, counts the principal's vaults, refuses if at quota, then writes the vault plus the creator's access policy and role assignment. Three repositories gain `CreateTx` siblings on their concrete structs, following the existing `ReadByIDTx` precedent.

**Tech Stack:** Go 1.24, `database/sql`, SQLite + PostgreSQL, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §5, §6

**Depends on:** `…-03-can-create-vault.md` — `CreateRight` must exist, and `createVault` must already admit grant holders.
**Followed by:** `…-05-scoped-list-vaults.md`.

## Global Constraints

- **The quota check must run inside the transaction that inserts the vault.** Checking outside it races the insert and the bound becomes advisory.
- **The row lock is not optional.** Under PostgreSQL's READ COMMITTED, two concurrent creates both count `N` and both insert, producing `N+2` against a quota of `N+1`. SQLite is accidentally safe via `SQLITE_BUSY`; PostgreSQL is not. Do not remove the no-op `UPDATE` as "dead code".
- Soft-deleted vaults count against quota; only a purge releases a slot.
- A grantee may not set `purge_protection` — otherwise it can protect a vault, soft-delete it, and pin the slot permanently, since `PurgeVault` refuses a protected vault.
- Tx-scoped repository methods go on the **concrete struct**, never the exported interface, so test doubles don't break (precedent: `VaultRepository.ReadByIDTx`, `vault_service.go:107-118`).
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: CreateTx siblings on the three repositories

**Files:**
- Modify: `internal/repositories/vault_repository.go` (add `CreateTx` beside `Create` at line 104)
- Modify: `internal/repositories/access_policy_repository.go` (add `CreateTx` beside `Create` at line 40)
- Modify: `internal/repositories/role_assignment_repository.go` (add `CreateTx` beside `Create` at line 37)
- Test: `internal/repositories/tx_create_test.go` (new)

**Interfaces:**
- Produces, all on concrete structs:
  - `func (r *VaultRepository) CreateTx(ctx context.Context, ex db.DBTX, v *model.Vault) error`
  - `func (r *accessPolicyRepository) CreateTx(ctx context.Context, ex db.DBTX, p *model.AccessPolicy) error`
  - `func (r *roleAssignmentRepository) CreateTx(ctx context.Context, ex db.DBTX, ra *model.RoleAssignment) error`
  - Task 2 consumes all three.

Refactor each existing `Create` to delegate to a shared private method taking `db.DBTX`, exactly as `ReadByID`/`ReadByIDTx` both delegate to `readByID` (`vault_repository.go:131-147`). Do not duplicate the SQL.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/tx_create_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestVaultRepository_CreateTx_RollsBack(t *testing.T) {
	database := newVaultTestDB(t) // existing helper
	repo := repositories.NewVaultRepository(database, newTestVaultLogger(t))
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	require.NoError(t, repo.CreateTx(ctx, tx, &model.Vault{
		ID: uuid.New(), Name: "rolled-back", CreatedBy: uuid.New(), RetentionDays: 90,
	}))
	require.NoError(t, tx.Rollback())

	_, err = repo.ReadByName(ctx, "rolled-back")
	require.Error(t, err, "a rolled-back CreateTx must leave no vault behind")
}

func TestVaultRepository_CreateTx_Commits(t *testing.T) {
	database := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(database, newTestVaultLogger(t))
	ctx := context.Background()

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.CreateTx(ctx, tx, &model.Vault{
		ID: uuid.New(), Name: "committed", CreatedBy: uuid.New(), RetentionDays: 90,
	}))
	require.NoError(t, tx.Commit())

	got, err := repo.ReadByName(ctx, "committed")
	require.NoError(t, err)
	require.Equal(t, "committed", got.Name)
}
```

Adjust `NewVaultRepository(...)` to its real signature. Add equivalent commit/rollback pairs for the access-policy and role-assignment repositories using their own in-memory schemas, following `newGrantTestDB` from plan 01 as the shape.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestVaultRepository_CreateTx -v`
Expected: FAIL — `repo.CreateTx` undefined.

- [ ] **Step 3: Refactor VaultRepository.Create and add CreateTx**

In `internal/repositories/vault_repository.go`, replace `Create` (line 104) with:

```go
func (r *VaultRepository) Create(ctx context.Context, v *model.Vault) error {
	return r.create(ctx, r.db, v)
}

// CreateTx inserts a vault on the given executor, so the insert can join a
// caller's transaction -- used by the provisioned create path, which writes
// the vault and the creator's grants atomically.
func (r *VaultRepository) CreateTx(ctx context.Context, ex db.DBTX, v *model.Vault) error {
	return r.create(ctx, ex, v)
}

func (r *VaultRepository) create(ctx context.Context, ex db.DBTX, v *model.Vault) error {
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	tagsJSON, err := marshalTags(v.Tags)
	if err != nil {
		return err
	}
	_, err = ex.ExecContext(ctx,
		"INSERT INTO vaults (id, name, enabled, purge_protection, retention_days, created_by, created_at, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		v.ID.String(), v.Name, v.Enabled, v.PurgeProtection, v.RetentionDays, v.CreatedBy.String(), v.CreatedAt, tagsJSON)
	if err != nil {
		return fmt.Errorf("failed to insert vault: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Do the same for the other two repositories**

In `internal/repositories/access_policy_repository.go`, split `Create` (line 40) into `Create` / `CreateTx` / `create(ctx, ex db.DBTX, p *model.AccessPolicy)`, moving the existing body verbatim into `create` and swapping `r.db.ExecContext` for `ex.ExecContext`.

In `internal/repositories/role_assignment_repository.go`, do the same for `Create` (line 37).

Do **not** add `CreateTx` to `AccessPolicyRepositoryInterface` or `RoleAssignmentRepositoryInterface` — keeping it off the interfaces is what stops every existing test double from breaking.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/repositories/ && go build ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/repositories/
git commit -S -m "feat(repo): add CreateTx to vault, policy, role repos"
```

---

### Task 2: Quota enforcement inside the transaction

**Files:**
- Modify: `internal/services/vaults/vault_service.go` (`CreateVault` at line 217; new interfaces and setters near `PolicyCleaner` at line 61 and `SetPolicyCleaner` at line 157)
- Test: `internal/services/vaults/vault_provisioned_create_test.go` (new)

**Interfaces:**
- Consumes: `CreateTx` and `CountByCreatedBy` from task 1 and plan 01; `authz.CreateRight` from plan 03.
- Produces:
  - `func (s *vaultService) CreateVaultProvisioned(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID, quotaBounded bool) (*model.Vault, error)` on the `VaultService` interface
  - `var ErrVaultQuotaExceeded = errors.New("vault provisioning quota exceeded")`
  - `type GrantLocker interface { LockAndReadQuotaTx(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error) }`
  - `func (s *vaultService) SetGrantLocker(l GrantLocker)`
  - Task 3 extends this method to write the creator's grants; plan 06 and the HTTP handler call it.

`quotaBounded` is passed in by the caller from `CreateRight` — the service does not re-derive the authorization decision, keeping one decision point.

- [ ] **Step 1: Add LockAndReadQuotaTx to the grant repository**

In `internal/repositories/vault_provisioning_grant_repository.go`, add to **both** `VaultProvisioningGrantRepositoryInterface` and the implementation — on the interface, unlike the `CreateTx` methods in task 1, because this repository is new in this series and has no existing test doubles to break. That also lets the container wire it with no type assertion:

```go
LockAndReadQuotaTx(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error)
```

Update `internal/services/provisioning/grant_service_test.go`'s `fakeGrantRepo` (plan 02) to satisfy the widened interface — return `(0, nil)`; it is never exercised there.

Implementation:

```go
// LockAndReadQuotaTx takes a row lock on the principal's grant and returns
// its quota. The no-op UPDATE is the lock: PostgreSQL takes a row lock on an
// updated row, SQLite escalates the transaction to RESERVED. Without it, two
// concurrent creates under READ COMMITTED both read the same count and both
// insert, exceeding the quota by one. This statement is load-bearing -- it is
// not a redundant write.
func (r *vaultProvisioningGrantRepository) LockAndReadQuotaTx(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error) {
	if _, err := ex.ExecContext(ctx,
		"UPDATE vault_provisioning_grants SET quota = quota WHERE principal_id = ?",
		principalID.String()); err != nil {
		return 0, fmt.Errorf("lock provisioning grant: %w", err)
	}
	var quota int
	err := ex.QueryRowContext(ctx,
		"SELECT quota FROM vault_provisioning_grants WHERE principal_id = ?",
		principalID.String()).Scan(&quota)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("provisioning grant for principal %s: %w", principalID, ErrNotFound)
	}
	if err != nil {
		return 0, fmt.Errorf("read provisioning quota: %w", err)
	}
	return quota, nil
}
```

- [ ] **Step 2: Write the failing test**

Create `internal/services/vaults/vault_provisioned_create_test.go`:

```go
package vaults_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/vaults"
	"rocketvault/model"
)

func TestCreateVaultProvisioned_RefusesAtQuota(t *testing.T) {
	svc := newProvisionedTestService(t, quota(2), existingVaults(2)) // helpers in Step 4

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "third"}, testPrincipal, true)

	require.True(t, errors.Is(err, vaults.ErrVaultQuotaExceeded),
		"a create at quota must be refused, not merely logged")
}

func TestCreateVaultProvisioned_AllowsBelowQuota(t *testing.T) {
	svc := newProvisionedTestService(t, quota(2), existingVaults(1))

	v, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "second"}, testPrincipal, true)

	require.NoError(t, err)
	require.Equal(t, "second", v.Name)
}

func TestCreateVaultProvisioned_UnboundedIgnoresQuota(t *testing.T) {
	svc := newProvisionedTestService(t, quota(1), existingVaults(5))

	// quotaBounded=false is the admin / global-policy path.
	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "admin-made"}, testPrincipal, false)

	require.NoError(t, err, "admins and global-policy holders are not quota-bounded")
}

func TestCreateVaultProvisioned_RejectsPurgeProtectionFromGrantee(t *testing.T) {
	svc := newProvisionedTestService(t, quota(5), existingVaults(0))
	protect := true

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "pinned", PurgeProtection: &protect}, testPrincipal, true)

	require.Error(t, err,
		"a grantee setting purge_protection could pin a quota slot permanently")
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestCreateVaultProvisioned -v`
Expected: FAIL — `CreateVaultProvisioned` undefined.

- [ ] **Step 4: Write the implementation**

In `internal/services/vaults/vault_service.go`, add near `PolicyCleaner` (line 61):

```go
// GrantLocker locks a principal's provisioning grant inside a transaction and
// returns its quota. Satisfied by the concrete
// repositories.vaultProvisioningGrantRepository.
type GrantLocker interface {
	LockAndReadQuotaTx(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error)
}
```

Add `grantLocker GrantLocker` to the struct, `SetGrantLocker(l GrantLocker)` to the `VaultService` interface, and beside line 157:

```go
// SetGrantLocker attaches the provisioning-grant locker used by the
// quota-bounded create path.
func (s *vaultService) SetGrantLocker(l GrantLocker) { s.grantLocker = l }
```

Add the sentinel and the method:

```go
// ErrVaultQuotaExceeded means the principal has reached the vault count its
// provisioning grant allows. Soft-deleted vaults still count -- only a purge
// releases a slot.
var ErrVaultQuotaExceeded = errors.New("vault provisioning quota exceeded")

// ErrPurgeProtectionNotPermitted means a quota-bounded caller tried to set
// purge_protection. Allowing it would let a grantee protect a vault,
// soft-delete it, and hold the quota slot forever, since PurgeVault refuses a
// protected vault and the purge scheduler honours the same flag.
var ErrPurgeProtectionNotPermitted = errors.New("purge protection may only be set by an administrator")

// CreateVaultProvisioned creates a vault, enforcing the caller's provisioning
// quota when quotaBounded is true. quotaBounded comes from the caller's
// authz.CreateRight: admins and global-policy holders pass false.
//
// Quota enforcement runs INSIDE the transaction that inserts the vault. A
// check outside it races the insert and the bound becomes advisory.
func (s *vaultService) CreateVaultProvisioned(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID, quotaBounded bool) (*model.Vault, error) {
	if err := model.ValidateVaultName(req.Name); err != nil {
		return nil, err
	}
	if err := model.ValidateVaultTags(req.Tags); err != nil {
		return nil, err
	}
	if quotaBounded && req.PurgeProtection != nil && *req.PurgeProtection {
		return nil, ErrPurgeProtectionNotPermitted
	}

	// No transaction wired (unit tests, and any deployment path that never
	// set a locker): fall back to the pre-existing non-transactional create.
	// An unbounded caller needs no quota check at all.
	if !quotaBounded || s.txBeginner == nil || s.grantLocker == nil {
		return s.CreateVault(ctx, req, createdBy)
	}

	v := s.buildVault(req, createdBy)

	txRepo, ok := s.repo.(txCapableCreateRepo)
	if !ok {
		return nil, fmt.Errorf("vault repository does not support transactional create")
	}

	err := s.withTx(ctx, func(tx *db.Tx) error {
		quota, err := s.grantLocker.LockAndReadQuotaTx(ctx, tx, createdBy)
		if err != nil {
			return err
		}
		count, err := txRepo.CountByCreatedBy(ctx, tx, createdBy)
		if err != nil {
			return err
		}
		if count >= quota {
			return fmt.Errorf("%w: %d of %d used", ErrVaultQuotaExceeded, count, quota)
		}
		return txRepo.CreateTx(ctx, tx, v)
	})
	if err != nil {
		return nil, err
	}
	if s.log != nil {
		s.log.LogAuditInfo(createdBy.String(), "create_vault", "success",
			fmt.Sprintf("Vault created under provisioning grant: %s", v.Name))
	}
	return v, nil
}
```

Add the capability interface beside `txCapableVaultRepo` (line 107):

```go
// txCapableCreateRepo is the provisioned-create half of the concrete
// VaultRepository's Tx surface. Kept off VaultRepositoryInterface for the
// same reason as txCapableVaultRepo: adding it there would ripple to every
// test double implementing that interface.
type txCapableCreateRepo interface {
	CreateTx(ctx context.Context, ex db.DBTX, v *model.Vault) error
	CountByCreatedBy(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error)
}
```

Extract the struct-building half of the existing `CreateVault` (lines 225-243) into a shared `buildVault(req model.CreateVaultRequest, createdBy uuid.UUID) *model.Vault` and call it from both `CreateVault` and `CreateVaultProvisioned`, so defaults cannot drift between the two paths.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/services/vaults/ -v`
Expected: PASS

- [ ] **Step 6: Write the concurrency test**

Add to the same file:

```go
func TestCreateVaultProvisioned_ConcurrentCreatesRespectQuota(t *testing.T) {
	// Quota 2, one vault already present: exactly one of two concurrent
	// creates may succeed.
	svc := newProvisionedTestServiceRealDB(t, quota(2), existingVaults(1))

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.CreateVaultProvisioned(context.Background(),
				model.CreateVaultRequest{Name: fmt.Sprintf("race-%d", i)}, testPrincipal, true)
		}(i)
	}
	wg.Wait()

	var ok, refused int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, vaults.ErrVaultQuotaExceeded):
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	require.Equal(t, 1, ok, "exactly one concurrent create may succeed")
	require.Equal(t, 1, refused, "the other must be refused for quota")
}
```

This needs a real database (`newProvisionedTestServiceRealDB` backed by a temp-file SQLite DB, not `:memory:`, so two connections see one database). Note it only *demonstrates* the guard; the race it guards against manifests on PostgreSQL. Note that in the test's doc comment.

- [ ] **Step 7: Run and commit**

Run: `go test ./internal/services/vaults/ -race -v`
Expected: PASS

```bash
git add internal/services/vaults/ internal/repositories/vault_provisioning_grant_repository.go
git commit -S -m "feat(vaults): enforce provisioning quota inside the create tx"
```

---

### Task 3: Grant the creator their rights in the same transaction

**Files:**
- Modify: `internal/services/vaults/vault_service.go` (`CreateVaultProvisioned`; new interfaces and setters)
- Modify: `internal/container/service_container.go` (wire the new setters)
- Modify: `api/vault.go` (`createVault` calls the provisioned method)
- Test: `internal/services/vaults/vault_provisioned_create_test.go`

**Interfaces:**
- Consumes: `CreateTx` on the policy and role repositories from task 1.
- Produces:
  - `type CreatorGranter interface { CreatePolicyTx(ctx, ex db.DBTX, p *model.AccessPolicy) error; CreateRoleTx(ctx, ex db.DBTX, ra *model.RoleAssignment) error }`
  - `func (s *vaultService) SetCreatorGranter(g CreatorGranter)`

The creator's role assignment is written **directly**, not through `RoleAssignmentService.AssignRole`: that method is not transaction-aware, performs its own compensating deletes on failure (`role_assignment_service.go:162-176`), and its `nonAdminGrantableRoles` gate is irrelevant here — this grant is made by the system on the creator's behalf, not by one principal to another.

- [ ] **Step 1: Write the failing test**

```go
func TestCreateVaultProvisioned_GrantsCreatorFullRights(t *testing.T) {
	svc, granter := newProvisionedTestServiceWithGranter(t, quota(5), existingVaults(0))

	v, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "acme-prod"}, testPrincipal, true)
	require.NoError(t, err)

	require.Len(t, granter.policies, 1)
	require.Equal(t, model.PolicyResourceVaults, granter.policies[0].ResourceType)
	require.Equal(t, model.OpManage, granter.policies[0].Operation)
	require.Equal(t, model.PolicyEffectAllow, granter.policies[0].Effect)
	require.NotNil(t, granter.policies[0].VaultID)
	require.Equal(t, v.ID, *granter.policies[0].VaultID,
		"the creator's manage policy must be scoped to the new vault, never global")

	require.Len(t, granter.roles, 1)
	require.Equal(t, model.RoleKeyVaultAdministrator, granter.roles[0].Role)
	require.Equal(t, v.ID, granter.roles[0].VaultID)
	require.Equal(t, testPrincipal, granter.roles[0].PrincipalID)
}

func TestCreateVaultProvisioned_RollsBackAllThreeWrites(t *testing.T) {
	svc, _ := newProvisionedTestServiceWithFailingGranter(t, quota(5), existingVaults(0))

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "doomed"}, testPrincipal, true)
	require.Error(t, err)

	_, err = svc.GetVault(context.Background(), "doomed")
	require.Error(t, err, "a failed grant write must roll back the vault insert too")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestCreateVaultProvisioned_Grants -v`
Expected: FAIL

- [ ] **Step 3: Extend the transaction body**

Add the interface beside `GrantLocker`:

```go
// CreatorGranter writes the creator's rights over a newly provisioned vault,
// inside the caller's transaction. Satisfied by an adapter over the concrete
// access-policy and role-assignment repositories.
type CreatorGranter interface {
	CreatePolicyTx(ctx context.Context, ex db.DBTX, p *model.AccessPolicy) error
	CreateRoleTx(ctx context.Context, ex db.DBTX, ra *model.RoleAssignment) error
}
```

Inside `CreateVaultProvisioned`'s `withTx` closure, after `txRepo.CreateTx(ctx, tx, v)` succeeds:

```go
		if err := txRepo.CreateTx(ctx, tx, v); err != nil {
			return err
		}
		if s.creatorGranter == nil {
			return nil
		}
		// The creator becomes full manager of what it created: vault-scoped
		// vaults:manage for lifecycle operations, and Key Vault Administrator
		// for the data plane. Both are scoped to this vault only -- a global
		// policy here would hand the grantee the instance.
		vaultID := v.ID
		if err := s.creatorGranter.CreatePolicyTx(ctx, tx, &model.AccessPolicy{
			ID:            uuid.New(),
			PrincipalID:   createdBy,
			PrincipalType: model.PrincipalTypeUser,
			ResourceType:  model.PolicyResourceVaults,
			Operation:     model.OpManage,
			Effect:        model.PolicyEffectAllow,
			VaultID:       &vaultID,
		}); err != nil {
			return fmt.Errorf("grant creator vault management: %w", err)
		}
		return s.creatorGranter.CreateRoleTx(ctx, tx, &model.RoleAssignment{
			ID:            uuid.New(),
			PrincipalID:   createdBy,
			PrincipalType: model.PrincipalTypeUser,
			Role:          model.RoleKeyVaultAdministrator,
			VaultID:       v.ID,
			CreatedBy:     createdBy,
		})
```

Add the `creatorGranter CreatorGranter` field and its setter.

- [ ] **Step 4: Wire the container**

In `internal/container/service_container.go`, after the role-assignment repository exists (line 434), add an adapter and wire all three setters:

```go
	c.vaultService.SetGrantLocker(c.vaultProvisioningGrantRepository)
	c.vaultService.SetCreatorGranter(&creatorGranterAdapter{
		policies: c.accessPolicyRepository,
		roles:    c.roleAssignmentRepository,
	})
```

Define `creatorGranterAdapter` in the container package, delegating to each repository's concrete `CreateTx` via a type assertion, mirroring how `txCapableVaultRepo` recovers the concrete Tx surface.

- [ ] **Step 5: Call the provisioned path from the handler**

In `api/vault.go`'s `createVault`, replace the `svc.CreateVault(...)` call with:

```go
	vault, err := svc.CreateVaultProvisioned(r.Context(), req, userID,
		right == authzServices.CreateRightProvisioningGrant)
```

Map the new sentinels in the handler's error switch: `ErrVaultQuotaExceeded` → `403` with the error's message, `ErrPurgeProtectionNotPermitted` → `403`. Follow the file's existing error-mapping style.

- [ ] **Step 6: Run everything**

Run: `go build ./... && go vet ./... && go test ./... -race`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/services/vaults/ internal/container/ api/vault.go
git commit -S -m "feat(vaults): grant the creator rights over what it provisions"
```
