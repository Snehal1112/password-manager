# Milestone 2: Per-Operation Access Policies Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add per-operation access policies that allow explicit allow/deny per principal per resource operation, sitting in front of — but falling back to — the existing RBAC layer.

**Architecture:** New `access_policies` table + `AccessPolicyService` in `internal/services/authorization/` + `PolicyMiddleware` method on the existing `Middleware` struct + `api/access_policies.go` handler file. The policy check runs *after* JWT validation but *before* the RBAC check. If no policy row exists, RBAC decides. Explicit `deny` rows always win over `allow` rows.

**Tech Stack:** Go stdlib, `database/sql`, `github.com/google/uuid`, `github.com/gorilla/mux`, testify, existing Viper + logging patterns.

---

## Context: What Already Exists (Do Not Rebuild)

- `internal/services/authorization/rbac_service.go` — existing RBAC, keep untouched
- `internal/middleware/middleware.go` — `Middleware` struct, `NewMiddleware`, `AuthorizationMiddleware` already there
- `api/soft_delete.go` — exemplar handler file: `userIDFromClaims`, `resourceIDFromVars` helpers
- `internal/container/service_container.go` — `ServiceContainerInterface` + `ServiceContainer` to extend
- `api/api.go` — `Init()` wires up middleware and routes; exemplar: how soft-delete routes are registered
- Module name: `rocketvault`

**What is missing:**
- `access_policies` DB table
- `internal/domain/access_policy.go` — `AccessPolicy` domain type + operation constants
- `internal/repositories/access_policy_repository.go` — CRUD + `ListByPrincipal`
- `internal/services/authorization/access_policy_service.go` — `CheckAccess`, CRUD wrappers
- `GetAccessPolicyService()` on `ServiceContainerInterface` and `ServiceContainer`
- `PolicyMiddleware` method on `Middleware` (checks per-operation policy before RBAC)
- `api/access_policies.go` — 6 HTTP handler functions
- Route registration in `api/api.go`

---

### Task 1: DB migration — access_policies table

**Files:**
- Create: `internal/db/migrations/20260308000002_add_access_policies.sql`

#### Step 1: Create the migration file

```sql
-- Migration: Add per-operation access policies table
-- Description: Stores explicit allow/deny decisions for (principal, resource_type, operation).
--              Checked before RBAC; explicit deny always wins.
-- Version: 20260308000002

CREATE TABLE IF NOT EXISTS access_policies (
    id             TEXT PRIMARY KEY,
    principal_id   TEXT NOT NULL,
    principal_type TEXT NOT NULL CHECK(principal_type IN ('user','service_account')),
    resource_type  TEXT NOT NULL CHECK(resource_type IN ('secrets','keys','certificates')),
    operation      TEXT NOT NULL,
    effect         TEXT NOT NULL CHECK(effect IN ('allow','deny')),
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_access_policies_principal ON access_policies(principal_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_lookup  ON access_policies(principal_id, resource_type, operation);
```

#### Step 2: Build to verify the embed picks up the new file

```bash
cd /home/numericlabs/data/Golang/password-manager
go build -o rocketvault .
```

Expected: no errors.

#### Step 3: Verify migration is listed

```bash
./rocketvault migrate:status
```

Expected: `[ ] 20260308000002 - add_access_policies (Pending)` in output.

#### Step 4: Apply migration

```bash
./rocketvault migrate
```

#### Step 5: Also add to createOptimizedSchema + migrateSchema in db.go

Open `internal/db/db.go`.

In `createOptimizedSchema()`, append before the closing backtick:

```sql
		CREATE TABLE IF NOT EXISTS access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_access_policies_principal ON access_policies(principal_id);
		CREATE INDEX IF NOT EXISTS idx_access_policies_lookup    ON access_policies(principal_id, resource_type, operation);
```

No `migrateSchema` entry needed — the table is entirely new, not a column addition.

#### Step 6: Rebuild and confirm

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 7: Commit

```bash
git add internal/db/migrations/20260308000002_add_access_policies.sql internal/db/db.go
git commit -m "feat(db): add access_policies table — Milestone 2"
```

---

### Task 2: Domain type — AccessPolicy

**Files:**
- Create: `internal/domain/access_policy.go`

#### Step 1: Create domain type

```go
package domain

import (
	"time"

	"github.com/google/uuid"
)

// PrincipalType identifies the kind of principal a policy applies to.
type PrincipalType string

const (
	PrincipalTypeUser           PrincipalType = "user"
	PrincipalTypeServiceAccount PrincipalType = "service_account"
)

// PolicyEffect is the result of a policy evaluation.
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// PolicyResourceType is the resource category a policy covers.
type PolicyResourceType string

const (
	PolicyResourceSecrets      PolicyResourceType = "secrets"
	PolicyResourceKeys         PolicyResourceType = "keys"
	PolicyResourceCertificates PolicyResourceType = "certificates"
)

// PolicyOperation is the exact operation a policy grants or denies.
type PolicyOperation string

const (
	// Secrets operations
	OpSecretsGet     PolicyOperation = "get"
	OpSecretsList    PolicyOperation = "list"
	OpSecretsSet     PolicyOperation = "set"
	OpSecretsDelete  PolicyOperation = "delete"
	OpSecretsBackup  PolicyOperation = "backup"
	OpSecretsRestore PolicyOperation = "restore"
	OpSecretsPurge   PolicyOperation = "purge"
	OpSecretsRecover PolicyOperation = "recover"

	// Keys operations
	OpKeysGet     PolicyOperation = "get"
	OpKeysList    PolicyOperation = "list"
	OpKeysCreate  PolicyOperation = "create"
	OpKeysDelete  PolicyOperation = "delete"
	OpKeysRotate  PolicyOperation = "rotate"
	OpKeysSign    PolicyOperation = "sign"
	OpKeysVerify  PolicyOperation = "verify"
	OpKeysEncrypt PolicyOperation = "encrypt"
	OpKeysDecrypt PolicyOperation = "decrypt"

	// Certificates operations
	OpCertificatesGet    PolicyOperation = "get"
	OpCertificatesList   PolicyOperation = "list"
	OpCertificatesCreate PolicyOperation = "create"
	OpCertificatesDelete PolicyOperation = "delete"
	OpCertificatesImport PolicyOperation = "import"
	OpCertificatesRenew  PolicyOperation = "renew"
)

// AccessPolicy maps a principal to an allow/deny effect for one operation on one resource type.
type AccessPolicy struct {
	ID            uuid.UUID          `json:"id"`
	PrincipalID   uuid.UUID          `json:"principal_id"`
	PrincipalType PrincipalType      `json:"principal_type"`
	ResourceType  PolicyResourceType `json:"resource_type"`
	Operation     PolicyOperation    `json:"operation"`
	Effect        PolicyEffect       `json:"effect"`
	CreatedAt     time.Time          `json:"created_at"`
}
```

#### Step 2: Build to verify

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 3: Commit

```bash
git add internal/domain/access_policy.go
git commit -m "feat(domain): add AccessPolicy domain type and operation constants"
```

---

### Task 3: Repository — AccessPolicyRepository (TDD)

**Files:**
- Create: `internal/repositories/access_policy_repository_test.go`
- Create: `internal/repositories/access_policy_repository.go`

#### Step 1: Write the failing tests

Create `internal/repositories/access_policy_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/repositories"
)

func TestAccessPolicyRepository_CreateAndGet(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	principalID := uuid.New()
	policy := &domain.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: domain.PrincipalTypeUser,
		ResourceType:  domain.PolicyResourceSecrets,
		Operation:     domain.OpSecretsGet,
		Effect:        domain.PolicyEffectAllow,
	}

	require.NoError(t, repo.Create(ctx, policy))

	got, err := repo.GetByID(ctx, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.ID, got.ID)
	assert.Equal(t, domain.PolicyEffectAllow, got.Effect)
}

func TestAccessPolicyRepository_ListByPrincipal(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	principalID := uuid.New()
	otherID := uuid.New()

	p1 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceSecrets, Operation: domain.OpSecretsGet, Effect: domain.PolicyEffectAllow,
	}
	p2 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceKeys, Operation: domain.OpKeysList, Effect: domain.PolicyEffectDeny,
	}
	p3 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: otherID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceSecrets, Operation: domain.OpSecretsList, Effect: domain.PolicyEffectAllow,
	}
	require.NoError(t, repo.Create(ctx, p1))
	require.NoError(t, repo.Create(ctx, p2))
	require.NoError(t, repo.Create(ctx, p3))

	results, err := repo.ListByPrincipal(ctx, principalID)
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestAccessPolicyRepository_Delete(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	policy := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceCertificates, Operation: domain.OpCertificatesGet,
		Effect: domain.PolicyEffectAllow,
	}
	require.NoError(t, repo.Create(ctx, policy))
	require.NoError(t, repo.Delete(ctx, policy.ID))

	_, err := repo.GetByID(ctx, policy.ID)
	assert.Error(t, err)
}
```

#### Step 2: Run tests to confirm they fail

```bash
go test ./internal/repositories/... -run TestAccessPolicy -v
```

Expected: compilation error ("NewAccessPolicyRepository" undefined).

#### Step 3: Implement the repository

Create `internal/repositories/access_policy_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/domain"
)

// AccessPolicyRepositoryInterface defines the data access contract for access policies.
type AccessPolicyRepositoryInterface interface {
	Create(ctx context.Context, policy *domain.AccessPolicy) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.AccessPolicy, error)
	List(ctx context.Context) ([]*domain.AccessPolicy, error)
	ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*domain.AccessPolicy, error)
	// FindEffects returns all policies that match the exact lookup triple.
	FindEffects(ctx context.Context, principalID uuid.UUID, resourceType domain.PolicyResourceType, operation domain.PolicyOperation) ([]*domain.AccessPolicy, error)
	Update(ctx context.Context, policy *domain.AccessPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type accessPolicyRepository struct {
	db *sql.DB
}

// NewAccessPolicyRepository creates a new AccessPolicyRepository.
func NewAccessPolicyRepository(db *sql.DB) AccessPolicyRepositoryInterface {
	return &accessPolicyRepository{db: db}
}

func (r *accessPolicyRepository) Create(ctx context.Context, p *domain.AccessPolicy) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(), p.PrincipalID.String(), string(p.PrincipalType),
		string(p.ResourceType), string(p.Operation), string(p.Effect), p.CreatedAt,
	)
	return err
}

func (r *accessPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.AccessPolicy, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, created_at
		 FROM access_policies WHERE id = ?`, id.String())
	return scanPolicy(row)
}

func (r *accessPolicyRepository) List(ctx context.Context) ([]*domain.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, created_at
		 FROM access_policies ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPolicies(rows)
}

func (r *accessPolicyRepository) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*domain.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, created_at
		 FROM access_policies WHERE principal_id = ? ORDER BY created_at DESC`, principalID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPolicies(rows)
}

func (r *accessPolicyRepository) FindEffects(ctx context.Context, principalID uuid.UUID, resourceType domain.PolicyResourceType, operation domain.PolicyOperation) ([]*domain.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, created_at
		 FROM access_policies
		 WHERE principal_id = ? AND resource_type = ? AND operation = ?`,
		principalID.String(), string(resourceType), string(operation))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPolicies(rows)
}

func (r *accessPolicyRepository) Update(ctx context.Context, p *domain.AccessPolicy) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE access_policies SET principal_type = ?, resource_type = ?, operation = ?, effect = ?
		 WHERE id = ?`,
		string(p.PrincipalType), string(p.ResourceType), string(p.Operation), string(p.Effect), p.ID.String(),
	)
	return err
}

func (r *accessPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM access_policies WHERE id = ?`, id.String())
	return err
}

// scanPolicy scans a single row into an AccessPolicy.
func scanPolicy(row *sql.Row) (*domain.AccessPolicy, error) {
	var p domain.AccessPolicy
	var idStr, principalStr string
	err := row.Scan(&idStr, &principalStr,
		&p.PrincipalType, &p.ResourceType, &p.Operation, &p.Effect, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("access policy not found")
	}
	if err != nil {
		return nil, err
	}
	p.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, err
	}
	p.PrincipalID, err = uuid.Parse(principalStr)
	return &p, err
}

// scanPolicies scans multiple rows into AccessPolicy slice.
func scanPolicies(rows *sql.Rows) ([]*domain.AccessPolicy, error) {
	var results []*domain.AccessPolicy
	for rows.Next() {
		var p domain.AccessPolicy
		var idStr, principalStr string
		if err := rows.Scan(&idStr, &principalStr,
			&p.PrincipalType, &p.ResourceType, &p.Operation, &p.Effect, &p.CreatedAt); err != nil {
			return nil, err
		}
		var err error
		p.ID, err = uuid.Parse(idStr)
		if err != nil {
			return nil, err
		}
		p.PrincipalID, err = uuid.Parse(principalStr)
		if err != nil {
			return nil, err
		}
		results = append(results, &p)
	}
	return results, rows.Err()
}
```

#### Step 4: Run tests to confirm they pass

```bash
go test ./internal/repositories/... -run TestAccessPolicy -v
```

Expected: PASS (3 tests).

#### Step 5: Commit

```bash
git add internal/repositories/access_policy_repository.go internal/repositories/access_policy_repository_test.go
git commit -m "feat(repositories): add AccessPolicyRepository with CRUD and FindEffects"
```

---

### Task 4: Service — AccessPolicyService (TDD)

**Files:**
- Create: `internal/services/authorization/access_policy_service_test.go`
- Create: `internal/services/authorization/access_policy_service.go`

#### Step 1: Write the failing tests

Create `internal/services/authorization/access_policy_service_test.go`:

```go
package authorization_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/services/authorization"
)

// mockPolicyRepo is a testify mock implementing AccessPolicyRepositoryInterface.
type mockPolicyRepo struct{ mock.Mock }

func (m *mockPolicyRepo) Create(ctx context.Context, p *domain.AccessPolicy) error {
	return m.Called(ctx, p).Error(0)
}
func (m *mockPolicyRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.AccessPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*domain.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) List(ctx context.Context) ([]*domain.AccessPolicy, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*domain.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) ListByPrincipal(ctx context.Context, id uuid.UUID) ([]*domain.AccessPolicy, error) {
	args := m.Called(ctx, id)
	return args.Get(0).([]*domain.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) FindEffects(ctx context.Context, pid uuid.UUID, rt domain.PolicyResourceType, op domain.PolicyOperation) ([]*domain.AccessPolicy, error) {
	args := m.Called(ctx, pid, rt, op)
	return args.Get(0).([]*domain.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) Update(ctx context.Context, p *domain.AccessPolicy) error {
	return m.Called(ctx, p).Error(0)
}
func (m *mockPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func TestCheckAccess_AllowWhenPolicyExists(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()

	repo.On("FindEffects", ctx, pid, domain.PolicyResourceSecrets, domain.OpSecretsGet).
		Return([]*domain.AccessPolicy{{Effect: domain.PolicyEffectAllow}}, nil)

	result, err := svc.CheckAccess(ctx, pid, domain.PolicyResourceSecrets, domain.OpSecretsGet)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessAllowed, result)
}

func TestCheckAccess_DenyWinsOverAllow(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()

	repo.On("FindEffects", ctx, pid, domain.PolicyResourceSecrets, domain.OpSecretsDelete).
		Return([]*domain.AccessPolicy{
			{Effect: domain.PolicyEffectAllow},
			{Effect: domain.PolicyEffectDeny},
		}, nil)

	result, err := svc.CheckAccess(ctx, pid, domain.PolicyResourceSecrets, domain.OpSecretsDelete)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessDenied, result)
}

func TestCheckAccess_FallbackWhenNoPolicies(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()

	repo.On("FindEffects", ctx, pid, domain.PolicyResourceKeys, domain.OpKeysCreate).
		Return([]*domain.AccessPolicy{}, nil)

	result, err := svc.CheckAccess(ctx, pid, domain.PolicyResourceKeys, domain.OpKeysCreate)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessFallback, result)
}
```

#### Step 2: Run tests to confirm they fail

```bash
go test ./internal/services/authorization/... -run TestCheckAccess -v
```

Expected: compilation error ("NewAccessPolicyService" undefined).

#### Step 3: Implement the service

Create `internal/services/authorization/access_policy_service.go`:

```go
package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/domain"
	"rocketvault/internal/repositories"
)

// AccessDecision is the result of CheckAccess.
type AccessDecision int

const (
	// AccessAllowed — an explicit allow policy exists and no deny policy exists.
	AccessAllowed AccessDecision = iota
	// AccessDenied — at least one explicit deny policy exists.
	AccessDenied
	// AccessFallback — no policy row found; caller should use RBAC.
	AccessFallback
)

// AccessPolicyService provides CRUD and access-check operations for access policies.
type AccessPolicyService interface {
	// CheckAccess evaluates policies for the principal/resource/operation triple.
	// Returns AccessAllowed, AccessDenied, or AccessFallback.
	CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType domain.PolicyResourceType, operation domain.PolicyOperation) (AccessDecision, error)

	CreatePolicy(ctx context.Context, policy *domain.AccessPolicy) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*domain.AccessPolicy, error)
	ListPolicies(ctx context.Context) ([]*domain.AccessPolicy, error)
	ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*domain.AccessPolicy, error)
	UpdatePolicy(ctx context.Context, policy *domain.AccessPolicy) error
	DeletePolicy(ctx context.Context, id uuid.UUID) error
}

type accessPolicyService struct {
	repo repositories.AccessPolicyRepositoryInterface
}

// NewAccessPolicyService creates a new AccessPolicyService.
func NewAccessPolicyService(repo repositories.AccessPolicyRepositoryInterface) AccessPolicyService {
	return &accessPolicyService{repo: repo}
}

func (s *accessPolicyService) CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType domain.PolicyResourceType, operation domain.PolicyOperation) (AccessDecision, error) {
	policies, err := s.repo.FindEffects(ctx, principalID, resourceType, operation)
	if err != nil {
		return AccessFallback, fmt.Errorf("access policy lookup: %w", err)
	}
	if len(policies) == 0 {
		return AccessFallback, nil
	}
	for _, p := range policies {
		if p.Effect == domain.PolicyEffectDeny {
			return AccessDenied, nil
		}
	}
	return AccessAllowed, nil
}

func (s *accessPolicyService) CreatePolicy(ctx context.Context, policy *domain.AccessPolicy) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}
	return s.repo.Create(ctx, policy)
}

func (s *accessPolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*domain.AccessPolicy, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *accessPolicyService) ListPolicies(ctx context.Context) ([]*domain.AccessPolicy, error) {
	return s.repo.List(ctx)
}

func (s *accessPolicyService) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*domain.AccessPolicy, error) {
	return s.repo.ListByPrincipal(ctx, principalID)
}

func (s *accessPolicyService) UpdatePolicy(ctx context.Context, policy *domain.AccessPolicy) error {
	return s.repo.Update(ctx, policy)
}

func (s *accessPolicyService) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	return s.repo.Delete(ctx, id)
}
```

#### Step 4: Run tests to confirm they pass

```bash
go test ./internal/services/authorization/... -v
```

Expected: PASS (all tests including the 3 new ones).

#### Step 5: Commit

```bash
git add internal/services/authorization/access_policy_service.go internal/services/authorization/access_policy_service_test.go
git commit -m "feat(authorization): add AccessPolicyService with CheckAccess logic"
```

---

### Task 5: Wire AccessPolicyService into ServiceContainer

**Files:**
- Modify: `internal/container/service_container.go`

#### Step 1: Add the interface method to `ServiceContainerInterface`

In `ServiceContainerInterface`, add after `GetRBACService()`:

```go
GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface
GetAccessPolicyService() authzServices.AccessPolicyService
```

#### Step 2: Add the fields to `ServiceContainer`

In the `ServiceContainer` struct, add after `rbacService`:

```go
accessPolicyRepository repositories.AccessPolicyRepositoryInterface
accessPolicyService    authzServices.AccessPolicyService
```

#### Step 3: Initialize in the initializer function

Find where `rbacService` is initialized and add after it:

```go
// Access policy
sc.accessPolicyRepository = repositories.NewAccessPolicyRepository(sc.db)
sc.accessPolicyService = authzServices.NewAccessPolicyService(sc.accessPolicyRepository)
```

#### Step 4: Add getter methods

```go
// GetAccessPolicyRepository returns the access policy repository.
func (sc *ServiceContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	return sc.accessPolicyRepository
}

// GetAccessPolicyService returns the access policy service.
func (sc *ServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return sc.accessPolicyService
}
```

#### Step 5: Build to verify

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 6: Run full tests

```bash
go test ./... -count=1
```

Expected: all pass.

#### Step 7: Commit

```bash
git add internal/container/service_container.go
git commit -m "feat(container): add AccessPolicyRepository and AccessPolicyService to service container"
```

---

### Task 6: PolicyMiddleware — per-operation policy check

**Files:**
- Modify: `internal/middleware/middleware.go`

The `PolicyMiddleware` sits **after** auth (JWT validated, claims in context) but provides a `http.Handler` wrapper that is applied per-route group. It does:
1. Extracts user UUID from context claims
2. Maps the current HTTP method + mux path template to (resource_type, operation)
3. Calls `AccessPolicyService.CheckAccess`
4. If `AccessDenied` → 403. If `AccessAllowed` or `AccessFallback` → continue (RBAC runs next if it's a fallback — the existing RBAC middleware is already in the chain).

#### Step 1: Add `GetAccessPolicyService` to the `Container` interface in middleware.go

In `middleware.go`, the local `Container` interface currently has:
```go
type Container interface {
    GetLogger() *logging.Logger
    GetAuthenticationService() authServices.AuthenticationService
    GetRBACService() authzServices.RBACService
}
```

Add the access policy getter:

```go
GetAccessPolicyService() authzServices.AccessPolicyService
```

Also add the needed import for `authzServices` (it already is imported — confirm with grep first).

#### Step 2: Add operation mapping helper

Append to `middleware.go`:

```go
// resolvePolicy maps an HTTP method and Gorilla route template to a
// (resource_type, operation) pair.  Returns ("", "") when no mapping exists
// (i.e., non-resource routes like /health or /users/login).
func resolvePolicy(method, routeTemplate string) (domain.PolicyResourceType, domain.PolicyOperation) {
	type mapping struct {
		method   string
		suffix   string
		resource domain.PolicyResourceType
		op       domain.PolicyOperation
	}
	mappings := []mapping{
		// Secrets
		{"GET", "/secrets", domain.PolicyResourceSecrets, domain.OpSecretsList},
		{"GET", "/secrets/{id}", domain.PolicyResourceSecrets, domain.OpSecretsGet},
		{"POST", "/secrets", domain.PolicyResourceSecrets, domain.OpSecretsSet},
		{"PUT", "/secrets/{id}", domain.PolicyResourceSecrets, domain.OpSecretsSet},
		{"DELETE", "/secrets/{id}", domain.PolicyResourceSecrets, domain.OpSecretsDelete},
		// Keys
		{"GET", "/keys", domain.PolicyResourceKeys, domain.OpKeysList},
		{"GET", "/keys/{id}", domain.PolicyResourceKeys, domain.OpKeysGet},
		{"POST", "/keys", domain.PolicyResourceKeys, domain.OpKeysCreate},
		{"PUT", "/keys/{id}", domain.PolicyResourceKeys, domain.OpKeysCreate},
		{"DELETE", "/keys/{id}", domain.PolicyResourceKeys, domain.OpKeysDelete},
		// Certificates
		{"GET", "/certificates", domain.PolicyResourceCertificates, domain.OpCertificatesList},
		{"GET", "/certificates/{id}", domain.PolicyResourceCertificates, domain.OpCertificatesGet},
		{"POST", "/certificates", domain.PolicyResourceCertificates, domain.OpCertificatesCreate},
		{"PUT", "/certificates/{id}", domain.PolicyResourceCertificates, domain.OpCertificatesCreate},
		{"DELETE", "/certificates/{id}", domain.PolicyResourceCertificates, domain.OpCertificatesDelete},
	}
	for _, m := range mappings {
		if m.method == method && strings.HasSuffix(routeTemplate, m.suffix) {
			return m.resource, m.op
		}
	}
	return "", ""
}
```

Add `"rocketvault/internal/domain"` to the middleware.go imports.

#### Step 3: Add PolicyMiddleware method

```go
// PolicyMiddleware checks per-operation access policies before passing the
// request to the next handler.  It runs AFTER AuthenticationMiddleware (claims
// are already in context).  If no policy row exists the request falls through
// to the existing RBAC layer unchanged.
func (m *Middleware) PolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(common.ContextKeyClaims).(*domain.Claims)
		if !ok || claims == nil {
			// Unauthenticated — let the auth middleware deal with it.
			next.ServeHTTP(w, r)
			return
		}

		principalID, err := uuid.Parse(claims.UserID)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		route := mux.CurrentRoute(r)
		var routeTemplate string
		if route != nil {
			routeTemplate, _ = route.GetPathTemplate()
		}

		resourceType, operation := resolvePolicy(r.Method, routeTemplate)
		if resourceType == "" {
			// Non-resource route (health, auth, etc.) — skip policy check.
			next.ServeHTTP(w, r)
			return
		}

		decision, err := m.container.GetAccessPolicyService().CheckAccess(
			r.Context(), principalID, resourceType, operation,
		)
		if err != nil {
			m.logger.WithError(err).Warn("policy check error — falling through to RBAC")
			next.ServeHTTP(w, r)
			return
		}

		if decision == authzServices.AccessDenied {
			common.RenderError(w, r, common.NewAppError("PolicyMiddleware",
				"Access denied by policy", nil, "", http.StatusForbidden))
			return
		}

		next.ServeHTTP(w, r)
	})
}
```

You'll need to import `"github.com/google/uuid"` and `"github.com/gorilla/mux"` — check if they're already present; add only what's missing.

#### Step 4: Register PolicyMiddleware in api.go

In `api/api.go`, in `Init()` where `BaseRoutes["ApiRoot"].Use(...)` is called, add `middleware.PolicyMiddleware` after the auth middleware:

```go
api.BaseRoutes["ApiRoot"].Use(middleware.PolicyMiddleware)
```

(The exact position: after `AuthenticationMiddleware`, before any business routes.)

#### Step 5: Build

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 6: Run full tests

```bash
go test ./... -count=1
```

Expected: all pass.

#### Step 7: Commit

```bash
git add internal/middleware/middleware.go api/api.go
git commit -m "feat(middleware): add PolicyMiddleware for per-operation access control"
```

---

### Task 7: API handlers for access policy CRUD

**Files:**
- Create: `api/access_policies.go`
- Modify: `api/api.go` (register new routes)

#### Step 1: Create API handler file

Create `api/access_policies.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/common"
	"rocketvault/internal/domain"
)

// listAccessPolicies returns all access policies (admin only).
func listAccessPolicies(c *Context, w http.ResponseWriter, r *http.Request) {
	policies, err := c.App.ServiceContainer.GetAccessPolicyService().ListPolicies(r.Context())
	if err != nil {
		c.Err = common.NewAppError("listAccessPolicies", "Failed to list policies", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"policies": policies, "total": len(policies)})
}

// createAccessPolicy creates a new access policy.
func createAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrincipalID   string `json:"principal_id"`
		PrincipalType string `json:"principal_type"`
		ResourceType  string `json:"resource_type"`
		Operation     string `json:"operation"`
		Effect        string `json:"effect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("createAccessPolicy", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	principalID, err := uuid.Parse(req.PrincipalID)
	if err != nil {
		c.Err = common.NewAppError("createAccessPolicy", "Invalid principal_id", nil, err.Error(), http.StatusBadRequest)
		return
	}
	policy := &domain.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: domain.PrincipalType(req.PrincipalType),
		ResourceType:  domain.PolicyResourceType(req.ResourceType),
		Operation:     domain.PolicyOperation(req.Operation),
		Effect:        domain.PolicyEffect(req.Effect),
		CreatedAt:     time.Now(),
	}
	if err := c.App.ServiceContainer.GetAccessPolicyService().CreatePolicy(r.Context(), policy); err != nil {
		c.Err = common.NewAppError("createAccessPolicy", "Failed to create policy", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

// getAccessPolicy returns a single access policy by ID.
func getAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "getAccessPolicy")
	if appErr != nil {
		c.Err = appErr
		return
	}
	policy, err := c.App.ServiceContainer.GetAccessPolicyService().GetPolicy(r.Context(), id)
	if err != nil {
		c.Err = common.NewAppError("getAccessPolicy", "Policy not found", nil, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// updateAccessPolicy replaces a policy's effect/operation fields.
func updateAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "updateAccessPolicy")
	if appErr != nil {
		c.Err = appErr
		return
	}
	var req struct {
		Effect    string `json:"effect"`
		Operation string `json:"operation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("updateAccessPolicy", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	policy, err := c.App.ServiceContainer.GetAccessPolicyService().GetPolicy(r.Context(), id)
	if err != nil {
		c.Err = common.NewAppError("updateAccessPolicy", "Policy not found", nil, err.Error(), http.StatusNotFound)
		return
	}
	if req.Effect != "" {
		policy.Effect = domain.PolicyEffect(req.Effect)
	}
	if req.Operation != "" {
		policy.Operation = domain.PolicyOperation(req.Operation)
	}
	if err := c.App.ServiceContainer.GetAccessPolicyService().UpdatePolicy(r.Context(), policy); err != nil {
		c.Err = common.NewAppError("updateAccessPolicy", "Failed to update policy", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// deleteAccessPolicy permanently deletes a policy.
func deleteAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "deleteAccessPolicy")
	if appErr != nil {
		c.Err = appErr
		return
	}
	if err := c.App.ServiceContainer.GetAccessPolicyService().DeletePolicy(r.Context(), id); err != nil {
		c.Err = common.NewAppError("deleteAccessPolicy", "Failed to delete policy", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Policy deleted", "id": id.String()})
}

// listAccessPoliciesByPrincipal returns all policies for a principal UUID.
func listAccessPoliciesByPrincipal(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	principalID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("listAccessPoliciesByPrincipal", "Invalid principal id", nil, err.Error(), http.StatusBadRequest)
		return
	}
	policies, err := c.App.ServiceContainer.GetAccessPolicyService().ListByPrincipal(r.Context(), principalID)
	if err != nil {
		c.Err = common.NewAppError("listAccessPoliciesByPrincipal", "Failed to list policies", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"policies": policies, "total": len(policies)})
}
```

#### Step 2: Register routes in api.go

Find the section in `api/api.go`'s `Init()` (or a dedicated route-init method) where secrets/keys/certs routes are registered. Add after the existing routes:

```go
// Access Policy routes (admin)
api.BaseRoutes["ApiRoot"].Handle("/access-policies", api.APIHandler(listAccessPolicies)).Methods("GET")
api.BaseRoutes["ApiRoot"].Handle("/access-policies", api.APIHandler(createAccessPolicy)).Methods("POST")
api.BaseRoutes["ApiRoot"].Handle("/access-policies/{id}", api.APIHandler(getAccessPolicy)).Methods("GET")
api.BaseRoutes["ApiRoot"].Handle("/access-policies/{id}", api.APIHandler(updateAccessPolicy)).Methods("PUT")
api.BaseRoutes["ApiRoot"].Handle("/access-policies/{id}", api.APIHandler(deleteAccessPolicy)).Methods("DELETE")
api.BaseRoutes["ApiRoot"].Handle("/access-policies/principal/{id}", api.APIHandler(listAccessPoliciesByPrincipal)).Methods("GET")
```

#### Step 3: Build

```bash
go build -o rocketvault .
```

Expected: no errors.

#### Step 4: Run full tests

```bash
go test ./... -count=1
```

Expected: all pass.

#### Step 5: Commit

```bash
git add api/access_policies.go api/api.go
git commit -m "feat(api): add access policy CRUD and principal-lookup endpoints — Milestone 2"
```

---

### Task 8: Full verification

#### Step 1: Run full test suite

```bash
go test ./... -count=1
```

Expected: all packages pass.

#### Step 2: Verify routes are registered

```bash
./rocketvault serve &
sleep 1
curl -si http://localhost:8080/api/v1/access-policies | head -3
kill %1
```

Expected: `HTTP/1.1 401 Unauthorized` (unauthenticated request — policy route exists but auth required). A `404` means the route wasn't registered.

#### Step 3: Push

```bash
git push origin v-4.0.0
```

---

## Summary

| Task | What | Commit |
|---|---|---|
| 1 | DB migration + schema update | `feat(db): add access_policies table — Milestone 2` |
| 2 | Domain type AccessPolicy | `feat(domain): add AccessPolicy domain type and operation constants` |
| 3 | AccessPolicyRepository | `feat(repositories): add AccessPolicyRepository with CRUD and FindEffects` |
| 4 | AccessPolicyService + CheckAccess | `feat(authorization): add AccessPolicyService with CheckAccess logic` |
| 5 | Wire into ServiceContainer | `feat(container): add AccessPolicyRepository and AccessPolicyService to service container` |
| 6 | PolicyMiddleware | `feat(middleware): add PolicyMiddleware for per-operation access control` |
| 7 | API handlers + routes | `feat(api): add access policy CRUD and principal-lookup endpoints — Milestone 2` |
| 8 | Verification + push | — |
