# CanCreateVault Authorization Decision — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one authorization primitive that decides whether a principal may create a vault, and route both the HTTP handler and the CLI through it.

**Architecture:** `CanCreateVault` returns *which* right applied — admin, global grant, or provisioning grant — so the caller can enforce quota only on the provisioning path and attribute the decision in the audit trail. HTTP and CLI share the one primitive so they cannot drift, matching how `CanManageVault` already backs both `api/vault.go` and `cmd/vaults/authz.go`.

**Tech Stack:** Go 1.24, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §5

**Depends on:** `…-02-purge-cleanup-and-service.md` — `provisioning.GrantService` and `GetGrantService()` must exist.
**Followed by:** `…-04-transactional-create.md`, which consumes the returned right to decide whether to enforce quota.

## Global Constraints

- **Release 1 is additive only.** A principal who could create a vault before this plan must still be able to afterwards. `CanCreateVault` widens the set of principals who may create; it never narrows it.
- The CLI bypasses `PolicyMiddleware` entirely, so a CLI command that skips its own check has no other enforcement point (`CLAUDE.md`, CLI Authorization).
- Authorization primitives fail closed: a nil dependency or a service error denies (`internal/services/authorization/vault_authz.go:27-33`).
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: The CanCreateVault primitive

**Files:**
- Modify: `internal/services/authorization/vault_authz.go`
- Test: `internal/services/authorization/vault_authz_test.go`

**Interfaces:**
- Consumes: `provisioning.GrantService` and `provisioning.ErrGrantNotFound` from plan 02.
- Produces:
  - `type CreateRight int` with `CreateRightNone`, `CreateRightAdmin`, `CreateRightGlobalPolicy`, `CreateRightProvisioningGrant`
  - `func CanCreateVault(ctx context.Context, accountRoles []string, policies AccessPolicyService, grants GrantReader, principalID uuid.UUID) CreateRight`
  - `type GrantReader interface { GetGrant(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error) }`
  - Tasks 2 and 3, and plan 04, all consume these.

A local `GrantReader` interface is declared here rather than importing `provisioning.GrantService` so the authorization package does not depend on the provisioning package — the dependency runs the other way in the container, and importing would risk a cycle.

Returning `CreateRight` rather than a bool is what lets plan 04 apply quota **only** on the provisioning path. An admin or global-policy holder is not quota-bounded.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/authorization/vault_authz_test.go`:

```go
// stubGrantReader returns a fixed grant or error for any principal.
type stubGrantReader struct {
	grant *model.VaultProvisioningGrant
	err   error
}

func (s *stubGrantReader) GetGrant(_ context.Context, _ uuid.UUID) (*model.VaultProvisioningGrant, error) {
	return s.grant, s.err
}

func TestCanCreateVault(t *testing.T) {
	principal := uuid.New()
	grant := &model.VaultProvisioningGrant{PrincipalID: principal, Quota: 3}

	tests := []struct {
		name     string
		roles    []string
		policies authz.AccessPolicyService
		grants   authz.GrantReader
		want     authz.CreateRight
	}{
		{
			name:  "global admin",
			roles: []string{string(model.RoleAdmin)},
			want:  authz.CreateRightAdmin,
		},
		{
			name:     "global vaults:manage allow",
			roles:    []string{"user"},
			policies: &stubPolicyService{decision: authz.AccessAllowed},
			want:     authz.CreateRightGlobalPolicy,
		},
		{
			name:     "provisioning grant",
			roles:    []string{"user"},
			policies: &stubPolicyService{decision: authz.AccessFallback},
			grants:   &stubGrantReader{grant: grant},
			want:     authz.CreateRightProvisioningGrant,
		},
		{
			name:     "no right at all",
			roles:    []string{"user"},
			policies: &stubPolicyService{decision: authz.AccessFallback},
			grants:   &stubGrantReader{err: provisioning.ErrGrantNotFound},
			want:     authz.CreateRightNone,
		},
		{
			name:     "explicit global deny beats a provisioning grant",
			roles:    []string{"user"},
			policies: &stubPolicyService{decision: authz.AccessDenied},
			grants:   &stubGrantReader{grant: grant},
			want:     authz.CreateRightNone,
		},
		{
			name:     "grant lookup error denies",
			roles:    []string{"user"},
			policies: &stubPolicyService{decision: authz.AccessFallback},
			grants:   &stubGrantReader{err: errors.New("database down")},
			want:     authz.CreateRightNone,
		},
		{
			name:     "nil grant reader denies without panicking",
			roles:    []string{"user"},
			policies: &stubPolicyService{decision: authz.AccessFallback},
			grants:   nil,
			want:     authz.CreateRightNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authz.CanCreateVault(context.Background(), tt.roles, tt.policies, tt.grants, principal)
			require.Equal(t, tt.want, got)
		})
	}
}
```

Reuse the package's existing access-policy stub if one is already present in that test file; only add `stubPolicyService` if there is none.

The "explicit global deny beats a provisioning grant" case is the important one. An operator who has explicitly denied a principal `(vaults, manage)` must not be silently overridden by a grant issued later — deny-overrides is the invariant `PolicyMiddleware` states and `CanManageRoleAssignments` already honours (`vault_authz.go:76-79`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run TestCanCreateVault -v`
Expected: FAIL — `undefined: authz.CanCreateVault`.

- [ ] **Step 3: Write the implementation**

Append to `internal/services/authorization/vault_authz.go`:

```go
// CreateRight identifies which authority permitted a vault creation. The
// caller needs to know which, not merely whether: only the provisioning-grant
// path is quota-bounded.
type CreateRight int

const (
	// CreateRightNone means the principal may not create a vault.
	CreateRightNone CreateRight = iota
	// CreateRightAdmin is the global admin account role. Not quota-bounded.
	CreateRightAdmin
	// CreateRightGlobalPolicy is a global (vault_id NULL) vaults:manage allow
	// policy. Not quota-bounded.
	CreateRightGlobalPolicy
	// CreateRightProvisioningGrant is a vault_provisioning_grants row. Quota
	// applies -- the caller MUST enforce it inside the creation transaction.
	CreateRightProvisioningGrant
)

// GrantReader reads a principal's provisioning grant. Declared here rather
// than importing internal/services/provisioning so this package keeps no
// dependency on that one; the container wires the concrete service in.
type GrantReader interface {
	GetGrant(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error)
}

// CanCreateVault reports which right, if any, permits principalID to create a
// vault: the global admin account role, a global vaults:manage allow policy,
// or a provisioning grant -- checked in that order.
//
// An explicit global DENY on (vaults, manage) short-circuits to
// CreateRightNone and is never outvoted by a provisioning grant, matching the
// deny-overrides invariant PolicyMiddleware states and CanManageRoleAssignments
// honours.
//
// A nil dependency or any service error denies -- this function fails closed.
func CanCreateVault(ctx context.Context, accountRoles []string, policies AccessPolicyService, grants GrantReader, principalID uuid.UUID) CreateRight {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return CreateRightAdmin
	}
	if policies != nil {
		decision, err := policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, uuid.Nil)
		if err == nil {
			if decision == AccessAllowed {
				return CreateRightGlobalPolicy
			}
			if decision == AccessDenied {
				return CreateRightNone
			}
		}
	}
	if grants == nil {
		return CreateRightNone
	}
	g, err := grants.GetGrant(ctx, principalID)
	if err != nil || g == nil {
		return CreateRightNone
	}
	return CreateRightProvisioningGrant
}
```

Add `"rocketvault/model"` to the imports if not already present.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/authorization/ -run TestCanCreateVault -v`
Expected: PASS

- [ ] **Step 5: Run the whole authorization suite**

Run: `go test ./internal/services/authorization/`
Expected: PASS — `CanManageVault` and `CanManageRoleAssignments` are untouched.

- [ ] **Step 6: Commit**

```bash
git add internal/services/authorization/vault_authz.go \
        internal/services/authorization/vault_authz_test.go
git commit -S -m "feat(authz): add CanCreateVault with provisioning grants"
```

---

### Task 2: Route the HTTP handler through it

**Files:**
- Modify: `api/vault.go:67-90` (`createVault`)
- Test: `api/vault_test.go`

**Interfaces:**
- Consumes: `authzServices.CanCreateVault` and `authzServices.CreateRight` from task 1; `c.App.ServiceContainer.GetGrantService()` from plan 02.
- Produces: `createVault` now admits provisioning-grant holders. Plan 04 adds the quota enforcement behind it.

**Until plan 04 lands, a grantee can create vaults without a quota being enforced.** That is acceptable only because no grant can exist until an operator issues one through plan 06's admin API, which also does not exist yet. Do not ship release 1 with plan 04 unimplemented.

- [ ] **Step 1: Write the failing test**

Add to `api/vault_test.go`:

```go
func TestCreateVault_ProvisioningGrantHolderAllowed(t *testing.T) {
	api := newTestAPIWithGrant(t, uuid.New(), 5) // helper added in Step 3

	w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults",
		[]byte(`{"name":"acme-prod"}`))

	require.Equal(t, http.StatusCreated, w.Code,
		"a provisioning-grant holder must be able to create a vault")
}

func TestCreateVault_NoRightStillForbidden(t *testing.T) {
	api := newTestAPINoGrant(t) // helper added in Step 3

	w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults",
		[]byte(`{"name":"acme-prod"}`))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a principal with neither admin, a global policy, nor a grant is still refused")
}
```

Build the helpers on the file's existing test-API constructor and `doVaultRequest` (used at `api/vault_webhook_test.go:91`); do not introduce a parallel harness.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/ -run 'TestCreateVault_ProvisioningGrantHolderAllowed|TestCreateVault_NoRightStillForbidden' -v`
Expected: FAIL — the grant holder gets `403`.

- [ ] **Step 3: Replace the check in createVault**

In `api/vault.go`, replace the `CanManageVault` call at line 77:

```go
	if !authzServices.CanManageVault(r.Context(), roles, c.App.ServiceContainer.GetAccessPolicyService(), userID, uuid.Nil) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
```

with:

```go
	// Vault creation has no single target vault, so authorization is a
	// three-way decision rather than a scoped check: the global admin role, a
	// global (vault_id NULL) vaults:manage allow policy, or a bounded
	// provisioning grant. Which one applied matters -- only the grant path is
	// quota-bounded, and the quota is enforced inside CreateVault's
	// transaction, where it cannot race the insert.
	right := authzServices.CanCreateVault(r.Context(), roles,
		c.App.ServiceContainer.GetAccessPolicyService(),
		c.App.ServiceContainer.GetGrantService(), userID)
	if right == authzServices.CreateRightNone {
		c.SetPermissionError("admin, vaults/manage, or a vault provisioning grant required")
		return
	}
```

Update the handler's doc comment (lines 61-66) to describe all three rights rather than only the global grant.

- [ ] **Step 4: Run tests**

Run: `go test ./api/ -run TestCreateVault -v`
Expected: PASS — including the pre-existing create tests.

- [ ] **Step 5: Commit**

```bash
git add api/vault.go api/vault_test.go
git commit -S -m "feat(api): admit provisioning-grant holders to createVault"
```

---

### Task 3: Route the CLI through it

**Files:**
- Modify: `cmd/vaults/authz.go:52-58` (`requireCanCreateVault`)
- Test: `cmd/vaults/authz_test.go`

**Interfaces:**
- Consumes: `authz.CanCreateVault` from task 1; `sc.GetGrantService()` from plan 02.
- Produces: `requireCanCreateVault` keeps its `(ctx, sc) error` signature, so no caller changes.

- [ ] **Step 1: Write the failing test**

Add to `cmd/vaults/authz_test.go`:

```go
func TestRequireCanCreateVault_AllowsGrantHolder(t *testing.T) {
	sc := newMockContainerWithGrant(t, testPrincipalID, 5) // helper on the file's existing mock container
	ctx := ctxWithClaims(t, testPrincipalID, []string{"user"})

	require.NoError(t, requireCanCreateVault(ctx, sc),
		"the CLI must reach the same decision as HTTP: both call CanCreateVault")
}

func TestRequireCanCreateVault_DeniesWithoutAnyRight(t *testing.T) {
	sc := newMockContainerNoGrant(t)
	ctx := ctxWithClaims(t, testPrincipalID, []string{"user"})

	require.Error(t, requireCanCreateVault(ctx, sc))
}
```

Use the file's existing mock-container and claims helpers; only add the grant-returning variants.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/vaults/ -run TestRequireCanCreateVault -v`
Expected: FAIL — the grant holder is denied.

- [ ] **Step 3: Update requireCanCreateVault**

In `cmd/vaults/authz.go`, replace the body's check:

```go
// requireCanCreateVault checks the three-way create decision: the global
// admin role, a global (not vault-specific) vaults:manage grant, or a bounded
// provisioning grant. There is no target vault to resolve yet when creating
// one, so this mirrors the HTTP createVault handler's use of CanCreateVault
// rather than a scoped check.
//
// The CLI bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path.
func requireCanCreateVault(ctx context.Context, sc container.ServiceContainerInterface) error {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	right := authz.CanCreateVault(ctx, roles, sc.GetAccessPolicyService(), sc.GetGrantService(), principalID)
	if right == authz.CreateRightNone {
		return fmt.Errorf("permission denied: admin, a global vaults/manage grant, or a vault provisioning grant required to create a vault")
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./cmd/vaults/ -v`
Expected: PASS

- [ ] **Step 5: Full build and vet**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/vaults/authz.go cmd/vaults/authz_test.go
git commit -S -m "feat(cli): admit provisioning-grant holders to vaults create"
```
