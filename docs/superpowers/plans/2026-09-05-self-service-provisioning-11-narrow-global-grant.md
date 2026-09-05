# Narrowing the Global `vaults:manage` Grant — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Narrow a global (`vault_id IS NULL`) `vaults:manage` allow to create-and-list only, so it no longer confers management of every existing vault or role-assignment management everywhere.

**Architecture:** Add `CheckVaultScopedAccess` to `AccessPolicyService`, where a NULL-scoped **deny** still matches but a NULL-scoped **allow** does not. `CanManageVault` and `CanManageRoleAssignments` call it whenever `vaultID != uuid.Nil`, and keep calling `CheckAccess` when `vaultID == uuid.Nil` (the create/list decision). Because the narrowing would otherwise strand a global-policy holder with a vault it cannot manage, the global-policy create path also starts writing the same creator grants the provisioning path already writes.

**Tech Stack:** Go 1.24, testify, SQLite/PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §2 and §9

**Depends on:** release 1 (plans 01–10), merged to `v-4.0.0` at `deff7e6`.

## Global Constraints

- **Do not implement the narrowing in `FindEffects` or `CheckAccess`.** Both are shared by `PolicyMiddleware` (`internal/middleware/middleware.go:536`) and `vaultcli.RequireDataAction` (`cmd/vaultcli/vault.go:47`) for secrets/keys/certificates, where `OR vault_id IS NULL` is exactly what makes a **global explicit deny** work. Narrowing there would silently disable every global deny — a worse security regression than the problem being fixed. Add a new method instead; leave `CheckAccess` untouched.
- **Both checks must be narrowed, not just one.** `CanManageRoleAssignments` alone is enough to self-award `Key Vault Administrator` in any vault, so narrowing only `CanManageVault` leaves the escalation path fully open.
- The global `admin` account role short-circuits every check (`vault_authz.go:24`) and must keep doing so. Platform operators are unaffected by this release.
- Deny widens, allow does not. That asymmetry is the entire point of `CheckVaultScopedAccess` — do not "simplify" it away.
- This is a **breaking** change. It is gated on release 1's `warnGlobalVaultManageGrants` diagnostic (`internal/db/db.go`) having reported from a real deployment.
- All commits are GPG-signed (`git commit -S`).
- `.claude/manual-testing-plan.md` and `.claude/roadmap-azure-parity-and-beyond.md` are gitignored and untracked (`.gitignore:127` ignores `.claude/` wholesale). Edit them, but do not expect them in `git status`, and do not `git add -f` without asking.

---

### Task 1: `CheckVaultScopedAccess`

Adds the new decision function and nothing else. No caller changes yet, so this task cannot alter behavior — it only makes the narrowed semantics available and pinned by tests.

**Files:**
- Modify: `internal/services/authorization/access_policy_service.go` (interface at `:31`, new method after `CheckAccess` at `:52-66`)
- Test: `internal/services/authorization/access_policy_service_test.go`
- Modify (mocks — the interface gained a method, so these stop compiling): `api/access_policies_test.go:49`, `cmd/testutils/test_utils.go:741`, `internal/middleware/middleware_test.go:938`, `internal/services/authorization/vault_authz_test.go:23`

**Interfaces:**
- Produces: `CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error)` on `AccessPolicyService`. Task 2 calls it.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/authorization/access_policy_service_test.go` (package `authorization_test`, using the existing `mockPolicyRepo`):

```go
// TestCheckVaultScopedAccess covers the asymmetry that defines this method: a
// NULL-scoped DENY still matches every vault, a NULL-scoped ALLOW matches none.
func TestCheckVaultScopedAccess(t *testing.T) {
	vaultID := uuid.New()
	otherVault := uuid.New()

	allowGlobal := &model.AccessPolicy{Effect: model.PolicyEffectAllow, VaultID: nil}
	denyGlobal := &model.AccessPolicy{Effect: model.PolicyEffectDeny, VaultID: nil}
	allowScoped := &model.AccessPolicy{Effect: model.PolicyEffectAllow, VaultID: &vaultID}
	denyScoped := &model.AccessPolicy{Effect: model.PolicyEffectDeny, VaultID: &vaultID}
	allowOther := &model.AccessPolicy{Effect: model.PolicyEffectAllow, VaultID: &otherVault}

	cases := []struct {
		name     string
		rows     []*model.AccessPolicy
		expected authorization.AccessDecision
	}{
		{"no rows falls back", nil, authorization.AccessFallback},
		{"global allow alone does NOT grant the vault", []*model.AccessPolicy{allowGlobal}, authorization.AccessFallback},
		{"global deny still blocks the vault", []*model.AccessPolicy{denyGlobal}, authorization.AccessDenied},
		{"vault-scoped allow grants", []*model.AccessPolicy{allowScoped}, authorization.AccessAllowed},
		{"vault-scoped deny blocks", []*model.AccessPolicy{denyScoped}, authorization.AccessDenied},
		{"global deny beats a vault-scoped allow", []*model.AccessPolicy{allowScoped, denyGlobal}, authorization.AccessDenied},
		{"global deny beats a scoped allow regardless of row order", []*model.AccessPolicy{denyGlobal, allowScoped}, authorization.AccessDenied},
		{"global allow plus vault-scoped allow grants", []*model.AccessPolicy{allowGlobal, allowScoped}, authorization.AccessAllowed},
		{"an allow scoped to another vault does not grant this one", []*model.AccessPolicy{allowOther}, authorization.AccessFallback},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &mockPolicyRepo{}
			svc := authorization.NewAccessPolicyService(repo)
			ctx := context.Background()
			pid := uuid.New()
			repo.On("FindEffects", ctx, pid, model.PolicyResourceVaults, model.OpManage, vaultID).
				Return(tc.rows, nil)

			got, err := svc.CheckVaultScopedAccess(ctx, pid, model.PolicyResourceVaults, model.OpManage, vaultID)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestCheckVaultScopedAccess_RepoErrorFailsClosed pins that a lookup failure is
// never reported as an allow.
func TestCheckVaultScopedAccess_RepoErrorFailsClosed(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()
	vaultID := uuid.New()
	repo.On("FindEffects", ctx, pid, model.PolicyResourceVaults, model.OpManage, vaultID).
		Return([]*model.AccessPolicy(nil), errors.New("db down"))

	got, err := svc.CheckVaultScopedAccess(ctx, pid, model.PolicyResourceVaults, model.OpManage, vaultID)
	require.Error(t, err)
	assert.Equal(t, authorization.AccessFallback, got)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run TestCheckVaultScopedAccess -v`
Expected: FAIL — `svc.CheckVaultScopedAccess undefined`.

- [ ] **Step 3: Add the method to the interface**

In `internal/services/authorization/access_policy_service.go`, add to the `AccessPolicyService` interface immediately after the `CheckAccess` declaration (`:31`):

```go
	// CheckVaultScopedAccess evaluates a policy against ONE specific vault. It
	// differs from CheckAccess in exactly one way, and the asymmetry is
	// deliberate: a NULL-scoped (global) DENY still matches, because a global
	// deny must keep blocking every vault; a NULL-scoped ALLOW does not,
	// because an instance-wide allow is a grant to operate on the vault
	// COLLECTION (create, list) and never authority over a vault someone else
	// owns.
	//
	// Callers pass a concrete vaultID. Use CheckAccess, not this, for the
	// collection-level (uuid.Nil) decision.
	CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error)
```

- [ ] **Step 4: Implement the method**

Add to `internal/services/authorization/access_policy_service.go`, immediately after `CheckAccess`:

```go
// CheckVaultScopedAccess evaluates access policies for the triple
// (principalID, resourceType, operation) against one specific vault.
//
// It reuses FindEffects — which matches "(vault_id = ? OR vault_id IS NULL)"
// — and then discards NULL-scoped ALLOW rows, keeping NULL-scoped DENY rows.
// The narrowing is applied here rather than in FindEffects or CheckAccess on
// purpose: those two are shared with PolicyMiddleware and
// vaultcli.RequireDataAction for secrets/keys/certificates, where the
// "OR vault_id IS NULL" clause is what makes a global explicit deny work.
func (s *accessPolicyService) CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error) {
	policies, err := s.repo.FindEffects(ctx, principalID, resourceType, operation, vaultID)
	if err != nil {
		return AccessFallback, fmt.Errorf("policy lookup: %w", err)
	}

	// Any deny wins outright, whatever its scope, so every row is inspected
	// for a deny before any allow can be honoured.
	scopedAllow := false
	for _, p := range policies {
		if p.Effect == model.PolicyEffectDeny {
			return AccessDenied, nil
		}
		if p.VaultID != nil && *p.VaultID == vaultID {
			scopedAllow = true
		}
	}
	if scopedAllow {
		return AccessAllowed, nil
	}
	// Either no rows, or only NULL-scoped allows -- which confer nothing here.
	return AccessFallback, nil
}
```

- [ ] **Step 5: Add the method to the four test doubles**

The interface grew, so every implementer must too. In `api/access_policies_test.go`, `cmd/testutils/test_utils.go`, and `internal/middleware/middleware_test.go`, add a `CheckVaultScopedAccess` alongside each existing `CheckAccess`, mirroring that double's style. For the two testify mocks (`cmd/testutils/test_utils.go`, `internal/middleware/middleware_test.go`):

```go
func (m *MockAccessPolicyService) CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error) {
	args := m.Called(ctx, principalID, resourceType, operation, vaultID)
	return args.Get(0).(authzServices.AccessDecision), args.Error(1)
}
```

In `internal/services/authorization/vault_authz_test.go`, the `fakeAccessPolicyService` (`:18`) returns one canned `decision` for every call. Give it a **separate** field, so a test can distinguish the collection-level answer from the vault-scoped one — without this, Task 2's tests would pass without proving anything:

```go
type fakeAccessPolicyService struct {
	decision AccessDecision // returned by CheckAccess (collection level)
	// scoped is returned by CheckVaultScopedAccess. Kept separate from
	// decision so a test can assert that a caller consults the vault-scoped
	// check and not the collection-level one.
	scoped    AccessDecision
	scopedSet bool
	err       error
}

func (f *fakeAccessPolicyService) CheckVaultScopedAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (AccessDecision, error) {
	if f.scopedSet {
		return f.scoped, f.err
	}
	return f.decision, f.err
}
```

- [ ] **Step 6: Run tests**

Run: `go build ./... && go test ./internal/services/authorization/ ./api/ ./cmd/... ./internal/middleware/`
Expected: PASS. Behavior is unchanged so far — no caller uses the new method yet.

- [ ] **Step 7: Commit**

```bash
git add internal/services/authorization/access_policy_service.go internal/services/authorization/access_policy_service_test.go internal/services/authorization/vault_authz_test.go api/access_policies_test.go cmd/testutils/test_utils.go internal/middleware/middleware_test.go
git commit -S -m "feat(authz): add CheckVaultScopedAccess"
```

---

### Task 2: Narrow both vault-management checks

This is the breaking change. After it, a global `vaults:manage` allow confers create and list only.

**Files:**
- Modify: `internal/services/authorization/vault_authz.go` (`CanManageVault` at `:23-35`, `CanManageRoleAssignments` at `:67-94`)
- Test: `internal/services/authorization/vault_authz_test.go`

**Interfaces:**
- Consumes: `AccessPolicyService.CheckVaultScopedAccess` from Task 1.
- Produces: no signature changes. `CanManageVault` and `CanManageRoleAssignments` keep their exact signatures; only their semantics narrow, so all 20+ call sites across `api/` and `cmd/` stay as they are.

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/authorization/vault_authz_test.go` (package `authorization`):

```go
// TestCanManageVault_GlobalAllowNoLongerManagesAVault pins the headline
// breaking change: a NULL-scoped vaults:manage allow used to satisfy every
// vault-scoped check. It no longer does.
func TestCanManageVault_GlobalAllowNoLongerManagesAVault(t *testing.T) {
	// CheckAccess would say allowed (the global row matches); the vault-scoped
	// check says fallback, because a NULL-scoped allow confers nothing here.
	policies := &fakeAccessPolicyService{decision: AccessAllowed, scoped: AccessFallback, scopedSet: true}
	if CanManageVault(context.Background(), nil, policies, uuid.New(), uuid.New()) {
		t.Fatal("a global vaults:manage allow must no longer confer management of an arbitrary vault")
	}
}

// TestCanManageVault_CollectionLevelStillUsesCheckAccess pins that create/list
// (uuid.Nil) keep consulting the unnarrowed check -- that is the one thing a
// global grant is still for.
func TestCanManageVault_CollectionLevelStillUsesCheckAccess(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed, scoped: AccessFallback, scopedSet: true}
	if !CanManageVault(context.Background(), nil, policies, uuid.New(), uuid.Nil) {
		t.Fatal("a global vaults:manage allow must still permit the collection-level create/list decision")
	}
}

// TestCanManageVault_ScopedAllowStillManages pins that the legitimate path --
// a vault-scoped allow, which is what provisioned creators receive -- is
// untouched.
func TestCanManageVault_ScopedAllowStillManages(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback, scoped: AccessAllowed, scopedSet: true}
	if !CanManageVault(context.Background(), nil, policies, uuid.New(), uuid.New()) {
		t.Fatal("a vault-scoped allow must still confer management of that vault")
	}
}

// TestCanManageVault_GlobalDenyStillBlocks pins the asymmetry: deny widens.
func TestCanManageVault_GlobalDenyStillBlocks(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied, scoped: AccessDenied, scopedSet: true}
	if CanManageVault(context.Background(), nil, policies, uuid.New(), uuid.New()) {
		t.Fatal("a deny must still block")
	}
}

// TestCanManageVault_AdminUnaffected pins that platform operators keep working.
func TestCanManageVault_AdminUnaffected(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback, scoped: AccessFallback, scopedSet: true}
	if !CanManageVault(context.Background(), []string{string(model.RoleAdmin)}, policies, uuid.New(), uuid.New()) {
		t.Fatal("the global admin role must short-circuit the narrowed check")
	}
}

// TestCanManageRoleAssignments_GlobalAllowCannotSelfAward is the escalation
// path from the design doc's Problem section, pinned shut. Narrowing only
// CanManageVault would leave this open: role-assignment management alone is
// enough to award oneself Key Vault Administrator in any vault.
func TestCanManageRoleAssignments_GlobalAllowCannotSelfAward(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed, scoped: AccessFallback, scopedSet: true}
	// An empty role repo: the principal holds no assignment in the target
	// vault, so nothing but the (now narrowed) policy could allow this.
	roleSvc := newSvc(newFakeRoleRepo(), newFakePolicyRepo(), &fakeUserLookup{})
	if CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, roleSvc, uuid.New(), uuid.New(), true) {
		t.Fatal("a global vaults:manage allow must no longer permit awarding role assignments in an arbitrary vault")
	}
}

// TestCanManageRoleAssignments_ScopedAllowStillManages pins that a vault-scoped
// allow -- what a provisioned creator holds -- still manages that vault's roles.
func TestCanManageRoleAssignments_ScopedAllowStillManages(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback, scoped: AccessAllowed, scopedSet: true}
	// nil roles is deliberate: an allow must short-circuit before the
	// role-assignment check is ever consulted.
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("a vault-scoped allow must still confer role-assignment management in that vault")
	}
}

// TestCanManageRoleAssignments_GlobalDenyStillBeatsARoleGrant pins that the
// deny-overrides invariant survives the narrowing.
func TestCanManageRoleAssignments_GlobalDenyStillBeatsARoleGrant(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied, scoped: AccessDenied, scopedSet: true}
	rr := newFakeRoleRepo()
	principalID := uuid.New()
	vaultID := uuid.New()
	// A real Data Access Administrator grant, which would otherwise allow.
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultDataAccessAdministrator,
	}
	roleSvc := newSvc(rr, newFakePolicyRepo(), &fakeUserLookup{})
	if CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, roleSvc, principalID, vaultID, true) {
		t.Fatal("an explicit deny must never be outvoted by a role grant")
	}
}
```

These use the file's existing doubles — `newSvc(rr, pr, ul)`, `newFakeRoleRepo()`, `newFakePolicyRepo()`, `fakeUserLookup` — exactly as `TestCanManageRoleAssignments_NonAdminAllowedByDataAccessAdministrator` does. Do not introduce new ones.

Also update the stale comment in the existing `TestCanManageRoleAssignments_NonAdminAllowedByAccessPolicy`: its "preserving today's documented behavior" now refers to a *vault-scoped* allow, since that test passes a concrete vault ID. The assertion itself stays correct and must keep passing.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/authorization/ -run 'TestCanManageVault_Global|TestCanManageVault_Collection|TestCanManageRoleAssignments_Global' -v`
Expected: FAIL — the two `GlobalAllow` tests fail because both functions still call `CheckAccess`, which returns `AccessAllowed`.

- [ ] **Step 3: Narrow `CanManageVault`**

Replace the body of `CanManageVault` in `internal/services/authorization/vault_authz.go`, and update its doc comment:

```go
// CanManageVault reports whether principalID may perform vault-management
// operations against vaultID: the global admin account role, or an
// access-policy allow on (vaults, manage).
//
// Which policy check applies depends on vaultID:
//
//   - vaultID == uuid.Nil is the COLLECTION-level decision (create, list).
//     CheckAccess applies, so a global (vault_id NULL) allow satisfies it.
//   - vaultID != uuid.Nil targets ONE vault (get, update, delete).
//     CheckVaultScopedAccess applies, so a global allow does NOT satisfy it,
//     though a global DENY still blocks it.
//
// That split is the narrowing: a global vaults:manage grant means "may create
// and list vaults", never "may manage every vault on the instance".
//
// A nil policies service, a service error, or any decision other than
// AccessAllowed denies — this function fails closed.
func CanManageVault(ctx context.Context, accountRoles []string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return true
	}
	if policies == nil {
		return false
	}
	var (
		decision AccessDecision
		err      error
	)
	if vaultID == uuid.Nil {
		decision, err = policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
	} else {
		decision, err = policies.CheckVaultScopedAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
	}
	if err != nil {
		return false
	}
	return decision == AccessAllowed
}
```

- [ ] **Step 4: Narrow `CanManageRoleAssignments`**

In the same file, replace the policy-check block inside `CanManageRoleAssignments` (currently `:71-81`) with the same split, and add to its doc comment:

```go
	if policies != nil {
		// Role assignments always target one vault, so the vault-scoped check
		// applies whenever vaultID is concrete. Narrowing CanManageVault alone
		// would leave the escalation path open: role-assignment management by
		// itself is enough to award oneself Key Vault Administrator anywhere.
		var (
			decision AccessDecision
			err      error
		)
		if vaultID == uuid.Nil {
			decision, err = policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
		} else {
			decision, err = policies.CheckVaultScopedAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
		}
		if err == nil {
			if decision == AccessAllowed {
				return true
			}
			if decision == AccessDenied {
				return false
			}
		}
	}
```

Also amend the function's doc comment, replacing "scoped to vaultID or global (preserves the pre-existing documented behavior)" with "scoped to vaultID — a global (vault_id NULL) allow no longer suffices, though a global deny still blocks".

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/services/authorization/ -v`
Expected: PASS.

- [ ] **Step 6: Pin the escalation path at the HTTP level**

The unit tests above pin the decision function. The spec asks for the escalation to be pinned at the route it actually travels, so add to `api/role_assignments_test.go`, using that file's existing `newRoleAssignmentCtx` helper and `mockAccessPolicyService`:

```go
// TestRoleAssignments_GlobalVaultsManageCannotGrantInAnyVault pins the
// escalation path from the design doc's Problem section. Before the narrowing,
// a NULL-scoped vaults:manage allow satisfied CanManageRoleAssignments for
// EVERY vault, so its holder could award itself Key Vault Administrator
// anywhere. CheckAccess still says allowed -- the global row does match -- and
// that must no longer be what the handler consults.
func TestRoleAssignments_GlobalVaultsManageCannotGrantInAnyVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessAllowed, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	c := newRoleAssignmentCtx("user", policySvc)
	w := httptest.NewRecorder()
	body := []byte(`{"principal":"alice","role":"key-vault-administrator"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code,
		"a global vaults:manage allow must not permit granting roles in a vault")
}
```

Run: `go test ./api/ -run TestRoleAssignments -v`
Expected: PASS.

- [ ] **Step 7: Run the global-deny regression suites**

The change must not have touched the data-plane deny path. Run the suites that exercise `PolicyMiddleware` and `vaultcli.RequireDataAction`:

Run: `go test ./internal/middleware/ ./cmd/vaultcli/ ./api/ -v`
Expected: PASS. If a global-deny test fails here, the narrowing leaked into `CheckAccess`/`FindEffects` — revert and re-read the first Global Constraint.

Then confirm by inspection that these suites genuinely cover a NULL-scoped deny on a data-plane resource: `grep -rn "vault_id IS NULL\|VaultID: nil\|global deny" internal/middleware/*_test.go cmd/vaultcli/*_test.go`. If nothing covers it, add one test before continuing — this release's central risk is silently disabling global denies, and a suite that never exercises one cannot detect that.

- [ ] **Step 8: Run the full suite**

Run: `go build ./... && go vet ./... && go test ./... -race`
Expected: PASS. Any failure here names a call site that depended on the old wide semantics — read it before changing it, because it may be pinning behavior this release intends to break, in which case the test is what needs updating.

- [ ] **Step 9: Commit**

```bash
git add internal/services/authorization/vault_authz.go internal/services/authorization/vault_authz_test.go api/role_assignments_test.go
git commit -S -m "feat(authz)!: narrow global vaults:manage to create-and-list"
```

---

### Task 3: Creator grants on the global-policy create path

Without this, Task 2 strands global-policy holders: they create a vault and immediately cannot get, update, delete, or manage roles in it. Admins are unaffected either way, because the admin role short-circuits every check, so they stay on the cheap non-transactional path.

**Files:**
- Modify: `internal/services/vaults/vault_service.go` (interface at `:162`, `CreateVaultProvisioned` at `:356-452`)
- Modify: `api/vault.go:99-100`
- Modify: `cmd/vaults/create.go:77-80`
- Modify: `cmd/testutils/test_utils.go:606` (mock signature)
- Test: `internal/services/vaults/vault_provisioned_create_test.go`, `cmd/vaults/vaults_test.go`, `cmd/vaults/vaults_more_test.go`

**Interfaces:**
- Produces: `CreateVaultProvisioned(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID, quotaBounded, grantCreatorRights bool) (*model.Vault, error)` — one added trailing `bool`. Callers map from `authz.CreateRight`: `quotaBounded = right == CreateRightProvisioningGrant`, `grantCreatorRights = right != CreateRightAdmin`.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/vaults/vault_provisioned_create_test.go`, using that file's existing helpers — `newProvisionedTestServiceWithGranter(t, quota(n), existingVaults(n))`, `newProvisionedTestServiceWithFailingGranter(...)`, the `stubCreatorGranter` with its `.policies`/`.roles` slices, and the package-level `testPrincipal`. Do not introduce new fixtures.

```go
// TestCreateVaultProvisioned_GlobalPolicyGetsCreatorGrants pins the fix for the
// stranding problem the narrowing would otherwise create: a global-policy
// holder is not quota-bounded, but must still receive vault-scoped rights over
// what it creates, because its global allow no longer covers that vault.
func TestCreateVaultProvisioned_GlobalPolicyGetsCreatorGrants(t *testing.T) {
	// quota is irrelevant on this path -- it must never be consulted.
	svc, granter := newProvisionedTestServiceWithGranter(t, quota(0), existingVaults(0))

	v, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "customer-a"}, testPrincipal,
		false /* quotaBounded */, true /* grantCreatorRights */)
	require.NoError(t, err,
		"a quota of 0 must not refuse an unbounded caller -- the quota check "+
			"must be skipped entirely, not merely satisfied")

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

// TestCreateVaultProvisioned_AdminSkipsCreatorGrants pins that the admin path
// stays on the cheap non-transactional create. Admin short-circuits every
// authorization check, so grants for it would be dead rows.
func TestCreateVaultProvisioned_AdminSkipsCreatorGrants(t *testing.T) {
	svc, granter := newProvisionedTestServiceWithGranter(t, quota(0), existingVaults(0))

	v, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "ops"}, testPrincipal,
		false /* quotaBounded */, false /* grantCreatorRights */)
	require.NoError(t, err)
	require.NotNil(t, v)

	require.Empty(t, granter.policies, "an admin create must write no creator policy")
	require.Empty(t, granter.roles, "an admin create must write no creator role assignment")
}

// TestCreateVaultProvisioned_UnboundedGrantFailureLeavesNoVault pins that the
// global-policy path fails closed the same way the quota-bounded path does: a
// vault whose creator holds no rights over it is worse than no vault.
func TestCreateVaultProvisioned_UnboundedGrantFailureLeavesNoVault(t *testing.T) {
	svc, _ := newProvisionedTestServiceWithFailingGranter(t, quota(0), existingVaults(0))

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "doomed-global"}, testPrincipal, false, true)
	require.Error(t, err)

	_, err = svc.GetVault(context.Background(), "doomed-global")
	require.ErrorIs(t, err, vaults.ErrVaultNotFound,
		"a failed grant write must roll back the vault insert too")
}
```

The three existing tests in this file (`_GrantsCreatorFullRights`, `_RollsBackAllThreeWrites`, `_RefusesAtQuota`) and every other `CreateVaultProvisioned` call in the package need a fifth argument: they are all quota-bounded, so append `, true`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestCreateVaultProvisioned_ -v`
Expected: FAIL — too many arguments to `CreateVaultProvisioned`.

- [ ] **Step 3: Change the signature and restructure the method**

In `internal/services/vaults/vault_service.go`, update the interface declaration (`:158-162`) and the implementation. Replace the guard-and-dispatch block (`:363-379`) with:

```go
	if quotaBounded && req.PurgeProtection != nil && *req.PurgeProtection {
		return nil, ErrPurgeProtectionNotPermitted
	}

	// An admin caller is neither quota-bounded nor in need of creator grants:
	// the admin role short-circuits every authorization check, so grants for
	// it would be dead rows. Fall back to the pre-existing non-transactional
	// create, which needs no transaction wiring.
	if !quotaBounded && !grantCreatorRights {
		return s.CreateVault(ctx, req, createdBy)
	}
	// Anything else touches more than one table and MUST be transactional. If
	// the deps are not wired we refuse rather than silently creating a vault
	// with no quota check or no creator rights -- a guard that degrades to "no
	// guard" on a wiring mistake is worse than no guard at all, because it
	// looks like it is working.
	if s.txBeginner == nil {
		return nil, fmt.Errorf("vault creation cannot be completed: transaction support is not wired")
	}
	if quotaBounded && s.grantLocker == nil {
		return nil, fmt.Errorf("provisioning quota cannot be enforced: grant locking is not wired")
	}
```

Then make the quota check inside the transaction conditional. Replace the opening of the `withTx` closure (`:389-401`) with:

```go
	err := s.withTx(ctx, func(tx *db.Tx) error {
		if quotaBounded {
			var err error
			quota, err = s.grantLocker.LockAndReadQuotaTx(ctx, tx, createdBy)
			if err != nil {
				return err
			}
			count, err = txRepo.CountByCreatedBy(ctx, tx, createdBy)
			if err != nil {
				return err
			}
			if count >= quota {
				return fmt.Errorf("%w: %d of %d used", ErrVaultQuotaExceeded, count, quota)
			}
		}
		if err := txRepo.CreateTx(ctx, tx, v); err != nil {
			return err
		}
```

The creator-granting block that follows (`:405-436`) stays exactly as it is — it already writes a vault-scoped policy plus a `Key Vault Administrator` assignment, which is precisely what a global-policy creator now needs. Only its guard comment needs widening, since it no longer applies solely to quota slots:

```go
		if s.creatorGranter == nil {
			// A vault whose creator holds no rights over it is worse than a
			// refused create. For a quota-bounded caller it also permanently
			// occupies a quota slot, since only a purge (which that caller
			// cannot perform) frees one. Fail closed either way.
			return fmt.Errorf("creator grants cannot be written: grant support is not wired")
		}
```

Finally, adjust the success audit line (`:447-450`) so it does not claim a provisioning grant on the global-policy path:

```go
	if s.log != nil {
		detail := fmt.Sprintf("Vault created: %s", v.Name)
		if quotaBounded {
			detail = fmt.Sprintf("Vault created under provisioning grant: %s", v.Name)
		}
		s.log.LogAuditInfo(createdBy.String(), "create_vault", "success", detail)
	}
```

- [ ] **Step 4: Update the two production call sites**

`api/vault.go:99-100`:

```go
	vault, err := svc.CreateVaultProvisioned(r.Context(), *req, userID,
		right == authzServices.CreateRightProvisioningGrant,
		right != authzServices.CreateRightAdmin)
```

`cmd/vaults/create.go:77-80` — replace the comment about global-policy holders taking the unbounded path, since they no longer take a grantless one:

```go
		// Only a provisioning grant is quota-bounded. Everyone except an admin
		// receives creator grants over what they create: after the global-grant
		// narrowing, a global-policy holder's instance-wide allow no longer
		// covers the vault it just made.
		vault, err := vaultService.CreateVaultProvisioned(ctx, req, userID,
			right == authz.CreateRightProvisioningGrant,
			right != authz.CreateRightAdmin)
```

- [ ] **Step 5: Update the mock and its call sites**

`cmd/testutils/test_utils.go:606`:

```go
func (m *MockVaultService) CreateVaultProvisioned(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID, quotaBounded, grantCreatorRights bool) (*model.Vault, error) {
	args := m.Called(ctx, req, createdBy, quotaBounded, grantCreatorRights)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
}
```

Keep the body's nil-handling identical to whatever is there now; only the parameter list and the `m.Called` argument list change.

Then fix the expectations in `cmd/vaults/vaults_test.go` (`:57`, `:223`, `:251`, `:289`) and `cmd/vaults/vaults_more_test.go` (`:119`, `:145`, `:168`), each of which passes four matchers and now needs five. The admin-path cases (currently `..., false)`) become `..., false, false)`; the provisioning-grant cases (currently `..., true)`) become `..., true, true)`. The `AssertNotCalled` at `vaults_test.go:223` needs one more `mock.Anything`.

- [ ] **Step 6: Verify the CLI mapping by inspection**

The existing `cmd/vaults` tests all run as the default admin caller, so they pin the `(false, false)` mapping and nothing else. Rather than build a non-admin global-policy caller fixture that does not exist yet, confirm the mapping directly:

Run: `grep -n "CreateVaultProvisioned" cmd/vaults/create.go`
Expected: the two argument expressions read `right == authz.CreateRightProvisioningGrant` and `right != authz.CreateRightAdmin` — not a repeated `quotaBounded`, and not a hardcoded literal. A copy-paste of the first expression into the second is the likely mistake, and it would silently deny creator grants to every global-policy holder, which is the exact bug this task exists to prevent.

The behaviour itself is covered at the service level by Step 1, which is where the grants are actually written.

- [ ] **Step 7: Run the tests**

Run: `go build ./... && go test ./internal/services/vaults/ ./cmd/vaults/ ./api/ -v`
Expected: PASS.

- [ ] **Step 8: Run the full suite**

Run: `go vet ./... && go test ./... -race`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/services/vaults/vault_service.go internal/services/vaults/vault_provisioned_create_test.go api/vault.go api/vault_authz_test.go cmd/vaults/create.go cmd/testutils/test_utils.go cmd/vaults/vaults_test.go cmd/vaults/vaults_more_test.go
git commit -S -m "feat(vaults): grant creator rights on the global-policy create path"
```

---

### Task 4: Documentation

**Files:**
- Create: `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`
- Modify: `scripts/docsgen/docs.go` (register the new release note, as release 1's note was registered)
- Modify: `CLAUDE.md` (Authorization and CLI Authorization sections)
- Modify: `.claude/manual-testing-plan.md` (§5, after the provisioning subsection)
- Modify: `.claude/roadmap-azure-parity-and-beyond.md` (mark release 2 shipped)

**Interfaces:** none — documentation only.

- [ ] **Step 1: Write the release note**

Create `docs/release-notes/v4.6.0-narrow-global-vault-manage.md` covering, each as its own section:

1. **The breaking change.** A global (`vault_id NULL`) `vaults:manage` allow now confers **create and list only**. Its holders lose exactly two things: get/update/delete on vaults they do not hold a scoped grant over (`CanManageVault`), and role-assignment management in those vaults (`CanManageRoleAssignments`). Name both, and say the global `admin` account role is unaffected.
2. **What did not change.** A global explicit **deny** still blocks every vault — the asymmetry is deliberate. `CheckAccess` and `FindEffects` are untouched, so every global deny on secrets/keys/certificates through `PolicyMiddleware` and `vaultcli.RequireDataAction` behaves exactly as before.
3. **Creator grants on the global-policy path.** Previously a global-policy holder creating a vault received no per-vault rights, which was harmless while its global allow covered everything. It is not harmless now, so that path writes the same vault-scoped `vaults:manage` policy plus `Key Vault Administrator` assignment the provisioning path writes. Admin creates are unchanged. This resolves the open question release 1's note left explicitly unresolved.
4. **Upgrade procedure.** Before upgrading, run the previous release and read its `warnGlobalVaultManageGrants` startup warnings — every principal it names loses those two behaviours. For each, either issue a bounded provisioning grant (`rocketvault vault-provisioning grant <principal> --quota <n>`) or add explicit vault-scoped `vaults:manage` policies for the vaults it must keep managing. Existing vault-scoped grants need no action.
5. **Rollback.** Reverting the two commits restores the old semantics; no schema change is involved, so no data migration is needed in either direction.

- [ ] **Step 2: Register the note with the docs generator**

Add the new file to the list in `scripts/docsgen/docs.go`, following the exact form of the `v4.5.0-vault-provisioning.md` entry immediately above it.

- [ ] **Step 3: Update CLAUDE.md**

Two edits:

- In the **Authorization** section, after the `RoleAssignmentService` bullet, record that a global `vaults:manage` allow is create-and-list only, that vault-scoped checks go through `AccessPolicyService.CheckVaultScopedAccess` where a NULL-scoped deny matches and a NULL-scoped allow does not, and link `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`.
- In the **CLI Authorization** section, amend the vault-management bullet: `CanManageVault`/`CanManageRoleAssignments` now consult the vault-scoped check for a concrete vault and `CheckAccess` only for the `uuid.Nil` create/list decision.

- [ ] **Step 4: Add the manual test procedure**

Add to `.claude/manual-testing-plan.md` §5, immediately after the self-service provisioning subsection, in that section's `- [ ]` style:

```markdown
#### Narrowed global vaults:manage (release 2)

- [ ] Give a non-admin principal a global `vaults:manage` allow
      (`vault_id: null`, via the admin-only `createAccessPolicy` HTTP route --
      there is no CLI for access policies).
- [ ] That principal can still **create** a vault and **list** vaults.
- [ ] It can manage the vault it just created -- get, update, role
      assignments -- because the create now writes it vault-scoped creator
      grants.
- [ ] Against a vault it did **not** create: `vaults get`, `vaults update`,
      `vaults delete` and `vault-access grant` all refuse. Before this release
      all four succeeded. Check the HTTP API too, not just the CLI.
- [ ] It cannot award itself `Key Vault Administrator` in another principal's
      vault -- this is the escalation path the release closes.
- [ ] A global `vaults:manage` **deny** still blocks that principal on every
      vault, including ones it created.
- [ ] A global **deny** on secrets still blocks reads and writes through both
      the API and the CLI. This path was deliberately not touched; if it
      regressed, the narrowing leaked into `CheckAccess`.
- [ ] An `admin` account role is unaffected throughout.
- [ ] A provisioning grantee is unaffected throughout -- its rights were
      already vault-scoped.
```

- [ ] **Step 5: Update the roadmap**

In `.claude/roadmap-azure-parity-and-beyond.md`, under the self-service provisioning entry's "What remains open after release 1", mark item 1 (the narrowing) shipped with today's date, and record that name prefixes and the tenant entity are still open. Note that release 1's open question about global-grant creators is now resolved, not deferred.

- [ ] **Step 6: Verify the docs build**

Run: `./scripts/docs.sh build`
Expected: succeeds, and `docs/release-notes/v4.6.0-narrow-global-vault-manage.html` is produced.

- [ ] **Step 7: Commit**

```bash
# .claude/ is gitignored; only the tracked files are added here.
git add CLAUDE.md docs/release-notes/v4.6.0-narrow-global-vault-manage.md scripts/docsgen/docs.go
git commit -S -m "docs: document the narrowed global vaults:manage grant"
```

Mention to the user that the `.claude/` edits are intentionally uncommitted, and ask before `git add -f`.

---

## Release 2 complete

Verify the whole feature end to end:

```bash
go build ./... && go vet ./... && go test ./... -race
```

Then walk §5's two provisioning subsections against a scratch instance
(`.claude/manual-testing-plan.md` §0 for isolated-config setup). The
release-1 subsection must still pass unchanged — a provisioning grantee's
rights were already vault-scoped, so nothing about it should have moved.

**Known limitation carried forward, not fixed here:** B57 — `cmd/secrets/`'s
five write commands run a legacy global-role gate ahead of the vault-scoped
check, so a creator holding only vault-scoped rights can write secrets over
HTTP but not through the CLI. This release does not change that, and it fails
closed. See `.claude/known-bugs.md` § B57.
