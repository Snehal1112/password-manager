# Scoped ListVaults — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a grantee see the vaults it can actually reach, instead of getting a blanket 403 from a listing gated on a global grant.

**Architecture:** `listVaults` and `requireCanListVaults` both check `CanManageVault(..., uuid.Nil)`, which a grantee never satisfies. Both gain a scoped path: admins and global-policy holders see everything; anyone else sees vaults where they hold vault-scoped `vaults:manage`. Filtering on the policy rather than `created_by` means a customer's whole team sees the same set once more than one principal is involved.

**Tech Stack:** Go 1.24, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §7

**Depends on:** `…-04-transactional-create.md` — provisioned creates must already write the creator's vault-scoped policy, or there is nothing for the filter to match.
**Followed by:** `…-06-admin-http-surface.md`.

## Global Constraints

- **Release 1 is additive only.** This plan strictly *widens* who can list: no principal who could list before may lose the ability.
- Quota counts by `created_by`; listing filters by policy. The asymmetry is deliberate — quota bounds what a principal created (a fact about history), listing answers what it can reach today (a fact about current rights). See the spec's §7 note.
- Authorization primitives fail closed: an error listing a principal's policies yields an empty list, never the full one.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Repository and service support

**Files:**
- Modify: `internal/repositories/access_policy_repository.go` (add `ListVaultIDsForPrincipal`)
- Modify: `internal/services/vaults/vault_service.go` (add `ListVaultsScoped`)
- Test: `internal/repositories/access_policy_repository_test.go`, `internal/services/vaults/vault_service_test.go`

**Interfaces:**
- Produces:
  - `AccessPolicyRepositoryInterface.ListVaultIDsForPrincipal(ctx context.Context, principalID uuid.UUID) ([]uuid.UUID, error)`
  - `VaultService.ListVaultsScoped(ctx context.Context, principalID uuid.UUID, includeDeleted, all bool) ([]model.Vault, error)`
  - Tasks 2 and 3 consume `ListVaultsScoped`.

`all=true` is the admin / global-policy path and returns exactly what `ListVaults` returns today, so the existing behaviour has one implementation, not two.

- [ ] **Step 1: Write the failing repository test**

```go
func TestListVaultIDsForPrincipal_ReturnsOnlyScopedManageAllows(t *testing.T) {
	repo := repositories.NewAccessPolicyRepository(newPolicyTestDB(t)) // existing helper
	ctx := context.Background()
	principal := uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()

	// A vault-scoped manage allow: must be returned.
	require.NoError(t, repo.Create(ctx, &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: principal, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceVaults, Operation: model.OpManage,
		Effect: model.PolicyEffectAllow, VaultID: &vaultA,
	}))
	// A deny: must NOT be returned.
	require.NoError(t, repo.Create(ctx, &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: principal, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceVaults, Operation: model.OpManage,
		Effect: model.PolicyEffectDeny, VaultID: &vaultB,
	}))
	// Another principal's allow: must NOT be returned.
	otherVault := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceVaults, Operation: model.OpManage,
		Effect: model.PolicyEffectAllow, VaultID: &otherVault,
	}))

	ids, err := repo.ListVaultIDsForPrincipal(ctx, principal)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{vaultA}, ids)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestListVaultIDsForPrincipal -v`
Expected: FAIL — method undefined.

- [ ] **Step 3: Implement the repository method**

```go
// ListVaultIDsForPrincipal returns the IDs of vaults where principalID holds
// a vault-scoped (vaults, manage) ALLOW. NULL-scoped rows are excluded
// deliberately: a global grant is handled by the caller's admin/global branch,
// and including it here would make every vault appear in a scoped listing.
// DENY rows are excluded because this answers "what may I reach", not "what
// policies exist".
func (r *accessPolicyRepository) ListVaultIDsForPrincipal(ctx context.Context, principalID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT DISTINCT vault_id FROM access_policies
		 WHERE principal_id = ? AND resource_type = ? AND operation = ?
		   AND effect = ? AND vault_id IS NOT NULL`,
		principalID.String(), string(model.PolicyResourceVaults),
		string(model.OpManage), string(model.PolicyEffectAllow))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []uuid.UUID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("parse policy vault_id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Add ListVaultsScoped to the service**

```go
// PolicyVaultLister lists the vaults a principal holds scoped management over.
type PolicyVaultLister interface {
	ListVaultIDsForPrincipal(ctx context.Context, principalID uuid.UUID) ([]uuid.UUID, error)
}

// ListVaultsScoped returns every vault when all is true (the admin and
// global-policy path, identical to ListVaults), and otherwise only vaults
// where principalID holds a vault-scoped vaults:manage allow.
//
// Fails closed: if the policy lookup errors, the caller sees an empty list
// rather than the full one.
func (s *vaultService) ListVaultsScoped(ctx context.Context, principalID uuid.UUID, includeDeleted, all bool) ([]model.Vault, error) {
	if all {
		return s.ListVaults(ctx, includeDeleted)
	}
	if s.policyVaults == nil {
		return nil, nil
	}
	ids, err := s.policyVaults.ListVaultIDsForPrincipal(ctx, principalID)
	if err != nil {
		return nil, nil
	}
	if len(ids) == 0 {
		return nil, nil
	}
	allowed := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		allowed[id] = struct{}{}
	}
	everything, err := s.ListVaults(ctx, includeDeleted)
	if err != nil {
		return nil, err
	}
	out := make([]model.Vault, 0, len(ids))
	for _, v := range everything {
		if _, ok := allowed[v.ID]; ok {
			out = append(out, v)
		}
	}
	return out, nil
}
```

Add the `policyVaults PolicyVaultLister` field, a `SetPolicyVaultLister` setter beside the other setters, the interface method on `VaultService`, and the container wiring beside `SetPolicyCleaner` (`service_container.go:433`).

- [ ] **Step 5: Write the service test**

```go
func TestListVaultsScoped_FiltersToPrincipalsVaults(t *testing.T) {
	svc, _ := newScopedListTestService(t, map[uuid.UUID][]string{
		testPrincipal: {"acme-prod"},
	})

	got, err := svc.ListVaultsScoped(context.Background(), testPrincipal, false, false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "acme-prod", got[0].Name)
}

func TestListVaultsScoped_AllReturnsEverything(t *testing.T) {
	svc, total := newScopedListTestService(t, map[uuid.UUID][]string{
		testPrincipal: {"acme-prod"},
	})

	got, err := svc.ListVaultsScoped(context.Background(), testPrincipal, false, true)
	require.NoError(t, err)
	require.Len(t, got, total, "all=true must match ListVaults exactly")
}

func TestListVaultsScoped_NoPoliciesReturnsEmpty(t *testing.T) {
	svc, _ := newScopedListTestService(t, nil)

	got, err := svc.ListVaultsScoped(context.Background(), uuid.New(), false, false)
	require.NoError(t, err)
	require.Empty(t, got, "a principal with no scoped policy sees nothing, not everything")
}
```

- [ ] **Step 6: Run tests and commit**

Run: `go test ./internal/repositories/ ./internal/services/vaults/ -v`
Expected: PASS

```bash
git add internal/repositories/access_policy_repository.go \
        internal/repositories/access_policy_repository_test.go \
        internal/services/vaults/vault_service.go \
        internal/services/vaults/vault_service_test.go \
        internal/container/service_container.go
git commit -S -m "feat(vaults): add policy-scoped vault listing"
```

---

### Task 2: HTTP listVaults

**Files:**
- Modify: `api/vault.go:111-135` (`listVaults`)
- Test: `api/vault_test.go`

**Interfaces:**
- Consumes: `ListVaultsScoped` from task 1; `CanManageVault` for the "all" determination.

- [ ] **Step 1: Write the failing test**

```go
func TestListVaults_GranteeSeesOnlyItsOwn(t *testing.T) {
	api := newTestAPIWithScopedVault(t, testPrincipal, "acme-prod", "someone-else")

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults", nil)

	require.Equal(t, http.StatusOK, w.Code,
		"a grantee must be able to list; a blanket 403 makes provisioning unusable")
	var got []model.VaultResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got, 1)
	require.Equal(t, "acme-prod", got[0].Name)
}

func TestListVaults_AdminStillSeesEverything(t *testing.T) {
	api := newTestAPIAsAdmin(t, "acme-prod", "someone-else")

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults", nil)

	require.Equal(t, http.StatusOK, w.Code)
	var got []model.VaultResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got, 2)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/ -run TestListVaults -v`
Expected: FAIL — the grantee gets `403`.

- [ ] **Step 3: Replace the check**

In `api/vault.go`'s `listVaults`, replace the `CanManageVault(..., uuid.Nil)` guard and the `svc.ListVaults(...)` call with:

```go
	// A global grant (or admin) lists every vault; any other principal lists
	// only the vaults it holds scoped management over. Listing is no longer
	// gated on a global grant, because a provisioning grantee holds none and
	// would otherwise be unable to see the vaults it just created.
	all := authzServices.CanManageVault(r.Context(), roles,
		c.App.ServiceContainer.GetAccessPolicyService(), userID, uuid.Nil)

	vaults, err := svc.ListVaultsScoped(r.Context(), userID, includeDeleted, all)
```

Keep the existing `includeDeleted` parsing and response marshalling untouched. Update the handler's doc comment (lines 108-110), which currently says the check uses `uuid.Nil` "like createVault".

- [ ] **Step 4: Run tests and commit**

Run: `go test ./api/ -v`
Expected: PASS

```bash
git add api/vault.go api/vault_test.go
git commit -S -m "feat(api): scope vault listing to what the caller can reach"
```

---

### Task 3: CLI vaults list

**Files:**
- Modify: `cmd/vaults/authz.go:66-79` (`requireCanListVaults`)
- Modify: `cmd/vaults/list.go` (call the scoped service method)
- Test: `cmd/vaults/authz_test.go`

**Interfaces:**
- Consumes: `ListVaultsScoped` from task 1.
- Produces: `requireCanListVaults` returns `(all bool, err error)` so the command knows which listing to request. Update its one caller in `cmd/vaults/list.go`.

- [ ] **Step 1: Write the failing test**

```go
func TestRequireCanListVaults_GranteeAllowedButNotAll(t *testing.T) {
	sc := newMockContainerWithScopedPolicy(t, testPrincipalID)
	ctx := ctxWithClaims(t, testPrincipalID, []string{"user"})

	all, err := requireCanListVaults(ctx, sc)
	require.NoError(t, err, "a scoped manager must be allowed to list")
	require.False(t, all, "but must not receive the instance-wide listing")
}

func TestRequireCanListVaults_AdminGetsAll(t *testing.T) {
	sc := newMockContainerNoGrant(t)
	ctx := ctxWithClaims(t, testPrincipalID, []string{string(model.RoleAdmin)})

	all, err := requireCanListVaults(ctx, sc)
	require.NoError(t, err)
	require.True(t, all)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/vaults/ -run TestRequireCanListVaults -v`
Expected: FAIL — signature mismatch.

- [ ] **Step 3: Update the helper**

```go
// requireCanListVaults reports whether the caller may list vaults, and
// whether it may list them all. A global grant or the admin role lists
// everything; any other principal lists only vaults it holds scoped
// management over. Mirrors HTTP listVaults.
//
// The CLI bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path.
func requireCanListVaults(ctx context.Context, sc container.ServiceContainerInterface) (bool, error) {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return false, err
	}
	if authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, uuid.Nil) {
		return true, nil
	}
	return false, nil
}
```

Listing is no longer refused outright: a principal with no reachable vault gets an empty list, which is the same information a 403 would leak minus the confirmation that vaults exist.

- [ ] **Step 4: Update the caller**

In `cmd/vaults/list.go`, use the returned `all` and call `ListVaultsScoped(ctx, principalID, includeDeleted, all)` instead of `ListVaults`.

- [ ] **Step 5: Run everything and commit**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS

```bash
git add cmd/vaults/
git commit -S -m "feat(cli): scope vaults list to what the caller can reach"
```
