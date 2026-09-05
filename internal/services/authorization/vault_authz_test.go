package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/provisioning"
	"rocketvault/model"
)

// fakeAccessPolicyService is a minimal test double for AccessPolicyService,
// returning a fixed decision/error for CheckAccess. The remaining interface
// methods are no-ops; no test in this file exercises them.
type fakeAccessPolicyService struct {
	decision AccessDecision // returned by CheckAccess (collection level)
	// scoped is returned by CheckVaultScopedAccess. Kept separate from
	// decision so a test can assert that a caller consults the vault-scoped
	// check and not the collection-level one.
	scoped    AccessDecision
	scopedSet bool
	err       error
}

func (f *fakeAccessPolicyService) CheckAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (AccessDecision, error) {
	return f.decision, f.err
}

func (f *fakeAccessPolicyService) CheckVaultScopedAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (AccessDecision, error) {
	if f.scopedSet {
		return f.scoped, f.err
	}
	return f.decision, f.err
}
func (f *fakeAccessPolicyService) CreatePolicy(context.Context, *model.AccessPolicy) error {
	return nil
}
func (f *fakeAccessPolicyService) GetPolicy(context.Context, uuid.UUID) (*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) ListPolicies(context.Context) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) ListByPrincipal(context.Context, uuid.UUID) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) UpdatePolicy(context.Context, *model.AccessPolicy) error {
	return nil
}
func (f *fakeAccessPolicyService) DeletePolicy(context.Context, uuid.UUID) error { return nil }

func TestCanManageVault_AdminAlwaysAllowed(t *testing.T) {
	// Even a policy service that would deny must not be consulted for admin.
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	if !CanManageVault(context.Background(), []string{model.RoleAdmin}, policies, uuid.New(), uuid.New()) {
		t.Fatal("admin must always be allowed to manage vaults")
	}
}

func TestCanManageVault_MultiRoleAdminAmongOthersAllowed(t *testing.T) {
	// Even a policy service that would deny must not be consulted when admin
	// is one of several roles held.
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	if !CanManageVault(context.Background(), []string{model.RoleSecretsManager, model.RoleAdmin}, policies, uuid.New(), uuid.New()) {
		t.Fatal("a principal holding admin among several roles must always be allowed to manage vaults")
	}
}

func TestCanManageVault_NonAdminAllowedOnPolicyAllow(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed}
	if !CanManageVault(context.Background(), []string{model.RoleUser}, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with an allow policy must be allowed")
	}
}

func TestCanManageVault_NonAdminDeniedOnPolicyDeny(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	if CanManageVault(context.Background(), []string{model.RoleUser}, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with a deny policy must be denied")
	}
}

func TestCanManageVault_NonAdminDeniedOnFallback(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	if CanManageVault(context.Background(), []string{model.RoleUser}, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with no matching policy (fallback) must be denied — vault management has no other grant source")
	}
}

func TestCanManageVault_NonAdminDeniedOnServiceError(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed, err: errors.New("db down")}
	if CanManageVault(context.Background(), []string{model.RoleUser}, policies, uuid.New(), uuid.New()) {
		t.Fatal("a service error must fail closed, not fail open")
	}
}

func TestCanManageVault_NonAdminDeniedOnNilService(t *testing.T) {
	if CanManageVault(context.Background(), []string{model.RoleUser}, nil, uuid.New(), uuid.New()) {
		t.Fatal("a nil AccessPolicyService must fail closed")
	}
}

func TestCanPurgeVault_AdminAlwaysAllowed(t *testing.T) {
	if !CanPurgeVault(context.Background(), []string{model.RoleAdmin}, nil, uuid.New(), uuid.New()) {
		t.Fatal("admin must always be allowed to purge, even with a nil role-assignment service")
	}
}

func TestCanPurgeVault_MultiRoleAdminAmongOthersAllowed(t *testing.T) {
	if !CanPurgeVault(context.Background(), []string{model.RoleSecretsManager, model.RoleAdmin}, nil, uuid.New(), uuid.New()) {
		t.Fatal("a principal holding admin among several roles must always be allowed to purge, even with a nil role-assignment service")
	}
}

func TestCanPurgeVault_NonAdminAllowedWithPurgeOperatorRole(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	principalID := uuid.New()
	vaultID := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultPurgeOperator,
	}

	if !CanPurgeVault(context.Background(), []string{model.RoleUser}, svc, principalID, vaultID) {
		t.Fatal("a principal holding Key Vault Purge Operator in this vault must be allowed to purge it")
	}
}

func TestCanPurgeVault_NonAdminDeniedWithWrongRole(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	principalID := uuid.New()
	vaultID := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultReader,
	}

	if CanPurgeVault(context.Background(), []string{model.RoleUser}, svc, principalID, vaultID) {
		t.Fatal("Key Vault Reader must not grant vault purge")
	}
}

func TestCanPurgeVault_NonAdminDeniedInWrongVault(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	principalID := uuid.New()
	grantedVault := uuid.New()
	targetVault := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: grantedVault, Role: model.RoleKeyVaultPurgeOperator,
	}

	if CanPurgeVault(context.Background(), []string{model.RoleUser}, svc, principalID, targetVault) {
		t.Fatal("a Purge Operator grant in vault A must not authorize purging vault B")
	}
}

func TestCanPurgeVault_NonAdminDeniedWithNoAssignments(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	if CanPurgeVault(context.Background(), []string{model.RoleUser}, svc, uuid.New(), uuid.New()) {
		t.Fatal("no role assignments at all must deny")
	}
}

func TestCanPurgeVault_NonAdminDeniedOnNilService(t *testing.T) {
	if CanPurgeVault(context.Background(), []string{model.RoleUser}, nil, uuid.New(), uuid.New()) {
		t.Fatal("a nil RoleAssignmentService must fail closed")
	}
}

func TestCanManageRoleAssignments_AdminAlwaysAllowed(t *testing.T) {
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleAdmin}, nil, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("admin must always be allowed, write=true")
	}
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleAdmin}, nil, nil, uuid.New(), uuid.New(), false) {
		t.Fatal("admin must always be allowed, write=false")
	}
}

func TestCanManageRoleAssignments_MultiRoleAdminAmongOthersAllowed(t *testing.T) {
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleSecretsManager, model.RoleAdmin}, nil, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("a principal holding admin among several roles must always be allowed, write=true")
	}
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleSecretsManager, model.RoleAdmin}, nil, nil, uuid.New(), uuid.New(), false) {
		t.Fatal("a principal holding admin among several roles must always be allowed, write=false")
	}
}

func TestCanManageRoleAssignments_NonAdminAllowedByAccessPolicy(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed}
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("an allow access-policy on (vaults, manage) must grant write, preserving today's documented behavior")
	}
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, nil, uuid.New(), uuid.New(), false) {
		t.Fatal("an allow access-policy on (vaults, manage) must also grant delete")
	}
}

func TestCanManageRoleAssignments_NonAdminAllowedByDataAccessAdministrator(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	roleSvc := newSvc(rr, pr, ul)
	policies := &fakeAccessPolicyService{decision: AccessFallback}

	principalID := uuid.New()
	vaultID := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultDataAccessAdministrator,
	}

	if !CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, roleSvc, principalID, vaultID, true) {
		t.Fatal("Data Access Administrator must grant write")
	}
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, roleSvc, principalID, vaultID, false) {
		t.Fatal("Data Access Administrator must grant delete")
	}
}

func TestCanManageRoleAssignments_NonAdminDeniedInWrongVault(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	roleSvc := newSvc(rr, pr, ul)
	policies := &fakeAccessPolicyService{decision: AccessFallback}

	principalID := uuid.New()
	grantedVault := uuid.New()
	targetVault := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: grantedVault, Role: model.RoleKeyVaultDataAccessAdministrator,
	}

	if CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, roleSvc, principalID, targetVault, true) {
		t.Fatal("Data Access Administrator in vault A must not authorize managing role assignments in vault B")
	}
}

// TestCanManageRoleAssignments_ExplicitDenyBeatsRoleGrant pins the invariant
// PolicyMiddleware documents: an explicit deny access-policy row cannot be
// outvoted by a role grant. Before this fix AccessDenied fell through to the
// HasDataAction check exactly like AccessFallback, so a Data Access
// Administrator assignment silently overrode the deny.
func TestCanManageRoleAssignments_ExplicitDenyBeatsRoleGrant(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	roleSvc := newSvc(rr, pr, ul)
	policies := &fakeAccessPolicyService{decision: AccessDenied}

	principalID := uuid.New()
	vaultID := uuid.New()
	rr.rows[uuid.New()] = &model.RoleAssignment{
		PrincipalID: principalID, VaultID: vaultID, Role: model.RoleKeyVaultDataAccessAdministrator,
	}

	// Sanity: the role grant alone would allow, so the deny is what decides.
	if !CanManageRoleAssignments(context.Background(), []string{model.RoleUser},
		&fakeAccessPolicyService{decision: AccessFallback}, roleSvc, principalID, vaultID, true) {
		t.Fatal("precondition: the Data Access Administrator grant must allow when no policy matches")
	}

	if CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, roleSvc, principalID, vaultID, true) {
		t.Fatal("an explicit deny must not be outvoted by a role grant (write)")
	}
	if CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, roleSvc, principalID, vaultID, false) {
		t.Fatal("an explicit deny must not be outvoted by a role grant (delete)")
	}
}

func TestCanManageRoleAssignments_NonAdminDeniedWithNothing(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	if CanManageRoleAssignments(context.Background(), []string{model.RoleUser}, policies, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("no policy allow and no role service must deny")
	}
}

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
		policies AccessPolicyService
		grants   GrantReader
		want     CreateRight
	}{
		{
			name:  "global admin",
			roles: []string{string(model.RoleAdmin)},
			want:  CreateRightAdmin,
		},
		{
			name:     "global vaults:manage allow",
			roles:    []string{"user"},
			policies: &fakeAccessPolicyService{decision: AccessAllowed},
			want:     CreateRightGlobalPolicy,
		},
		{
			name:     "provisioning grant",
			roles:    []string{"user"},
			policies: &fakeAccessPolicyService{decision: AccessFallback},
			grants:   &stubGrantReader{grant: grant},
			want:     CreateRightProvisioningGrant,
		},
		{
			name:     "no right at all",
			roles:    []string{"user"},
			policies: &fakeAccessPolicyService{decision: AccessFallback},
			grants:   &stubGrantReader{err: provisioning.ErrGrantNotFound},
			want:     CreateRightNone,
		},
		{
			name:     "explicit global deny beats a provisioning grant",
			roles:    []string{"user"},
			policies: &fakeAccessPolicyService{decision: AccessDenied},
			grants:   &stubGrantReader{grant: grant},
			want:     CreateRightNone,
		},
		{
			name:     "grant lookup error denies",
			roles:    []string{"user"},
			policies: &fakeAccessPolicyService{decision: AccessFallback},
			grants:   &stubGrantReader{err: errors.New("database down")},
			want:     CreateRightNone,
		},
		{
			name:     "nil grant reader denies without panicking",
			roles:    []string{"user"},
			policies: &fakeAccessPolicyService{decision: AccessFallback},
			grants:   nil,
			want:     CreateRightNone,
		},
		{
			// The real grantService.GetGrant maps not-found to
			// ErrGrantNotFound and so never returns (nil, nil) today, but
			// GrantReader is an interface -- a future implementation could.
			// CanCreateVault must fail closed regardless of which
			// implementation is behind it, so this pins the `g == nil` half
			// of the guard independently of the `err != nil` half.
			name:     "grant reader returns a nil grant with no error",
			roles:    []string{"user"},
			policies: &fakeAccessPolicyService{decision: AccessFallback},
			grants:   &stubGrantReader{}, // zero value: nil grant, nil error
			want:     CreateRightNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanCreateVault(context.Background(), tt.roles, tt.policies, tt.grants, principal)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestCanCreateVault_PolicyServiceErrorDeniesEvenWithValidGrant pins the
// fail-closed invariant this function's own doc comment promises: "A nil
// dependency or any service error denies." A principal can hold both a
// provisioning grant and a global explicit (vaults, manage, deny) policy --
// the shape an operator uses to suspend a grantee without revoking their
// grant. If a transient policy-read error (connection reset, statement
// timeout) were treated like AccessFallback and allowed to fall through to
// the grant check, that suspension would be silently bypassed. The grant
// here is valid on its own -- if this case failed to deny, it would prove
// the fall-through, not a broken grant.
func TestCanCreateVault_PolicyServiceErrorDeniesEvenWithValidGrant(t *testing.T) {
	principal := uuid.New()
	grant := &model.VaultProvisioningGrant{PrincipalID: principal, Quota: 3}
	policies := &fakeAccessPolicyService{err: errors.New("db down")}
	grants := &stubGrantReader{grant: grant}

	got := CanCreateVault(context.Background(), []string{"user"}, policies, grants, principal)
	require.Equal(t, CreateRightNone, got, "a policy-service error must deny outright, not fall through to the provisioning grant")
}
