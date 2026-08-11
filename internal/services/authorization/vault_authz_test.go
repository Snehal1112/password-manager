package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// fakeAccessPolicyService is a minimal test double for AccessPolicyService,
// returning a fixed decision/error for CheckAccess. The remaining interface
// methods are no-ops; no test in this file exercises them.
type fakeAccessPolicyService struct {
	decision AccessDecision
	err      error
}

func (f *fakeAccessPolicyService) CheckAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (AccessDecision, error) {
	return f.decision, f.err
}
func (f *fakeAccessPolicyService) CreatePolicy(context.Context, *model.AccessPolicy) error { return nil }
func (f *fakeAccessPolicyService) GetPolicy(context.Context, uuid.UUID) (*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) ListPolicies(context.Context) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) ListByPrincipal(context.Context, uuid.UUID) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakeAccessPolicyService) UpdatePolicy(context.Context, *model.AccessPolicy) error { return nil }
func (f *fakeAccessPolicyService) DeletePolicy(context.Context, uuid.UUID) error           { return nil }

func TestCanManageVault_AdminAlwaysAllowed(t *testing.T) {
	// Even a policy service that would deny must not be consulted for admin.
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	if !CanManageVault(context.Background(), model.RoleAdmin, policies, uuid.New(), uuid.New()) {
		t.Fatal("admin must always be allowed to manage vaults")
	}
}

func TestCanManageVault_NonAdminAllowedOnPolicyAllow(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed}
	if !CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with an allow policy must be allowed")
	}
}

func TestCanManageVault_NonAdminDeniedOnPolicyDeny(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	if CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with a deny policy must be denied")
	}
}

func TestCanManageVault_NonAdminDeniedOnFallback(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	if CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("non-admin with no matching policy (fallback) must be denied — vault management has no other grant source")
	}
}

func TestCanManageVault_NonAdminDeniedOnServiceError(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed, err: errors.New("db down")}
	if CanManageVault(context.Background(), model.RoleUser, policies, uuid.New(), uuid.New()) {
		t.Fatal("a service error must fail closed, not fail open")
	}
}

func TestCanManageVault_NonAdminDeniedOnNilService(t *testing.T) {
	if CanManageVault(context.Background(), model.RoleUser, nil, uuid.New(), uuid.New()) {
		t.Fatal("a nil AccessPolicyService must fail closed")
	}
}

func TestCanPurgeVault_AdminAlwaysAllowed(t *testing.T) {
	if !CanPurgeVault(context.Background(), model.RoleAdmin, nil, uuid.New(), uuid.New()) {
		t.Fatal("admin must always be allowed to purge, even with a nil role-assignment service")
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

	if !CanPurgeVault(context.Background(), model.RoleUser, svc, principalID, vaultID) {
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

	if CanPurgeVault(context.Background(), model.RoleUser, svc, principalID, vaultID) {
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

	if CanPurgeVault(context.Background(), model.RoleUser, svc, principalID, targetVault) {
		t.Fatal("a Purge Operator grant in vault A must not authorize purging vault B")
	}
}

func TestCanPurgeVault_NonAdminDeniedWithNoAssignments(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{}
	svc := newSvc(rr, pr, ul)

	if CanPurgeVault(context.Background(), model.RoleUser, svc, uuid.New(), uuid.New()) {
		t.Fatal("no role assignments at all must deny")
	}
}

func TestCanPurgeVault_NonAdminDeniedOnNilService(t *testing.T) {
	if CanPurgeVault(context.Background(), model.RoleUser, nil, uuid.New(), uuid.New()) {
		t.Fatal("a nil RoleAssignmentService must fail closed")
	}
}

func TestCanManageRoleAssignments_AdminAlwaysAllowed(t *testing.T) {
	if !CanManageRoleAssignments(context.Background(), model.RoleAdmin, nil, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("admin must always be allowed, write=true")
	}
	if !CanManageRoleAssignments(context.Background(), model.RoleAdmin, nil, nil, uuid.New(), uuid.New(), false) {
		t.Fatal("admin must always be allowed, write=false")
	}
}

func TestCanManageRoleAssignments_NonAdminAllowedByAccessPolicy(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed}
	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("an allow access-policy on (vaults, manage) must grant write, preserving today's documented behavior")
	}
	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, nil, uuid.New(), uuid.New(), false) {
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

	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, roleSvc, principalID, vaultID, true) {
		t.Fatal("Data Access Administrator must grant write")
	}
	if !CanManageRoleAssignments(context.Background(), model.RoleUser, policies, roleSvc, principalID, vaultID, false) {
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

	if CanManageRoleAssignments(context.Background(), model.RoleUser, policies, roleSvc, principalID, targetVault, true) {
		t.Fatal("Data Access Administrator in vault A must not authorize managing role assignments in vault B")
	}
}

func TestCanManageRoleAssignments_NonAdminDeniedWithNothing(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	if CanManageRoleAssignments(context.Background(), model.RoleUser, policies, nil, uuid.New(), uuid.New(), true) {
		t.Fatal("no policy allow and no role service must deny")
	}
}
