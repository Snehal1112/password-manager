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
