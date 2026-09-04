package container

import (
	"context"
	"fmt"

	"rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// txCapablePolicyRepo is implemented by AccessPolicyRepositoryInterface's
// concrete type when it also supports the Tx-scoped create used by the
// provisioned vault-create path. CreateTx lives only on the concrete
// accessPolicyRepository struct, not on the exported
// AccessPolicyRepositoryInterface, so adding it doesn't ripple to every test
// double implementing that interface -- the same reasoning as
// vaultServices' txCapableVaultRepo.
type txCapablePolicyRepo interface {
	CreateTx(ctx context.Context, ex db.DBTX, p *model.AccessPolicy) error
}

// txCapableRoleRepo is the role-assignment half of the same pattern.
type txCapableRoleRepo interface {
	CreateTx(ctx context.Context, ex db.DBTX, ra *model.RoleAssignment) error
}

// creatorGranterAdapter satisfies vaultServices.CreatorGranter by recovering
// the Tx-scoped create capability from the concrete access-policy and
// role-assignment repositories via type assertion.
type creatorGranterAdapter struct {
	policies repositories.AccessPolicyRepositoryInterface
	roles    repositories.RoleAssignmentRepositoryInterface
}

// CreatePolicyTx writes the creator's access policy inside the caller's transaction.
func (a *creatorGranterAdapter) CreatePolicyTx(ctx context.Context, ex db.DBTX, p *model.AccessPolicy) error {
	txRepo, ok := a.policies.(txCapablePolicyRepo)
	if !ok {
		return fmt.Errorf("access policy repository %T does not support transactional create", a.policies)
	}
	return txRepo.CreateTx(ctx, ex, p)
}

// CreateRoleTx writes the creator's role assignment inside the caller's transaction.
func (a *creatorGranterAdapter) CreateRoleTx(ctx context.Context, ex db.DBTX, ra *model.RoleAssignment) error {
	txRepo, ok := a.roles.(txCapableRoleRepo)
	if !ok {
		return fmt.Errorf("role assignment repository %T does not support transactional create", a.roles)
	}
	return txRepo.CreateTx(ctx, ex, ra)
}
