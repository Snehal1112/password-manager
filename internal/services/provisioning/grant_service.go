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
//
// The repository's upsert only updates quota on a conflicting principal_id
// (id, created_by and created_at survive unchanged), so the freshly-built
// struct passed to Upsert may not match what was actually persisted on a
// re-issue. IssueGrant reads the row back after writing it and returns that,
// so the caller — including an HTTP handler that reports created_by as "who
// issued this grant" — never sees values that disagree with the database.
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
	stored, err := s.repo.GetByPrincipal(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("read back issued grant: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo(issuedBy.String(), "issue_provisioning_grant", "success",
			fmt.Sprintf("Provisioning grant issued: principal=%s quota=%d", stored.PrincipalID, stored.Quota))
	}
	return stored, nil
}

// GetGrant returns the grant for principalID, or ErrGrantNotFound if none
// exists.
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

// RevokeGrant deletes the grant for principalID. Revocation does not cascade:
// it stops future creation and leaves the principal's existing vaults and
// their rights untouched. Cascading revocation would let one DELETE strip a
// customer's access to live vaults; removing those is a separate operator
// action.
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

// ListGrants returns every provisioning grant.
func (s *grantService) ListGrants(ctx context.Context) ([]*model.VaultProvisioningGrant, error) {
	return s.repo.List(ctx)
}
