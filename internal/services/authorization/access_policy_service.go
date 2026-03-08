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
	// CheckAccess evaluates policies for the (principal, resourceType, operation) triple.
	// Returns AccessAllowed, AccessDenied, or AccessFallback (use RBAC).
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

// NewAccessPolicyService creates a new AccessPolicyService backed by repo.
func NewAccessPolicyService(repo repositories.AccessPolicyRepositoryInterface) AccessPolicyService {
	return &accessPolicyService{repo: repo}
}

// CheckAccess evaluates access policies for the triple (principalID, resourceType, operation).
// Explicit deny always wins. Falls back to RBAC when no matching policy exists.
func (s *accessPolicyService) CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType domain.PolicyResourceType, operation domain.PolicyOperation) (AccessDecision, error) {
	policies, err := s.repo.FindEffects(ctx, principalID, resourceType, operation)
	if err != nil {
		return AccessFallback, fmt.Errorf("policy lookup: %w", err)
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
