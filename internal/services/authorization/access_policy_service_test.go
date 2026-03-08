package authorization_test

import (
"context"
"errors"
"testing"

"github.com/google/uuid"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/mock"
"github.com/stretchr/testify/require"

"rocketvault/internal/domain"
"rocketvault/internal/services/authorization"
)

// mockPolicyRepo implements AccessPolicyRepositoryInterface for testing.
type mockPolicyRepo struct{ mock.Mock }

func (m *mockPolicyRepo) Create(ctx context.Context, p *domain.AccessPolicy) error {
	return m.Called(ctx, p).Error(0)
}
func (m *mockPolicyRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.AccessPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
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

	repo.On("FindEffects", ctx, pid, domain.PolicyResourceSecrets, domain.OpGet).
		Return([]*domain.AccessPolicy{{Effect: domain.PolicyEffectAllow}}, nil)

	result, err := svc.CheckAccess(ctx, pid, domain.PolicyResourceSecrets, domain.OpGet)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessAllowed, result)
	repo.AssertExpectations(t)
}

func TestCheckAccess_DenyWinsOverAllow(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()

	repo.On("FindEffects", ctx, pid, domain.PolicyResourceSecrets, domain.OpDelete).
		Return([]*domain.AccessPolicy{
{Effect: domain.PolicyEffectAllow},
{Effect: domain.PolicyEffectDeny},
}, nil)

	result, err := svc.CheckAccess(ctx, pid, domain.PolicyResourceSecrets, domain.OpDelete)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessDenied, result)
	repo.AssertExpectations(t)
}

func TestCheckAccess_FallbackWhenNoPolicies(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()

	repo.On("FindEffects", ctx, pid, domain.PolicyResourceKeys, domain.OpCreate).
		Return([]*domain.AccessPolicy{}, nil)

	result, err := svc.CheckAccess(ctx, pid, domain.PolicyResourceKeys, domain.OpCreate)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessFallback, result)
	repo.AssertExpectations(t)
}

func TestCheckAccess_ReturnsErrorOnRepoFailure(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()

	repo.On("FindEffects", ctx, pid, domain.PolicyResourceCertificates, domain.OpDelete).
		Return([]*domain.AccessPolicy{}, errors.New("db error"))

	result, err := svc.CheckAccess(ctx, pid, domain.PolicyResourceCertificates, domain.OpDelete)
	require.Error(t, err)
	assert.Equal(t, authorization.AccessFallback, result)
	repo.AssertExpectations(t)
}

func TestCreatePolicy_AssignsIDAndTimestamp(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()

	policy := &domain.AccessPolicy{
		PrincipalID:   uuid.New(),
		PrincipalType: domain.PrincipalTypeUser,
		ResourceType:  domain.PolicyResourceSecrets,
		Operation:     domain.OpGet,
		Effect:        domain.PolicyEffectAllow,
	}

	repo.On("Create", ctx, mock.MatchedBy(func(p *domain.AccessPolicy) bool {
return p.ID != uuid.Nil && !p.CreatedAt.IsZero()
	})).Return(nil)

	require.NoError(t, svc.CreatePolicy(ctx, policy))
	assert.NotEqual(t, uuid.Nil, policy.ID)
	repo.AssertExpectations(t)
}
