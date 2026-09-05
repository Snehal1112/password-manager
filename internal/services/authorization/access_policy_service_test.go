package authorization_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// mockPolicyRepo implements AccessPolicyRepositoryInterface for testing.
type mockPolicyRepo struct{ mock.Mock }

func (m *mockPolicyRepo) Create(ctx context.Context, p *model.AccessPolicy) error {
	return m.Called(ctx, p).Error(0)
}
func (m *mockPolicyRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) List(ctx context.Context) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) ListByPrincipal(ctx context.Context, id uuid.UUID) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx, id)
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) FindEffects(ctx context.Context, pid uuid.UUID, rt model.PolicyResourceType, op model.PolicyOperation, vaultID uuid.UUID) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx, pid, rt, op, vaultID)
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx, vaultID)
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}
func (m *mockPolicyRepo) Update(ctx context.Context, p *model.AccessPolicy) error {
	return m.Called(ctx, p).Error(0)
}
func (m *mockPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockPolicyRepo) DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error {
	return m.Called(ctx, assignmentID).Error(0)
}
func (m *mockPolicyRepo) DeleteByVault(ctx context.Context, vaultID uuid.UUID) error {
	return m.Called(ctx, vaultID).Error(0)
}
func (m *mockPolicyRepo) ListVaultIDsForPrincipal(ctx context.Context, principalID uuid.UUID) ([]uuid.UUID, error) {
	args := m.Called(ctx, principalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uuid.UUID), args.Error(1)
}

func TestCheckAccess_AllowWhenPolicyExists(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()
	vaultID := uuid.New()

	repo.On("FindEffects", ctx, pid, model.PolicyResourceSecrets, model.OpGet, vaultID).
		Return([]*model.AccessPolicy{{Effect: model.PolicyEffectAllow}}, nil)

	result, err := svc.CheckAccess(ctx, pid, model.PolicyResourceSecrets, model.OpGet, vaultID)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessAllowed, result)
	repo.AssertExpectations(t)
}

func TestCheckAccess_DenyWinsOverAllow(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()
	vaultID := uuid.New()

	repo.On("FindEffects", ctx, pid, model.PolicyResourceSecrets, model.OpDelete, vaultID).
		Return([]*model.AccessPolicy{
			{Effect: model.PolicyEffectAllow},
			{Effect: model.PolicyEffectDeny},
		}, nil)

	result, err := svc.CheckAccess(ctx, pid, model.PolicyResourceSecrets, model.OpDelete, vaultID)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessDenied, result)
	repo.AssertExpectations(t)
}

func TestCheckAccess_VaultDenyOverridesGlobalAllow(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()
	vaultID := uuid.New()

	// One global allow (nil VaultID) and one vault-specific deny for the same
	// (principal, resource, operation); deny must win across scopes.
	repo.On("FindEffects", ctx, pid, model.PolicyResourceSecrets, model.OpGet, vaultID).
		Return([]*model.AccessPolicy{
			{VaultID: nil, Effect: model.PolicyEffectAllow},
			{VaultID: &vaultID, Effect: model.PolicyEffectDeny},
		}, nil)

	result, err := svc.CheckAccess(ctx, pid, model.PolicyResourceSecrets, model.OpGet, vaultID)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessDenied, result)
	repo.AssertExpectations(t)
}

func TestCheckAccess_FallbackWhenNoPolicies(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()
	vaultID := uuid.New()

	repo.On("FindEffects", ctx, pid, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return([]*model.AccessPolicy{}, nil)

	result, err := svc.CheckAccess(ctx, pid, model.PolicyResourceKeys, model.OpCreate, vaultID)
	require.NoError(t, err)
	assert.Equal(t, authorization.AccessFallback, result)
	repo.AssertExpectations(t)
}

func TestCheckAccess_ReturnsErrorOnRepoFailure(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()
	pid := uuid.New()
	vaultID := uuid.New()

	repo.On("FindEffects", ctx, pid, model.PolicyResourceCertificates, model.OpDelete, vaultID).
		Return([]*model.AccessPolicy{}, errors.New("db error"))

	result, err := svc.CheckAccess(ctx, pid, model.PolicyResourceCertificates, model.OpDelete, vaultID)
	require.Error(t, err)
	assert.Equal(t, authorization.AccessFallback, result)
	repo.AssertExpectations(t)
}

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

// TestCheckAccess_GlobalDenyBlocksDataPlaneInEveryVault is the regression pin
// for the one thing the vault-management narrowing must never touch: a
// NULL-scoped (global) DENY on a data-plane resource keeps blocking in every
// vault. That is what CheckAccess and the repository's
// "(vault_id = ? OR vault_id IS NULL)" clause exist for, and it is the sole
// mechanism behind an operator suspending a principal instance-wide.
//
// Every other suite that covers a deny -- PolicyMiddleware's and
// vaultcli.RequireDataAction's -- stubs the AccessPolicyService itself, so it
// asserts only "AccessDenied yields 403", never that a NULL-scoped row
// produces AccessDenied. This test therefore runs the real service over the
// real repository against SQLite, so a narrowing that leaked into CheckAccess
// or FindEffects would fail here rather than pass unnoticed everywhere.
func TestCheckAccess_GlobalDenyBlocksDataPlaneInEveryVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	_, err = sqlDB.ExecContext(ctx, `CREATE TABLE access_policies (
		id             TEXT PRIMARY KEY,
		principal_id   TEXT NOT NULL,
		principal_type TEXT NOT NULL,
		resource_type  TEXT NOT NULL,
		operation      TEXT NOT NULL,
		effect         TEXT NOT NULL,
		vault_id       TEXT NULL,
		assignment_id  TEXT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)

	repo := repositories.NewAccessPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite))
	svc := authorization.NewAccessPolicyService(repo)
	principalID := uuid.New()

	// A single global deny row: no vault_id, so it belongs to no vault.
	require.NoError(t, repo.Create(ctx, &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpGet,
		Effect: model.PolicyEffectDeny, VaultID: nil,
	}))

	// Two unrelated vaults, neither named by the policy row.
	for _, vaultID := range []uuid.UUID{uuid.New(), uuid.New()} {
		got, err := svc.CheckAccess(ctx, principalID, model.PolicyResourceSecrets, model.OpGet, vaultID)
		require.NoError(t, err)
		assert.Equal(t, authorization.AccessDenied, got,
			"a global deny on secrets:get must block in every vault")
	}
}

func TestCreatePolicy_AssignsIDAndTimestamp(t *testing.T) {
	repo := &mockPolicyRepo{}
	svc := authorization.NewAccessPolicyService(repo)
	ctx := context.Background()

	policy := &model.AccessPolicy{
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
	}

	repo.On("Create", ctx, mock.MatchedBy(func(p *model.AccessPolicy) bool {
		return p.ID != uuid.Nil && !p.CreatedAt.IsZero()
	})).Return(nil)

	require.NoError(t, svc.CreatePolicy(ctx, policy))
	assert.NotEqual(t, uuid.Nil, policy.ID)
	repo.AssertExpectations(t)
}
