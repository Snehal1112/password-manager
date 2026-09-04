package provisioning_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/provisioning"
	"rocketvault/model"
)

// fakeGrantRepo is an in-memory VaultProvisioningGrantRepositoryInterface.
type fakeGrantRepo struct {
	grants map[uuid.UUID]*model.VaultProvisioningGrant
}

func newFakeGrantRepo() *fakeGrantRepo {
	return &fakeGrantRepo{grants: map[uuid.UUID]*model.VaultProvisioningGrant{}}
}

func (f *fakeGrantRepo) Upsert(_ context.Context, g *model.VaultProvisioningGrant) error {
	f.grants[g.PrincipalID] = g
	return nil
}

func (f *fakeGrantRepo) GetByPrincipal(_ context.Context, id uuid.UUID) (*model.VaultProvisioningGrant, error) {
	g, ok := f.grants[id]
	if !ok {
		return nil, repositories.ErrNotFound
	}
	return g, nil
}

func (f *fakeGrantRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.grants, id)
	return nil
}

func (f *fakeGrantRepo) List(_ context.Context) ([]*model.VaultProvisioningGrant, error) {
	out := make([]*model.VaultProvisioningGrant, 0, len(f.grants))
	for _, g := range f.grants {
		out = append(out, g)
	}
	return out, nil
}

func TestIssueGrant_StoresAndReturns(t *testing.T) {
	repo := newFakeGrantRepo()
	svc := provisioning.NewGrantService(repo, nil)
	principal, issuer := uuid.New(), uuid.New()

	g, err := svc.IssueGrant(context.Background(), principal, 5, issuer)
	require.NoError(t, err)
	require.Equal(t, 5, g.Quota)
	require.Equal(t, issuer, g.CreatedBy)
	require.NotEqual(t, uuid.Nil, g.ID)
}

func TestIssueGrant_RejectsNonPositiveQuota(t *testing.T) {
	svc := provisioning.NewGrantService(newFakeGrantRepo(), nil)

	for _, quota := range []int{0, -1} {
		_, err := svc.IssueGrant(context.Background(), uuid.New(), quota, uuid.New())
		require.True(t, errors.Is(err, model.ErrInvalidQuota),
			"quota %d must be rejected: a zero-quota grant is indistinguishable from no grant", quota)
	}
}

func TestIssueGrant_IsUpsert(t *testing.T) {
	repo := newFakeGrantRepo()
	svc := provisioning.NewGrantService(repo, nil)
	principal := uuid.New()

	_, err := svc.IssueGrant(context.Background(), principal, 5, uuid.New())
	require.NoError(t, err)
	_, err = svc.IssueGrant(context.Background(), principal, 9, uuid.New())
	require.NoError(t, err)

	all, err := svc.ListGrants(context.Background())
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.Equal(t, 9, all[0].Quota)
}

func TestGetGrant_MissingReturnsErrGrantNotFound(t *testing.T) {
	svc := provisioning.NewGrantService(newFakeGrantRepo(), nil)

	_, err := svc.GetGrant(context.Background(), uuid.New())
	require.True(t, errors.Is(err, provisioning.ErrGrantNotFound),
		"callers branch on this sentinel to mean 'no provisioning right', not 'lookup failed'")
}

func TestRevokeGrant(t *testing.T) {
	repo := newFakeGrantRepo()
	svc := provisioning.NewGrantService(repo, nil)
	principal := uuid.New()

	_, err := svc.IssueGrant(context.Background(), principal, 5, uuid.New())
	require.NoError(t, err)
	require.NoError(t, svc.RevokeGrant(context.Background(), principal))

	_, err = svc.GetGrant(context.Background(), principal)
	require.True(t, errors.Is(err, provisioning.ErrGrantNotFound))
}
