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

// Upsert mirrors the real repository's
// `ON CONFLICT (principal_id) DO UPDATE SET quota = excluded.quota`: on a
// conflicting principal_id, only Quota changes; ID, CreatedBy and CreatedAt
// keep the values from the original insert.
func (f *fakeGrantRepo) Upsert(_ context.Context, g *model.VaultProvisioningGrant) error {
	if existing, ok := f.grants[g.PrincipalID]; ok {
		existing.Quota = g.Quota
		return nil
	}
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

// TestIssueGrant_ReissueReturnsPersistedIdentity guards against the service
// handing back a freshly-built struct that disagrees with what the repository
// actually persisted. The repository's upsert only updates quota on a
// conflicting principal_id -- id and created_by must survive a re-issue
// unchanged, and the object IssueGrant returns must reflect that, not the
// caller-supplied issuedBy from the second call.
func TestIssueGrant_ReissueReturnsPersistedIdentity(t *testing.T) {
	repo := newFakeGrantRepo()
	svc := provisioning.NewGrantService(repo, nil)
	principal := uuid.New()
	firstIssuer := uuid.New()

	first, err := svc.IssueGrant(context.Background(), principal, 5, firstIssuer)
	require.NoError(t, err)

	second, err := svc.IssueGrant(context.Background(), principal, 9, uuid.New())
	require.NoError(t, err)

	all, err := svc.ListGrants(context.Background())
	require.NoError(t, err)
	require.Len(t, all, 1, "re-issuing must replace, not add, the principal's grant")

	require.Equal(t, 9, second.Quota, "returned grant must reflect the new quota")
	require.Equal(t, first.ID, second.ID, "id must survive a re-issue unchanged")
	require.Equal(t, firstIssuer, second.CreatedBy,
		"created_by is not updated on conflict, so the returned grant must still report the original issuer")
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
