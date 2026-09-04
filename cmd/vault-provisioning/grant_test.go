package vaultprovisioning

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/services/provisioning"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// resolvePrincipal
// ---------------------------------------------------------------------------

func TestResolvePrincipal_AcceptsUUID(t *testing.T) {
	id := uuid.New()

	// sc is nil to prove the UUID branch never touches the service
	// container -- a service account is not a users row, so it must not
	// require one to resolve.
	got, err := resolvePrincipal(context.Background(), nil, id.String())

	require.NoError(t, err)
	require.Equal(t, id, got,
		"a service account is not a users row, so a raw UUID must be accepted")
}

func TestResolvePrincipal_AcceptsUsername(t *testing.T) {
	tc := testutils.NewTestContext(t)
	wantID := uuid.New()
	tc.MockUserService.On("GetUserByUsername", mock.Anything, "alice").
		Return(&model.User{ID: wantID}, nil)

	got, err := resolvePrincipal(tc.Ctx, tc.MockContainer, "alice")

	require.NoError(t, err)
	require.Equal(t, wantID, got)
}

func TestResolvePrincipal_UnknownUsernameErrors(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockUserService.On("GetUserByUsername", mock.Anything, "nobody").
		Return(nil, errors.New("user not found"))

	_, err := resolvePrincipal(tc.Ctx, tc.MockContainer, "nobody")

	require.Error(t, err)
}

func TestResolvePrincipal_NilContainerWithUsernameErrors(t *testing.T) {
	_, err := resolvePrincipal(context.Background(), nil, "alice")

	require.Error(t, err, "a non-UUID argument with no container to resolve it against must error, not panic")
}

// ---------------------------------------------------------------------------
// grant
// ---------------------------------------------------------------------------

// fakeGrantSvc is a minimal provisioning.GrantService recording what reached
// it, so a denial or validation-refusal test can prove the service was never
// called.
type fakeGrantSvc struct {
	issueCalled bool
	issuePrinc  uuid.UUID
	issueQuota  int
	issueBy     uuid.UUID
	issueResult *model.VaultProvisioningGrant
	issueErr    error

	revokeCalled bool
	revokePrinc  uuid.UUID
	revokeBy     uuid.UUID
	revokeErr    error

	listCalled bool
	listResult []*model.VaultProvisioningGrant
	listErr    error
}

func (f *fakeGrantSvc) IssueGrant(_ context.Context, principalID uuid.UUID, quota int, issuedBy uuid.UUID) (*model.VaultProvisioningGrant, error) {
	f.issueCalled = true
	f.issuePrinc = principalID
	f.issueQuota = quota
	f.issueBy = issuedBy
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	if f.issueResult != nil {
		return f.issueResult, nil
	}
	return &model.VaultProvisioningGrant{PrincipalID: principalID, Quota: quota, CreatedBy: issuedBy}, nil
}

func (f *fakeGrantSvc) GetGrant(_ context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error) {
	return nil, provisioning.ErrGrantNotFound
}

func (f *fakeGrantSvc) RevokeGrant(_ context.Context, principalID, revokedBy uuid.UUID) error {
	f.revokeCalled = true
	f.revokePrinc = principalID
	f.revokeBy = revokedBy
	return f.revokeErr
}

func (f *fakeGrantSvc) ListGrants(_ context.Context) ([]*model.VaultProvisioningGrant, error) {
	f.listCalled = true
	return f.listResult, f.listErr
}

func TestGrantCommand_RequiresPositiveQuota(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeGrantSvc{}
	tc.MockContainer.GrantService = fake

	err := runGrant(tc.Ctx, tc.MockContainer, uuid.New().String(), 0, &bytes.Buffer{})

	require.Error(t, err, "a zero-quota grant is indistinguishable from no grant")
	require.False(t, fake.issueCalled, "the service must not be reached with an invalid quota")
}

func TestGrantCommand_NegativeQuotaRefused(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeGrantSvc{}
	tc.MockContainer.GrantService = fake

	err := runGrant(tc.Ctx, tc.MockContainer, uuid.New().String(), -5, &bytes.Buffer{})

	require.Error(t, err)
	require.False(t, fake.issueCalled)
}

func TestGrantCommand_NonAdminRefused(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeGrantSvc{}
	tc.MockContainer.GrantService = fake
	ctx := ctxWithClaims(uuid.New(), []string{"user"})

	err := runGrant(ctx, tc.MockContainer, uuid.New().String(), 5, &bytes.Buffer{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
	require.False(t, fake.issueCalled, "the service must not be reached when the caller is denied")
}

func TestGrantCommand_IssuesForUUIDPrincipal(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeGrantSvc{}
	tc.MockContainer.GrantService = fake
	principal := uuid.New()
	admin := uuid.New()
	ctx := ctxWithClaims(admin, []string{string(model.RoleAdmin)})

	var out bytes.Buffer
	err := runGrant(ctx, tc.MockContainer, principal.String(), 5, &out)

	require.NoError(t, err)
	require.True(t, fake.issueCalled)
	require.Equal(t, principal, fake.issuePrinc)
	require.Equal(t, 5, fake.issueQuota)
	require.Equal(t, admin, fake.issueBy, "the acting principal from requireGrantAdmin must be attributed as issuedBy")
	require.Contains(t, out.String(), principal.String())
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

func TestRevokeCommand_NonAdminRefused(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeGrantSvc{}
	tc.MockContainer.GrantService = fake
	ctx := ctxWithClaims(uuid.New(), []string{"user"})

	err := runRevoke(ctx, tc.MockContainer, uuid.New().String(), &bytes.Buffer{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
	require.False(t, fake.revokeCalled, "the service must not be reached when the caller is denied")
}

// TestRevokeCommand_PassesActingPrincipalAsRevokedBy is the Ruling-28 test:
// RevokeGrant's revokedBy parameter exists to fix a defect where revocation
// logged an unattributable, empty actor. This proves the real acting
// principal from requireGrantAdmin reaches the service, not uuid.Nil.
func TestRevokeCommand_PassesActingPrincipalAsRevokedBy(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeGrantSvc{}
	tc.MockContainer.GrantService = fake
	admin := uuid.New()
	principal := uuid.New()
	ctx := ctxWithClaims(admin, []string{string(model.RoleAdmin)})

	err := runRevoke(ctx, tc.MockContainer, principal.String(), &bytes.Buffer{})

	require.NoError(t, err)
	require.True(t, fake.revokeCalled)
	require.Equal(t, principal, fake.revokePrinc)
	require.Equal(t, admin, fake.revokeBy,
		"revokedBy must be the real acting principal returned by requireGrantAdmin, never uuid.Nil")
	require.NotEqual(t, uuid.Nil, fake.revokeBy)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

func TestListCommand_NonAdminRefused(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeGrantSvc{}
	tc.MockContainer.GrantService = fake
	ctx := ctxWithClaims(uuid.New(), []string{"user"})

	err := runList(ctx, tc.MockContainer, &bytes.Buffer{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
	require.False(t, fake.listCalled)
}

func TestListCommand_PrintsGrants(t *testing.T) {
	tc := testutils.NewTestContext(t)
	principal := uuid.New()
	fake := &fakeGrantSvc{
		listResult: []*model.VaultProvisioningGrant{
			{PrincipalID: principal, Quota: 3},
		},
	}
	tc.MockContainer.GrantService = fake

	var out bytes.Buffer
	err := runList(tc.Ctx, tc.MockContainer, &out)

	require.NoError(t, err)
	require.True(t, fake.listCalled)
	require.Contains(t, out.String(), principal.String())
	require.Contains(t, out.String(), "3")
}
