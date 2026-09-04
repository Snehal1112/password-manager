// Package vaults — unit tests for authz.go's shared CLI authorization
// checks. requireCanCreateVault and callerIdentity had no dedicated test
// coverage before this file.
package vaults

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/internal/services/provisioning"
	"rocketvault/model"
)

// testPrincipalID is the fixed principal used across this file's tests.
var testPrincipalID = uuid.New()

// ctxWithClaims returns a context carrying claims for principalID with the
// given account roles, mirroring cmd/vault-access/authz_test.go's
// nonAdminCtx pattern.
func ctxWithClaims(t *testing.T, principalID uuid.UUID, roles []string) context.Context {
	t.Helper()
	return context.WithValue(context.Background(), common.ClaimsKey,
		&model.Claims{UserID: principalID, Roles: roles})
}

// fakeGrantService is a minimal test double for provisioning.GrantService,
// returning a fixed grant (or provisioning.ErrGrantNotFound) for any
// principal -- only GetGrant is exercised by CanCreateVault; the remaining
// methods are unused here and are no-ops. Mirrors
// internal/services/authorization/vault_authz_test.go's stubGrantReader.
type fakeGrantService struct {
	grant *model.VaultProvisioningGrant
}

func (f *fakeGrantService) IssueGrant(context.Context, uuid.UUID, int, uuid.UUID) (*model.VaultProvisioningGrant, error) {
	return nil, nil
}

func (f *fakeGrantService) GetGrant(context.Context, uuid.UUID) (*model.VaultProvisioningGrant, error) {
	if f.grant == nil {
		return nil, provisioning.ErrGrantNotFound
	}
	return f.grant, nil
}

func (f *fakeGrantService) RevokeGrant(context.Context, uuid.UUID) error { return nil }

func (f *fakeGrantService) ListGrants(context.Context) ([]*model.VaultProvisioningGrant, error) {
	return nil, nil
}

// newMockContainerWithGrant returns the file's existing mock container
// (testutils.MockServiceContainer), wired so no global vaults:manage policy
// applies and a provisioning grant for principalID/quota does -- exercising
// requireCanCreateVault's CreateRightProvisioningGrant path.
func newMockContainerWithGrant(t *testing.T, principalID uuid.UUID, quota int) *testutils.MockServiceContainer {
	t.Helper()
	tc := testutils.NewTestContext(t)
	policySvc := &testutils.MockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessFallback, nil)
	tc.MockContainer.AccessPolicyService = policySvc
	tc.MockContainer.GrantService = &fakeGrantService{
		grant: &model.VaultProvisioningGrant{ID: uuid.New(), PrincipalID: principalID, Quota: quota},
	}
	return tc.MockContainer
}

// newMockContainerNoGrant mirrors newMockContainerWithGrant but wires
// neither a global policy nor a provisioning grant.
func newMockContainerNoGrant(t *testing.T) *testutils.MockServiceContainer {
	t.Helper()
	tc := testutils.NewTestContext(t)
	policySvc := &testutils.MockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, uuid.Nil).
		Return(authzServices.AccessFallback, nil)
	tc.MockContainer.AccessPolicyService = policySvc
	tc.MockContainer.GrantService = &fakeGrantService{}
	return tc.MockContainer
}

// TestRequireCanCreateVault_AllowsGrantHolder proves a non-admin caller with
// no global policy but a provisioning grant is admitted by
// requireCanCreateVault -- the CLI must reach the same decision as HTTP:
// both call CanCreateVault.
func TestRequireCanCreateVault_AllowsGrantHolder(t *testing.T) {
	sc := newMockContainerWithGrant(t, testPrincipalID, 5)
	ctx := ctxWithClaims(t, testPrincipalID, []string{"user"})

	right, err := requireCanCreateVault(ctx, sc)
	require.NoError(t, err,
		"the CLI must reach the same decision as HTTP: both call CanCreateVault")
	require.Equal(t, authzServices.CreateRightProvisioningGrant, right,
		"the caller needs the right, not merely a nil error, to know the create is quota-bounded")
}

// TestRequireCanCreateVault_DeniesWithoutAnyRight proves a caller with none
// of the three rights -- admin, global policy, or provisioning grant -- is
// still refused.
func TestRequireCanCreateVault_DeniesWithoutAnyRight(t *testing.T) {
	sc := newMockContainerNoGrant(t)
	ctx := ctxWithClaims(t, testPrincipalID, []string{"user"})

	right, err := requireCanCreateVault(ctx, sc)
	require.Error(t, err)
	require.Equal(t, authzServices.CreateRightNone, right)
}

// TestCallerIdentity_MissingClaims proves callerIdentity fails closed with an
// error, not a zero-value principal, when the context carries no claims --
// a wiring bug, not a permission denial.
func TestCallerIdentity_MissingClaims(t *testing.T) {
	_, _, err := callerIdentity(context.Background())
	require.Error(t, err)
}

// TestCallerIdentity_ReturnsRolesAndID proves callerIdentity extracts the
// account roles and user ID carried by the context's claims.
func TestCallerIdentity_ReturnsRolesAndID(t *testing.T) {
	ctx := ctxWithClaims(t, testPrincipalID, []string{"user", "admin"})

	roles, principalID, err := callerIdentity(ctx)
	require.NoError(t, err)
	require.Equal(t, testPrincipalID, principalID)
	require.ElementsMatch(t, []string{"user", "admin"}, roles)
}
