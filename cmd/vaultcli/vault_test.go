package vaultcli

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

func newTestCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("vault", "", "")
	return cmd
}

func TestResolveVaultID_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	id, err := ResolveVaultID(context.Background(), cmd, tc.MockContainer)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if id != tc.TestVaultID {
		t.Fatalf("expected default vault id %s, got %s", tc.TestVaultID, id)
	}
}

func TestResolveVaultID_UnknownVault(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()
	if err := cmd.Flags().Set("vault", "does-not-exist"); err != nil {
		t.Fatal(err)
	}
	tc.MockVaultService.On("GetVault", mock.Anything, "does-not-exist").
		Return(nil, testutils.ErrVaultNotFoundForTest).Maybe()

	_, err := ResolveVaultID(context.Background(), cmd, tc.MockContainer)
	if err == nil {
		t.Fatal("expected an error for an unknown vault")
	}
}

func TestRequireDataAction_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	// Replace the default-allow instance with one that asserts it was called
	// with the exact principal/vault/action, not just "some" values — a
	// transposed argument (e.g. principalID and vaultID swapped) must fail
	// this test, not pass it.
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsGet).
		Return(true, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles

	vaultID, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet, model.OpGet)
	if err != nil {
		t.Fatalf("expected no error (default mock allows), got %v", err)
	}
	if vaultID != tc.TestVaultID {
		t.Fatalf("expected default vault id %s, got %s", tc.TestVaultID, vaultID)
	}
	roles.AssertExpectations(t)
}

func TestRequireDataAction_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	// Replace the default-allow instance with a fresh, deny-everything one.
	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	_, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet, model.OpGet)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}

// TestRequireDataAction_DeniedByPolicy proves the access_policies
// explicit-deny override short-circuits before the role-assignment check
// even runs — a principal explicitly denied via an access policy must be
// blocked regardless of any role assignment they hold. This is the exact
// scenario the final whole-branch review of Plan 01 found unguarded.
func TestRequireDataAction_DeniedByPolicy(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	denyPolicy := &testutils.MockAccessPolicyService{}
	denyPolicy.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpGet, tc.TestVaultID).
		Return(authzServices.AccessDenied, nil).Once()
	tc.MockContainer.AccessPolicyService = denyPolicy

	// A role assignment that would otherwise allow the action — proving the
	// policy deny wins even when a qualifying role assignment exists.
	roles := &testutils.MockRoleAssignmentService{}
	tc.MockContainer.RoleAssignmentService = roles

	_, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet, model.OpGet)
	if err == nil {
		t.Fatal("expected forbidden error from the access-policy deny")
	}
	denyPolicy.AssertExpectations(t)
	roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestRequireDataAction_CheckAccessError proves a lookup failure from
// CheckAccess propagates as a distinct error, not a silent allow or a plain
// deny, and short-circuits before HasDataAction runs.
func TestRequireDataAction_CheckAccessError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	wantErr := errors.New("policy lookup exploded")
	failingPolicy := &testutils.MockAccessPolicyService{}
	failingPolicy.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpGet, tc.TestVaultID).
		Return(authzServices.AccessFallback, wantErr).Once()
	tc.MockContainer.AccessPolicyService = failingPolicy

	roles := &testutils.MockRoleAssignmentService{}
	tc.MockContainer.RoleAssignmentService = roles

	_, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet, model.OpGet)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v, got %v", wantErr, err)
	}
	roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
