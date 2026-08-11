package vaultcli

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
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

	vaultID, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet)
	if err != nil {
		t.Fatalf("expected no error (default mock allows), got %v", err)
	}
	if vaultID != tc.TestVaultID {
		t.Fatalf("expected default vault id %s, got %s", tc.TestVaultID, vaultID)
	}
}

func TestRequireDataAction_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := newTestCommand()

	// Replace the default-allow instance with a fresh, deny-everything one.
	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	_, err := RequireDataAction(context.Background(), cmd, tc.MockContainer, tc.TestUserID, model.ActionSecretsGet)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}
