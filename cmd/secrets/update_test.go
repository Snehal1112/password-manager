package secrets

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	authzServices "rocketvault/internal/services/authorization"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

func TestUpdateCommand_CallsServiceUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()
	newValue := "new-secret-value"

	// The request must carry a vault scope built from the real authenticated
	// user, matching api/secrets.go's updateSecret handler on the
	// /vaults/{name}/secrets/... route (scopeFromRequest returns a vault
	// scope there). Any vault member holding a role that grants
	// ActionSecretsSet can update the secret; the actor is still the real
	// authenticated user so the audit row is attributed correctly.
	tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.UpdateSecretRequest) bool {
		return r.SecretID == secretID &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) &&
			r.Value != nil && *r.Value == newValue
	})).Return(nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	// Assert the exact args reaching both authorization checks, not just
	// "some" values — a transposed action/op or swapped principal/vault must
	// fail this test, not pass it.
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsSet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpSet, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetArgs([]string{secretID.String(), newValue})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestUpdateCommand_WithTags(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.UpdateSecretRequest) bool {
		return r.SecretID == secretID && r.Tags != nil && len(*r.Tags) == 2
	})).Return(nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetArgs([]string{secretID.String(), "value", "--tags=env:prod,team:backend"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

func TestUpdateCommand_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.Anything).
		Return(fmt.Errorf("update failed"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetArgs([]string{secretID.String(), "value"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update secret")
}

func TestUpdateCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetArgs([]string{secretID.String(), "value"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "UpdateSecret", mock.Anything, mock.Anything)
}
