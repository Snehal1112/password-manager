package secrets

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

func TestUpdateCommand_CallsServiceUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()
	newValue := "new-secret-value"

	// The request must carry an owner scope built from the real authenticated
	// user. A vault scope would let a CLI caller overwrite any co-member's
	// secret, and a uuid.Nil actor would attribute the audit row to nobody.
	tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.UpdateSecretRequest) bool {
		return r.SecretID == secretID &&
			r.Scope == model.NewOwnerScope(tc.TestVaultID, tc.TestUserID) &&
			r.Value != nil && *r.Value == newValue
	})).Return(nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

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
