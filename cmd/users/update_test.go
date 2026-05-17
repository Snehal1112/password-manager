package users

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/model"
)

// newUpdateTestContextWithRole creates a test context where the caller has the given role and user ID.
func newUpdateTestContextWithRole(t *testing.T, callerID uuid.UUID, role string) *testutils.TestContext {
	tc := testutils.NewTestContext(t)
	claims := &model.Claims{
		UserID:   callerID,
		Username: "testuser",
		Role:     role,
	}
	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.UserIDKey, callerID)
	tc.Ctx = ctx
	return tc
}

func TestUpdateUserRoleEnforcement(t *testing.T) {
	ownID := uuid.New()

	tests := []struct {
		name        string
		callerRole  string
		targetID    string
		newRole     string
		expectError string
	}{
		{
			name:        "non-admin cannot change own role",
			callerRole:  model.RoleUser,
			targetID:    ownID.String(),
			newRole:     model.RoleAdmin,
			expectError: "forbidden",
		},
		{
			name:        "non-admin cannot change other user role",
			callerRole:  model.RoleSecretsManager,
			targetID:    uuid.New().String(),
			newRole:     model.RoleUser,
			expectError: "forbidden",
		},
		{
			name:        "invalid role substring bypass blocked",
			callerRole:  model.RoleAdmin,
			targetID:    uuid.New().String(),
			newRole:     "min",
			expectError: "invalid role",
		},
		{
			name:        "invalid role manager substring blocked",
			callerRole:  model.RoleAdmin,
			targetID:    uuid.New().String(),
			newRole:     "_manager",
			expectError: "invalid role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			tc := newUpdateTestContextWithRole(t, ownID, tt.callerRole)

			cmd := &cobra.Command{
				Use:  "update",
				Args: cobra.ExactArgs(1),
				RunE: updateCmd.RunE,
			}
			cmd.Flags().String("new-username", "", "")
			cmd.Flags().String("new-password", "", "")
			cmd.Flags().String("new-role", "", "")
			cmd.SetContext(tc.Ctx)
			cmd.SetArgs([]string{tt.targetID, "--new-role=" + tt.newRole})

			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
			tc.MockUserService.AssertNotCalled(t, "UpdateUser")
		})
	}
}
