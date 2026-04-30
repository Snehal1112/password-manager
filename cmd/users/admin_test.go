package users

import (
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/domain"
	userServices "rocketvault/internal/services/users"
)

func TestAdminCommand_UsesContextContainer(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockUserService.On("ValidateBootstrapToken", mock.Anything, "test-token").
		Return(true, nil)
	tc.MockUserService.On("CreateUser", mock.Anything, mock.MatchedBy(func(r userServices.CreateUserRequest) bool {
		return r.Username == "newadmin" && r.Role == domain.RoleAdmin
	})).Return(&userServices.CreateUserResult{
		UserID:     uuid.New(),
		Username:   "newadmin",
		Role:       domain.RoleAdmin,
		TOTPSecret: "otpauth://totp/...?secret=ABCDEF",
	}, nil)
	tc.MockUserService.On("InvalidateBootstrapToken", mock.Anything, "test-token").
		Return(nil)

	cmd := &cobra.Command{Use: "admin", RunE: registerAdminCmd.RunE}
	cmd.Flags().String("admin-username", "newadmin", "")
	cmd.Flags().String("admin-password", "pass123", "")
	cmd.Flags().String("bootstrap-token", "test-token", "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}

func TestAdminCommand_InvalidToken(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockUserService.On("ValidateBootstrapToken", mock.Anything, "bad-token").
		Return(false, nil)

	cmd := &cobra.Command{Use: "admin", RunE: registerAdminCmd.RunE}
	cmd.Flags().String("admin-username", "newadmin", "")
	cmd.Flags().String("admin-password", "pass123", "")
	cmd.Flags().String("bootstrap-token", "bad-token", "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or used bootstrap token")
}
