/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package users

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	userService "rocketvault/internal/services/users"
	"rocketvault/model"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update user information",
	Long:  `Update a user's username, password, or role by their UUID. Accessible by the user themselves or users with the admin role.`,
	Example: `  # Update user information by ID
  rocketvault users update <user-id> \
    --username admin --password admin123 --totp-code <code> \
    --new-username newuser --new-password newpass123 --new-role user`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}

		id, err := uuid.Parse(args[0])
		if err != nil {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", fmt.Sprintf("invalid user ID: %s", err), err)
			return fmt.Errorf("invalid user ID: %w", err)
		}

		if claims.UserID != id && claims.Role != model.RoleAdmin {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: cannot update other users", nil)
			return fmt.Errorf("forbidden: cannot update other users")
		}

		// Read flags directly so tests work without viper binding.
		newUsername, _ := cmd.Flags().GetString("new-username")
		newPassword, _ := cmd.Flags().GetString("new-password")
		newRole, _ := cmd.Flags().GetString("new-role")

		if newUsername == "" && newPassword == "" && newRole == "" {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "at least one field must be provided", nil)
			return fmt.Errorf("at least one field (new-username, new-password, new-role) must be provided")
		}

		// Only admins may change roles — including changing their own role.
		if newRole != "" && claims.Role != model.RoleAdmin {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: only admins can change roles", nil)
			return fmt.Errorf("forbidden: only admins can change roles")
		}

		// Validate role is an exact known value (not a substring match).
		validRoles := map[string]bool{
			model.RoleAdmin:              true,
			model.RoleUser:               true,
			model.RoleSecretsManager:     true,
			model.RoleCryptoManager:      true,
			model.RoleCertificateManager: true,
			model.RoleServiceAccount:     true,
		}
		if newRole != "" && !validRoles[newRole] {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "invalid role", nil)
			return fmt.Errorf("invalid role: must be one of admin, secrets_manager, crypto_manager, certificate_manager, user, service_account")
		}

		// Use user service for update.
		userSvc := serviceContainer.GetUserService()

		// Convert string values to pointers for optional fields.
		var usernamePtr, passwordPtr, rolePtr *string
		if newUsername != "" {
			usernamePtr = &newUsername
		}
		if newPassword != "" {
			passwordPtr = &newPassword
		}
		if newRole != "" {
			rolePtr = &newRole
		}

		if err := userSvc.UpdateUser(ctx, userService.UpdateUserRequest{
			UserID:     id,
			CallerID:   claims.UserID,
			CallerRole: claims.Role,
			Username:   usernamePtr,
			Password:   passwordPtr,
			Role:       rolePtr,
		}); err != nil {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", fmt.Sprintf("failed to update user: %s", err), err)
			return fmt.Errorf("failed to update user: %w", err)
		}

		logger := serviceContainer.GetLogger()
		logger.LogAuditInfo(claims.UserID.String(), "update_user", "success", fmt.Sprintf("user updated: %s", id))
		fmt.Printf("User %s updated successfully\n", id)
		return nil
	},
}

// InitUsersUpdate initializes the update command for users
// and adds it to the users command. It also sets up the necessary flags
// and configuration settings. The update command allows users to update
// information about a specific user by username. It requires the username
// to be specified.
//
// parameters:
//
// - usersCmd: The parent command under which the update command will be added.
//
// returns:
//
// - *cobra.Command: The initialized update command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The update command is a subcommand of the users command and is used to update user information.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitUsersUpdate(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("new-username", "", "New username for the user")
	updateCmd.Flags().String("new-password", "", "New password for the user")
	updateCmd.Flags().String("new-role", "", "New role for the user (admin, secrets_manager, crypto_manager, certificate_manager)")
	viper.BindPFlag("new-username", updateCmd.Flags().Lookup("new-username")) //nolint:errcheck
	viper.BindPFlag("new-password", updateCmd.Flags().Lookup("new-password")) //nolint:errcheck
	viper.BindPFlag("new-role", updateCmd.Flags().Lookup("new-role"))         //nolint:errcheck

	return usersCmd
}
