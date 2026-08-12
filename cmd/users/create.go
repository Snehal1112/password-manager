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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	userService "rocketvault/internal/services/users"
	"rocketvault/model"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Long:  `Create a new user with a username, password, and role, generating a TOTP secret for MFA. Requires admin role for authentication.`,
	Example: `  # Create a new user (requires admin role)
  rocketvault users create \
    --username admin --password admin123 --totp-code <code> \
    --new-username testuser --new-password password123 --new-role user`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		// Require admin role to create any user account.
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok || claims == nil {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		if claims.Role != model.RoleAdmin {
			return fmt.Errorf("forbidden: only admin users can create new accounts")
		}

		// Get service container from context (using interface for testability).
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}

		// Get new user details from flags directly.
		username, _ := cmd.Flags().GetString("new-username")
		password, _ := cmd.Flags().GetString("new-password")
		role, _ := cmd.Flags().GetString("new-role")

		if username == "" || password == "" || role == "" {
			return fmt.Errorf("username, password, and role are required")
		}

		// Create user using service.
		userSvc := serviceContainer.GetUserService()
		result, err := userSvc.CreateUser(ctx, userService.CreateUserRequest{
			Username:   username,
			Password:   password,
			Role:       role,
			CallerRole: claims.Role,
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		logrus.WithFields(logrus.Fields{
			"username":   result.Username,
			"user_id":    result.UserID.String(),
			"role":       result.Role,
			"totpSecret": result.TOTPSecret,
		}).Info("User created successfully. Configure this TOTP secret in your authenticator app (e.g., Google Authenticator)")

		fmt.Printf("User created successfully:\n")
		fmt.Printf("  Username: %s\n", result.Username)
		fmt.Printf("  User ID: %s\n", result.UserID.String())
		fmt.Printf("  Role: %s\n", result.Role)
		fmt.Printf("  TOTP Secret: %s\n", result.TOTPSecret)
		fmt.Printf("\nConfigure the TOTP secret in your authenticator app for MFA.\n")

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {},
}

// InitUsersCreate initializes the create command for users
// and adds it to the users command.
// It also sets up the necessary flags and configuration settings.
// The create command allows users to create a new user with a username, password, and role.
// It also sets up the command to use the database and logger from the context.
// The command will generate a TOTP secret for the user to use with MFA.
// Parameters:
//
// - usersCmd: The parent command to which the create command will be added.
//
// Returns:
//
// - *cobra.Command: The modified users command with the create command added.
//
// This function is called in the main package to set up the command.
// Example usage:
// usersCmd := &cobra.Command{Use: "users"}
// usersCmd = InitUsersCreate(usersCmd)
// usersCmd.Execute()
// The create command is used to create a new user in the system.
// It requires a username, password, and role to be specified.
func InitUsersCreate(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	// Flags for registration.
	createCmd.Flags().String("new-username", "", "Username for the new user")
	createCmd.Flags().String("new-password", "", "Password for the new user")
	createCmd.Flags().String("new-role", "", "Role for the new user (e.g., secrets_manager, crypto_manager, certificate_manager)")

	viper.BindPFlag("new-username", createCmd.Flags().Lookup("new-username")) //nolint:errcheck
	viper.BindPFlag("new-password", createCmd.Flags().Lookup("new-password")) //nolint:errcheck
	viper.BindPFlag("new-role", createCmd.Flags().Lookup("new-role"))         //nolint:errcheck

	return usersCmd
}
