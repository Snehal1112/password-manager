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

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/domain"
	userService "rocketvault/internal/services/users"
)

// registerAdminCmd registers the initial admin user using the context service container.
var registerAdminCmd = &cobra.Command{
	Use:     "admin",
	Short:   "Register the initial admin user",
	Long:    `Register the first admin user for the Password Manager using a bootstrap token. This command is only allowed when no users exist and requires a valid token.`,
	Example: `rocketvault users admin --admin-username admin --bootstrap-token <token>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		username, _ := cmd.Flags().GetString("admin-username")
		token, _ := cmd.Flags().GetString("bootstrap-token")
		password, _ := cmd.Flags().GetString("admin-password")

		if username == "" || token == "" || password == "" {
			return fmt.Errorf("admin-username, bootstrap-token, and admin-password are required")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		userSvc := sc.GetUserService()

		valid, err := userSvc.ValidateBootstrapToken(ctx, token)
		if err != nil {
			return fmt.Errorf("failed to validate bootstrap token: %w", err)
		}
		if !valid {
			return fmt.Errorf("invalid or used bootstrap token")
		}

		result, err := userSvc.CreateUser(ctx, userService.CreateUserRequest{
			Username: username,
			Password: password,
			Role:     domain.RoleAdmin,
		})
		if err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		if err := userSvc.InvalidateBootstrapToken(ctx, token); err != nil {
			return fmt.Errorf("failed to invalidate bootstrap token: %w", err)
		}

		fmt.Printf("Admin user %s created successfully with ID: %s\n", result.Username, result.UserID)
		fmt.Printf("TOTP Secret: %s\n", result.TOTPSecret)
		fmt.Printf("Configure the TOTP secret in your authenticator app for MFA.\n")
		return nil
	},
}

// InitUsersRegisterAdmin adds the admin sub-command to the users command.
// It does not require prior authentication but requires a bootstrap token.
func InitUsersRegisterAdmin(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(registerAdminCmd)
	registerAdminCmd.Flags().String("admin-username", "", "Username for the admin user")
	registerAdminCmd.Flags().String("bootstrap-token", "", "Bootstrap token for initial admin registration")
	registerAdminCmd.Flags().String("admin-password", "", "Password for the admin user")
	return usersCmd
}
