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

	"rocketvault/internal/container"
	"rocketvault/internal/db"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	userService "rocketvault/internal/services/users"
)

// registerAdminCmd represents the register/admin command
var registerAdminCmd = &cobra.Command{
	Use:     "admin",
	Short:   "Register the initial admin user",
	Long:    `Register the first admin user for the Password Manager using a bootstrap token. This command is only allowed when no users exist and requires a valid token.`,
	Example: `rocketvault users admin --admin-username admin --bootstrap-token <token>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize the logger.
		log := logging.InitLogger()

		// Ensure database is initialized.
		database := db.NewRepository(log)
		database.InitializeDB()

		// Create service container for admin registration
		serviceContainer, err := container.NewServiceContainer(container.Config{
			Database: database.GetDB(),
			Logger:   log,
		})
		if err != nil {
			return fmt.Errorf("failed to create service container: %w", err)
		}

		ctx := cmd.Context()
		username := viper.GetString("admin-username")
		token := viper.GetString("bootstrap-token")
		password := viper.GetString("admin-password")

		if username == "" || token == "" || password == "" {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", "admin-username, bootstrap-token, and admin-password are required", nil)
			return fmt.Errorf("admin-username, bootstrap-token, and admin-password are required")
		}

		log.Println("Registering initial admin user...")

		// Validate bootstrap token using service
		userSvc := serviceContainer.GetUserService()
		log.Println("Validating bootstrap token...", token)
		valid, err := userSvc.ValidateBootstrapToken(ctx, token)
		if err != nil {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", fmt.Sprintf("failed to validate bootstrap token: %s", err), err)
			return fmt.Errorf("failed to validate bootstrap token: %w", err)
		}

		log.Println("Bootstrap token valid:", valid)
		if !valid {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", "invalid or used bootstrap token", nil)
			return fmt.Errorf("invalid or used bootstrap token")
		}

		// Create admin user using service
		result, err := userSvc.CreateUser(ctx, userService.CreateUserRequest{
			Username: username,
			Password: password,
			Role:     domain.RoleAdmin,
		})
		if err != nil {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", fmt.Sprintf("failed to create admin user: %s", err), err)
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		// Invalidate bootstrap token
		if err := userSvc.InvalidateBootstrapToken(ctx, token); err != nil {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", fmt.Sprintf("failed to invalidate bootstrap token: %s", err), err)
			return fmt.Errorf("failed to invalidate bootstrap token: %w", err)
		}

		log.LogAuditInfo(uuid.Nil.String(), "register_admin", "success", fmt.Sprintf("admin user created: %s (ID: %s)", result.Username, result.UserID))
		fmt.Printf("Admin user %s created successfully with ID: %s\n", result.Username, result.UserID)
		fmt.Printf("TOTP Secret: %s\n", result.TOTPSecret)
		fmt.Printf("Configure the TOTP secret in your authenticator app for MFA.\n")
		return nil
	},
}

// InitUsersRegisterAdmin initializes the register/admin command for users.
// It adds the command to the users command and sets up flags for admin registration.
// This command does not require prior authentication but requires a bootstrap token.
//
// Parameters:
// - usersCmd: The parent Cobra command to which the register/admin command will be added.
// Returns: The updated parent Cobra command with the register/admin subcommand attached.
func InitUsersRegisterAdmin(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(registerAdminCmd)

	registerAdminCmd.Flags().String("admin-username", "", "Username for the admin user")
	registerAdminCmd.Flags().String("bootstrap-token", "", "Bootstrap token for initial admin registration")
	registerAdminCmd.Flags().String("admin-password", "", "Password for the admin user")
	viper.BindPFlag("admin-username", registerAdminCmd.Flags().Lookup("admin-username"))
	viper.BindPFlag("bootstrap-token", registerAdminCmd.Flags().Lookup("bootstrap-token"))
	viper.BindPFlag("admin-password", registerAdminCmd.Flags().Lookup("admin-password"))

	return usersCmd
}
