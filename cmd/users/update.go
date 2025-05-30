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
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/logging"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:     "update <id>",
	Short:   "Update user information",
	Long:    `Update a user's username, password, or role by their UUID. Accessible by the user themselves or users with the admin role.`,
	Example: `password-manager users update <user-id> --username admin --password admin123 --totp-code <code> --new-username newuser --new-password newpass123 --new-role user`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		id, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_user", "failed", fmt.Sprintf("invalid user ID: %s", err), err)
			return fmt.Errorf("invalid user ID: %w", err)
		}

		if claims.UserID != id && claims.Role != auth.RoleAdmin {
			log.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: cannot update other users", nil)
			return fmt.Errorf("forbidden: cannot update other users")
		}

		newUsername := viper.GetString("new-username")
		newPassword := viper.GetString("new-password")
		newRole := viper.GetString("new-role")

		if newUsername == "" && newPassword == "" && newRole == "" {
			log.LogAuditError(claims.UserID.String(), "update_user", "failed", "at least one field (new-username, new-password, new-role) must be provided", nil)
			return fmt.Errorf("at least one field (new-username, new-password, new-role) must be provided")
		}

		if newRole != "" && !strings.Contains("admin,secrets_manager,crypto_manager,certificate_manager,user", newRole) {
			log.LogAuditError(claims.UserID.String(), "update_user", "failed", "invalid role", nil)
			return fmt.Errorf("invalid role: must be admin, secrets_manager, crypto_manager, certificate_manager, or user")
		}

		userRepo := auth.NewUserRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		user, err := userRepo.Read(ctx, id)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_user", "failed", fmt.Sprintf("failed to read user: %s", err), err)
			return fmt.Errorf("failed to read user: %w", err)
		}

		// Update fields only if provided
		if newUsername != "" {
			user.Username = newUsername
		}
		if newPassword != "" {
			user.PasswordHash = newPassword
		}
		if newRole != "" {
			user.Role = newRole
		}

		if err := userRepo.Update(ctx, user); err != nil {
			log.LogAuditError(claims.UserID.String(), "update_user", "failed", fmt.Sprintf("failed to update user: %s", err), err)
			return fmt.Errorf("failed to update user: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "update_user", "success", fmt.Sprintf("user updated: %s", user.Username))
		fmt.Printf("User %s updated successfully\n", user.ID)
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
	viper.BindPFlag("new-username", updateCmd.Flags().Lookup("new-username"))
	viper.BindPFlag("new-password", updateCmd.Flags().Lookup("new-password"))
	viper.BindPFlag("new-role", updateCmd.Flags().Lookup("new-role"))

	return usersCmd
}
