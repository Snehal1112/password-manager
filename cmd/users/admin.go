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
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/db"
	"password-manager/internal/logging"
)

// registerAdminCmd represents the register/admin command
var registerAdminCmd = &cobra.Command{
	Use:     "admin",
	Short:   "Register the initial admin user",
	Long:    `Register the first admin user for the Password Manager using a bootstrap token. This command is only allowed when no users exist and requires a valid token.`,
	Example: `password-manager users admin --admin-username admin --bootstrap-token <token>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize the logger.
		log := logging.InitLogger()

		// Ensure database is initialized.
		database := db.NewRepository(log)
		database.InitializeDB()

		ctx := context.WithValue(cmd.Context(), common.DBKey, database.GetDB())
		ctx = context.WithValue(ctx, common.DBClassKey, database)
		ctx = context.WithValue(ctx, common.LogKey, log)

		userRepo := auth.NewUserRepository(ctx.Value(common.DBKey).(*sql.DB), log)

		// Verify terminal input for security
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", "command must be run interactively", nil)
			return fmt.Errorf("command must be run interactively from a terminal")
		}

		username := viper.GetString("admin-username")
		token := viper.GetString("bootstrap-token")
		if username == "" || token == "" {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", "admin-username and bootstrap-token are required", nil)
			return fmt.Errorf("admin-username and bootstrap-token are required")
		}

		log.Println("Registering initial admin user...", token)

		// Validate bootstrap token
		valid, err := userRepo.ValidateBootstrapToken(ctx, token)
		if err != nil {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", fmt.Sprintf("failed to validate bootstrap token: %s", err), err)
			return fmt.Errorf("failed to validate bootstrap token: %w", err)
		}
		if !valid {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", "invalid or used bootstrap token", nil)
			return fmt.Errorf("invalid or used bootstrap token")
		}

		// Prompt for password securely
		fmt.Print("Enter admin password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", "failed to read password", err)
			return fmt.Errorf("failed to read password: %w", err)
		}
		password := strings.TrimSpace(string(passwordBytes))
		if password == "" {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", "password cannot be empty", nil)
			return fmt.Errorf("password cannot be empty")
		}

		user := &auth.User{
			Username:     username,
			PasswordHash: password,
			Role:         auth.RoleAdmin,
		}

		err = userRepo.Create(ctx, user)
		if err != nil {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", fmt.Sprintf("failed to create admin user: %s", err), err)
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		// Invalidate bootstrap token
		if err := userRepo.InvalidateBootstrapToken(ctx, token); err != nil {
			log.LogAuditError(uuid.Nil.String(), "register_admin", "failed", fmt.Sprintf("failed to invalidate bootstrap token: %s", err), err)
			return fmt.Errorf("failed to invalidate bootstrap token: %w", err)
		}

		log.LogAuditInfo(uuid.Nil.String(), "register_admin", "success", fmt.Sprintf("admin user created: %s", username))
		fmt.Printf("Admin user created successfully, TOTP secret: %s\nConfigure this secret in a TOTP app (e.g., Google Authenticator) for MFA.\n", user.TOTPSecret)
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
	viper.BindPFlag("admin-username", registerAdminCmd.Flags().Lookup("admin-username"))
	viper.BindPFlag("bootstrap-token", registerAdminCmd.Flags().Lookup("bootstrap-token"))

	return usersCmd
}
