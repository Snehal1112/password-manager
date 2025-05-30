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

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/logging"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:     "login",
	Short:   "Authenticate a user",
	Long:    `Authenticate a user with their username, password, and TOTP code, returning a JWT token for subsequent operations.`,
	Example: `password-manager users login --username admin --password admin123 --totp-code <code>`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		log := ctx.Value(common.LogKey).(*logging.Logger)

		username := viper.GetString("username")
		password := viper.GetString("password")
		totpCode := viper.GetString("totp-code")

		if username == "" || password == "" || totpCode == "" {
			log.LogAuditError(uuid.Nil.String(), "login", "failed", "username, password, and totp-code are required", nil)
			return fmt.Errorf("username, password, and totp-code are required")
		}

		userRepo := auth.NewUserRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		token, err := userRepo.Login(ctx, username, password, totpCode)
		if err != nil {
			log.LogAuditError(uuid.Nil.String(), "login", "failed", fmt.Sprintf("failed to login: %s", err), err)
			return fmt.Errorf("failed to login: %w", err)
		}

		log.LogAuditInfo(uuid.Nil.String(), "login", "success", fmt.Sprintf("user logged in: %s", username))
		fmt.Printf("Login successful, JWT token: %s\n", token)
		return nil
	},
}

// InitUsersLogin initializes the login command for user-related operations.
// It adds the login command to the users command and sets up flags for authentication.
// The command does not require prior authentication.
//
// Parameters:
// - usersCmd: The parent Cobra command to which the login command will be added.
// Returns: The updated parent Cobra command with the login subcommand attached.
func InitUsersLogin(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(loginCmd)

	loginCmd.Flags().String("username", "", "Username for authentication")
	loginCmd.Flags().String("password", "", "Password for authentication")
	loginCmd.Flags().String("totp-code", "", "TOTP code for MFA")
	viper.BindPFlag("username", loginCmd.Flags().Lookup("username"))
	viper.BindPFlag("password", loginCmd.Flags().Lookup("password"))
	viper.BindPFlag("totp-code", loginCmd.Flags().Lookup("totp-code"))

	return usersCmd
}
