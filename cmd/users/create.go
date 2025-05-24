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
	"os"
	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/db"
	"password-manager/internal/logging"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:     "create",
	Short:   "Create a new user",
	Long:    `Create a new user with a username, password, and role, generating a TOTP secret for MFA.`,
	Example: `users create --username <username> --password <password> --role <role>`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log := logging.InitLogger()

		db := db.NewRepository(log)
		db.InitializeDB()

		ctx := context.WithValue(cmd.Context(), common.DBKey, db)
		cmd.SetContext(ctx)

		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		role, _ := cmd.Flags().GetString("role")
		if username == "" || password == "" || role == "" {
			log.Fatal("Username, password, and role are required")
			logrus.Error("Username, password, and role are required")
			os.Exit(0)
		}

		userRepo := auth.NewUserRepository(db.GetDB(), log)

		user := auth.User{
			Username:     username,
			PasswordHash: password,
			Role:         "secrets_manager;crypto_manager",
		}

		if err := userRepo.Create(ctx, &user); err != nil {
			log.Error("Failed to register user: ", err)
			logrus.Error("Failed to register user: ", err)
			os.Exit(0)
			return
		}

		logrus.WithFields(logrus.Fields{
			"username":   username,
			"totpSecret": user.TOTPSecret,
		}).Info("Configure this secret in a TOTP app (e.g., Google Authenticator) for MFA.")
	},
	Run: func(cmd *cobra.Command, args []string) {},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		cmd.Context().Value(common.DBKey).(*db.DBRepository).CloseDB()
		return nil
	},
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
	createCmd.Flags().String("username", "", "Username for the new user")
	createCmd.Flags().String("password", "", "Password for the new user")
	createCmd.Flags().String("role", "", "Role for the new user (e.g., secrets_manager, crypto_manager, certificate_manager)")

	return usersCmd
}
