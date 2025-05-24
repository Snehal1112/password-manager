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
	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/logging"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// deleteCmd represents the delete command
// The delete command allows users to delete an existing user by ID.
// It requires the user ID to be specified as an argument.
var deleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a user",
	Long:    `Delete a user by their UUID. Accessible by the user themselves or users with the crypto_manager role. This action cannot be undone.`,
	Example: `password-manager users delete <user-id> --username admin --password admin123 --totp-code <code>`,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		id := uuid.MustParse(args[0])

		if claims.UserID != id && claims.Role != auth.RoleCryptoManager {
			log.LogAuditError(claims.UserID.String(), "delete_user", "failed", "forbidden: cannot delete other users", nil)
			return
		}

		userRepo := auth.NewUserRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		if err := userRepo.Delete(ctx, id); err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_user", "failed", fmt.Sprintf("failed to delete user: %s", err), err)
			return
		}
		// If the user is deleting themselves, we should log them out
		log.LogAuditInfo(claims.UserID.String(), "delete_user", "success", fmt.Sprintf("user deleted: %s", id))
		fmt.Printf("User %s deleted successfully\n", id)
	},
}

// InitUsersDelete initializes the delete command for users
// and adds it to the users command.
// It also sets up the necessary flags and configuration settings.
// The delete command allows users to delete an existing user by ID.
// It requires the user ID to be specified.
// parameters:
//
// - usersCmd: The parent command under which the delete command will be added.
//
// returns:
//
// - *cobra.Command: The initialized delete command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The delete command is a subcommand of the users command and is used to delete a user.
func InitUsersDelete(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(deleteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deleteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deleteCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	return usersCmd
}
