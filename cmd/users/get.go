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
	"time"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/logging"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:     "get",
	Short:   "Get user information",
	Long:    `Retrieve information about a specific user by their username.`,
	Example: `password-manager users get <id> --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		id, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_user", "failed", fmt.Sprintf("invalid user ID: %s", err), err)
			return fmt.Errorf("invalid user ID: %w", err)
		}

		if claims.UserID != id && claims.Role != auth.RoleAdmin {
			log.LogAuditError(claims.UserID.String(), "get_user", "failed", "forbidden: cannot access other users", nil)
			return fmt.Errorf("forbidden: cannot access other users")
		}

		userRepo := auth.NewUserRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		user, err := userRepo.Read(ctx, id)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_user", "failed", fmt.Sprintf("failed to get user: %s", err), err)
			return fmt.Errorf("failed to get user: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "get_user", "success", fmt.Sprintf("user retrieved: %s", user.Username))
		fmt.Printf("User: ID=%s, Username=%s, Role=%s, CreatedAt=%s\n",
			user.ID, user.Username, user.Role, user.CreatedAt.Format(time.RFC3339))
		return nil
	},
}

// InitUsersGet initializes the get command for users
// and adds it to the users command.
// It also sets up the necessary flags and configuration settings.
// The get command allows users to retrieve information about a specific user by username.
// It requires the username to be specified.
// parameters:
//
// - usersCmd: The parent command under which the get command will be added.
//
// returns:
//
// - *cobra.Command: The initialized get command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The get command is a subcommand of the users command and is used to retrieve user information.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitUsersGet(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(getCmd)

	return usersCmd
}
