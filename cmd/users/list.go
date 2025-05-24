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
	"encoding/json"
	"fmt"
	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/logging"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all users",
	Long:    `Retrieve a list of all users in the system. This command does not require any additional parameters.`,
	Example: `users list`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		userRepo := auth.NewUserRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		users, err := userRepo.List(ctx)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_users", "failed", fmt.Sprintf("failed to list users: %s", err), err)
			return
		}

		t, _ := json.MarshalIndent(users, "", "  ")
		fmt.Println(string(t))
	},
}

// InitUsersList initializes the list command for users
// and adds it to the users command. It also sets up the necessary flags
// and configuration settings. The list command allows users to retrieve
// a list of all users in the system. It does not require any additional parameters.
//
// parameters:
//
// - usersCmd: The parent command under which the list command will be added.
//
// returns:
//
// - *cobra.Command: The initialized list command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The list command is a subcommand of the users command and is used to list all users.
// It does not require any additional parameters.
// The command is defined using the Cobra library, which provides a simple way to create command-line applications in Go.
// The list command is a subcommand of the users command and is used to list all users.
func InitUsersList(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	return usersCmd
}
