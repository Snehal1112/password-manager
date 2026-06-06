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
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Long:  `Retrieve a list of all users in the Password Manager. Accessible only by users with the admin role.`,
	Example: `  # List all users (requires admin role)
  rocketvault users list \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}

		if claims.Role != model.RoleAdmin {
			return fmt.Errorf("forbidden: requires admin role")
		}

		userSvc := serviceContainer.GetUserService()
		users, err := userSvc.ListUsers(ctx)
		if err != nil {
			return fmt.Errorf("failed to list users: %w", err)
		}

		logger := serviceContainer.GetLogger()
		logger.LogAuditInfo(claims.UserID.String(), "list_users", "success", fmt.Sprintf("listed %d users", len(users)))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Username", "Role", "Created"}
		rows := make([][]string, len(users))
		for i, u := range users {
			rows[i] = []string{
				u.ID.String(),
				u.Username,
				u.Role,
				u.CreatedAt.Format(time.RFC3339),
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
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
