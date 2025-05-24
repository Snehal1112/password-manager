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
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:     "login",
	Short:   "Login to the system",
	Long:    `Authenticate a user to the system. This command may require additional parameters in the future.`,
	Example: `users login --username <username> --password <password> --totp-code <code>`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("login called")
	},
}

// InitUsersLogin initializes the login command for user-related operations.
// It adds the loginCmd as a subcommand to the provided userCmd and sets up
// any necessary flags or configuration settings for the login command.
//
// Parameters:
//
//	userCmd - The parent Cobra command to which the login command will be added.
//
// Returns:
//
//	The updated parent Cobra command with the login subcommand attached.
//
// This function is part of the Cobra library, which is used for creating
// command-line applications in Go. The login command is used to authenticate
// a user and may require additional flags or configuration settings in the future.
// The command is defined using the Cobra library, which provides a simple way
// to create command-line applications in Go. The login command is a subcommand
// of the users command and is used to authenticate a user. It may require
// additional flags or configuration settings in the future.
func InitUsersLogin(userCmd *cobra.Command) *cobra.Command {
	userCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	return userCmd
}
