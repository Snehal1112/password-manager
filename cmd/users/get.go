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

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get [username]",
	Short: "Get user information",
	Long:  `Retrieve information about a specific user by their username.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Username is required")
			return
		}
		username := args[0]
		fmt.Println("get called for user:", username)
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
