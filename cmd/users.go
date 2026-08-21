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

package cmd

import (
	"github.com/spf13/cobra"

	"rocketvault/cmd/users"
)

// usersCmd represents the users command
var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Manage users in the password manager",
	Long: `Manage the accounts that authenticate to RocketVault, and the cached CLI
session they use: create, inspect, update, and delete users, bootstrap the
first administrator, and log in or out.

Creating a user and listing users require the admin role. A non-admin may get,
update, or delete only their own account, and only an admin may change a
user's role. Accounts are instance-wide rather than vault-scoped, so --vault
has no effect here; what an account may do inside a vault is granted
separately with 'rocketvault vault-access'.

login, logout, and admin need no existing session. login exchanges a password
and TOTP code — or a browser flow with --oidc — for one and caches it under
~/.rocketvault/sessions, where every other command picks it up. logout clears
that cache on this machine only; it does not revoke the token server-side.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Create a user with a role
  rocketvault users create --new-username <username> \
    --new-password <password> --new-role secrets_manager

  # List users as JSON
  rocketvault users list --output json

  # Clear the cached session
  rocketvault users logout`,
	Args: cobra.NoArgs,
}

func init() {
	rootCmd.AddCommand(usersCmd)

	users.InitUsersCreate(usersCmd)
	users.InitUsersDelete(usersCmd)
	users.InitUsersGet(usersCmd)
	users.InitUsersUpdate(usersCmd)
	users.InitUsersList(usersCmd)
	users.InitUsersRegisterAdmin(usersCmd)
	users.InitUsersLogin(usersCmd)
	users.InitUsersLogout(usersCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// usersCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// usersCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
