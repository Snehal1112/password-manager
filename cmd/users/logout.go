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
	"github.com/spf13/viper"

	"rocketvault/common"
)

// logoutCmd represents the logout command.
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear a cached CLI session",
	Long: `Removes the session cache written by 'rocketvault users login' (with or
without --oidc). This does not revoke the session server-side — the
underlying JWT simply expires naturally. Without --username, clears
whichever session is currently active (the one commands use when run
without --username/--password).`,
	Example: `  # Log out of whichever session is currently active
  rocketvault users logout

  # Log out a specific cached user without affecting others
  rocketvault users logout --username <username>`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLogout(viper.GetString("logout-username"))
	},
}

// runLogout resolves which cached session to remove — an explicit
// username, or whichever the current-session pointer references — and
// deletes it. Extracted from logoutCmd's RunE so it is unit testable
// without driving cobra/viper flag parsing.
func runLogout(username string) error {
	if username == "" {
		current, err := common.LoadCurrentSession()
		if err != nil {
			return fmt.Errorf("failed to read current session: %w", err)
		}
		if current == nil {
			fmt.Println("No cached session to log out of.")
			return nil
		}
		username = current.Username
	}

	if err := common.DeleteSession(username); err != nil {
		return fmt.Errorf("failed to log out: %w", err)
	}

	fmt.Printf("Logged out %s.\n", username)
	return nil
}

// InitUsersLogout registers the logout command under usersCmd.
func InitUsersLogout(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(logoutCmd)

	logoutCmd.Flags().String("username", "", "Log out this specific cached user instead of the current one")
	viper.BindPFlag("logout-username", logoutCmd.Flags().Lookup("username")) //nolint:errcheck,gosec

	return usersCmd
}
