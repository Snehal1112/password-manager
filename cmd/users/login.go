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
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	authServices "rocketvault/internal/services/auth"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate a user",
	Long: `Authenticate a user with their username, password, and TOTP code (local
users), or via the configured OIDC provider through a browser (--oidc).
Either way, the resulting session is cached to disk so subsequent commands
don't need credentials repeated.`,
	Example: `  # Log in with a local username/password/TOTP account
  rocketvault users login \
    --username <username> --password <password> --totp-code <code>

  # Log in via the configured OIDC provider (opens a browser)
  rocketvault users login --oidc`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		logger := serviceContainer.GetLogger()

		oidc, _ := cmd.Flags().GetBool("oidc")
		if oidc {
			return runOIDCLogin(cmd, serviceContainer)
		}

		username := viper.GetString("username")
		password := viper.GetString("password")
		totpCode := viper.GetString("totp-code")

		if username == "" || password == "" || totpCode == "" {
			logger.LogAuditError(uuid.Nil.String(), "login", "failed", "username, password, and totp-code are required", nil)
			return fmt.Errorf("username, password, and totp-code are required")
		}

		session, err := performPasswordLogin(ctx, serviceContainer.GetAuthenticationService(), username, password, totpCode)
		if err != nil {
			logger.LogAuditError(uuid.Nil.String(), "login", "failed", fmt.Sprintf("failed to login: %s", err), err)
			return fmt.Errorf("failed to login: %w", err)
		}

		logger.LogAuditInfo(session.UserID.String(), "login", "success", fmt.Sprintf("user logged in: %s", username))
		fmt.Printf("Login successful, JWT token: %s\n", session.Token)
		return nil
	},
}

// performPasswordLogin authenticates via username/password/TOTP and caches
// the resulting session to disk. Extracted from loginCmd's RunE so it is
// unit testable without driving cobra/viper flag parsing.
func performPasswordLogin(ctx context.Context, authSvc authServices.AuthenticationService, username, password, totpCode string) (*common.SessionCache, error) {
	result, err := authSvc.AuthenticateUser(ctx, username, password, totpCode)
	if err != nil {
		return nil, err
	}

	session := &common.SessionCache{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID,
		Username:     result.Username,
		Roles:        result.Roles,
		ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
	}
	if err := common.SaveSession(session); err != nil {
		return nil, fmt.Errorf("authenticated but failed to cache session: %w", err)
	}
	return session, nil
}

// InitUsersLogin initializes the login command for user-related operations.
// It adds the login command to the users command and sets up flags for
// authentication. The command does not require prior authentication.
//
// Parameters:
// - usersCmd: The parent Cobra command to which the login command will be added.
// Returns: The updated parent Cobra command with the login subcommand attached.
func InitUsersLogin(usersCmd *cobra.Command) *cobra.Command {
	usersCmd.AddCommand(loginCmd)

	loginCmd.Flags().String("username", "", "Username for authentication")
	loginCmd.Flags().String("password", "", "Password for authentication")
	loginCmd.Flags().String("totp-code", "", "TOTP code for MFA")
	loginCmd.Flags().Bool("oidc", false, "Log in via the configured OIDC provider using a browser, instead of username/password/TOTP")
	viper.BindPFlag("username", loginCmd.Flags().Lookup("username"))   //nolint:errcheck,gosec
	viper.BindPFlag("password", loginCmd.Flags().Lookup("password"))   //nolint:errcheck,gosec
	viper.BindPFlag("totp-code", loginCmd.Flags().Lookup("totp-code")) //nolint:errcheck,gosec

	return usersCmd
}
