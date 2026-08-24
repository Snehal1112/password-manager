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

package secrets

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Retrieve a secret by ID",
	Long: `Retrieve one secret by its ID and print its decrypted value alongside its
version, enabled state, content type, tags and validity dates. The value is
printed in plaintext, so redirect the output rather than leaving it in the
terminal scrollback.

Requires the Microsoft.KeyVault/vaults/secrets/getSecret/action data action
in the target vault. No global role is checked here, so a user who holds
neither the admin nor the secrets_manager role can still read a secret when
a role assignment in that vault grants the action.

Acts on the vault named by --vault, which defaults to "default". The lookup
is vault scoped, so a member holding the action can read a secret another
member created.`,
	Example: `  # Get a secret from the default vault
  rocketvault secrets get <id>

  # Get a secret from a named vault
  rocketvault secrets get <id> --vault <vault-name>

  # Get a secret as JSON
  rocketvault secrets get <id> --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID: %w", err)
		}

		ctx := cmd.Context()

		if target, ok := ctx.Value(common.RemoteTargetKey).(*cliclient.Target); ok && target != nil {
			return runSecretsGetRemote(cmd, ctx, target, secretID.String())
		}

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsGet, model.OpGet)
		if err != nil {
			return err
		}

		// The scope's actor is the real authenticated caller, not uuid.Nil, so
		// the audit row for this read is attributed to the person who made it.
		secret, err := secretService.GetSecret(ctx, secretID, model.NewVaultScope(vaultID, userID))
		if err != nil {
			return fmt.Errorf("failed to retrieve secret: %w", err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Value", "Version", "Enabled", "ContentType", "Tags", "Expires", "NotBefore", "Created"}
		row := []string{
			secret.ID.String(),
			secret.Name,
			secret.Value,
			strconv.Itoa(secret.Version),
			strconv.FormatBool(secret.Enabled),
			secret.ContentType,
			strings.Join(secret.Tags, ","),
			formatOptionalTime(secret.ExpiresAt),
			formatOptionalTime(secret.NotBefore),
			secret.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// runSecretsGetRemote is "secrets get"'s remote-mode path.
func runSecretsGetRemote(cmd *cobra.Command, ctx context.Context, target *cliclient.Target, id string) error {
	httpClient, ok := ctx.Value(common.RemoteHTTPClientKey).(*http.Client)
	if !ok || httpClient == nil {
		return fmt.Errorf("remote HTTP client not available in context")
	}
	token, ok := ctx.Value(common.TokenKey).(string)
	if !ok || token == "" {
		return fmt.Errorf("remote session token not available in context")
	}
	fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
	if !ok {
		return fmt.Errorf("output formatter not available in context")
	}

	vault, _ := cmd.Flags().GetString("vault")
	if vault == "" {
		vault = target.Vault
	}

	secret, err := cliclient.GetSecretRemote(ctx, httpClient, token, target.Server, vault, id)
	if err != nil {
		return err
	}

	headers := []string{"ID", "Name", "Value", "Version", "Enabled", "ContentType", "Tags", "Expires", "NotBefore", "Created"}
	row := []string{
		secret.ID,
		secret.Name,
		secret.Value,
		strconv.Itoa(secret.Version),
		strconv.FormatBool(secret.Enabled),
		secret.ContentType,
		strings.Join(secret.Tags, ","),
		formatOptionalTime(secret.ExpiresAt),
		formatOptionalTime(secret.NotBefore),
		secret.CreatedAt,
	}
	return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
}

// InitSecretsGet initializes the get command for secrets
// It sets up the command flags and adds it to the secrets command tree.
// This function is called in the main function of the application to set up the command structure.
// It returns the modified secrets command.
// Parameters:
//
//	secretsCmd: The parent command under which the get command will be added.
//
// Returns:
//
//	The modified secrets command with the get command added.
func InitSecretsGet(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(getCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	return secretsCmd
}

// formatOptionalTime formats a pointer to time.Time as RFC3339, returning empty string for nil.
func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
