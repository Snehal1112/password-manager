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
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	secretsServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:     "create <name> <value>",
	Aliases: []string{"add"},
	Short:   "Create a new secret",
	Long: `Create a secret in the target vault. The value is encrypted before it is
stored, and the new secret starts at version 1. Creating a second secret
with the same name does not replace the first one; both are stored.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/setSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default".

--content-type is restricted to text/plain, application/json,
application/xml, application/x-pem-file, application/x-pkcs12 and
application/octet-stream. Any other value is rejected before the secret is
stored. --purge-protection is only written when it is true, and it blocks
the later permanent purge of the secret once it has been soft-deleted.`,
	Example: `  # Create a secret in the default vault
  rocketvault secrets create <name> <value>

  # Create a secret with tags and a content type
  rocketvault secrets create <name> <value> \
    --tags prod,db --content-type application/json

  # Create a purge-protected secret in a named vault
  rocketvault secrets create <name> <value> \
    --purge-protection --vault <vault-name>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("requires <name> and <value> arguments")
		}
		name := args[0]
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")
		contentType, _ := cmd.Flags().GetString("content-type")

		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		userID := claims.UserID

		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleSecretsManager) {
			return fmt.Errorf("forbidden: requires admin or secrets_manager role")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsSet, model.OpCreate)
		if err != nil {
			return err
		}

		req := secretsServices.CreateSecretRequest{
			UserID:      userID,
			VaultID:     vaultID,
			Name:        name,
			Value:       value,
			Tags:        tags,
			ContentType: contentType,
		}
		// Only send purge protection when the flag was explicitly passed.
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		secret, err := secretService.CreateSecret(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Version", "Enabled", "Created"}
		row := []string{
			secret.ID.String(),
			secret.Name,
			strconv.Itoa(secret.Version),
			strconv.FormatBool(secret.Enabled),
			secret.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitSecretsCreate initializes the create command for secrets.
// It sets up the command with flags and adds it to the secrets command group.
// The create command allows users to create a new secret with a name, value, and optional tags.
// It also sets up the command to use the database and logger from the context.
// Parameters:
//   - secretsCmd: *cobra.Command - the parent command to which the create command will be added
//
// Return type: *cobra.Command - the initialized create command
// Example usage:
//
//	secretsCmd := &cobra.Command{Use: "secrets"}
//	createCmd := InitSecretsCreate(secretsCmd)
//	createCmd.Execute()
func InitSecretsCreate(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(createCmd)

	createCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")
	createCmd.Flags().String("content-type", "", "Media type of the secret value (e.g. application/json)")
	createCmd.Flags().Bool("purge-protection", false, "Protect the secret from being purged")

	return secretsCmd
}
