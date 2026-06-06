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

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	secretsServices "rocketvault/internal/services/secrets"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:     "create <name> <value>",
	Aliases: []string{"add"},
	Short:   "Create a new secret",
	Long:    `Create a new secret in the password manager. You can specify the secret name, value, and optional tags.`,
	Example: `  # Create a simple secret
  rocketvault secrets create my-secret my-value \
    --username admin --password admin123 --totp-code <code>

  # Create a secret with tags and content type
  rocketvault secrets create my-secret my-value --tags prod,db --content-type application/json \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("requires <name> and <value> arguments")
		}
		name := args[0]
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")
		contentType, _ := cmd.Flags().GetString("content-type")

		ctx := cmd.Context()
		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		vaultID, err := resolveVaultID(ctx, cmd, serviceContainer)
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

	return secretsCmd
}
