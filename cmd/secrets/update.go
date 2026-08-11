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

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// updateCmd represents the update command.
var updateCmd = &cobra.Command{
	Use:   "update [id] [value]",
	Short: "Update a secret",
	Long: `Update a secret's value and tags by its ID.
Any member of the target vault holding a role that grants ActionSecretsSet
(e.g. Key Vault Secrets Officer) can update the secret, matching the HTTP
API's vault-scoped update route.`,
	Example: `  # Update a secret's value
  rocketvault secrets update <id> <new-value> \
    --username admin --password admin123 --totp-code <code>

  # Update value, tags and content type
  rocketvault secrets update <id> <new-value> --tags prod,db --content-type text/plain \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID: %w", err)
		}
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")
		contentType, _ := cmd.Flags().GetString("content-type")

		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user not authenticated")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsSet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsSet, model.OpSet)
		if err != nil {
			return err
		}

		// Vault-scoped: this matches api/secrets.go's updateSecret handler,
		// which calls scopeFromRequest and gets a vault scope back on the
		// /vaults/{name}/secrets/... route. Any vault member holding a role
		// that grants ActionSecretsSet can update another member's secret,
		// not just the secret's creator.
		req := secretServices.UpdateSecretRequest{
			SecretID: secretID,
			Scope:    model.NewVaultScope(vaultID, userID),
			Value:    &value,
		}
		if len(tags) > 0 {
			req.Tags = &tags
		}
		// Only set ContentType when the flag was explicitly passed.
		var contentTypePtr *string
		if cmd.Flags().Changed("content-type") {
			contentTypePtr = &contentType
		}
		req.ContentType = contentTypePtr

		if err := sc.GetSecretService().UpdateSecret(ctx, req); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		fmt.Printf("Secret %s updated successfully\n", secretID)
		return nil
	},
}

// InitSecretsUpdate adds the update command to the secrets command.
func InitSecretsUpdate(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(updateCmd)
	updateCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")
	updateCmd.Flags().String("content-type", "", "Media type of the secret value")
	return secretsCmd
}
