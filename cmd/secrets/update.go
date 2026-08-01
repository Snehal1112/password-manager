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
Only secrets owned by the authenticated user can be updated; secrets owned by
other members of the same vault are not writable through this command.`,
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

		// Resolve the target vault by name, matching the get/list/delete commands.
		vaultID, err := resolveVaultID(ctx, cmd, sc)
		if err != nil {
			return err
		}

		// Update stays owner-scoped: a vault scope would let any co-member
		// overwrite another member's secret. The actor is the real
		// authenticated user so the audit row is attributed correctly.
		req := secretServices.UpdateSecretRequest{
			SecretID: secretID,
			Scope:    model.NewOwnerScope(vaultID, userID),
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
