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
)

// updateCmd represents the update command.
var updateCmd = &cobra.Command{
	Use:   "update [id] [value]",
	Short: "Update a secret",
	Long:  `Update a secret's value and tags by its ID for the authenticated user.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID: %w", err)
		}
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")

		ctx := cmd.Context()
		userID := ctx.Value(common.UserIDKey).(uuid.UUID)

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		req := secretServices.UpdateSecretRequest{
			SecretID: secretID,
			UserID:   userID,
			Value:    &value,
		}
		if len(tags) > 0 {
			req.Tags = &tags
		}

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
	return secretsCmd
}
