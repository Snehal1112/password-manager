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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/model"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a secret by ID",
	Long: `Soft-delete a secret in the target vault by its ID. The secret is marked
deleted and all of its tags are removed, but the row is retained so it can
still be recovered. Recovery and permanent purge are exposed only over the
REST API; this CLI has no secrets recover or purge subcommand.

A background scheduler permanently removes soft-deleted secrets once the
configured retention period has elapsed, unless purge protection is set on
the secret or on its vault.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/delete data action in the target vault.

Acts on the vault named by --vault, which defaults to "default". A secret
held in another vault is not visible to this command.`,
	Example: `  # Soft-delete a secret in the default vault
  rocketvault secrets delete <id>

  # Soft-delete a secret in a named vault
  rocketvault secrets delete <id> --vault <vault-name>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID: %w", err)
		}

		ctx := cmd.Context()

		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		userID := claims.UserID

		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleSecretsManager) {
			return fmt.Errorf("forbidden: requires admin or secrets_manager role")
		}

		// Get service container and secret service
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsDelete.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsDelete, model.OpDelete)
		if err != nil {
			return err
		}

		// Delete secret via service (includes access control). The scope's
		// actor is the real authenticated caller, not uuid.Nil, so the audit
		// row for this delete is attributed to the person who made it.
		err = secretService.DeleteSecret(ctx, secretID, model.NewVaultScope(vaultID, userID))
		if err != nil {
			return fmt.Errorf("failed to delete secret: %w", err)
		}

		logrus.WithFields(logrus.Fields{
			"secret_id": secretID.String(),
			"vault_id":  vaultID.String(),
		}).Info("Secret deleted successfully")
		return nil
	},
}

// InitSecretsDelete initializes the delete command for secrets
// and adds it to the secrets command.
// It also sets up the necessary flags and configuration settings.
// This function is called in the main package to set up the command.
// It returns the modified secrets command.
// Parameters:
// - secretsCmd: The parent command to which the delete command will be added.
// Returns:
// - *cobra.Command: The modified secrets command with the delete command added.
func InitSecretsDelete(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(deleteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deleteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deleteCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	return secretsCmd
}
