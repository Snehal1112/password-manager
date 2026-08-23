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
	Use:   "update <id> <value>",
	Short: "Update a secret",
	Long: `Update a secret's value, and optionally its tags, content type and purge
protection, by its ID. The previous value is first snapshotted as a version
row and the secret's version number is then incremented, so an update never
discards history.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/setSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The update
is vault scoped, so a member holding the action can update a secret another
member created.

--tags replaces the secret's whole tag set and is ignored when empty, so
tags cannot be cleared through this command. --content-type is written only
when the flag is passed, against the same allowlist "secrets create"
enforces. --purge-protection is likewise written only when the flag is
passed, and can be set either way.`,
	Example: `  # Update a secret's value in the default vault
  rocketvault secrets update <id> <new-value>

  # Replace the tag set and set a content type
  rocketvault secrets update <id> <new-value> \
    --tags prod,db --content-type text/plain

  # Update a secret in a named vault and protect it from purge
  rocketvault secrets update <id> <new-value> \
    --vault <vault-name> --purge-protection`,
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

		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		userID := claims.UserID

		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleSecretsManager) {
			return fmt.Errorf("forbidden: requires admin or secrets_manager role")
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

		// Only change purge protection when the flag was explicitly passed.
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
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
	updateCmd.Flags().String("content-type", "", "Media type of the secret value")
	updateCmd.Flags().Bool("purge-protection", false, "Protect the secret from being purged")
	return secretsCmd
}
