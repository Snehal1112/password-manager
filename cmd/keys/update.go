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

package keys

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// updateCmd represents the update command for cryptographic keys.
var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update a cryptographic key",
	Long: `Change a cryptographic key's mutable attributes by its UUID: its name, its
tags, its revocation flag, or its purge protection. Key material, type and
curve cannot be changed here; use "keys rotate" for new material.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/update data action in the target vault,
which defaults to "default".

At least one of --name, --tags, --revoked or --purge-protection must be
supplied, or the command fails. An empty --name or --tags value counts as
not supplied; --revoked and --purge-protection are applied only when the
flag is actually present on the command line, so an unset boolean never
overwrites the stored value. --tags replaces the existing tag set rather
than adding to it. Revoking a key leaves its metadata readable but makes
every crypto operation on it fail.`,
	Example: `  # Rename a key
  rocketvault keys update <key-id> --name <new-name>

  # Replace the tag set on a key in a named vault
  rocketvault keys update <key-id> --tags prod,secure --vault payments

  # Revoke a key
  rocketvault keys update <key-id> --revoked

  # Clear purge protection so the key can be purged
  rocketvault keys update <key-id> --purge-protection=false`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCryptoManager) {
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		keyID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid key ID: %w", err)
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		newName, _ := cmd.Flags().GetString("name")
		tagsStr, _ := cmd.Flags().GetString("tags")

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionKeysUpdate, model.OpSet)
		if err != nil {
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		req := keyServices.UpdateKeyRequest{
			KeyID: keyID,
			Scope: model.NewVaultScope(vaultID, claims.UserID),
		}

		hasUpdate := false

		if newName != "" {
			req.Name = &newName
			hasUpdate = true
		}
		if tagsStr != "" {
			tags := strings.Split(tagsStr, ",")
			for i, t := range tags {
				tags[i] = strings.TrimSpace(t)
			}
			req.Tags = tags
			hasUpdate = true
		}
		if cmd.Flags().Changed("revoked") {
			revoked, _ := cmd.Flags().GetBool("revoked")
			req.Revoked = &revoked
			hasUpdate = true
		}
		// Only change purge protection when the flag was explicitly passed.
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
			hasUpdate = true
		}

		if !hasUpdate {
			return fmt.Errorf("at least one update field (name, revoked, tags, purge-protection) must be provided")
		}

		if err := sc.GetKeyService().UpdateKey(ctx, req); err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}

		fmt.Printf("Key %s updated successfully at %s\n", keyID, time.Now().Format(time.RFC3339))
		return nil
	},
}

// InitKeysUpdate adds the update subcommand to the keys command.
func InitKeysUpdate(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(updateCmd)
	updateCmd.Flags().String("name", "", "New name for the key")
	updateCmd.Flags().Bool("revoked", false, "Set key revocation status")
	updateCmd.Flags().String("tags", "", "Comma-separated tags to replace existing tags")
	updateCmd.Flags().Bool("purge-protection", false, "Protect the key from being purged")
	viper.BindPFlag("name", updateCmd.Flags().Lookup("name"))       //nolint:errcheck,gosec
	viper.BindPFlag("revoked", updateCmd.Flags().Lookup("revoked")) //nolint:errcheck,gosec
	viper.BindPFlag("tags", updateCmd.Flags().Lookup("tags"))       //nolint:errcheck,gosec
	return keysCmd
}
