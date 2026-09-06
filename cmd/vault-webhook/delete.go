package vaultwebhook

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
)

// InitVaultWebhookDelete registers the delete command, which removes a
// vault's webhook configuration. Deleting a vault with no webhook configured
// succeeds (mirrors VaultWebhookService.Delete's idempotent contract).
func InitVaultWebhookDelete(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a vault's webhook configuration",
		Long: `Delete a vault's webhook configuration. Deleting a vault with no webhook
configured still succeeds — this command is idempotent.

Requires the admin role, or an access-policy grant of manage on vaults
scoped to this vault. Acts on the vault named by
--vault, defaulting to "default".`,
		Example: `  # Delete the webhook configuration for the default vault
  rocketvault vault-webhook delete

  # Delete it for a named vault
  rocketvault vault-webhook delete --vault prod`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultName := common.ResolveVaultName(cmd)
			vaultID, err := vaultcli.ResolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			actor, err := requireCanManageVault(ctx, sc, vaultID, vaultName)
			if err != nil {
				return err
			}

			if err := sc.GetVaultWebhookService().Delete(ctx, vaultID, actor); err != nil {
				return fmt.Errorf("delete webhook failed: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "webhook configuration deleted for vault %q\n", vaultName) //nolint:errcheck
			return nil
		},
	}
	vaultcli.AddVaultFlag(cmd)
	parent.AddCommand(cmd)
}
