package vaultwebhook

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	vaultServices "rocketvault/internal/services/vaults"
)

// InitVaultWebhookDelete registers the delete command, which removes a
// vault's webhook configuration. Deleting a vault with no webhook configured
// succeeds (mirrors VaultWebhookService.Delete's idempotent contract).
func InitVaultWebhookDelete(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a vault's webhook configuration",
		Example: `  # Delete a vault's webhook configuration
  rocketvault vault-webhook delete --vault prod \
    --username admin --password admin123 --totp-code <code>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultName := common.ResolveVaultName(cmd)
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			if err := requireCanManageVault(ctx, sc, vaultID, vaultName); err != nil {
				return err
			}

			if err := sc.GetVaultWebhookService().Delete(ctx, vaultID); err != nil {
				if errors.Is(err, vaultServices.ErrWebhookNotFound) {
					return fmt.Errorf("no webhook configured for vault %q", vaultName)
				}
				return fmt.Errorf("delete webhook failed: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "webhook configuration deleted for vault %q\n", vaultName) //nolint:errcheck
			return nil
		},
	}
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
