package vaults

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// purgeCmd represents the vaults purge command.
var purgeCmd = &cobra.Command{
	Use:   "purge <name>",
	Short: "Permanently purge a vault by name",
	Long:  `Permanently remove a vault by name. This operation cannot be undone.`,
	Example: `  # Permanently purge a soft-deleted vault
  rocketvault vaults purge <name> \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if err := requireCanPurgeVault(ctx, serviceContainer, name); err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.PurgeVault(ctx, name); err != nil {
			return fmt.Errorf("failed to purge vault %q: %w", name, err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Vault %q purged successfully\n", name)
		return nil
	},
}

// InitVaultsPurge registers the purge command under the vaults command group.
func InitVaultsPurge(vaultsCmd *cobra.Command) *cobra.Command {
	vaultsCmd.AddCommand(purgeCmd)
	return vaultsCmd
}
