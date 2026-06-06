package vaults

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// recoverCmd represents the vaults recover command.
var recoverCmd = &cobra.Command{
	Use:   "recover <name>",
	Short: "Recover a soft-deleted vault by name",
	Long:  `Recover a soft-deleted vault and its contents by name.`,
	Example: `  # Recover a soft-deleted vault
  rocketvault vaults recover <name> \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.RecoverVault(ctx, name); err != nil {
			return fmt.Errorf("failed to recover vault %q: %w", name, err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Vault %q recovered successfully\n", name)
		return nil
	},
}

// InitVaultsRecover registers the recover command under the vaults command group.
func InitVaultsRecover(vaultsCmd *cobra.Command) *cobra.Command {
	vaultsCmd.AddCommand(recoverCmd)
	return vaultsCmd
}
