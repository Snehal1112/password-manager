package vaults

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// deleteCmd represents the vaults delete command.
var deleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Soft-delete a vault by name",
	Long:  `Soft-delete a vault and its contents by name.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.DeleteVault(ctx, name); err != nil {
			return fmt.Errorf("failed to delete vault %q: %w", name, err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Vault %q deleted successfully\n", name)
		return nil
	},
}

// InitVaultsDelete registers the delete command under the vaults command group.
func InitVaultsDelete(vaultsCmd *cobra.Command) *cobra.Command {
	vaultsCmd.AddCommand(deleteCmd)
	return vaultsCmd
}
