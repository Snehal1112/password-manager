package vaults

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
)

// listCmd represents the vaults list command.
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List vaults",
	Long: `List vaults, optionally including soft-deleted ones still inside their
retention window.

The admin account role, or an access-policy allow on (vaults, manage)
granted globally, lists every vault. Any other caller lists only the vaults
where it holds that allow scoped to the vault itself -- not a 403, an empty
list if it holds none.

Not vault scoped by --vault: this command lists vaults, not the contents of
one.`,
	Example: `  # List vaults
  rocketvault vaults list

  # Include soft-deleted vaults
  rocketvault vaults list --include-deleted`,
	RunE: func(cmd *cobra.Command, args []string) error {
		includeDeleted, _ := cmd.Flags().GetBool("include-deleted")

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		all, err := requireCanListVaults(ctx, serviceContainer)
		if err != nil {
			return err
		}
		_, principalID, err := vaultcli.CallerIdentity(ctx)
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		vaults, err := vaultService.ListVaultsScoped(ctx, principalID, includeDeleted, all)
		if err != nil {
			return fmt.Errorf("failed to list vaults: %w", err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Enabled", "RetentionDays", "Created"}
		rows := make([][]string, len(vaults))
		for i, v := range vaults {
			rows[i] = []string{
				v.ID.String(),
				v.Name,
				strconv.FormatBool(v.Enabled),
				strconv.Itoa(v.RetentionDays),
				v.CreatedAt.Format(time.RFC3339),
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
	},
}

// InitVaultsList registers the list command under the vaults command group.
func InitVaultsList(vaultsCmd *cobra.Command) {
	vaultsCmd.AddCommand(listCmd)

	listCmd.Flags().Bool("include-deleted", false, "Include soft-deleted vaults")
}
