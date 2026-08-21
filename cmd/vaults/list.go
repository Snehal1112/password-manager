package vaults

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
)

// listCmd represents the vaults list command.
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List vaults",
	Long: `List every vault, optionally including soft-deleted ones still inside
their retention window.

Requires the admin account role, or an access-policy allow on (vaults,
manage) granted globally — list has no single target vault to scope the
check to.

Not vault scoped by --vault: this command lists every vault the caller may
manage, not the contents of one.`,
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
		if err := requireCanListVaults(ctx, serviceContainer); err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		vaults, err := vaultService.ListVaults(ctx, includeDeleted)
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
func InitVaultsList(vaultsCmd *cobra.Command) *cobra.Command {
	vaultsCmd.AddCommand(listCmd)

	listCmd.Flags().Bool("include-deleted", false, "Include soft-deleted vaults")
	return vaultsCmd
}
