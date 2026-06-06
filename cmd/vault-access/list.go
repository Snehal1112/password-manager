package vaultaccess

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// InitVaultAccessList registers the list command, which lists role assignments in a vault.
func InitVaultAccessList(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List role assignments in a vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			list, err := sc.GetRoleAssignmentService().ListAssignments(ctx, vaultID)
			if err != nil {
				return fmt.Errorf("list failed: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-38s %-20s %s\n", "ASSIGNMENT-ID", "ROLE", "PRINCIPAL-ID")
			for _, ra := range list {
				fmt.Fprintf(out, "%-38s %-20s %s\n", ra.ID, ra.Role, ra.PrincipalID)
			}
			return nil
		},
	}
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
