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
		Long: `List every role assignment in a vault: assignment ID, role name, and
principal ID.

Requires the admin account role, an access-policy allow on (vaults, manage)
for this vault, or a Key Vault Data Access Administrator role assignment
holding Microsoft.Authorization/roleAssignments/delete in this vault. That
is the same check vault-access revoke uses — there is no separate,
narrower permission tier for listing.

Vault scoped via --vault; defaults to the ROCKETVAULT_VAULT environment
variable, then config, then "default" if none of those is set.`,
		Example: `  # List role assignments in a vault
  rocketvault vault-access list --vault prod

  # List role assignments in the default vault
  rocketvault vault-access list`,
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
			if err := requireCanManageRoleAssignments(ctx, sc, vaultID, false); err != nil {
				return err
			}
			list, err := sc.GetRoleAssignmentService().ListAssignments(ctx, vaultID)
			if err != nil {
				return fmt.Errorf("list failed: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-38s %-20s %s\n", "ASSIGNMENT-ID", "ROLE", "PRINCIPAL-ID") //nolint:errcheck
			for _, ra := range list {
				fmt.Fprintf(out, "%-38s %-20s %s\n", ra.ID, ra.Role, ra.PrincipalID) //nolint:errcheck
			}
			return nil
		},
	}
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
