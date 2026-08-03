package vaultaccess

import (
	"fmt"

	"github.com/spf13/cobra"

	authz "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// InitVaultAccessRoles registers the roles command, which lists built-in vault roles.
func InitVaultAccessRoles(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "List built-in vault roles and their permissions",
		Example: `  # List built-in vault roles and their permissions (no auth required)
  rocketvault vault-access roles`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for _, name := range authz.BuiltInRoleNames() {
				// Legacy names remain in BuiltInRoleNames (IsValidRole still
				// recognizes them for display and upgrade translation), but
				// AssignRole now refuses to grant them: a legacy-named
				// role_assignments row grants zero data-plane access.
				// Printing them with a permission list here would repeat that
				// lie back to the operator.
				if authz.IsLegacyRole(name) {
					fmt.Fprintf(out, "%s (deprecated: no longer grantable, grants no access — use an Azure role instead)\n", name)
					continue
				}
				if model.IsAzureRole(name) {
					fmt.Fprintf(out, "%s\n", name)
					for _, action := range model.AzureRoleDataActions(name) {
						fmt.Fprintf(out, "  %s\n", action)
					}
					continue
				}
				perms, err := authz.RolePermissions(name)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%s\n", name)
				for _, p := range perms {
					fmt.Fprintf(out, "  %s/%s\n", p[0], p[1])
				}
			}
			return nil
		},
	}
	parent.AddCommand(cmd)
}
