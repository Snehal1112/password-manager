package vaultaccess

import (
	"fmt"

	"github.com/spf13/cobra"

	authz "rocketvault/internal/services/authorization"
)

// InitVaultAccessRoles registers the roles command, which lists built-in vault roles.
func InitVaultAccessRoles(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "List built-in vault roles and their permissions",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for _, name := range authz.BuiltInRoleNames() {
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
