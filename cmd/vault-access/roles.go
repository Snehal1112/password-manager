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
		Long: `Print every built-in Azure Key Vault role name, and the data actions
each one grants. Deprecated legacy role names are listed too, marked as no
longer grantable and conferring no access, so an operator can tell why a
role from before the Azure-parity migration no longer works.

Requires no authentication: this reads only compiled-in role definitions,
never the database.`,
		Example: `  # List built-in vault roles and their permissions
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
					fmt.Fprintf(out, "%s (deprecated: no longer grantable, grants no access — use an Azure role instead)\n", name) //nolint:errcheck
					continue
				}
				if !model.IsAzureRole(name) {
					// Every name BuiltInRoleNames returns is either legacy or
					// an Azure role — see TestRolesCommand_EveryNameIsLegacyOrAzure.
					// Fail closed rather than silently dropping the name from
					// the output if that invariant is ever violated.
					return fmt.Errorf("internal error: role %q is neither a legacy nor an Azure built-in role", name)
				}
				fmt.Fprintf(out, "%s\n", name) //nolint:errcheck
				for _, action := range model.AzureRoleDataActions(name) {
					fmt.Fprintf(out, "  %s\n", action) //nolint:errcheck
				}
			}
			return nil
		},
	}
	parent.AddCommand(cmd)
}
