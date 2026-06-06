package cmd

import (
	"github.com/spf13/cobra"

	vaultaccess "rocketvault/cmd/vault-access"
)

// vaultAccessCmd is the command group for vault-scoped role assignments.
var vaultAccessCmd = &cobra.Command{
	Use:   "vault-access",
	Short: "Manage vault-scoped role assignments",
}

func init() {
	rootCmd.AddCommand(vaultAccessCmd)
	vaultaccess.InitVaultAccessGrant(vaultAccessCmd)
	vaultaccess.InitVaultAccessList(vaultAccessCmd)
	vaultaccess.InitVaultAccessRevoke(vaultAccessCmd)
	vaultaccess.InitVaultAccessRoles(vaultAccessCmd)
}
