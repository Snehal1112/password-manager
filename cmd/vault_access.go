package cmd

import (
	"github.com/spf13/cobra"

	vaultaccess "rocketvault/cmd/vault-access"
)

// vaultAccessCmd is the command group for vault-scoped role assignments.
var vaultAccessCmd = &cobra.Command{
	Use:   "vault-access",
	Short: "Manage vault-scoped role assignments",
	Example: `  # Grant a role to a principal in a vault
  rocketvault vault-access grant alice --role "Key Vault Secrets User" --vault prod \
    --username admin --password admin123 --totp-code <code>

  # List built-in roles (no auth required)
  rocketvault vault-access roles`,
}

func init() {
	rootCmd.AddCommand(vaultAccessCmd)
	vaultaccess.InitVaultAccessGrant(vaultAccessCmd)
	vaultaccess.InitVaultAccessList(vaultAccessCmd)
	vaultaccess.InitVaultAccessRevoke(vaultAccessCmd)
	vaultaccess.InitVaultAccessRoles(vaultAccessCmd)
}
