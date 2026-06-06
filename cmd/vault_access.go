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
  rocketvault vault-access grant alice --role secrets-user --vault prod \
    --username admin --password admin123 --totp-code <code>

  # List built-in roles
  rocketvault vault-access roles \
    --username admin --password admin123 --totp-code <code>`,
}

func init() {
	rootCmd.AddCommand(vaultAccessCmd)
	vaultaccess.InitVaultAccessGrant(vaultAccessCmd)
	vaultaccess.InitVaultAccessList(vaultAccessCmd)
	vaultaccess.InitVaultAccessRevoke(vaultAccessCmd)
	vaultaccess.InitVaultAccessRoles(vaultAccessCmd)
}
