package cmd

import (
	"github.com/spf13/cobra"

	vaultaccess "rocketvault/cmd/vault-access"
)

// vaultAccessCmd is the command group for vault-scoped role assignments.
var vaultAccessCmd = &cobra.Command{
	Use:   "vault-access",
	Short: "Manage vault-scoped role assignments",
	Long: `Grant, list, and revoke the role assignments that authorize a principal to
work with a vault's secrets, keys, and certificates. RocketVault mirrors the
Azure Key Vault built-in roles; 'vault-access roles' prints them with the data
actions each one carries.

Data-plane access is deny-by-default. An account's global role grants nothing
inside a vault on its own, so every principal that needs to read or write a
vault's contents needs an assignment made here — including a global admin.

grant, list, and revoke require the admin role, a vaults/manage grant, or the
Key Vault Data Access Administrator role in the target vault, which is the one
role that can delegate access without holding any itself. They act on the
vault named by --vault, defaulting to "default". roles reads nothing but the
built-in role table and needs no session at all.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Grant a role to a principal in a vault
  rocketvault vault-access grant <principal> \
    --role "Key Vault Secrets User" --vault prod

  # List the assignments in that vault
  rocketvault vault-access list --vault prod

  # Print the built-in roles; no session required
  rocketvault vault-access roles`,
}

func init() {
	rootCmd.AddCommand(vaultAccessCmd)
	vaultaccess.InitVaultAccessGrant(vaultAccessCmd)
	vaultaccess.InitVaultAccessList(vaultAccessCmd)
	vaultaccess.InitVaultAccessRevoke(vaultAccessCmd)
	vaultaccess.InitVaultAccessRoles(vaultAccessCmd)
}
