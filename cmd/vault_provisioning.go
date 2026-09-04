package cmd

import (
	"github.com/spf13/cobra"

	vaultprovisioning "rocketvault/cmd/vault-provisioning"
)

// vaultProvisioningCmd is the command group for bounded vault-creation
// rights: an operator issues one grant per customer instead of provisioning
// each vault by hand.
var vaultProvisioningCmd = &cobra.Command{
	Use:   "vault-provisioning",
	Short: "Manage bounded vault-creation rights",
	Long: `Issue, list, and revoke provisioning grants: bounded rights that let a
principal create up to a fixed number of vaults without any authority over
vaults it did not create. This is the delegated alternative to a global
vaults:manage policy, which additionally confers authority over every vault
that already exists.

All three commands require the admin role and are deliberately
non-delegable: a principal able to amend grants could raise its own quota,
and the bound the grant exists to impose would be decorative. None of them
are vault scoped -- a grant is a global right to create vaults, not a right
inside one.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Issue a grant
  rocketvault vault-provisioning grant alice --quota 5

  # List every grant
  rocketvault vault-provisioning list

  # Revoke a grant
  rocketvault vault-provisioning revoke alice`,
}

func init() {
	rootCmd.AddCommand(vaultProvisioningCmd)
	vaultprovisioning.InitVaultProvisioningGrant(vaultProvisioningCmd)
	vaultprovisioning.InitVaultProvisioningRevoke(vaultProvisioningCmd)
	vaultprovisioning.InitVaultProvisioningList(vaultProvisioningCmd)
}
