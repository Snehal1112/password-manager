/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaults"
)

// vaultsCmd represents the vaults command group.
var vaultsCmd = &cobra.Command{
	Use:   "vaults",
	Short: "Manage vaults",
	Long: `Manage the vaults themselves — the isolation boundaries that hold secrets,
keys, and certificates. Create a vault, inspect and list vaults, change its
enabled, purge-protection, and retention settings, soft-delete one, recover
it, or purge it for good. Every deployment ships with a vault named "default".

Creating, reading, listing, updating, deleting, and recovering require the
admin role or a vaults/manage grant. Purging additionally accepts the Key
Vault Purge Operator role in the target vault. Managing a vault carries no
access to what is inside it; that is granted separately with 'rocketvault
vault-access'.

These commands name their vault as a positional argument, so the global
--vault flag does not apply to them. delete is a soft delete: the vault and
its contents stay recoverable until the retention window elapses, after which
the background scheduler purges them. purge destroys a soft-deleted vault and
everything in it immediately and cannot be undone.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Create a vault with purge protection
  rocketvault vaults create <name> --purge-protection --retention-days 90

  # List vaults, including soft-deleted ones
  rocketvault vaults list --include-deleted

  # Soft-delete a vault, then recover it within its retention window
  rocketvault vaults delete <name>
  rocketvault vaults recover <name>`,
}

func init() {
	rootCmd.AddCommand(vaultsCmd)

	vaults.InitVaultsCreate(vaultsCmd)
	vaults.InitVaultsList(vaultsCmd)
	vaults.InitVaultsGet(vaultsCmd)
	vaults.InitVaultsUpdate(vaultsCmd)
	vaults.InitVaultsDelete(vaultsCmd)
	vaults.InitVaultsRecover(vaultsCmd)
	vaults.InitVaultsPurge(vaultsCmd)
	vaults.InitVaultsPreviewMigration(vaultsCmd)
}
