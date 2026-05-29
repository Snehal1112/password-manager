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
	Long: `A command group for creating, retrieving, listing, deleting, recovering,
and purging vaults that hold secrets, keys, and certificates.`,
	Example: `rocketvault vaults create my-vault`,
}

func init() {
	rootCmd.AddCommand(vaultsCmd)

	vaults.InitVaultsCreate(vaultsCmd)
	vaults.InitVaultsList(vaultsCmd)
	vaults.InitVaultsGet(vaultsCmd)
	vaults.InitVaultsDelete(vaultsCmd)
	vaults.InitVaultsRecover(vaultsCmd)
	vaults.InitVaultsPurge(vaultsCmd)
}
