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

package keys

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List cryptographic keys",
	Long: `List the cryptographic keys in the target vault, newest first, showing ID,
name, type, revocation status, tags and creation time. Listing is vault
scoped rather than owner scoped: every key in the vault is returned,
whoever created it. Soft-deleted keys are excluded.

Requires the Microsoft.KeyVault/vaults/keys/read data action in the target
vault. No global role is checked here.

The vault is named by --vault and defaults to "default". --type matches the
stored key type exactly (RSA, ECDSA or ES256K), and --tags returns any key
carrying at least one of the listed tags.`,
	Example: `  # List the keys in the default vault
  rocketvault keys list

  # List the keys in a named vault
  rocketvault keys list --vault payments

  # Filter by type and tags
  rocketvault keys list --type RSA --tags prod,secure

  # Machine-readable output
  rocketvault keys list --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Begin(cmd, vaultcli.Op{
			Audit: "list_keys", Action: model.ActionKeysRead, Policy: model.OpGet,
		})
		if err != nil {
			return err
		}

		keyType, _ := cmd.Flags().GetString("type")
		tagsStr, _ := cmd.Flags().GetString("tags")

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		keys, err := s.Container.GetKeyService().ListKeys(s.Ctx, s.Scope,
			model.KeyFilter{Type: keyType, Tags: tags})
		if err != nil {
			return s.Fail("failed to list keys", err)
		}

		s.OK(fmt.Sprintf("listed %d keys", len(keys)))
		return vaultcli.Print(s, keyColumns, keys...)
	},
}

// InitKeysList initializes the list command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The list command allows users to retrieve
// a list of all keys in the system. It does not require any additional parameters.
//
// parameters:
//
// - keysCmd: The parent command under which the list command will be added.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The list command is a subcommand of the keys command and is used to retrieve a list of all keys.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysList(keysCmd *cobra.Command) {
	keysCmd.AddCommand(listCmd)

	listCmd.Flags().String("type", "", "Filter by key type (RSA, ECDSA)")
	listCmd.Flags().String("tags", "", "Comma-separated tags to filter keys")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
