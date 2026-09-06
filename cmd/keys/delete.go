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

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a cryptographic key",
	Long: `Soft-delete a cryptographic key by its UUID. The key row is retained with a
deletion timestamp rather than destroyed, so it drops out of "keys list" and
stops resolving for crypto operations but remains recoverable until it is
purged. Recovery and purge are REST API operations; the CLI has no
equivalent subcommand.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/delete data action in the target vault.

Only keys in the vault named by --vault are addressable, defaulting to
"default"; a key that lives in another vault is reported as not found.`,
	Example: `  # Delete a key in the default vault
  rocketvault keys delete <key-id>

  # Delete a key in a named vault
  rocketvault keys delete <key-id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "delete_key", Action: model.ActionKeysDelete, Policy: model.OpDelete,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		keyID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		// Authorize only after the input is known good, so a malformed
		// argument still reports itself rather than a permission error.
		if err := s.Authorize(); err != nil {
			return err
		}

		// Service layer handles ownership validation and deletion.
		if _, err := s.Container.GetKeyService().DeleteKey(s.Ctx, keyID, s.Scope); err != nil {
			return s.Fail("failed to delete key", err)
		}

		s.OK(fmt.Sprintf("key deleted: %s", keyID))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Key %s deleted successfully\n", keyID)
		return nil
	},
}

// InitKeysDelete initializes the delete command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The delete command allows users to delete
// a specific key by its ID. It requires the key ID to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the delete command will be added.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The delete command is a subcommand of the keys command and is used to delete a specific key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysDelete(keysCmd *cobra.Command) {
	keysCmd.AddCommand(deleteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deleteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deleteCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
