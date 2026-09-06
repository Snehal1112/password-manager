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

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Retrieve a cryptographic key",
	Long: `Print the metadata of one cryptographic key by its UUID: ID, name, type,
revocation status, tags and creation time. Key material is never printed.

Requires the Microsoft.KeyVault/vaults/keys/read data action in the target
vault. No global role is checked here, so any principal holding a role
assignment that grants that action can read key metadata.

The lookup is scoped to the vault named by --vault, defaulting to
"default"; a key that lives in another vault is reported as not found. A
key that is disabled, or outside its not-before/expiry window, is refused
even though it exists.`,
	Example: `  # Show a key in the default vault
  rocketvault keys get <key-id>

  # Show a key in a named vault
  rocketvault keys get <key-id> --vault payments

  # Machine-readable output
  rocketvault keys get <key-id> --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "get_key", Action: model.ActionKeysRead, Policy: model.OpGet,
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

		// Access control is handled by the service layer, via s.Scope.
		key, err := s.Container.GetKeyService().GetKey(s.Ctx, keyID, s.Scope)
		if err != nil {
			return s.Fail("failed to get key", err)
		}

		s.OK(fmt.Sprintf("key retrieved: %s", key.Name))
		return vaultcli.Print(s, keyColumns, *key)
	},
}

// InitKeysGet initializes the get command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The get command allows users to retrieve
// information about a specific key by its ID. It requires the key ID
// to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the get command will be added.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The get command is a subcommand of the keys command and is used to retrieve information about a specific key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysGet(keysCmd *cobra.Command) {
	keysCmd.AddCommand(getCmd)
}
