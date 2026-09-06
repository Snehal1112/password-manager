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
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// rotateCmd represents the rotate command
var rotateCmd = &cobra.Command{
	Use:   "rotate <id>",
	Short: "Rotate a cryptographic key",
	Long: `Rotate a cryptographic key in place. New material is generated with the same
type, bit size and curve as the existing key, the previous material is
archived as a numbered version, and the new material becomes current. The
key keeps its UUID, name and tags, and the old material is not revoked:
earlier versions stay usable through the --version flag on "keys sign",
"keys verify", "keys wrap" and "keys unwrap".

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/rotate/action data action in the target
vault, which defaults to "default".

Only RSA, ECDSA and ES256K keys can be rotated; any other stored type is
rejected. Rotation works on a disabled or expired key. If the key has an
enabled rotation policy with an expiry_days lifetime action, this manual
rotation stamps a fresh expiry on the key just as a scheduled rotation
would.`,
	Example: `  # Rotate a key in the default vault
  rocketvault keys rotate <key-id>

  # Rotate a key in a named vault
  rocketvault keys rotate <key-id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "rotate_key", Action: model.ActionKeysRotate, Policy: model.OpRotate,
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

		// Rotate the key, scoped to the resolved --vault.
		newKey, err := s.Container.GetKeyService().RotateKey(s.Ctx, keyID, s.Scope)
		if err != nil {
			return s.Fail("failed to rotate key", err)
		}

		s.OK(fmt.Sprintf("key rotated: %s", newKey.KeyID))
		fmt.Fprintf(cmd.OutOrStdout(), "Key rotated successfully: ID=%s, Name=%s, Type=%s, CreatedAt=%s, Tags=%v\n", //nolint:errcheck
			newKey.KeyID, newKey.Name, newKey.Type, newKey.CreatedAt.Format(time.RFC3339), newKey.Tags)
		return nil
	},
}

// InitKeysRotate initializes the rotate command for keys.
// It adds the rotate command to the keys command. Authentication flags are inherited from the root command.
func InitKeysRotate(keysCmd *cobra.Command) {
	keysCmd.AddCommand(rotateCmd)
}
