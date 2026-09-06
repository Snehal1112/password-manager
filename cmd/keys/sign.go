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
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/internal/crypto"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// signCmd represents the sign subcommand.
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data using a vault key",
	Long: `Sign data with a key held in the target vault and print the signature to
stdout as standard base64. --data is itself standard base64 and is decoded
before signing, so raw text must be encoded first.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/sign/action data action in the target vault,
which defaults to "default".

--key-id and --data are both required. --algorithm defaults to RS256 and
must suit the key type: RS256/RS384/RS512 and PS256/PS384/PS512 for RSA
keys, ES256/ES384/ES512 for ECDSA keys. --version selects an archived key
version produced by "keys rotate"; 0 or omitted signs with the key's
current material. A key that is revoked, disabled, or outside its
not-before/expiry window is refused.`,
	Example: `  # Sign with the key's current version, using the default RS256
  rocketvault keys sign --key-id <uuid> --data <base64>

  # Sign with an ECDSA key in a named vault
  rocketvault keys sign --key-id <uuid> --data <base64> \
    --algorithm ES256 --vault payments

  # Sign with an earlier version of a rotated key
  rocketvault keys sign --key-id <uuid> --data <base64> --version 1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "sign_key", Action: model.ActionKeysSign, Policy: model.OpSign,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		keyIDStr, _ := cmd.Flags().GetString("key-id")
		dataB64, _ := cmd.Flags().GetString("data")
		algorithm, _ := cmd.Flags().GetString("algorithm")
		version, _ := cmd.Flags().GetInt("version")

		if keyIDStr == "" || dataB64 == "" {
			return s.Fail("--key-id and --data are required", nil)
		}
		if algorithm == "" {
			algorithm = "RS256"
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			return s.Fail("failed to decode --data (must be standard base64)", err)
		}

		// Authorize only after the input is known good, so a malformed
		// argument still reports itself rather than a permission error.
		if err := s.Authorize(); err != nil {
			return err
		}

		cryptoService := s.Container.GetCryptoService()

		result, err := cryptoService.Sign(s.Ctx, keyServices.SignRequest{
			KeyID:     keyID,
			Data:      data,
			Algorithm: crypto.SignatureAlgorithm(algorithm),
			UserID:    s.Claims.UserID,
			VaultID:   s.VaultID,
			Scope:     s.Scope,
			Version:   version,
		})
		if err != nil {
			return s.Fail("sign failed", err)
		}

		s.OK(fmt.Sprintf("data signed with vault key %s", keyID))
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(result.Signature))
		return nil
	},
}

// NewSignCmd returns the sign cobra command (used in registration).
func NewSignCmd() *cobra.Command {
	return signCmd
}

// InitKeysSign adds the sign subcommand to the keys command.
func InitKeysSign(keysCmd *cobra.Command) {
	keysCmd.AddCommand(signCmd)

	signCmd.Flags().String("key-id", "", "UUID of the vault key used to sign")
	signCmd.Flags().String("data", "", "Base64-encoded data to sign")
	signCmd.Flags().String("algorithm", "RS256", "Signature algorithm (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)")
	signCmd.Flags().Int("version", 0, "Key version to use (0 or omitted = the key's current version)")
}
