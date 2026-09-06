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

// verifyCmd represents the verify subcommand.
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature using a vault key",
	Long: `Verify a base64-encoded signature against base64-encoded data using a key
held in the target vault. The outcome is printed as a row of key ID,
algorithm and validity, and the command exits non-zero when the signature
does not check out, so it composes directly in scripts (e.g. "if
rocketvault keys verify ...; then").

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/verify/action data action in the target
vault, which defaults to "default".

--key-id, --data and --signature are all required, and --data and
--signature must both be standard base64. --algorithm defaults to RS256 and
must match the algorithm the signature was produced with. --version selects
an archived key version produced by "keys rotate"; 0 or omitted verifies
against the key's current material. A key that is revoked, disabled, or
outside its not-before/expiry window is refused.`,
	Example: `  # Verify a signature produced by "keys sign"
  rocketvault keys verify --key-id <uuid> --data <base64> \
    --signature <base64>

  # Verify against an ECDSA key in a named vault
  rocketvault keys verify --key-id <uuid> --data <base64> \
    --signature <base64> --algorithm ES256 --vault payments

  # Verify against an earlier version of a rotated key
  rocketvault keys verify --key-id <uuid> --data <base64> \
    --signature <base64> --version 1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "verify_key", Action: model.ActionKeysVerify, Policy: model.OpVerify,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		keyIDStr, _ := cmd.Flags().GetString("key-id")
		dataB64, _ := cmd.Flags().GetString("data")
		signatureB64, _ := cmd.Flags().GetString("signature")
		algorithm, _ := cmd.Flags().GetString("algorithm")
		version, _ := cmd.Flags().GetInt("version")

		if keyIDStr == "" || dataB64 == "" || signatureB64 == "" {
			return s.Fail("--key-id, --data, and --signature are required", nil)
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

		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			return s.Fail("failed to decode --signature (must be standard base64)", err)
		}

		// Authorize only after the input is known good, so a malformed
		// argument still reports itself rather than a permission error.
		if err := s.Authorize(); err != nil {
			return err
		}

		cryptoService := s.Container.GetCryptoService()

		result, err := cryptoService.Verify(s.Ctx, keyServices.VerifyRequest{
			KeyID:     keyID,
			Data:      data,
			Signature: signature,
			Algorithm: crypto.SignatureAlgorithm(algorithm),
			UserID:    s.Claims.UserID,
			VaultID:   s.VaultID,
			Scope:     s.Scope,
			Version:   version,
		})
		if err != nil {
			return s.Fail("verify failed", err)
		}

		s.OK(fmt.Sprintf("signature check for vault key %s: valid=%v", keyID, result.Valid))

		if err := vaultcli.Print(s, verifyColumns, result); err != nil {
			return err
		}

		if !result.Valid {
			return fmt.Errorf("signature verification failed")
		}
		return nil
	},
}

// NewVerifyCmd returns the verify cobra command (used in registration).
func NewVerifyCmd() *cobra.Command {
	return verifyCmd
}

// InitKeysVerify adds the verify subcommand to the keys command.
func InitKeysVerify(keysCmd *cobra.Command) {
	keysCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().String("key-id", "", "UUID of the vault key used to verify")
	verifyCmd.Flags().String("data", "", "Base64-encoded original data")
	verifyCmd.Flags().String("signature", "", "Base64-encoded signature to verify")
	verifyCmd.Flags().String("algorithm", "RS256", "Signature algorithm (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)")
	verifyCmd.Flags().Int("version", 0, "Key version to use (0 or omitted = the key's current version)")
}
