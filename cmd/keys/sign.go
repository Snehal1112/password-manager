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
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
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
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "sign_key", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		keyIDStr := viper.GetString("sign-key-id")
		dataB64 := viper.GetString("sign-data")
		algorithm := viper.GetString("sign-algorithm")
		version := viper.GetInt("sign-version")

		if keyIDStr == "" || dataB64 == "" {
			log.LogAuditError(claims.UserID.String(), "sign_key", "failed", "--key-id and --data are required", nil)
			return fmt.Errorf("--key-id and --data are required")
		}
		if algorithm == "" {
			algorithm = "RS256"
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "sign_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "sign_key", "failed", "failed to decode data", err)
			return fmt.Errorf("failed to decode --data (must be standard base64): %w", err)
		}

		// Get service container from context.
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "sign_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysSign, model.OpSign)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "sign_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.Sign(ctx, keyServices.SignRequest{
			KeyID:     keyID,
			Data:      data,
			Algorithm: crypto.SignatureAlgorithm(algorithm),
			UserID:    claims.UserID,
			VaultID:   vaultID,
			Scope:     model.NewVaultScope(vaultID, claims.UserID),
			Version:   version,
		})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "sign_key", "failed", fmt.Sprintf("sign failed: %s", err), err)
			return fmt.Errorf("sign failed: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "sign_key", "success",
			fmt.Sprintf("data signed with vault key %s", keyID))
		fmt.Println(base64.StdEncoding.EncodeToString(result.Signature))
		return nil
	},
}

// NewSignCmd returns the sign cobra command (used in registration).
func NewSignCmd() *cobra.Command {
	return signCmd
}

// InitKeysSign adds the sign subcommand to the keys command.
func InitKeysSign(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(signCmd)

	signCmd.Flags().String("key-id", "", "UUID of the vault key used to sign")
	signCmd.Flags().String("data", "", "Base64-encoded data to sign")
	signCmd.Flags().String("algorithm", "RS256", "Signature algorithm (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)")
	signCmd.Flags().Int("version", 0, "Key version to use (0 or omitted = the key's current version)")
	viper.BindPFlag("sign-key-id", signCmd.Flags().Lookup("key-id"))       //nolint:errcheck,gosec
	viper.BindPFlag("sign-data", signCmd.Flags().Lookup("data"))           //nolint:errcheck,gosec
	viper.BindPFlag("sign-algorithm", signCmd.Flags().Lookup("algorithm")) //nolint:errcheck,gosec
	viper.BindPFlag("sign-version", signCmd.Flags().Lookup("version"))     //nolint:errcheck,gosec

	return keysCmd
}
