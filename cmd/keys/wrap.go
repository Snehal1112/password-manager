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
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// wrapCmd represents the wrap subcommand.
var wrapCmd = &cobra.Command{
	Use:   "wrap",
	Short: "Wrap key material using a vault RSA key",
	Long:  `Encrypt plaintext key material with RSA-OAEP using an existing vault key. The input key material must be base64-encoded.`,
	Example: `  # Wrap key material with RSA key
  rocketvault keys wrap --key-id <uuid> --key-material <base64> \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		keyIDStr := viper.GetString("wrap-key-id")
		keyMaterialB64 := viper.GetString("wrap-key-material")

		if keyIDStr == "" || keyMaterialB64 == "" {
			log.LogAuditError(claims.UserID.String(), "wrap_key", "failed", "--key-id and --key-material are required", nil)
			return fmt.Errorf("--key-id and --key-material are required")
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "wrap_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		plaintext, err := base64.StdEncoding.DecodeString(keyMaterialB64)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "wrap_key", "failed", "failed to decode key material", err)
			return fmt.Errorf("failed to decode --key-material (must be standard base64): %w", err)
		}

		// Get service container from context.
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "wrap_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysWrap, model.OpCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "wrap_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.WrapKey(ctx, keyServices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       claims.UserID,
			VaultID:      vaultID,
			Scope:        model.NewVaultScope(vaultID, claims.UserID),
			PlaintextKey: plaintext,
			Algorithm:    "RSA-OAEP",
		})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "wrap_key", "failed", fmt.Sprintf("wrap failed: %s", err), err)
			return fmt.Errorf("wrap failed: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "wrap_key", "success",
			fmt.Sprintf("key material wrapped with vault key %s", keyID))
		fmt.Println(base64.StdEncoding.EncodeToString(result.WrappedKey))
		return nil
	},
}

// NewWrapCmd returns the wrap cobra command (used in registration).
func NewWrapCmd() *cobra.Command {
	return wrapCmd
}

// InitKeysWrap adds the wrap subcommand to the keys command.
func InitKeysWrap(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(wrapCmd)

	wrapCmd.Flags().String("key-id", "", "UUID of the vault RSA key used for wrapping")
	wrapCmd.Flags().String("key-material", "", "Base64-encoded plaintext key material to wrap")
	viper.BindPFlag("wrap-key-id", wrapCmd.Flags().Lookup("key-id"))
	viper.BindPFlag("wrap-key-material", wrapCmd.Flags().Lookup("key-material"))

	return keysCmd
}
