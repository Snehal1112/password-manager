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

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
)

// unwrapCmd represents the unwrap subcommand.
var unwrapCmd = &cobra.Command{
	Use:     "unwrap",
	Short:   "Unwrap key material using a vault RSA key",
	Long:    `Decrypt wrapped key material with RSA-OAEP using an existing vault key. The wrapped key must be base64-encoded.`,
	Example: `rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*domain.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		keyIDStr := viper.GetString("unwrap-key-id")
		wrappedKeyB64 := viper.GetString("unwrap-wrapped-key")

		if keyIDStr == "" || wrappedKeyB64 == "" {
			log.LogAuditError(claims.UserID.String(), "unwrap_key", "failed", "--key-id and --wrapped-key are required", nil)
			return fmt.Errorf("--key-id and --wrapped-key are required")
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "unwrap_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyB64)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "unwrap_key", "failed", "failed to decode wrapped key", err)
			return fmt.Errorf("failed to decode --wrapped-key (must be standard base64): %w", err)
		}

		// Get service container from context.
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "unwrap_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.UnwrapKey(ctx, keyServices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     claims.UserID,
			WrappedKey: wrappedKey,
			Algorithm:  "RSA-OAEP",
		})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "unwrap_key", "failed", fmt.Sprintf("unwrap failed: %s", err), err)
			return fmt.Errorf("unwrap failed: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "unwrap_key", "success",
			fmt.Sprintf("key material unwrapped with vault key %s", keyID))
		fmt.Println(base64.StdEncoding.EncodeToString(result.PlaintextKey))
		return nil
	},
}

// NewUnwrapCmd returns the unwrap cobra command (used in registration).
func NewUnwrapCmd() *cobra.Command {
	return unwrapCmd
}

// InitKeysUnwrap adds the unwrap subcommand to the keys command.
func InitKeysUnwrap(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(unwrapCmd)

	unwrapCmd.Flags().String("key-id", "", "UUID of the vault RSA key used for unwrapping")
	unwrapCmd.Flags().String("wrapped-key", "", "Base64-encoded wrapped key material to unwrap")
	viper.BindPFlag("unwrap-key-id", unwrapCmd.Flags().Lookup("key-id"))
	viper.BindPFlag("unwrap-wrapped-key", unwrapCmd.Flags().Lookup("wrapped-key"))

	return keysCmd
}
