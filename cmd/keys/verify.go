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
	"strconv"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/crypto"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// verifyCmd represents the verify subcommand.
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature using a vault key",
	Long: `Verify a base64-encoded signature against base64-encoded data using an
existing vault key. Prints the result and exits non-zero if the signature is
invalid, so the command composes directly in scripts (e.g. "if rocketvault
keys verify ...; then").`,
	Example: `  # Verify a signature produced by "keys sign"
  rocketvault keys verify --key-id <uuid> --data <base64> --signature <base64> --algorithm RS256 \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		keyIDStr := viper.GetString("verify-key-id")
		dataB64 := viper.GetString("verify-data")
		signatureB64 := viper.GetString("verify-signature")
		algorithm := viper.GetString("verify-algorithm")
		version := viper.GetInt("verify-version")

		if keyIDStr == "" || dataB64 == "" || signatureB64 == "" {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "--key-id, --data, and --signature are required", nil)
			return fmt.Errorf("--key-id, --data, and --signature are required")
		}
		if algorithm == "" {
			algorithm = "RS256"
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "failed to decode data", err)
			return fmt.Errorf("failed to decode --data (must be standard base64): %w", err)
		}

		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "failed to decode signature", err)
			return fmt.Errorf("failed to decode --signature (must be standard base64): %w", err)
		}

		// Get service container from context.
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysVerify, model.OpVerify)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		cryptoService := serviceContainer.GetCryptoService()

		result, err := cryptoService.Verify(ctx, keyServices.VerifyRequest{
			KeyID:     keyID,
			Data:      data,
			Signature: signature,
			Algorithm: crypto.SignatureAlgorithm(algorithm),
			UserID:    claims.UserID,
			VaultID:   vaultID,
			Scope:     model.NewVaultScope(vaultID, claims.UserID),
			Version:   version,
		})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "verify_key", "failed", fmt.Sprintf("verify failed: %s", err), err)
			return fmt.Errorf("verify failed: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "verify_key", "success",
			fmt.Sprintf("signature check for vault key %s: valid=%v", keyID, result.Valid))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"Key ID", "Algorithm", "Valid"}
		row := []string{
			result.KeyID.String(),
			string(result.Algorithm),
			strconv.FormatBool(result.Valid),
		}
		if err := fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row}); err != nil {
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
func InitKeysVerify(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().String("key-id", "", "UUID of the vault key used to verify")
	verifyCmd.Flags().String("data", "", "Base64-encoded original data")
	verifyCmd.Flags().String("signature", "", "Base64-encoded signature to verify")
	verifyCmd.Flags().String("algorithm", "RS256", "Signature algorithm (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)")
	verifyCmd.Flags().Int("version", 0, "Key version to use (0 or omitted = the key's current version)")
	viper.BindPFlag("verify-key-id", verifyCmd.Flags().Lookup("key-id"))       //nolint:errcheck,gosec
	viper.BindPFlag("verify-data", verifyCmd.Flags().Lookup("data"))           //nolint:errcheck,gosec
	viper.BindPFlag("verify-signature", verifyCmd.Flags().Lookup("signature")) //nolint:errcheck,gosec
	viper.BindPFlag("verify-algorithm", verifyCmd.Flags().Lookup("algorithm")) //nolint:errcheck,gosec
	viper.BindPFlag("verify-version", verifyCmd.Flags().Lookup("version"))     //nolint:errcheck,gosec

	return keysCmd
}
