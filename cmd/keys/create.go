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
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new key",
	Long: `Generate a new asymmetric key and store its material in the target vault,
encrypted with the server master key. Software keys are stored as encrypted
PEM; when an HSM is configured, only a PKCS#11 handle is stored.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/create data action in the target vault.

--name and --type are both required. --type accepts only RSA or ECDSA;
any other value is rejected before any key is generated. RSA keys must be
2048, 3072 or 4096 bits. ECDSA keys must use curve P-256, P-384, P-521 or
P-256K, and a P-256K key is recorded with type ES256K. Symmetric OCT keys
are HSM-only and cannot be created from the CLI at all.

The key is created in the vault named by --vault, which defaults to
"default".`,
	Example: `  # RSA key in the default vault
  rocketvault keys create --name <name> --type RSA --bits 2048

  # ECDSA key in a named vault, with tags
  rocketvault keys create --name <name> --type ECDSA \
    --curve P-384 --tags prod,secure --vault payments

  # RSA key that cannot be purged until purge protection is cleared
  rocketvault keys create --name <name> --type RSA --bits 4096 \
    --purge-protection`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}
		name := viper.GetString("key-name")
		keyType := viper.GetString("key-type")
		bits := viper.GetInt("key-bits")
		curve := viper.GetString("key-curve")
		tagsStr := viper.GetString("key-tags")

		if name == "" || keyType == "" {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", "name and type are required", nil)
			return fmt.Errorf("name and type are required")
		}

		keyType = strings.ToUpper(keyType)
		if keyType != "RSA" && keyType != "ECDSA" {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", "invalid key type: must be RSA or ECDSA", nil)
			return fmt.Errorf("invalid key type: must be RSA or ECDSA")
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		keyService := serviceContainer.GetKeyService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysCreate, model.OpCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		// Create key request
		req := keyServices.CreateKeyRequest{
			Name:    name,
			Type:    keyType,
			Bits:    bits,
			Curve:   curve,
			Tags:    tags,
			UserID:  claims.UserID,
			VaultID: vaultID,
		}
		// Only send purge protection when the flag was explicitly passed.
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		var result *keyServices.CreateKeyResult

		if keyType == "RSA" {
			result, err = keyService.CreateRSAKey(ctx, req)
		} else {
			result, err = keyService.CreateECDSAKey(ctx, req)
		}

		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", fmt.Sprintf("failed to create key: %s", err), err)
			return fmt.Errorf("failed to create key: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "create_key", "success", fmt.Sprintf("key created: %s, ID: %s", result.Name, result.KeyID))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Type", "Tags", "Created"}
		row := []string{
			result.KeyID.String(),
			result.Name,
			result.Type,
			strings.Join(result.Tags, ","),
			result.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitKeysCreate initializes the create command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The create command allows users to create
// a new key. It requires the key details to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the create command will be added.
//
// returns:
//
// - *cobra.Command: The initialized create command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The create command is a subcommand of the keys command and is used to create a new key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysCreate(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(createCmd)

	createCmd.Flags().String("name", "", "Name for the new key")
	createCmd.Flags().String("type", "", "Key type (RSA, ECDSA)")
	createCmd.Flags().Int("bits", 2048, "RSA key size in bits (2048, 3072 or 4096)")
	createCmd.Flags().String("curve", "P-256", "ECDSA curve (P-256, P-384, P-521, P-256K)")
	createCmd.Flags().String("tags", "", "Comma-separated tags for the key")
	createCmd.Flags().Bool("purge-protection", false, "Protect the key from being purged")
	viper.BindPFlag("key-name", createCmd.Flags().Lookup("name"))   //nolint:errcheck,gosec
	viper.BindPFlag("key-type", createCmd.Flags().Lookup("type"))   //nolint:errcheck,gosec
	viper.BindPFlag("key-bits", createCmd.Flags().Lookup("bits"))   //nolint:errcheck,gosec
	viper.BindPFlag("key-curve", createCmd.Flags().Lookup("curve")) //nolint:errcheck,gosec
	viper.BindPFlag("key-tags", createCmd.Flags().Lookup("tags"))   //nolint:errcheck,gosec

	return keysCmd
}
