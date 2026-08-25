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
	"os"
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

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an externally-generated key",
	Long: `Import an RSA or ECDSA private key supplied as a JWK into the target vault,
storing it exactly as if RocketVault had generated it -- encrypted PEM for a
software-backed vault, a non-extractable PKCS#11 object for an HSM-backed one.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/import/action data action in the target vault.

--name and one of --jwk-file or --jwk (inline JSON) are required. A JWK with
no private key material (public-only) is rejected.

The key is created in the vault named by --vault, which defaults to
"default".`,
	Example: `  # Import from a JWK file
  rocketvault keys import --name <name> --jwk-file ./key.jwk.json

  # Import from inline JSON
  rocketvault keys import --name <name> --jwk '{"kty":"RSA","n":"...","e":"AQAB","d":"..."}'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		name := viper.GetString("key-import-name")
		jwkInline := viper.GetString("key-import-jwk")
		jwkFile := viper.GetString("key-import-jwk-file")
		tagsStr := viper.GetString("key-import-tags")

		if name == "" {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "name is required", nil)
			return fmt.Errorf("name is required")
		}
		if jwkInline == "" && jwkFile == "" {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "one of --jwk or --jwk-file is required", nil)
			return fmt.Errorf("one of --jwk or --jwk-file is required")
		}
		if jwkInline != "" && jwkFile != "" {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "--jwk and --jwk-file are mutually exclusive", nil)
			return fmt.Errorf("--jwk and --jwk-file are mutually exclusive")
		}

		var jwkBytes []byte
		if jwkFile != "" {
			data, err := os.ReadFile(jwkFile)
			if err != nil {
				log.LogAuditError(claims.UserID.String(), "import_key", "failed", fmt.Sprintf("failed to read jwk file: %s", err), err)
				return fmt.Errorf("failed to read jwk file: %w", err)
			}
			jwkBytes = data
		} else {
			jwkBytes = []byte(jwkInline)
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		keyService := serviceContainer.GetKeyService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysImport, model.OpCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		req := keyServices.ImportKeyRequest{
			Name:    name,
			JWK:     jwkBytes,
			Tags:    tags,
			UserID:  claims.UserID,
			VaultID: vaultID,
		}
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		result, err := keyService.ImportKey(ctx, req)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "import_key", "failed", fmt.Sprintf("failed to import key: %s", err), err)
			return fmt.Errorf("failed to import key: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "import_key", "success", fmt.Sprintf("key imported: %s, ID: %s", result.Name, result.KeyID))

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

// InitKeysImport initializes the import command for keys and adds it to the
// keys command.
func InitKeysImport(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(importCmd)

	importCmd.Flags().String("name", "", "Name for the imported key")
	importCmd.Flags().String("jwk", "", "Inline JWK JSON containing private key material")
	importCmd.Flags().String("jwk-file", "", "Path to a file containing JWK JSON")
	importCmd.Flags().String("tags", "", "Comma-separated tags for the key")
	importCmd.Flags().Bool("purge-protection", false, "Protect the key from being purged")
	viper.BindPFlag("key-import-name", importCmd.Flags().Lookup("name"))         //nolint:errcheck,gosec
	viper.BindPFlag("key-import-jwk", importCmd.Flags().Lookup("jwk"))           //nolint:errcheck,gosec
	viper.BindPFlag("key-import-jwk-file", importCmd.Flags().Lookup("jwk-file")) //nolint:errcheck,gosec
	viper.BindPFlag("key-import-tags", importCmd.Flags().Lookup("tags"))         //nolint:errcheck,gosec

	return keysCmd
}
