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

package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

var (
	exportFormat     string
	exportFile       string
	exportEncrypt    bool
	exportTags       []string
	exportFilterTags []string
)

var secretsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets to a file",
	Long: `Export the target vault's secrets to a JSON or CSV file holding each
secret's name, plaintext value and tags. Nothing in the file is encrypted:
--encrypt is accepted but never read by this command. The file is written
with 0600 permissions, and any missing parent directories are created.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/getSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The export
is vault scoped, so it includes secrets created by other members of that
vault, not only the caller's own.

--tags and --filter-tags are merged into one tag filter. Passing neither
exports every secret in the vault.`,
	Example: `  # Export every secret in the default vault as JSON
  rocketvault secrets export --file secrets.json

  # Export as CSV, restricted to secrets tagged production
  rocketvault secrets export --format csv --file secrets.csv \
    --tags production

  # Export a named vault's secrets
  rocketvault secrets export --file payments.json --vault <vault-name>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		userID := claims.UserID

		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleSecretsManager) {
			return fmt.Errorf("forbidden: requires admin or secrets_manager role")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		format := strings.ToLower(exportFormat)
		if format != "json" && format != "csv" {
			return fmt.Errorf("unsupported format: %s (supported: json, csv)", exportFormat)
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsGet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsGet, model.OpCreate)
		if err != nil {
			return err
		}

		allTags := append(exportTags, exportFilterTags...)

		// Vault-scoped: this matches api/secrets.go's exportSecrets handler,
		// which calls scopeFromRequest and gets a vault scope back on the
		// /vaults/{name}/secrets/... route. Any vault member holding a role
		// that grants ActionSecretsGet can export another member's plaintext
		// secret values into their own local file.
		data, err := sc.GetSecretService().ExportSecrets(ctx, secretServices.ExportSecretsRequest{
			Scope:       model.NewVaultScope(vaultID, userID),
			Format:      format,
			FilterTags:  allTags,
			IncludeTags: true,
		})
		if err != nil {
			return fmt.Errorf("failed to export secrets: %w", err)
		}

		dir := filepath.Dir(exportFile)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
		}
		if err := os.WriteFile(exportFile, data, 0o600); err != nil {
			return fmt.Errorf("failed to write export file: %w", err)
		}

		fmt.Printf("Secrets exported successfully\nFormat: %s\nFile: %s\n", format, exportFile)
		return nil
	},
}

// InitSecretsExport registers the export sub-command under the given parent.
func InitSecretsExport(parentCmd *cobra.Command) {
	parentCmd.AddCommand(secretsExportCmd)
	secretsExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Export format (json or csv)")
	secretsExportCmd.Flags().StringVarP(&exportFile, "file", "o", "", "Output file path (required)")
	secretsExportCmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", true, "Encrypt the export file")
	secretsExportCmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "Include only secrets with these tags")
	secretsExportCmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "Filter secrets by these tags")
	secretsExportCmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}
