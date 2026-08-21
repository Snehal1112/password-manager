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
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

var (
	importFormat    string
	importFile      string
	importEncrypted bool
	importOverwrite bool
)

// secretsImportCmd represents the import command.
var secretsImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from a file",
	Long: `Import secrets into the target vault from a JSON or CSV file in the layout
"secrets export" produces. Every record is created as a new secret at
version 1, so an existing secret of the same name is never replaced:
--overwrite is passed to the import service but never acted on, and
--encrypted is accepted and unused because the export is plaintext.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/setSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The caller
becomes the owner of every imported secret.

Records missing a name or a value are skipped rather than failing the run,
and the imported and skipped counts are printed when the run finishes.`,
	Example: `  # Import secrets from a JSON file into the default vault
  rocketvault secrets import --file secrets.json

  # Import a CSV export
  rocketvault secrets import --format csv --file secrets.csv

  # Import into a named vault
  rocketvault secrets import --file secrets.json --vault <vault-name>`,
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

		format := strings.ToLower(importFormat)
		if format != "json" && format != "csv" {
			return fmt.Errorf("unsupported format: %s (supported: json, csv)", importFormat)
		}

		if _, err := os.Stat(importFile); os.IsNotExist(err) {
			return fmt.Errorf("import file does not exist: %s", importFile)
		}

		data, err := os.ReadFile(importFile)
		if err != nil {
			return fmt.Errorf("failed to read import file: %w", err)
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsSet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsSet, model.OpImport)
		if err != nil {
			return err
		}

		// The scope's actor becomes the owner of every imported secret, so it
		// must carry the real authenticated user; uuid.Nil would orphan every
		// row (and fail the PostgreSQL foreign key outright).
		result, err := sc.GetSecretService().ImportSecrets(ctx, secretServices.ImportSecretsRequest{
			Scope:     model.NewVaultScope(vaultID, userID),
			Data:      data,
			Format:    format,
			Overwrite: importOverwrite,
		})
		if err != nil {
			return fmt.Errorf("failed to import secrets: %w", err)
		}

		fmt.Printf("Secrets imported successfully\nImported: %d\nSkipped: %d\n",
			result.ImportedCount, result.SkippedCount)
		return nil
	},
}

// InitSecretsImport initializes the secrets import command.
func InitSecretsImport(parentCmd *cobra.Command) {
	parentCmd.AddCommand(secretsImportCmd)
	secretsImportCmd.Flags().StringVarP(&importFormat, "format", "f", "json", "Import format (json or csv)")
	secretsImportCmd.Flags().StringVarP(&importFile, "file", "i", "", "Input file path (required)")
	secretsImportCmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", true, "File is encrypted")
	secretsImportCmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "Overwrite existing secrets")
	secretsImportCmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}
