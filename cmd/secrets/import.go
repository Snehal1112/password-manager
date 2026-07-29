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

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
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
	Long: `Import secrets from a JSON or CSV file.
The file must be compatible with the export format produced by the export command.`,
	Example: `  # Import secrets from JSON file
  rocketvault secrets import --file secrets.json \
    --username admin --password admin123 --totp-code <code>

  # Import and overwrite existing secrets
  rocketvault secrets import --file secrets.json --overwrite \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		_, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user not authenticated")
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

		result, err := sc.GetSecretService().ImportSecrets(ctx, secretServices.ImportSecretsRequest{
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
	secretsImportCmd.MarkFlagRequired("file")
}
