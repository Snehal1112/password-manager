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

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
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
	Long: `Export secrets to an encrypted JSON or CSV file.
The export includes all secrets for the authenticated user with optional tag filtering.`,
	Example: `  # Export all secrets to JSON
  rocketvault secrets export --format json --file secrets.json \
    --username admin --password admin123 --totp-code <code>

  # Export secrets filtered by tags to CSV
  rocketvault secrets export --format csv --file secrets.csv --tags production \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user not authenticated")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		format := strings.ToLower(exportFormat)
		if format != "json" && format != "csv" {
			return fmt.Errorf("unsupported format: %s (supported: json, csv)", exportFormat)
		}

		allTags := append(exportTags, exportFilterTags...)

		data, err := sc.GetSecretService().ExportSecrets(ctx, secretServices.ExportSecretsRequest{
			UserID:      userID,
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
	secretsExportCmd.MarkFlagRequired("file")
}
