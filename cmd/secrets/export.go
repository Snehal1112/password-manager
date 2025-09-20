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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"password-manager/common"
	"password-manager/internal/db"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
	"password-manager/internal/repositories"
)

var (
	exportFormat     string
	exportFile       string
	exportEncrypt    bool
	exportTags       []string
	exportFilterTags []string
	exportUsername   string
)

// secretsExportCmd represents the export command
var secretsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets to encrypted file",
	Long: `Export secrets to an encrypted JSON or CSV file format.
The export includes all secrets for the specified user with optional tag filtering.
The exported file is encrypted using the master key for security.`,
	Example: `  # Export all secrets to encrypted JSON
  secrets export --format json --file secrets.json --encrypt

  # Export secrets with specific tags to CSV
  secrets export --format csv --file secrets.csv --tags production,api --encrypt

  # Export unencrypted JSON for development
  secrets export --format json --file secrets-dev.json --username dev-user`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSecretsExport(cmd, args)
	},
}

// InitSecretsExport initializes the secrets export command.
func InitSecretsExport(parentCmd *cobra.Command) {
	parentCmd.AddCommand(secretsExportCmd)

	secretsExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Export format (json or csv)")
	secretsExportCmd.Flags().StringVarP(&exportFile, "file", "o", "", "Output file path (required)")
	secretsExportCmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", true, "Encrypt the export file")
	secretsExportCmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "Include only secrets with these tags")
	secretsExportCmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "Filter secrets by these tags")
	secretsExportCmd.Flags().StringVarP(&exportUsername, "username", "u", "", "Username for export (defaults to current user)")

	secretsExportCmd.MarkFlagRequired("file")
}

// runSecretsExport executes the secrets export command.
func runSecretsExport(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logger := logging.InitLogger()

	// Initialize database
	database := db.NewRepository(logger)
	if err := database.InitializeDB(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	sqlDB := database.GetDB()
	defer sqlDB.Close()

	// Initialize secrets repository
	secretsRepo := repositories.NewSecretRepository(sqlDB, logger)

	// Validate format
	var format domain.ExportFormat
	switch strings.ToLower(exportFormat) {
	case "json":
		format = domain.ExportFormatJSON
	case "csv":
		format = domain.ExportFormatCSV
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, csv)", exportFormat)
	}

	// Get user ID from authentication context
	userIDValue := cmd.Context().Value(common.UserIDKey)
	if userIDValue == nil {
		return fmt.Errorf("user not authenticated")
	}
	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		return fmt.Errorf("invalid user ID in context")
	}

	// Prepare export options
	options := domain.ExportOptions{
		Format:      format,
		IncludeTags: true,
		FilterTags:  append(exportTags, exportFilterTags...),
		Encrypt:     exportEncrypt,
		UserID:      userID,
		ExportedAt:  time.Now(),
		ExportedBy:  exportUsername,
	}

	// Create context
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.DBKey, sqlDB)
	ctx = context.WithValue(ctx, common.LogKey, logger)

	// Export secrets
	data, err := secretsRepo.ExportSecrets(ctx, options)
	if err != nil {
		return fmt.Errorf("failed to export secrets: %w", err)
	}

	// Ensure output directory exists
	dir := filepath.Dir(exportFile)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Write to file
	if err := os.WriteFile(exportFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	// Success message
	status := "encrypted"
	if !exportEncrypt {
		status = "unencrypted"
	}

	fmt.Printf("✅ Secrets exported successfully!\n")
	fmt.Printf("📄 Format: %s\n", format)
	fmt.Printf("📁 File: %s\n", exportFile)
	fmt.Printf("🔒 Status: %s\n", status)
	if len(options.FilterTags) > 0 {
		fmt.Printf("🏷️  Tags: %s\n", strings.Join(options.FilterTags, ", "))
	}

	return nil
}
