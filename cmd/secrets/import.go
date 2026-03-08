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
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/db"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

var (
	importFormat    string
	importFile      string
	importEncrypted bool
	importOverwrite bool
	importUsername  string
)

// secretsImportCmd represents the import command
var secretsImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from encrypted file",
	Long: `Import secrets from an encrypted JSON or CSV file format.
The import supports both encrypted and unencrypted files and can optionally overwrite existing secrets.
The file must be compatible with the current master key for decryption.`,
	Example: `  # Import encrypted JSON file
  secrets import --format json --file secrets.json --encrypted

  # Import CSV file and overwrite existing secrets
  secrets import --format csv --file secrets.csv --encrypted --overwrite

  # Import unencrypted development file
  secrets import --format json --file secrets-dev.json --username dev-user`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSecretsImport()
	},
}

// InitSecretsImport initializes the secrets import command.
func InitSecretsImport(parentCmd *cobra.Command) {
	parentCmd.AddCommand(secretsImportCmd)

	secretsImportCmd.Flags().StringVarP(&importFormat, "format", "f", "json", "Import format (json or csv)")
	secretsImportCmd.Flags().StringVarP(&importFile, "file", "i", "", "Input file path (required)")
	secretsImportCmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", true, "File is encrypted")
	secretsImportCmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "Overwrite existing secrets")
	secretsImportCmd.Flags().StringVarP(&importUsername, "username", "u", "", "Username for import (defaults to current user)")

	secretsImportCmd.MarkFlagRequired("file")
}

// runSecretsImport executes the secrets import command.
func runSecretsImport() error {
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
	switch strings.ToLower(importFormat) {
	case "json":
		format = domain.ExportFormatJSON
	case "csv":
		format = domain.ExportFormatCSV
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, csv)", importFormat)
	}

	// Check if file exists
	if _, err := os.Stat(importFile); os.IsNotExist(err) {
		return fmt.Errorf("import file does not exist: %s", importFile)
	}

	// Read import file
	data, err := os.ReadFile(importFile)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	// Get user ID - for now, generate a sample UUID
	// In a real implementation, this would come from authentication context
	var userID uuid.UUID
	if importUsername != "" {
		// In production, you'd look up the user by username
		userID = uuid.New() // placeholder
	} else {
		userID = uuid.New() // placeholder - would be current authenticated user
	}

	// Prepare import options
	options := domain.ImportOptions{
		Format:            format,
		OverwriteExisting: importOverwrite,
		Encrypted:         importEncrypted,
		UserID:            userID,
		ImportedBy:        importUsername,
	}

	// Create context
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.DBKey, sqlDB)
	ctx = context.WithValue(ctx, common.LogKey, logger)

	// Import secrets
	fmt.Printf("🔄 Importing secrets from %s...\n", importFile)

	importedCount, err := secretsRepo.ImportSecrets(ctx, data, options)
	if err != nil {
		return fmt.Errorf("failed to import secrets: %w", err)
	}

	// Success message
	status := "encrypted"
	if !importEncrypted {
		status = "unencrypted"
	}

	overwriteMsg := "preserving existing"
	if importOverwrite {
		overwriteMsg = "overwriting existing"
	}

	fmt.Printf("✅ Secrets imported successfully!\n")
	fmt.Printf("📄 Format: %s\n", format)
	fmt.Printf("📁 File: %s\n", importFile)
	fmt.Printf("🔒 Status: %s\n", status)
	fmt.Printf("📊 Imported: %d secrets\n", importedCount)
	fmt.Printf("🔄 Mode: %s\n", overwriteMsg)

	if importedCount == 0 {
		fmt.Println("⚠️  No secrets were imported. Check if file contains valid data or if secrets already exist.")
	}

	return nil
}
