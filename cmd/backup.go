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

package cmd

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/backup"
	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// requireBackupAdmin returns the caller's claims if they're logged in as
// admin. Backup operates on the whole database across every vault -- there's
// no vault to scope this to, so the global admin role is the only applicable
// gate (same category as users/vaults/migrate commands).
func requireBackupAdmin(cmd *cobra.Command) (*model.Claims, error) {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("unauthorized: missing authentication claims")
	}
	if claims.Role != model.RoleAdmin {
		return nil, fmt.Errorf("forbidden: requires admin role")
	}
	return claims, nil
}

// backupDialect resolves the SQL dialect from configuration for backup
// introspection queries. Defaults to SQLite.
func backupDialect() db.Dialect {
	return db.DialectFromDriver(viper.GetString("database.driver"))
}

var (
	backupOutput         string
	backupEncrypt        bool
	backupListDir        string
	backupRestoreFile    string
	backupRestoreDecrypt bool
)

// backupCmd represents the backup command group
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Manage database backups",
	Long: `Create, list, and restore encrypted database backups.
Supports full database backup and restore operations with optional encryption.`,
	Example: `  # Create an encrypted backup (default)
  rocketvault backup create --output ./backups/backup-2024.backup

  # Create an unencrypted backup
  rocketvault backup create --output ./backups/backup-2024.backup --encrypt=false

  # List available backups
  rocketvault backup list --dir ./backups

  # Restore from an encrypted backup (default)
  rocketvault backup restore --file ./backups/backup-2024.backup

  # Restore from an unencrypted backup
  rocketvault backup restore --file ./backups/backup-2024.backup --decrypt=false`,
}

func init() {
	rootCmd.AddCommand(backupCmd)

	// Add subcommands
	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupListCmd)
	backupCmd.AddCommand(backupRestoreCmd)
}

// backupCreateCmd represents the backup create command
var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a database backup",
	Long: `Create a complete backup of the database including all tables and data.
The backup is encrypted by default using the master key for security.`,
	Example: `  # Create an encrypted backup (default)
  rocketvault backup create --output ./backup-2024.backup

  # Create an unencrypted backup
  rocketvault backup create --output ./backup-2024.backup --encrypt=false`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBackupCreate(cmd)
	},
}

// backupListCmd represents the backup list command
var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available backup files",
	Long:  `List all backup files in the specified directory with their metadata.`,
	Example: `  # List available backups in a directory
  rocketvault backup list --dir ./backups`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBackupList(cmd)
	},
}

// backupRestoreCmd represents the backup restore command
var backupRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore database from backup",
	Long:  `Restore the database from a backup file. This will replace all existing data.`,
	Example: `  # Restore from an encrypted backup (default)
  rocketvault backup restore --file ./backup-2024.backup

  # Restore from an unencrypted backup
  rocketvault backup restore --file ./backup-2024.backup --decrypt=false`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBackupRestore(cmd)
	},
}

func init() {
	// Create command flags
	backupCreateCmd.Flags().StringVarP(&backupOutput, "output", "o", "", "Output file path for backup (required)")
	backupCreateCmd.Flags().BoolVar(&backupEncrypt, "encrypt", true, "Encrypt the backup file (use --encrypt=false to disable)")
	backupCreateCmd.MarkFlagRequired("output") //nolint:errcheck,gosec

	// List command flags
	backupListCmd.Flags().StringVarP(&backupListDir, "dir", "d", "./backups", "Directory to scan for backup files")

	// Restore command flags
	backupRestoreCmd.Flags().StringVarP(&backupRestoreFile, "file", "f", "", "Backup file to restore from (required)")
	backupRestoreCmd.Flags().BoolVar(&backupRestoreDecrypt, "decrypt", true, "Decrypt the backup file (use --decrypt=false to disable)")
	backupRestoreCmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}

func runBackupCreate(cmd *cobra.Command) error {
	if _, err := requireBackupAdmin(cmd); err != nil {
		return err
	}

	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Generate default filename if not provided with full path
	if backupOutput == "" {
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		backupOutput = fmt.Sprintf("./backup-%s.backup", timestamp)
	}

	// Ensure the directory exists
	dir := filepath.Dir(backupOutput)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup manager
	manager := backup.NewManager(db, backupDialect(), logger)

	// Create backup
	if err := manager.CreateBackup(backupOutput, backupEncrypt); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	fmt.Printf("✅ Backup created successfully!\n")
	fmt.Printf("📁 File: %s\n", backupOutput)
	fmt.Printf("🔒 Encrypted: %t\n", backupEncrypt)

	return nil
}

func runBackupList(cmd *cobra.Command) error {
	if _, err := requireBackupAdmin(cmd); err != nil {
		return err
	}

	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Create backup manager
	manager := backup.NewManager(db, backupDialect(), logger)

	// List backups
	backups, err := manager.ListBackups(backupListDir)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	if len(backups) == 0 {
		fmt.Printf("No backup files found in %s\n", backupListDir)
		return nil
	}

	// Display results in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tVERSION\tTABLES\tRECORDS\tENCRYPTED\tFILE") //nolint:errcheck
	fmt.Fprintln(w, "---------\t-------\t------\t-------\t---------\t----") //nolint:errcheck

	for _, b := range backups {
		filename := filepath.Base(fmt.Sprintf("backup-%s.backup", b.Timestamp.Format("2006-01-02_15-04-05")))
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%t\t%s\n", //nolint:errcheck
			b.Timestamp.Format("2006-01-02 15:04:05"),
			b.Version,
			b.TableCount,
			b.RecordCount,
			b.Encrypted,
			filename)
	}

	w.Flush() //nolint:errcheck,gosec
	fmt.Printf("\n📊 Found %d backup files in %s\n", len(backups), backupListDir)

	return nil
}

func runBackupRestore(cmd *cobra.Command) error {
	if _, err := requireBackupAdmin(cmd); err != nil {
		return err
	}

	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Confirm destructive operation
	fmt.Printf("⚠️  WARNING: This will replace all existing data in the database!\n")
	fmt.Printf("📁 Backup file: %s\n", backupRestoreFile)
	fmt.Printf("🔓 Decrypt: %t\n", backupRestoreDecrypt)
	fmt.Print("Are you sure you want to continue? (type 'yes' to confirm): ")

	var confirmation string
	fmt.Scanln(&confirmation)
	if confirmation != "yes" {
		fmt.Println("❌ Restore cancelled")
		return nil
	}

	// Check if backup file exists
	if _, err := os.Stat(backupRestoreFile); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupRestoreFile)
	}

	// Create backup manager
	manager := backup.NewManager(db, backupDialect(), logger)

	// Perform restore
	if err := manager.RestoreBackup(backupRestoreFile, backupRestoreDecrypt); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}

	fmt.Printf("✅ Database restored successfully from %s\n", backupRestoreFile)

	return nil
}
