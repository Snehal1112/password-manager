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
	if !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
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
	Long: `Create, list, and restore whole-database backups. A backup is a single JSON
file holding every table in the database — every vault's secrets, keys and
certificates, plus users, role assignments and audit rows — and is encrypted
with the instance's master key by default.

Every subcommand requires the global admin role. There is no vault-scoped
form of backup: it always covers the whole instance, so --vault does not
apply and an operator with a role in only one vault cannot use these
commands.

An encrypted backup is sealed with the master key in force when it was
written, and "master-key rotate" does not re-encrypt existing backup files.
Keep the old key if you may ever need to restore a backup taken before a
rotation.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Create an encrypted backup
  rocketvault backup create --file ./backups/<name>.backup

  # List the backups in a directory
  rocketvault backup list --dir ./backups

  # Replace the database from a backup
  rocketvault backup restore --file ./backups/<name>.backup`,
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
	Long: `Write every table in the database to one JSON file: all vaults' secrets, keys
and certificates, including soft-deleted rows, together with users, sessions,
role assignments and the audit log. Rows are copied verbatim, so values that
are sealed in the database stay sealed inside the file.

Requires the global admin role. The backup spans every vault, so --vault does
not apply.

--file is required; its directory is created if missing and the file is
written readable only by its owner. The default --encrypt=true seals the
whole file with the master key, which means it can only be restored on an
instance holding that same key. --encrypt=false writes plain JSON instead:
secret values and private keys inside it remain master-key sealed, but names,
tags, users, password hashes and role assignments become readable by anyone
who can read the file. Both encrypted and unencrypted backups appear in
"backup list"; only an unencrypted one shows its table and record counts
there, since listing never decrypts the payload.`,
	Example: `  # Create an encrypted backup (the default)
  rocketvault backup create --file ./backups/<name>.backup

  # Create an unencrypted backup, readable in full by "backup list"
  rocketvault backup create --file ./backups/<name>.backup \
    --encrypt=false`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBackupCreate(cmd)
	},
}

// backupListCmd represents the backup list command
var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available backup files",
	Long: `Scan a directory for files matching "*.backup" and print one row per file:
when it was taken, its format version, how many tables and records it holds,
whether it is encrypted, its filename, size and modification time. The scan
is not recursive.

Requires the global admin role.

Listing never requires the master key and never decrypts a backup. Metadata
is read by attempting a plaintext JSON parse; a backup written with the
default encryption fails that parse, so its TIMESTAMP, VERSION, TABLES and
RECORDS columns print "-" instead of real values. FILE, SIZE and MODIFIED
always come from the filesystem, so an encrypted backup — or even a corrupt
one — still appears as a row, identified by its actual filename, instead of
being silently skipped. A directory holding only encrypted backups is never
reported as empty.`,
	Example: `  # List the backups in the default ./backups directory
  rocketvault backup list

  # List the backups in another directory
  rocketvault backup list --dir /var/backups/rocketvault`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBackupList(cmd)
	},
}

// backupRestoreCmd represents the backup restore command
var backupRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore database from backup",
	Long: `Replace the database contents with a backup file. Every table present in the
backup is emptied and refilled from the file in foreign-key order, inside a
single transaction, so the restore either lands completely or leaves the
database as it was. Tables the backup does not contain are left alone.

Requires the global admin role. The restore covers every vault in the file,
so --vault does not apply.

This is destructive and has no undo: current secrets, keys, certificates,
users and audit rows are discarded in favour of the file's. The command
prints the target file and waits for you to type "yes"; anything else
cancels, and there is no flag to skip the prompt. --decrypt must match how
the backup was written — the default expects a master-key-encrypted file and
fails unless this instance holds the key that sealed it. Stop the RocketVault
server first: a running server keeps serving cached secrets that the restore
does not invalidate.`,
	Example: `  # Restore from an encrypted backup (the default)
  rocketvault backup restore --file ./backups/<name>.backup

  # Restore from a backup written with --encrypt=false
  rocketvault backup restore --file ./backups/<name>.backup \
    --decrypt=false`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBackupRestore(cmd)
	},
}

func init() {
	// Create command flags
	backupCreateCmd.Flags().StringVarP(&backupOutput, "file", "f", "", "Backup file path to write (required)")
	backupCreateCmd.Flags().BoolVar(&backupEncrypt, "encrypt", true, "Encrypt the backup file (use --encrypt=false to disable)")
	backupCreateCmd.MarkFlagRequired("file") //nolint:errcheck,gosec

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

	fmt.Printf("Backup created successfully.\n")
	fmt.Printf("File: %s\n", backupOutput)
	fmt.Printf("Encrypted: %t\n", backupEncrypt)

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
	fmt.Fprintln(w, "TIMESTAMP\tVERSION\tTABLES\tRECORDS\tENCRYPTED\tFILE\tSIZE\tMODIFIED") //nolint:errcheck
	fmt.Fprintln(w, "---------\t-------\t------\t-------\t---------\t----\t----\t--------") //nolint:errcheck

	for _, b := range backups {
		row := backupListRow(b)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck
			row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7])
	}

	w.Flush() //nolint:errcheck,gosec
	fmt.Printf("\nFound %d backup files in %s\n", len(backups), backupListDir)

	return nil
}

// backupListRow renders one "backup list" row as
// [timestamp, version, tables, records, encrypted, file, size, modified].
// Timestamp, version, tables and records come from the backup's payload and
// render as "-" when b.Readable is false -- an encrypted (or corrupt) backup
// never has its payload read during listing, so those columns are honestly
// unknown rather than guessed. File, size and modified always come from the
// filesystem and are populated regardless of readability.
func backupListRow(b backup.BackupMetadata) [8]string {
	timestamp, version, tables, records := "-", "-", "-", "-"
	if b.Readable {
		timestamp = b.Timestamp.Format("2006-01-02 15:04:05")
		version = b.Version
		tables = fmt.Sprintf("%d", b.TableCount)
		records = fmt.Sprintf("%d", b.RecordCount)
	}
	return [8]string{
		timestamp,
		version,
		tables,
		records,
		fmt.Sprintf("%t", b.Encrypted),
		b.Filename,
		fmt.Sprintf("%d", b.Size),
		b.ModTime.Format("2006-01-02 15:04:05"),
	}
}

func runBackupRestore(cmd *cobra.Command) error {
	if _, err := requireBackupAdmin(cmd); err != nil {
		return err
	}

	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Confirm destructive operation
	fmt.Printf("WARNING: This will replace all existing data in the database.\n")
	fmt.Printf("Backup file: %s\n", backupRestoreFile)
	fmt.Printf("Decrypt: %t\n", backupRestoreDecrypt)
	fmt.Print("Are you sure you want to continue? (type 'yes' to confirm): ")

	var confirmation string
	fmt.Scanln(&confirmation)
	if confirmation != "yes" {
		fmt.Println("Restore cancelled.")
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

	fmt.Printf("Database restored successfully from %s\n", backupRestoreFile)

	return nil
}
