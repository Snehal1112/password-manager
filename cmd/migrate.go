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
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/internal/db"
	"rocketvault/internal/db/migrations"
	"rocketvault/internal/logging"
)

// migrateCmd represents the migrate command
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Long: `Run database migrations to update the database schema.
This command applies all pending migrations in order.

Examples:
  # Run all pending migrations
  rocketvault migrate

  # Check migration status
  rocketvault migrate:status

  # Migrate to specific version
  rocketvault migrate:to <version>`,
	RunE: runMigrations,
}

// migrateStatusCmd represents the migrate:status command
var migrateStatusCmd = &cobra.Command{
	Use:   "migrate:status",
	Short: "Show migration status",
	Long:  `Display the current database schema version and list all migrations with their status.`,
	Example: `  # Show pending and applied migrations
  rocketvault migrate:status`,
	RunE: showMigrationStatus,
}

// migrateToCmd represents the migrate:to command
var migrateToCmd = &cobra.Command{
	Use:   "migrate:to [version]",
	Short: "Migrate to a specific version",
	Long:  `Apply migrations up to and including the specified version.`,
	Example: `  # Migrate the database to a specific version
  rocketvault migrate:to <version>`,
	Args: cobra.ExactArgs(1),
	RunE: migrateToVersion,
}

// migrateCreateCmd represents the migrate:create command.
var migrateCreateCmd = &cobra.Command{
	Use:   "migrate:create [description]",
	Short: "Create a new migration file",
	Long: `Create a new timestamped migration file in internal/db/migrations/.

The description words are joined with underscores to form the filename.`,
	Example: `  # Create a new migration file
  rocketvault migrate:create "add purge_protection column"`,
	Args: cobra.MinimumNArgs(1),
	RunE: createMigration,
}

func init() {
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(migrateStatusCmd)
	rootCmd.AddCommand(migrateToCmd)
	rootCmd.AddCommand(migrateCreateCmd)
}

// runMigrations applies all pending migrations
func runMigrations(cmd *cobra.Command, args []string) error {
	// Initialize logger
	log := logging.InitLogger()

	log.Info("Starting database migration")

	// Initialize database repository
	repository := db.NewRepository(log)

	// Open database connection without running InitializeDB (which creates schema)
	// We'll use the database connection directly
	dbConfig, err := repository.LoadDatabaseConfig()
	if err != nil {
		log.WithError(err).Error("Failed to load database configuration")
		return fmt.Errorf("failed to load database config: %w", err)
	}

	database, err := repository.OpenDatabase(dbConfig)
	if err != nil {
		log.WithError(err).Error("Failed to open database connection")
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	// Verify database connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := database.PingContext(ctx); err != nil {
		log.WithError(err).Error("Failed to ping database")
		return fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info("Database connection established")

	// Create migration runner
	runner := migrations.NewMigrationRunner(database, log.Logger)

	// Run migrations
	if err := runner.MigrateUp(ctx); err != nil {
		log.WithError(err).Error("Migration failed")
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Info("All migrations completed successfully")
	return nil
}

// showMigrationStatus displays the current migration status
func showMigrationStatus(cmd *cobra.Command, args []string) error {
	// Initialize logger
	log := logging.InitLogger()

	// Initialize database repository
	repository := db.NewRepository(log)

	// Open database connection
	dbConfig, err := repository.LoadDatabaseConfig()
	if err != nil {
		return fmt.Errorf("failed to load database config: %w", err)
	}

	database, err := repository.OpenDatabase(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create migration runner
	runner := migrations.NewMigrationRunner(database, log.Logger)

	// Get current version
	currentVersion, err := runner.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	fmt.Printf("\n📊 Migration Status\n")
	fmt.Printf("═══════════════════\n\n")
	fmt.Printf("Current Schema Version: %s\n\n", currentVersion)

	// Get applied migrations
	applied, err := runner.GetAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Get available migrations
	available, err := runner.LoadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if len(available) == 0 {
		fmt.Println("No migration files found")
		return nil
	}

	fmt.Println("Migrations:")
	fmt.Println("───────────")

	appliedCount := 0
	pendingCount := 0

	for _, migration := range available {
		status := "[ ]"
		statusText := "Pending"
		if applied[migration.Version] {
			status = "[✓]"
			statusText = "Applied"
			appliedCount++
		} else {
			pendingCount++
		}

		fmt.Printf("%s %s - %s (%s)\n", status, migration.Version, migration.Name, statusText)
	}

	fmt.Printf("\n📈 Summary\n")
	fmt.Printf("──────────\n")
	fmt.Printf("Total migrations: %d\n", len(available))
	fmt.Printf("Applied: %d\n", appliedCount)
	fmt.Printf("Pending: %d\n", pendingCount)

	if pendingCount > 0 {
		fmt.Printf("\n💡 Run 'rocketvault migrate' to apply pending migrations\n")
	} else {
		fmt.Printf("\n✅ All migrations are up to date\n")
	}

	return nil
}

// migrateToVersion migrates to a specific version
func migrateToVersion(cmd *cobra.Command, args []string) error {
	targetVersion := args[0]

	// Initialize logger
	log := logging.InitLogger()

	log.WithField("target_version", targetVersion).Info("Starting targeted migration")

	// Initialize database repository
	repository := db.NewRepository(log)

	// Open database connection
	dbConfig, err := repository.LoadDatabaseConfig()
	if err != nil {
		return fmt.Errorf("failed to load database config: %w", err)
	}

	database, err := repository.OpenDatabase(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create migration runner
	runner := migrations.NewMigrationRunner(database, log.Logger)

	// Run migrations to target version
	if err := runner.MigrateToVersion(ctx, targetVersion); err != nil {
		log.WithError(err).Error("Migration to target version failed")
		return fmt.Errorf("migration failed: %w", err)
	}

	log.WithField("target_version", targetVersion).Info("Migration to target version completed successfully")
	return nil
}

// createMigration creates a new migration file in internal/db/migrations/.
func createMigration(cmd *cobra.Command, args []string) error {
	const migrationsDir = "internal/db/migrations"

	today := time.Now().Format("20060102")
	slug := strings.Join(args, "_")

	version, err := nextMigrationVersion(migrationsDir, today)
	if err != nil {
		return fmt.Errorf("failed to determine next version: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.sql", version, slug)
	path := fmt.Sprintf("%s/%s", migrationsDir, filename)

	content := migrationFileContent(version, slug)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write migration file: %w", err)
	}

	fmt.Printf("Created: %s\n", path)
	return nil
}

// migrationFileContent renders the template for a new migration file.
// slug is the underscore-separated description (e.g. "add_priority_to_secrets").
func migrationFileContent(version, slug string) string {
	title := strings.ReplaceAll(slug, "_", " ")
	// Title-case: capitalise first letter only (keep rest as-is).
	if len(title) > 0 {
		title = strings.ToUpper(title[:1]) + title[1:]
	}
	return fmt.Sprintf(`-- Migration: %s
-- Description: TODO
-- Version: %s

-- TODO: Add your SQL here
-- Example: ALTER TABLE secrets ADD COLUMN my_col TEXT DEFAULT '';
`, title, version)
}

// nextMigrationVersion returns the next version string for a new migration.
// It scans dir for .sql files whose names start with today, finds the highest
// 6-digit sequence suffix, and returns today + (max+1) zero-padded to 6 digits.
func nextMigrationVersion(dir string, today string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("failed to read migrations directory: %w", err)
	}

	max := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		if !strings.HasPrefix(name, today) {
			continue
		}
		// Filename format: YYYYMMDDNNNNNN_description.sql
		// Sequence occupies characters [8:14].
		if len(name) < 14 {
			continue
		}
		seq, err := strconv.Atoi(name[8:14])
		if err != nil {
			continue
		}
		if seq > max {
			max = seq
		}
	}

	return fmt.Sprintf("%s%06d", today, max+1), nil
}
