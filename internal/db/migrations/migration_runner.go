// Package migrations provides database migration functionality for the password manager.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

//go:embed *.sql
var migrationFiles embed.FS

// Migration represents a database migration.
type Migration struct {
	Version   string
	Name      string
	UpSQL     string
	DownSQL   string
	Timestamp time.Time
}

// MigrationRunner manages database migrations.
type MigrationRunner struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewMigrationRunner creates a new migration runner.
func NewMigrationRunner(db *sql.DB, logger *logrus.Logger) *MigrationRunner {
	return &MigrationRunner{
		db:     db,
		logger: logger,
	}
}

// Initialize creates the migrations tracking table if it doesn't exist.
func (r *MigrationRunner) Initialize(ctx context.Context) error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := r.db.ExecContext(ctx, createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

// GetAppliedMigrations returns a list of already applied migrations.
func (r *MigrationRunner) GetAppliedMigrations(ctx context.Context) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %w", err)
		}
		applied[version] = true
	}

	return applied, nil
}

// LoadMigrations loads all available migration files from the embedded filesystem.
func (r *MigrationRunner) LoadMigrations() ([]Migration, error) {
	files, err := migrationFiles.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read migration files: %w", err)
	}

	var migrations []Migration
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		content, err := migrationFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", name, err)
		}

		// Parse filename to extract version and direction
		base := strings.TrimSuffix(name, ".sql")
		parts := strings.Split(base, "_")
		if len(parts) < 2 {
			continue // Skip files that don't match expected format
		}

		version := parts[0]
		migrationName := strings.Join(parts[1:], "_")

		migration := Migration{
			Version: version,
			Name:    migrationName,
			UpSQL:   string(content),
		}

		// Try to parse timestamp from version
		if ts, err := time.Parse("20060102150405", version); err == nil {
			migration.Timestamp = ts
		}

		migrations = append(migrations, migration)
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// ApplyMigration applies a single migration.
func (r *MigrationRunner) ApplyMigration(ctx context.Context, migration Migration) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute the migration SQL
	if _, err := tx.ExecContext(ctx, migration.UpSQL); err != nil {
		return fmt.Errorf("failed to execute migration %s: %w", migration.Version, err)
	}

	// Record the migration as applied
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (version) VALUES (?)",
		migration.Version); err != nil {
		return fmt.Errorf("failed to record migration %s: %w", migration.Version, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration %s: %w", migration.Version, err)
	}

	r.logger.WithFields(logrus.Fields{
		"version": migration.Version,
		"name":    migration.Name,
	}).Info("Migration applied successfully")

	return nil
}

// MigrateUp applies all pending migrations.
func (r *MigrationRunner) MigrateUp(ctx context.Context) error {
	if err := r.Initialize(ctx); err != nil {
		return err
	}

	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	migrations, err := r.LoadMigrations()
	if err != nil {
		return err
	}

	appliedCount := 0
	for _, migration := range migrations {
		if applied[migration.Version] {
			continue // Skip already applied migrations
		}

		r.logger.WithFields(logrus.Fields{
			"version": migration.Version,
			"name":    migration.Name,
		}).Info("Applying migration")

		if err := r.ApplyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}

		appliedCount++
	}

	if appliedCount == 0 {
		r.logger.Info("No pending migrations found")
	} else {
		r.logger.WithField("count", appliedCount).Info("All pending migrations applied")
	}

	return nil
}

// MigrateToVersion applies migrations up to a specific version.
func (r *MigrationRunner) MigrateToVersion(ctx context.Context, targetVersion string) error {
	if err := r.Initialize(ctx); err != nil {
		return err
	}

	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	migrations, err := r.LoadMigrations()
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if migration.Version > targetVersion {
			break // Stop at target version
		}

		if applied[migration.Version] {
			continue // Skip already applied migrations
		}

		r.logger.WithFields(logrus.Fields{
			"version": migration.Version,
			"name":    migration.Name,
		}).Info("Applying migration")

		if err := r.ApplyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}
	}

	r.logger.WithField("target_version", targetVersion).Info("Migrated to target version")
	return nil
}

// GetCurrentVersion returns the current database schema version.
func (r *MigrationRunner) GetCurrentVersion(ctx context.Context) (string, error) {
	if err := r.Initialize(ctx); err != nil {
		return "", err
	}

	var version string
	err := r.db.QueryRowContext(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		return "", fmt.Errorf("failed to get current version: %w", err)
	}

	if version == "" {
		return "0", nil // No migrations applied yet
	}

	return version, nil
}

// Example usage:
//
// // In your application initialization:
// runner := NewMigrationRunner(db, logger)
// if err := runner.MigrateUp(context.Background()); err != nil {
//     logrus.WithError(err).Fatal("Failed to run migrations")
// }
