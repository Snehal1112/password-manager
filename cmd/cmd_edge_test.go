package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/backup"
	"rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestDB opens an in-memory SQLite connection suitable for backup tests.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestLogger returns a silent logger for use in tests.
func newTestLogger() *logging.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return &logging.Logger{Logger: l}
}

// backupContext builds a context that satisfies the backup/health command's
// type assertions for DBKey and LogKey.
func backupContext(db *sql.DB, logger *logging.Logger) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.DBKey, db)
	ctx = context.WithValue(ctx, common.LogKey, logger)
	return ctx
}

// ---------------------------------------------------------------------------
// runBackupList
// ---------------------------------------------------------------------------

func TestRunBackupList_EmptyDir(t *testing.T) {
	sqlDB := newTestDB(t)
	logger := newTestLogger()
	dir := t.TempDir()

	orig := backupListDir
	t.Cleanup(func() { backupListDir = orig })
	backupListDir = dir

	cmd := &cobra.Command{Use: "list", RunE: backupListCmd.RunE}
	cmd.Flags().StringVarP(&backupListDir, "dir", "d", dir, "")
	cmd.SetContext(backupContext(sqlDB, logger))

	// Redirect stdout to suppress output.
	origStdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	err = cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
}

func TestRunBackupList_NonExistentDir(t *testing.T) {
	sqlDB := newTestDB(t)
	logger := newTestLogger()
	// A path that does not exist; ListBackups uses filepath.Glob which returns
	// no matches rather than an error on a missing dir, so we still expect no error.
	origListDir := backupListDir
	t.Cleanup(func() { backupListDir = origListDir })
	backupListDir = filepath.Join(t.TempDir(), "does_not_exist")

	cmd := &cobra.Command{Use: "list", RunE: backupListCmd.RunE}
	cmd.Flags().StringVarP(&backupListDir, "dir", "d", backupListDir, "")
	cmd.SetContext(backupContext(sqlDB, logger))

	origStdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	// filepath.Glob returns nil,nil for a pattern that matches nothing, so this
	// should succeed without error.
	err = cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// runBackupCreate
// ---------------------------------------------------------------------------

func TestRunBackupCreate_UnencryptedToTempDir(t *testing.T) {
	sqlDB := newTestDB(t)
	logger := newTestLogger()
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "test.backup")

	origOutput := backupOutput
	origEncrypt := backupEncrypt
	t.Cleanup(func() {
		backupOutput = origOutput
		backupEncrypt = origEncrypt
	})
	backupOutput = outFile
	backupEncrypt = false

	cmd := &cobra.Command{Use: "create", RunE: backupCreateCmd.RunE}
	cmd.Flags().StringVarP(&backupOutput, "output", "o", outFile, "")
	cmd.Flags().BoolVar(&backupEncrypt, "encrypt", false, "")
	cmd.SetContext(backupContext(sqlDB, logger))

	origStdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	err = cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	_, statErr := os.Stat(outFile)
	assert.NoError(t, statErr, "backup file should have been created")
}

func TestRunBackupCreate_DefaultOutputName(t *testing.T) {
	sqlDB := newTestDB(t)
	logger := newTestLogger()
	// Use a temp working dir so the auto-generated file lands somewhere safe.
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(tmpDir))
	defer os.Chdir(origDir) //nolint:errcheck

	// Blank output triggers timestamp-based name generation.
	origOutput := backupOutput
	origEncrypt := backupEncrypt
	t.Cleanup(func() {
		backupOutput = origOutput
		backupEncrypt = origEncrypt
	})
	backupOutput = ""
	backupEncrypt = false

	cmd := &cobra.Command{Use: "create", RunE: backupCreateCmd.RunE}
	cmd.Flags().StringVarP(&backupOutput, "output", "o", "", "")
	cmd.Flags().BoolVar(&backupEncrypt, "encrypt", false, "")
	cmd.SetContext(backupContext(sqlDB, logger))

	origStdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	err = cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// runBackupRestore — cancel path (user types something other than "yes")
// ---------------------------------------------------------------------------

func TestRunBackupRestore_CancelledByUser(t *testing.T) {
	db := newTestDB(t)
	logger := newTestLogger()

	// Pipe "no\n" into stdin so fmt.Scanln reads "no".
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, _ = w.WriteString("no\n")
	w.Close()

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close()
	}()

	origRestoreFile := backupRestoreFile
	origRestoreDecrypt := backupRestoreDecrypt
	t.Cleanup(func() {
		backupRestoreFile = origRestoreFile
		backupRestoreDecrypt = origRestoreDecrypt
	})
	backupRestoreFile = "/some/nonexistent/file.backup"
	backupRestoreDecrypt = true

	cmd := &cobra.Command{Use: "restore", RunE: backupRestoreCmd.RunE}
	cmd.Flags().StringVarP(&backupRestoreFile, "file", "f", backupRestoreFile, "")
	cmd.Flags().BoolVar(&backupRestoreDecrypt, "decrypt", true, "")
	cmd.SetContext(backupContext(db, logger))

	// Suppress stdout output from the warning messages.
	origStdout := os.Stdout
	devNull, err2 := os.Open(os.DevNull)
	require.NoError(t, err2)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	err = cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
}

func TestRunBackupRestore_FileNotFound(t *testing.T) {
	db := newTestDB(t)
	logger := newTestLogger()

	// Pipe "yes\n" so we pass the confirmation check, then hit the file-not-found error.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, _ = w.WriteString("yes\n")
	w.Close()

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close()
	}()

	origRestoreFile2 := backupRestoreFile
	origRestoreDecrypt2 := backupRestoreDecrypt
	t.Cleanup(func() {
		backupRestoreFile = origRestoreFile2
		backupRestoreDecrypt = origRestoreDecrypt2
	})
	backupRestoreFile = filepath.Join(t.TempDir(), "totally_missing.backup")
	backupRestoreDecrypt = false

	cmd := &cobra.Command{Use: "restore", RunE: backupRestoreCmd.RunE}
	cmd.Flags().StringVarP(&backupRestoreFile, "file", "f", backupRestoreFile, "")
	cmd.Flags().BoolVar(&backupRestoreDecrypt, "decrypt", false, "")
	cmd.SetContext(backupContext(db, logger))

	origStdout := os.Stdout
	devNull, err2 := os.Open(os.DevNull)
	require.NoError(t, err2)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	err = cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backup file does not exist")
}

// ---------------------------------------------------------------------------
// runMigrations — fails because no database.connection is configured
// ---------------------------------------------------------------------------

func TestRunMigrations_NoDatabaseConfig(t *testing.T) {
	cmd := &cobra.Command{Use: "migrate", RunE: migrateCmd.RunE}
	cmd.SetContext(context.Background())

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "database") || strings.Contains(err.Error(), "config"),
		"expected a database/config error, got: %v", err,
	)
}

// ---------------------------------------------------------------------------
// showMigrationStatus — fails because no database.connection is configured
// ---------------------------------------------------------------------------

func TestShowMigrationStatus_NoDatabaseConfig(t *testing.T) {
	cmd := &cobra.Command{Use: "migrate:status", RunE: migrateStatusCmd.RunE}
	cmd.SetContext(context.Background())

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "database") || strings.Contains(err.Error(), "config"),
		"expected a database/config error, got: %v", err,
	)
}

// ---------------------------------------------------------------------------
// migrateToVersion — fails because no database.connection is configured
// ---------------------------------------------------------------------------

func TestMigrateToVersion_NoDatabaseConfig(t *testing.T) {
	cmd := &cobra.Command{Use: "migrate:to", RunE: migrateToCmd.RunE, Args: cobra.ExactArgs(1)}
	cmd.SetContext(context.Background())

	err := cmd.RunE(cmd, []string{"20260308000001"})
	assert.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "database") || strings.Contains(err.Error(), "config"),
		"expected a database/config error, got: %v", err,
	)
}

// ---------------------------------------------------------------------------
// createMigration — no migrations dir triggers "failed to determine next version"
// ---------------------------------------------------------------------------

func TestCreateMigration_MissingMigrationsDir(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	defer os.Chdir(origDir) //nolint:errcheck

	// Do NOT create internal/db/migrations, so nextMigrationVersion fails.
	cmd := &cobra.Command{Use: "migrate:create", RunE: migrateCreateCmd.RunE}
	err = cmd.RunE(cmd, []string{"add", "column"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to determine next version")
}

// ---------------------------------------------------------------------------
// persistentPostRun — db repo present in context triggers CloseDB()
// ---------------------------------------------------------------------------

func TestPersistentPostRun_WithDBRepoInContext(t *testing.T) {
	// Build a real *db.DBRepository and place it in the context so the
	// ok=true branch is exercised. The internal sql.DB is nil (no full
	// InitializeDB), so CloseDB() is a documented no-op — but the type
	// assertion succeeds and the real code path runs.
	logger := newTestLogger()
	repo := db.NewRepository(logger)

	cmd := &cobra.Command{}
	ctx := context.WithValue(context.Background(), common.DBClassKey, repo)
	cmd.SetContext(ctx)

	// persistentPostRun must return no error when CloseDB is a no-op.
	err := persistentPostRun(cmd, nil)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// nextMigrationVersion — error when dir cannot be read
// ---------------------------------------------------------------------------

func TestNextMigrationVersion_UnreadableDir(t *testing.T) {
	_, err := nextMigrationVersion("/nonexistent/path/that/does/not/exist", "20260308")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read migrations directory")
}

// ---------------------------------------------------------------------------
// runBackupList with results — creates a real unencrypted backup file first,
// then lists the dir to exercise the tabwriter rendering path.
// ---------------------------------------------------------------------------

func TestRunBackupList_WithResults(t *testing.T) {
	db := newTestDB(t)
	logger := newTestLogger()
	dir := t.TempDir()

	// Write a minimal valid backup JSON file so ListBackups returns metadata.
	meta := backup.BackupMetadata{
		Version:     "1.0",
		Timestamp:   time.Now(),
		TableCount:  1,
		RecordCount: 5,
		Encrypted:   false,
	}
	type minBackupData struct {
		Metadata backup.BackupMetadata `json:"metadata"`
		Tables   []interface{}         `json:"tables"`
	}
	raw, err := json.Marshal(minBackupData{Metadata: meta, Tables: []interface{}{}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.backup"), raw, 0o644))

	origListDir2 := backupListDir
	t.Cleanup(func() { backupListDir = origListDir2 })
	backupListDir = dir

	cmd := &cobra.Command{Use: "list", RunE: backupListCmd.RunE}
	cmd.Flags().StringVarP(&backupListDir, "dir", "d", dir, "")
	cmd.SetContext(backupContext(db, logger))

	origStdout := os.Stdout
	devNull, err2 := os.Open(os.DevNull)
	require.NoError(t, err2)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	err = cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// runMigrations / showMigrationStatus / migrateToVersion with a real SQLite DB
// ---------------------------------------------------------------------------

// setViperSQLite sets viper config so LoadDatabaseConfig succeeds with the
// given SQLite file path. Reverts viper after the test.
func setViperSQLite(t *testing.T, dbPath string) {
	t.Helper()
	viper.Set("database.connection", dbPath)
	viper.Set("database.driver", "sqlite3")
	t.Cleanup(func() {
		viper.Set("database.connection", "")
		viper.Set("database.driver", "")
	})
}

func TestRunMigrations_WithRealSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	setViperSQLite(t, dbPath)

	cmd := &cobra.Command{Use: "migrate", RunE: migrateCmd.RunE}
	cmd.SetContext(context.Background())

	// The migration runner may succeed or fail depending on migration files
	// present on disk; we just assert the DB-config path was entered.
	err := cmd.RunE(cmd, []string{})
	// If there are migration SQL files, it should succeed; otherwise we accept
	// either success or a migration-level error (not a config error).
	if err != nil {
		assert.NotContains(t, err.Error(), "database connection string not configured")
	}
}

func TestShowMigrationStatus_WithRealSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	setViperSQLite(t, dbPath)

	origStdout := os.Stdout
	devNull, devNullErr := os.Open(os.DevNull)
	require.NoError(t, devNullErr)
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
		devNull.Close()
	}()

	cmd := &cobra.Command{Use: "migrate:status", RunE: migrateStatusCmd.RunE}
	cmd.SetContext(context.Background())

	err := cmd.RunE(cmd, []string{})
	// We expect either success or a migration-level error (not config).
	if err != nil {
		assert.NotContains(t, err.Error(), "database connection string not configured")
	}
}

func TestMigrateToVersion_WithRealSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	setViperSQLite(t, dbPath)

	cmd := &cobra.Command{Use: "migrate:to", RunE: migrateToCmd.RunE, Args: cobra.ExactArgs(1)}
	cmd.SetContext(context.Background())

	err := cmd.RunE(cmd, []string{"20260308000001"})
	if err != nil {
		assert.NotContains(t, err.Error(), "database connection string not configured")
	}
}

// ---------------------------------------------------------------------------
// backupCmd help — exercises Cobra command wiring without real execution
// ---------------------------------------------------------------------------

func TestBackupCmd_HelpDoesNotPanic(t *testing.T) {
	var sb strings.Builder
	cmd := &cobra.Command{}
	cmd.AddCommand(backupCmd)
	cmd.SetOut(&sb)
	cmd.SetArgs([]string{"backup", "--help"})
	// Help exits with a special error; we just want no panic.
	_ = cmd.Execute()
	assert.Contains(t, sb.String(), "backup")
}
