package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextMigrationVersion_EmptyDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000001", version)
}

func TestNextMigrationVersion_ExistingFilesForToday(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Create two existing migration files for today
	touch(t, dir, "20260308000001_first.sql")
	touch(t, dir, "20260308000003_third.sql") // gap in sequence — should still give 000004
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000004", version)
}

func TestNextMigrationVersion_FilesFromOtherDays(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	touch(t, dir, "20260307000005_yesterday.sql") // different day — must be ignored
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000001", version)
}

func TestNextMigrationVersion_NonSQLFilesIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	touch(t, dir, "20260308000001_migration.go") // .go file — must be ignored
	version, err := nextMigrationVersion(dir, "20260308")
	require.NoError(t, err)
	assert.Equal(t, "20260308000001", version)
}

// touch creates an empty file in dir with the given name.
func touch(t *testing.T, dir, name string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	require.NoError(t, err)
	f.Close()
}

func TestMigrationFileContent(t *testing.T) {
	t.Parallel()
	content := migrationFileContent("20260308000001", "add_priority_to_secrets")
	assert.Contains(t, content, "-- Version: 20260308000001")
	assert.Contains(t, content, "-- Migration: Add priority to secrets")
	assert.Contains(t, content, "-- Description: TODO")
	assert.Contains(t, content, "-- TODO: Add your SQL here")
	assert.Contains(t, content, "-- Example: ALTER TABLE")
}

func TestMigrationFileContent_SingleWord(t *testing.T) {
	t.Parallel()
	content := migrationFileContent("20260308000002", "users")
	assert.Contains(t, content, "-- Migration: Users")
	assert.Contains(t, content, "-- Version: 20260308000002")
}
