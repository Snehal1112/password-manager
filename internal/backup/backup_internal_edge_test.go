// Internal edge tests for backup.go unexported methods.
package backup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestReadBackupFileEncrypted(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "enc.backup")

	mgr := NewManager(db, logging.InitLogger())
	require.NoError(t, mgr.CreateBackup(backupPath, true))

	// Restoring an encrypted backup with encrypted=true must succeed.
	require.NoError(t, mgr.RestoreBackup(backupPath, true))
}

func TestRestoreBackupBadFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mgr := NewManager(db, logging.InitLogger())
	err := mgr.RestoreBackup("/nonexistent/path/backup.bak", false)
	require.Error(t, err)
}

func TestRestoreBackupInvalidJSON(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "bad.backup")
	require.NoError(t, os.WriteFile(badPath, []byte("{not json}"), 0600))

	mgr := NewManager(db, logging.InitLogger())
	err := mgr.RestoreBackup(badPath, false)
	require.Error(t, err)
}

func TestValidateBackupDataMissingVersion(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "nover.backup")
	content := `{"metadata":{"version":"","table_count":0},"tables":[]}`
	require.NoError(t, os.WriteFile(backupPath, []byte(content), 0600))

	mgr := NewManager(db, logging.InitLogger())
	err := mgr.RestoreBackup(backupPath, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing backup version")
}

func TestValidateBackupDataTableCountMismatch(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "mismatch.backup")
	content := `{"metadata":{"version":"1.0","table_count":3},"tables":[]}`
	require.NoError(t, os.WriteFile(backupPath, []byte(content), 0600))

	mgr := NewManager(db, logging.InitLogger())
	err := mgr.RestoreBackup(backupPath, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "table count mismatch")
}

func TestListBackupsWithEncryptedFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	mgr := NewManager(db, logging.InitLogger())

	// One plain backup that can be read, one encrypted that will be skipped.
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "good.backup"), false))
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "enc.backup"), true))

	backups, err := mgr.ListBackups(tmpDir)
	require.NoError(t, err)
	require.Len(t, backups, 1)
}

func TestGetBackupMetadataEncryptedFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "enc.backup")
	mgr := NewManager(db, logging.InitLogger())
	require.NoError(t, mgr.CreateBackup(encPath, true))

	_, err := mgr.getBackupMetadata(encPath)
	require.Error(t, err)
}
