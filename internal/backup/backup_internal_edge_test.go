// Internal edge tests for backup.go unexported methods.
package backup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

func TestReadBackupFileEncrypted(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "enc.backup")

	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
	require.NoError(t, mgr.CreateBackup(backupPath, true))

	// Restoring an encrypted backup with encrypted=true must succeed.
	require.NoError(t, mgr.RestoreBackup(backupPath, true))
}

func TestRestoreBackupBadFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
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

	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
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

	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
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

	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
	err := mgr.RestoreBackup(backupPath, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "table count mismatch")
}

func TestListBackupsWithEncryptedFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())

	// One plain backup and one encrypted backup -- both must appear.
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "good.backup"), false))
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "enc.backup"), true))

	backups, err := mgr.ListBackups(tmpDir)
	require.NoError(t, err)
	require.Len(t, backups, 2)

	byFile := make(map[string]BackupMetadata, len(backups))
	for _, b := range backups {
		byFile[b.Filename] = b
	}

	good, ok := byFile["good.backup"]
	require.True(t, ok)
	require.True(t, good.Readable)
	require.False(t, good.Encrypted)
	require.NotZero(t, good.TableCount)

	enc, ok := byFile["enc.backup"]
	require.True(t, ok)
	require.False(t, enc.Readable)
	require.True(t, enc.Encrypted)
	require.Zero(t, enc.TableCount)
	require.Zero(t, enc.RecordCount)
	require.True(t, enc.Timestamp.IsZero())
	require.Positive(t, enc.Size)
}

// TestListBackupsAllEncrypted is the B40 headline case: a directory holding
// only encrypted backups must list them, not report an empty directory.
func TestListBackupsAllEncrypted(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())

	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "enc1.backup"), true))
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "enc2.backup"), true))

	backups, err := mgr.ListBackups(tmpDir)
	require.NoError(t, err)
	require.NotEmpty(t, backups)
	require.Len(t, backups, 2)
	for _, b := range backups {
		require.False(t, b.Readable)
		require.True(t, b.Encrypted)
		require.NotEmpty(t, b.Filename)
		require.Positive(t, b.Size)
	}
}

func TestGetBackupMetadataEncryptedFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "enc.backup")
	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
	require.NoError(t, mgr.CreateBackup(encPath, true))

	meta, err := mgr.getBackupMetadata(encPath)
	require.NoError(t, err)
	require.False(t, meta.Readable)
	require.True(t, meta.Encrypted)
	require.Equal(t, "enc.backup", meta.Filename)
	require.Positive(t, meta.Size)
	require.Zero(t, meta.TableCount)
	require.Zero(t, meta.RecordCount)
	require.True(t, meta.Timestamp.IsZero())
}

// TestGetBackupMetadataCorruptFile covers a file that is neither plaintext
// backup JSON nor a normal encrypted backup -- e.g. truncated or hand-edited.
// The content-based detection in getBackupMetadata cannot distinguish this
// from "encrypted" (both fail the plaintext-JSON-parse test), so it gets the
// same treatment: list it, don't error.
func TestGetBackupMetadataCorruptFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	corruptPath := filepath.Join(tmpDir, "corrupt.backup")
	// Starts with '{' but is not valid backup JSON.
	require.NoError(t, os.WriteFile(corruptPath, []byte("{not valid json"), 0600))

	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
	meta, err := mgr.getBackupMetadata(corruptPath)
	require.NoError(t, err)
	require.False(t, meta.Readable)
	require.Equal(t, "corrupt.backup", meta.Filename)
}
