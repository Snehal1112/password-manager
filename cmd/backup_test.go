package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
)

func TestBackupListRowReadable(t *testing.T) {
	ts := time.Date(2026, 8, 20, 10, 30, 0, 0, time.UTC)
	mod := time.Date(2026, 8, 20, 10, 30, 5, 0, time.UTC)
	b := backup.BackupMetadata{
		Filename:    "good.backup",
		Size:        1024,
		ModTime:     mod,
		Readable:    true,
		Version:     "1.0",
		Timestamp:   ts,
		TableCount:  5,
		RecordCount: 42,
		Encrypted:   false,
	}

	row := backupListRow(b)

	require.Equal(t, "2026-08-20 10:30:00", row[0]) // timestamp
	require.Equal(t, "1.0", row[1])                 // version
	require.Equal(t, "5", row[2])                   // tables
	require.Equal(t, "42", row[3])                  // records
	require.Equal(t, "false", row[4])               // encrypted
	require.Equal(t, "good.backup", row[5])         // file
	require.Equal(t, "1024", row[6])                // size
	require.Equal(t, "2026-08-20 10:30:05", row[7]) // modified
}

func TestBackupListRowUnreadable(t *testing.T) {
	mod := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	b := backup.BackupMetadata{
		Filename:  "enc.backup",
		Size:      2048,
		ModTime:   mod,
		Readable:  false,
		Encrypted: true,
	}

	row := backupListRow(b)

	require.Equal(t, "-", row[0]) // timestamp unknown -- listing never decrypts
	require.Equal(t, "-", row[1]) // version unknown
	require.Equal(t, "-", row[2]) // tables unknown
	require.Equal(t, "-", row[3]) // records unknown
	require.Equal(t, "true", row[4])
	require.Equal(t, "enc.backup", row[5]) // actual filename, not synthesized from a timestamp
	require.Equal(t, "2048", row[6])
	require.Equal(t, "2026-08-21 09:00:00", row[7])
}
