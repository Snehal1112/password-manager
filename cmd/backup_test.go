package cmd

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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

// TestBackupCreateCmd_FileFlagRegistered is a regression test for B48:
// backupCreateCmd used to register its destination-path flag as "--output",
// which shadowed root's persistent "--output" format selector (table/json/
// yaml) since pflag resolves a local flag over an inherited one of the same
// name. That made "backup create --output <path>" fail: PersistentPreRunE
// read the path back as if it were a format string and rejected it. The fix
// renamed the local flag to "--file"/"-f", matching backupRestoreCmd's
// existing convention for the same concept. This test asserts the flag is
// registered under its new name and that root's "--output" is no longer
// shadowed.
func TestBackupCreateCmd_FileFlagRegistered(t *testing.T) {
	fileFlag := backupCreateCmd.Flags().Lookup("file")
	require.NotNil(t, fileFlag, "backup create must register a --file flag")
	assert.Equal(t, "f", fileFlag.Shorthand, "backup create's --file flag must have shorthand -f")

	_, required := fileFlag.Annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, required, "backup create's --file flag must be marked required")

	// The old "--output" name must not be registered locally on this command
	// any more -- that's the collision this bug was about.
	assert.Nil(t, backupCreateCmd.Flags().Lookup("output"),
		"backup create must not register its own --output flag; it should fall through to root's persistent flag")

	// "--output" must still resolve on this command, but only via
	// inheritance from root's persistent flag (the global table/json/yaml
	// format selector), not a local override.
	outputFlag := backupCreateCmd.InheritedFlags().Lookup("output")
	require.NotNil(t, outputFlag, "--output must be inherited from root's persistent flag")
	assert.Equal(t, "table", outputFlag.DefValue, "inherited --output must be root's format selector, default \"table\"")
}

// TestBackupCreateCmd_FileAndOutputFlagsParseIndependently proves the two
// flags no longer fight over the same name once parsed together: "--file"
// captures the destination path (backupOutput) and "--output" independently
// captures the display format, inherited from root, exactly as
// "backup create --file <path> --output json" needs to behave.
func TestBackupCreateCmd_FileAndOutputFlagsParseIndependently(t *testing.T) {
	// backupOutput and root's persistent "output" flag are package-level
	// state shared across tests (cobra command objects are package
	// globals); save and restore both so this test doesn't leak into
	// others.
	prevBackupOutput := backupOutput
	prevRootOutput := rootCmd.PersistentFlags().Lookup("output").Value.String()
	t.Cleanup(func() {
		backupOutput = prevBackupOutput
		require.NoError(t, rootCmd.PersistentFlags().Set("output", prevRootOutput))
	})

	dest := filepath.Join(t.TempDir(), "b48.backup")

	err := backupCreateCmd.ParseFlags([]string{"--file", dest, "--output", "json"})
	require.NoError(t, err)

	gotFile, err := backupCreateCmd.Flags().GetString("file")
	require.NoError(t, err)
	assert.Equal(t, dest, gotFile, "--file must capture the destination path")

	gotOutput, err := backupCreateCmd.Flags().GetString("output")
	require.NoError(t, err)
	assert.Equal(t, "json", gotOutput, "--output must independently capture the format selector")

	// The bound Go variable behind --file holds the path, not "json" --
	// confirming --file's StringVarP wiring is untouched by --output being
	// present in the same invocation.
	assert.Equal(t, dest, backupOutput)
}
