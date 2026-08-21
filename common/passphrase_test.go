package common

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePassphraseFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw.txt")
	require.NoError(t, os.WriteFile(path, []byte("  s3cret  \nignored second line\n"), 0o600))

	got, err := ResolvePassphrase(PassphraseSource{File: path})
	require.NoError(t, err)
	assert.Equal(t, "s3cret", got, "first line should be used and trimmed")
}

func TestResolvePassphraseFromFileMissing(t *testing.T) {
	_, err := ResolvePassphrase(PassphraseSource{File: filepath.Join(t.TempDir(), "absent")})
	require.Error(t, err)
}

func TestResolvePassphraseRejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	require.NoError(t, os.WriteFile(path, []byte("\n"), 0o600))

	_, err := ResolvePassphrase(PassphraseSource{File: path})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestResolvePassphraseFromEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_TEST_PASSPHRASE", "from-env")

	got, err := ResolvePassphrase(PassphraseSource{EnvVar: "ROCKETVAULT_TEST_PASSPHRASE"})
	require.NoError(t, err)
	assert.Equal(t, "from-env", got)
}

func TestResolvePassphraseFilePrecedesEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_TEST_PASSPHRASE", "from-env")
	dir := t.TempDir()
	path := filepath.Join(dir, "pw.txt")
	require.NoError(t, os.WriteFile(path, []byte("from-file"), 0o600))

	got, err := ResolvePassphrase(PassphraseSource{File: path, EnvVar: "ROCKETVAULT_TEST_PASSPHRASE"})
	require.NoError(t, err)
	assert.Equal(t, "from-file", got)
}

func TestResolvePassphraseNoSourceNonInteractive(t *testing.T) {
	// go test runs with stdin detached, so this exercises the non-TTY branch.
	_, err := ResolvePassphrase(PassphraseSource{EnvVar: "ROCKETVAULT_DEFINITELY_UNSET"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoPassphraseAvailable), "got %v", err)
}
