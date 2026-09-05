package signing

import (
	"os"
	"testing"
)

// TestMain ensures every test in this package's test binary (both the
// white-box `signing` tests and the black-box `signing_test` package) uses
// an in-memory fake OS keychain instead of the real one, so `go test` never
// reads or writes real GNOME Keyring / macOS Keychain / Windows Credential
// Manager entries -- including "jwt-signing-key-rocketvault", the same slot
// name production uses by default. It also points $HOME at a throwaway
// directory so OSStoreProvider's PEM fallback file (used when even the fake
// keychain's Set fails) never reads or writes the real
// ~/.local/share/rocketvault/jwt-signing.pem.
func TestMain(m *testing.M) {
	restore := UseFakeKeychainForTesting()

	origHome, hadHome := os.LookupEnv("HOME")
	os.Setenv("HOME", mustTempDir()) //nolint:errcheck

	code := m.Run()

	if hadHome {
		os.Setenv("HOME", origHome) //nolint:errcheck
	} else {
		os.Unsetenv("HOME") //nolint:errcheck
	}
	restore()
	os.Exit(code)
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "rocketvault-signing-test-home-*")
	if err != nil {
		panic(err)
	}
	return dir
}
