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
// name production uses by default.
func TestMain(m *testing.M) {
	restore := UseFakeKeychainForTesting()
	code := m.Run()
	restore()
	os.Exit(code)
}
