package signing

import (
	"errors"
	"sync"
)

// fakeTestKeychain is a minimal in-memory keychainBackend used only by
// UseFakeKeychainForTesting. It is intentionally distinct from the
// `fakeKeychain` type in os_store_test.go: that type lives in a "_test.go"
// file and is therefore only visible within this package's own test
// binary, not to other packages' tests (e.g. internal/container, which
// calls NewServiceContainer -> signing.NewProvider). This type lives in a
// regular source file so UseFakeKeychainForTesting is part of the normal
// package archive and reachable from any importer's tests.
type fakeTestKeychain struct {
	mu    sync.Mutex
	store map[string]string
}

var errFakeTestKeychainNotFound = errors.New("fakeTestKeychain: not found")

func newFakeTestKeychain() *fakeTestKeychain {
	return &fakeTestKeychain{store: make(map[string]string)}
}

func (f *fakeTestKeychain) Get(service, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.store[service+"/"+user]
	if !ok {
		return "", errFakeTestKeychainNotFound
	}
	return v, nil
}

func (f *fakeTestKeychain) Set(service, user, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[service+"/"+user] = secret
	return nil
}

// UseFakeKeychainForTesting swaps the production OS keychain backend (used
// by NewOSStoreProvider and NewProvider with jwt.key_source=os_store) for an
// in-memory fake. It returns a restore func that puts the original backend
// back. Safe to call once for the lifetime of a test binary (e.g. from a
// package's TestMain), so `go test` never reads or writes real GNOME
// Keyring / macOS Keychain / Windows Credential Manager entries -- including
// "jwt-signing-key-rocketvault", the same slot name production uses by
// default. Never called from production code paths.
func UseFakeKeychainForTesting() (restore func()) {
	old := defaultKeychain
	defaultKeychain = newFakeTestKeychain()
	return func() { defaultKeychain = old }
}
