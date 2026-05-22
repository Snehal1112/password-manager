package signing

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

type fakeKeychain struct {
	store  map[string]string
	setErr error
}

func newFakeKeychain() *fakeKeychain {
	return &fakeKeychain{store: make(map[string]string)}
}

func (f *fakeKeychain) Get(service, user string) (string, error) {
	v, ok := f.store[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (f *fakeKeychain) Set(service, user, secret string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.store[service+"/"+user] = secret
	return nil
}

func TestOSStore_KeychainHappyPath(t *testing.T) {
	kc := newFakeKeychain()

	p1, err := newOSStoreProviderWithKeychain("test-cn", kc)
	require.NoError(t, err)
	assert.Equal(t, "RS256", p1.Algorithm())
	assert.NotEmpty(t, p1.KeyID())

	stored, err := kc.Get(keychainService, keychainUser("test-cn"))
	require.NoError(t, err)
	assert.Contains(t, stored, "RSA PRIVATE KEY")

	p2, err := newOSStoreProviderWithKeychain("test-cn", kc)
	require.NoError(t, err)
	assert.Equal(t, p1.KeyID(), p2.KeyID(), "kid must be stable across restarts")
}

func TestOSStore_KeychainUnavailable(t *testing.T) {
	kc := newFakeKeychain()
	kc.setErr = errors.New("keychain daemon not running")

	p, err := newOSStoreProviderWithKeychain("test-cn-unavail", kc)
	require.NoError(t, err)
	assert.Equal(t, "RS256", p.Algorithm())
	assert.NotEmpty(t, p.KeyID())

	_, getErr := kc.Get(keychainService, keychainUser("test-cn-unavail"))
	assert.Error(t, getErr, "key should not be in keychain when Set failed")
}

func TestOSStore_KeychainMissingKey(t *testing.T) {
	kc := newFakeKeychain()

	p, err := newOSStoreProviderWithKeychain("test-cn-missing", kc)
	require.NoError(t, err)
	assert.NotEmpty(t, p.KeyID())

	_, err = kc.Get(keychainService, keychainUser("test-cn-missing"))
	assert.NoError(t, err, "key should be stored after generation")
}

func TestOSStore_DifferentCNsDontCollide(t *testing.T) {
	kc := newFakeKeychain()

	p1, err := newOSStoreProviderWithKeychain("cn-alpha", kc)
	require.NoError(t, err)

	p2, err := newOSStoreProviderWithKeychain("cn-beta", kc)
	require.NoError(t, err)

	assert.NotEqual(t, p1.KeyID(), p2.KeyID(), "different CNs must produce different keys")
}

func TestLoadFromKeychain_InvalidPEM(t *testing.T) {
	kc := newFakeKeychain()
	kc.store[keychainService+"/"+keychainUser("bad-cn")] = "not-valid-pem"

	_, err := loadFromKeychain(kc, "bad-cn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid PEM")
}

func TestKeychainUser(t *testing.T) {
	assert.Equal(t, "jwt-signing-key-rocketvault", keychainUser("rocketvault"))
	assert.Equal(t, "jwt-signing-key-my-app", keychainUser("my-app"))
}
