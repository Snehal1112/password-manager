// internal/cache/secret_cache_l2_test.go
package cache

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// fakeL2 mirrors internal/cachekit's own test double (unexported there too
// -- each package keeps a small local copy rather than exporting a
// test-only type from a production package).
type fakeL2 struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeL2() *fakeL2 { return &fakeL2{data: make(map[string][]byte)} }

func (f *fakeL2) Get(wireKey string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.data[wireKey]
	return b, ok
}
func (f *fakeL2) Set(wireKey string, payload []byte, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[wireKey] = payload
}
func (f *fakeL2) Invalidate(wireKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, wireKey)
}
func (f *fakeL2) Keys(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

var _ cachekit.L2 = (*fakeL2)(nil)

func TestNewSecretCacheWithL2_RoundTrip_AndCiphertextOnWire(t *testing.T) {
	// Set up master key in viper for encryption.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	masterKey := base64.StdEncoding.EncodeToString(key)
	viper.Set("master_key", masterKey)
	defer viper.Set("master_key", "")

	l2 := newFakeL2()
	c := NewSecretCacheWithL2(
		cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0},
		logrus.New(), l2, time.Minute,
	)
	defer c.Stop()

	ctx := context.Background()
	vaultID, secretID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	secret := &model.Secret{ID: secretID, VaultID: vaultID, Name: "n", Value: "TOP-SECRET-PLAINTEXT", Version: 1, CreatedAt: time.Now(), Enabled: true}

	require.NoError(t, c.Set(ctx, secret, scope))

	got, ok := c.Get(ctx, secretID, scope)
	require.True(t, ok)
	assert.Equal(t, "TOP-SECRET-PLAINTEXT", got.Value, "round-trip through L1+L2 must reproduce the exact plaintext")

	// Inspect what actually landed on the wire in L2 -- it must never
	// contain the plaintext substring.
	found := false
	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:secret:") {
			found = true
			assert.False(t, strings.Contains(string(payload), "TOP-SECRET-PLAINTEXT"),
				"secret plaintext must never appear in the L2 wire payload")
		}
	}
	assert.True(t, found, "Set must have written something to L2 under the rocketvault:secret: prefix")
}
