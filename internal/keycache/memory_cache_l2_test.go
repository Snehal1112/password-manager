// internal/keycache/memory_cache_l2_test.go
package keycache

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

// fakeL2 mirrors internal/cachekit's own test double -- see the note in
// internal/cache/secret_cache_l2_test.go about each package keeping a
// small local copy.
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

func TestNewCacheWithL2_RoundTrip_AndCiphertextOnWire(t *testing.T) {
	l2 := newFakeL2()
	c := NewCacheWithL2(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0}, l2, time.Minute)
	defer c.Stop()

	keyID := uuid.New()
	entry := &Entry{PrivateKey: PEMKey{PEM: []byte("-----BEGIN PRIVATE KEY-----SECRET-----END PRIVATE KEY-----")}, KeyType: "RSA", Version: 1}
	c.Set(keyID, 1, entry)

	got, ok := c.Get(keyID, 1)
	require.True(t, ok)
	pemKey, ok := got.PrivateKey.(PEMKey)
	require.True(t, ok)
	assert.Equal(t, entry.PrivateKey.(PEMKey).PEM, pemKey.PEM)

	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:key:") {
			assert.False(t, strings.Contains(string(payload), "SECRET"),
				"key PEM plaintext must never appear in the L2 wire payload")
		}
	}
}
