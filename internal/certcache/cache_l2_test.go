// internal/certcache/cache_l2_test.go
package certcache

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
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

func TestNewCacheWithL2_RoundTrip_PlainCodec(t *testing.T) {
	l2 := newFakeL2()
	c := NewCacheWithL2(
		cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0},
		logrus.New(), l2, time.Minute,
	)
	defer c.Stop()

	ctx := context.Background()
	vaultID, certID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: certID, VaultID: vaultID, Name: "n", Certificate: "PUBLIC-PEM", PrivateKey: "encrypted-ciphertext", Enabled: true, CreatedAt: time.Now()}

	require.NoError(t, c.Set(ctx, cert, scope))
	got, ok := c.Get(ctx, certID, scope)
	require.True(t, ok)
	assert.Equal(t, "PUBLIC-PEM", got.Certificate)
	assert.Equal(t, "encrypted-ciphertext", got.PrivateKey)

	found := false
	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:cert:") {
			found = true
			// Plain codec: readable JSON is expected here (no decrypted
			// secret ever enters this cache -- PrivateKey is already
			// ciphertext), unlike internal/cache's encrypted codec.
			assert.Contains(t, string(payload), "encrypted-ciphertext")
		}
	}
	assert.True(t, found, "Set must have written something to L2 under the rocketvault:cert: prefix")
}
