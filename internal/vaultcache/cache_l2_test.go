// internal/vaultcache/cache_l2_test.go
package vaultcache

import (
	"strings"
	"sync"
	"testing"
	"time"

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

// panicL2 fails the test the instant any method is invoked. Used to prove a
// disabled domain cache never touches L2 at all, even when rocket_mem itself
// is enabled -- see TestNewCacheWithL2_Disabled_NeverTouchesL2.
type panicL2 struct{ t *testing.T }

func (p panicL2) Get(wireKey string) ([]byte, bool) {
	p.t.Fatalf("L2.Get must not be called when the domain cache is disabled (wireKey=%q)", wireKey)
	return nil, false
}
func (p panicL2) Set(wireKey string, _ []byte, _ time.Duration) {
	p.t.Fatalf("L2.Set must not be called when the domain cache is disabled (wireKey=%q)", wireKey)
}
func (p panicL2) Invalidate(wireKey string) {
	p.t.Fatalf("L2.Invalidate must not be called when the domain cache is disabled (wireKey=%q)", wireKey)
}
func (p panicL2) Keys(prefix string) []string {
	p.t.Fatalf("L2.Keys must not be called when the domain cache is disabled (prefix=%q)", prefix)
	return nil
}

var _ cachekit.L2 = panicL2{}

// TestNewCacheWithL2_Disabled_NeverTouchesL2 proves the Critical fix:
// cache.vaults.enabled: false must not be silently overridden by
// cache.rocket_mem.enabled: true. Set is a no-op, Get always misses -- and L2
// is never touched (panicL2 would fail the test otherwise).
func TestNewCacheWithL2_Disabled_NeverTouchesL2(t *testing.T) {
	c := NewCacheWithL2(cachekit.Config{Enabled: false, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0}, panicL2{t: t}, time.Minute)
	defer c.Stop()

	c.Set("acme", &model.Vault{Name: "acme", Enabled: true})
	_, ok := c.Get("acme")
	assert.False(t, ok, "a disabled cache must never yield a hit")
}

func TestNewCacheWithL2_RoundTrip_PlainCodec(t *testing.T) {
	l2 := newFakeL2()
	c := NewCacheWithL2(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0}, l2, time.Minute)
	defer c.Stop()

	v := &model.Vault{Name: "acme", Enabled: true}
	c.Set("acme", v)

	got, ok := c.Get("acme")
	require.True(t, ok)
	assert.Equal(t, "acme", got.Name)

	found := false
	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:vault:") {
			found = true
			assert.Contains(t, string(payload), "acme")
		}
	}
	assert.True(t, found, "Set must have written something to L2 under the rocketvault:vault: prefix")

	c.Invalidate("acme")
	_, ok = c.Get("acme")
	assert.False(t, ok)
}
