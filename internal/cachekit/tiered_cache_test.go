package cachekit_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

// fakeL2 is an in-memory stand-in for a real network L2 (e.g.
// internal/rocketmemcache's go-redis client). down simulates the L2 being
// completely unreachable — every method degrades exactly as the spec
// requires a real network failure to degrade.
type fakeL2 struct {
	mu   sync.Mutex
	data map[string][]byte
	down bool
}

func newFakeL2() *fakeL2 { return &fakeL2{data: make(map[string][]byte)} }

func (f *fakeL2) Get(wireKey string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, false
	}
	b, ok := f.data[wireKey]
	return b, ok
}

func (f *fakeL2) Set(wireKey string, payload []byte, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return
	}
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
	if f.down {
		return nil
	}
	var out []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

// compile-time check: fakeL2 satisfies cachekit.L2
var _ cachekit.L2 = (*fakeL2)(nil)

func identityKeyCodec() cachekit.KeyCodec[string] {
	return cachekit.KeyCodec[string]{
		ToWire:   func(k string) string { return k },
		FromWire: func(w string) (string, bool) { return w, true },
	}
}

func newTieredForTest(l1 cachekit.Interface[string, *codecTestValue], l2 cachekit.L2) *cachekit.TieredCache[string, *codecTestValue] {
	return cachekit.NewTieredCache[string, *codecTestValue](
		l1, l2, cachekit.PlainJSONCodec[*codecTestValue]{}, identityKeyCodec(), "test:", time.Minute,
	)
}

func TestTieredCache_L1Hit_NeverTouchesL2(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true // if Get ever reaches L2, this proves it by forcing a miss
	tc := newTieredForTest(l1, l2)

	l1.Set("k1", &codecTestValue{Name: "a", N: 1})
	v, ok := tc.Get("k1")
	require.True(t, ok)
	assert.Equal(t, "a", v.Name)
}

func TestTieredCache_L1Miss_L2Hit_PopulatesL1(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	payload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "b", N: 2})
	require.NoError(t, err)
	l2.Set("test:k2", payload, time.Minute)

	v, ok := tc.Get("k2")
	require.True(t, ok)
	assert.Equal(t, "b", v.Name)

	// L1 should now be populated -- prove it by killing L2 and reading again.
	l2.down = true
	v2, ok2 := tc.Get("k2")
	require.True(t, ok2)
	assert.Equal(t, "b", v2.Name)
}

func TestTieredCache_BothMiss(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	tc := newTieredForTest(l1, newFakeL2())

	_, ok := tc.Get("missing")
	assert.False(t, ok)
}

func TestTieredCache_Set_ReachesBothTiers(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	tc.Set("k3", &codecTestValue{Name: "c", N: 3})

	_, ok := l2.Get("test:k3")
	assert.True(t, ok, "Set must reach L2")
	v, ok := l1.Get("k3")
	require.True(t, ok)
	assert.Equal(t, "c", v.Name)
}

func TestTieredCache_Invalidate_EvictsBothTiers(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)
	tc.Set("k4", &codecTestValue{Name: "d", N: 4})

	tc.Invalidate("k4")

	_, l1ok := l1.Get("k4")
	_, l2ok := l2.Get("test:k4")
	assert.False(t, l1ok)
	assert.False(t, l2ok)
}

func TestTieredCache_L2Down_GetDegradesToMiss_NoPanic(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true
	tc := newTieredForTest(l1, l2)

	assert.NotPanics(t, func() {
		_, ok := tc.Get("anything")
		assert.False(t, ok)
	})
}

func TestTieredCache_L2Down_SetIsSilentNoOp_NoPanic(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true
	tc := newTieredForTest(l1, l2)

	assert.NotPanics(t, func() { tc.Set("k5", &codecTestValue{Name: "e", N: 5}) })
	// L1 must still have gotten the write even though L2 is down.
	v, ok := l1.Get("k5")
	require.True(t, ok)
	assert.Equal(t, "e", v.Name)
}
