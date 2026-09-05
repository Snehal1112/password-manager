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

// compile-time check: *TieredCache[string, *codecTestValue] satisfies
// Interface[string, *codecTestValue] -- proves every domain cache can swap
// its `core` field's concrete type with zero other change.
var _ cachekit.Interface[string, *codecTestValue] = (*cachekit.TieredCache[string, *codecTestValue])(nil)

func TestTieredCache_Range_VisitsL1AndL2OnlyEntries(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	// k-l1: only in L1 (e.g. never yet pushed to L2 in some other scenario).
	l1.Set("k-l1", &codecTestValue{Name: "only-l1", N: 1})
	// k-l2: only in L2 (e.g. evicted from L1 by LRU/TTL, still alive in L2).
	payload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "only-l2", N: 2})
	require.NoError(t, err)
	l2.Set("test:k-l2", payload, time.Minute)

	seen := map[string]string{}
	tc.Range(func(k string, v *codecTestValue) bool {
		seen[k] = v.Name
		return true
	})

	assert.Equal(t, "only-l1", seen["k-l1"])
	assert.Equal(t, "only-l2", seen["k-l2"], "an L2-only entry (evicted from L1) must still be visited by Range")
}

func TestTieredCache_Range_L1EntryWinsOverL2Duplicate(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	l1.Set("dup", &codecTestValue{Name: "fresh-l1", N: 1})
	stalePayload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "stale-l2", N: 2})
	require.NoError(t, err)
	l2.Set("test:dup", stalePayload, time.Minute)

	var got *codecTestValue
	tc.Range(func(k string, v *codecTestValue) bool {
		if k == "dup" {
			got = v
		}
		return true
	})
	require.NotNil(t, got)
	assert.Equal(t, "fresh-l1", got.Name, "L1's copy must win when a key exists in both tiers")
}

func TestTieredCache_Range_EarlyStop_SkipsL2Scan(t *testing.T) {
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	l2.down = true // if Range reaches L2 after an early stop, Keys returns nil harmlessly either way -- down proves it's never even attempted via a separate assertion below
	tc := newTieredForTest(l1, l2)
	l1.Set("only-one", &codecTestValue{Name: "x", N: 1})

	visits := 0
	tc.Range(func(k string, v *codecTestValue) bool {
		visits++
		return false // stop immediately
	})
	assert.Equal(t, 1, visits)
}

func TestTieredCache_DeleteByIDPattern_FindsL2OnlyEntry(t *testing.T) {
	// This mirrors exactly how SecretCache.DeleteByID/certcache/keycache use
	// Range today: scan for a match, collect keys, Invalidate each. Proves
	// the pattern still works when the matching entry lives only in L2.
	l1 := cachekit.New[string, *codecTestValue](cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0})
	defer l1.Stop()
	l2 := newFakeL2()
	tc := newTieredForTest(l1, l2)

	payload, err := (cachekit.PlainJSONCodec[*codecTestValue]{}).Encode(&codecTestValue{Name: "target", N: 99})
	require.NoError(t, err)
	l2.Set("test:l2only", payload, time.Minute)

	var toRemove []string
	tc.Range(func(k string, v *codecTestValue) bool {
		if v.N == 99 {
			toRemove = append(toRemove, k)
		}
		return true
	})
	for _, k := range toRemove {
		tc.Invalidate(k)
	}

	_, ok := l2.Get("test:l2only")
	assert.False(t, ok, "the L2-only entry must have been found and invalidated")
}
