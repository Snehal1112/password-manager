package cachekit_test

import (
	"strings"
	"sync"
	"time"

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
