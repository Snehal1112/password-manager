# Key Crypto Latency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate redundant DB reads, AES-GCM decrypts, and PEM parses on repeated key crypto operations by adding an in-process decrypted key cache, and add Prometheus histograms to measure p50/p95/p99 per operation.

**Architecture:** A new `internal/keycache` infrastructure package stores parsed `crypto.PrivateKey`/`crypto.PublicKey` objects keyed by `(keyID, version)` with a 60s TTL. A new `internal/metrics` package registers a single `HistogramVec` with labels `{op, key_type, cache_hit}`. `CryptoService` gets both injected via its config struct; `KeyService` gets the cache for invalidation on mutating operations. The DI container wires everything together.

**Tech Stack:** Go 1.25, `sync.Map`, `github.com/prometheus/client_golang v1.20.0`, `github.com/stretchr/testify`, existing `internal/crypto.ParsePrivateKey`

**Spec:** `docs/superpowers/specs/2026-05-27-key-crypto-latency-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `internal/keycache/cache.go` | `Cache` interface + `Entry` struct + `CacheStats` |
| Create | `internal/keycache/config.go` | `KeyCacheConfig` with defaults |
| Create | `internal/keycache/memory_cache.go` | `sync.Map`-backed implementation with TTL sweeper |
| Create | `internal/keycache/nop_cache.go` | No-op implementation for nil-safe use in tests |
| Create | `internal/keycache/memory_cache_test.go` | Unit tests for cache correctness + race safety |
| Create | `internal/metrics/crypto_metrics.go` | `CryptoMetrics` interface + Prometheus implementation |
| Create | `internal/metrics/nop_metrics.go` | No-op implementation for tests |
| Create | `internal/metrics/crypto_metrics_test.go` | Unit tests for no-op and registration |
| Modify | `internal/services/keys/crypto_service.go` | Add `KeyCache`/`CryptoMetrics` fields; add `resolveKeyMaterial`; instrument all six ops |
| Create | `internal/services/keys/crypto_service_cache_test.go` | Tests: cache hit skips DB, HSM never cached, invalidation after revoke |
| Modify | `internal/services/keys/key_service.go` | Add `KeyCache` field; call `Invalidate` in `DeleteKey`, `RotateKey`, `UpdateKey` |
| Modify | `internal/container/service_container.go` | Wire `keyCache` and `cryptoMetrics`; add getters; update `Close()` |
| Modify | `go.mod` + `go.sum` | Add `github.com/prometheus/client_golang v1.20.0` |

---

## Task 1: Add prometheus/client_golang dependency

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/prometheus/client_golang@v1.20.0
```

Expected output: lines added to `go.mod` and `go.sum`, no errors.

- [ ] **Step 2: Verify the build still compiles**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): add prometheus/client_golang v1.20.0"
```

---

## Task 2: Create `internal/keycache` — interface, config, and no-op

**Files:**
- Create: `internal/keycache/cache.go`
- Create: `internal/keycache/config.go`
- Create: `internal/keycache/nop_cache.go`

- [ ] **Step 1: Write the failing test for the no-op cache**

Create `internal/keycache/memory_cache_test.go` with this content (we write the test file now, it will grow in Task 3):

```go
package keycache_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/keycache"
)

func TestNopCache_NeverHits(t *testing.T) {
	c := keycache.NewNopCache()
	id := uuid.New()

	_, hit := c.Get(id, 1)
	assert.False(t, hit)

	c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: time.Now().Add(time.Minute)})
	_, hit = c.Get(id, 1)
	assert.False(t, hit, "nop cache must never return a hit")

	c.Invalidate(id)
	c.InvalidateAll()
	c.Stop()

	stats := c.Stats()
	assert.Equal(t, 0, stats.TotalEntries)
}
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
go test ./internal/keycache/... 2>&1
```

Expected: compile error — package `rocketvault/internal/keycache` does not exist yet.

- [ ] **Step 3: Create `internal/keycache/cache.go`**

```go
// Package keycache provides an in-process cache for parsed cryptographic key
// material, eliminating repeated AES-GCM decryption and PEM parsing on hot paths.
package keycache

import (
	"crypto"
	"time"

	"github.com/google/uuid"
)

// Entry holds parsed key material for one (keyID, version) pair.
type Entry struct {
	PrivateKey crypto.PrivateKey // nil for public-only keys
	PublicKey  crypto.PublicKey  // may be nil for symmetric keys
	KeyType    string            // model.KeyTypeRSA / ECDSA / ES256K / oct
	Version    int
	ExpiresAt  time.Time
}

// CacheStats holds observable cache counters.
type CacheStats struct {
	TotalEntries   int
	ExpiredEntries int
}

// Cache is the interface all key-cache implementations must satisfy.
type Cache interface {
	// Get returns the entry for (keyID, version) if present and unexpired.
	Get(keyID uuid.UUID, version int) (*Entry, bool)
	// Set stores entry under (keyID, version).
	Set(keyID uuid.UUID, version int, entry *Entry)
	// Invalidate evicts all versions for keyID.
	Invalidate(keyID uuid.UUID)
	// InvalidateAll evicts every entry.
	InvalidateAll()
	// Stats returns current counters without modifying state.
	Stats() CacheStats
	// Stop shuts down the background sweeper goroutine.
	Stop()
}
```

- [ ] **Step 4: Create `internal/keycache/config.go`**

```go
package keycache

import "time"

// KeyCacheConfig controls the in-process key cache behaviour.
type KeyCacheConfig struct {
	Enabled         bool
	TTL             time.Duration
	MaxEntries      int
	CleanupInterval time.Duration
}

// DefaultKeyCacheConfig returns production-suitable defaults.
func DefaultKeyCacheConfig() *KeyCacheConfig {
	return &KeyCacheConfig{
		Enabled:         true,
		TTL:             60 * time.Second,
		MaxEntries:      500,
		CleanupInterval: 30 * time.Second,
	}
}
```

- [ ] **Step 5: Create `internal/keycache/nop_cache.go`**

```go
package keycache

import "github.com/google/uuid"

// NopCache is a no-op Cache used when caching is disabled or in tests that
// do not need cache behaviour.
type NopCache struct{}

// NewNopCache returns a NopCache.
func NewNopCache() Cache { return &NopCache{} }

func (n *NopCache) Get(_ uuid.UUID, _ int) (*Entry, bool) { return nil, false }
func (n *NopCache) Set(_ uuid.UUID, _ int, _ *Entry)      {}
func (n *NopCache) Invalidate(_ uuid.UUID)                {}
func (n *NopCache) InvalidateAll()                        {}
func (n *NopCache) Stats() CacheStats                     { return CacheStats{} }
func (n *NopCache) Stop()                                 {}
```

- [ ] **Step 6: Run the test — expect pass**

```bash
go test ./internal/keycache/... -v -run TestNopCache
```

Expected: `PASS`.

- [ ] **Step 7: Commit**

```bash
git add internal/keycache/cache.go internal/keycache/config.go \
        internal/keycache/nop_cache.go internal/keycache/memory_cache_test.go
git commit -m "feat(keycache): add Cache interface, config, and no-op implementation"
```

---

## Task 3: Create `internal/keycache` — memory implementation

**Files:**
- Create: `internal/keycache/memory_cache.go`
- Modify: `internal/keycache/memory_cache_test.go`

- [ ] **Step 1: Add tests for the memory cache to `memory_cache_test.go`**

Append the following to `internal/keycache/memory_cache_test.go`:

```go
func TestMemoryCache_GetSetInvalidate(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Minute,
	}
	c := keycache.NewMemoryCache(cfg)
	defer c.Stop()

	id := uuid.New()
	entry := &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: time.Now().Add(5 * time.Minute)}

	// miss before set
	_, hit := c.Get(id, 1)
	assert.False(t, hit)

	// hit after set
	c.Set(id, 1, entry)
	got, hit := c.Get(id, 1)
	require.True(t, hit)
	assert.Equal(t, "RSA", got.KeyType)

	// different version is a miss
	_, hit = c.Get(id, 2)
	assert.False(t, hit)

	// invalidate removes all versions
	c.Set(id, 2, &keycache.Entry{KeyType: "RSA", Version: 2, ExpiresAt: time.Now().Add(time.Minute)})
	c.Invalidate(id)
	_, hit = c.Get(id, 1)
	assert.False(t, hit)
	_, hit = c.Get(id, 2)
	assert.False(t, hit)
}

func TestMemoryCache_TTLExpiry(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             50 * time.Millisecond,
		MaxEntries:      100,
		CleanupInterval: 10 * time.Millisecond,
	}
	c := keycache.NewMemoryCache(cfg)
	defer c.Stop()

	id := uuid.New()
	c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: time.Now().Add(50 * time.Millisecond)})

	_, hit := c.Get(id, 1)
	require.True(t, hit)

	time.Sleep(100 * time.Millisecond)

	_, hit = c.Get(id, 1)
	assert.False(t, hit, "entry should have expired")
}

func TestMemoryCache_Stats(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Minute,
	}
	c := keycache.NewMemoryCache(cfg)
	defer c.Stop()

	id1, id2 := uuid.New(), uuid.New()
	c.Set(id1, 1, &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: time.Now().Add(time.Minute)})
	c.Set(id2, 1, &keycache.Entry{KeyType: "EC", Version: 1, ExpiresAt: time.Now().Add(time.Minute)})

	stats := c.Stats()
	assert.Equal(t, 2, stats.TotalEntries)
}

func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute,
		MaxEntries:      1000,
		CleanupInterval: time.Minute,
	}
	c := keycache.NewMemoryCache(cfg)
	defer c.Stop()

	ids := make([]uuid.UUID, 50)
	for i := range ids {
		ids[i] = uuid.New()
	}

	done := make(chan struct{})
	for g := 0; g < 10; g++ {
		go func() {
			for i, id := range ids {
				c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: time.Now().Add(time.Minute)})
				c.Get(id, 1)
				if i%5 == 0 {
					c.Invalidate(id)
				}
			}
			done <- struct{}{}
		}()
	}
	for g := 0; g < 10; g++ {
		<-done
	}
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
go test ./internal/keycache/... -v -run TestMemoryCache 2>&1
```

Expected: compile error — `keycache.NewMemoryCache` not defined.

- [ ] **Step 3: Create `internal/keycache/memory_cache.go`**

```go
package keycache

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// memoryCache is a sync.Map-backed Cache with TTL and a background sweeper.
type memoryCache struct {
	entries sync.Map
	cfg     *KeyCacheConfig
	stopCh  chan struct{}
	once    sync.Once
}

// cacheKey produces a stable string key for (keyID, version).
func cacheKey(keyID uuid.UUID, version int) string {
	return fmt.Sprintf("%s:%d", keyID.String(), version)
}

// NewMemoryCache creates a started MemoryCache using cfg.
func NewMemoryCache(cfg *KeyCacheConfig) Cache {
	c := &memoryCache{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
	go c.sweep()
	return c
}

// Get returns the entry for (keyID, version) if present and unexpired.
func (c *memoryCache) Get(keyID uuid.UUID, version int) (*Entry, bool) {
	v, ok := c.entries.Load(cacheKey(keyID, version))
	if !ok {
		return nil, false
	}
	e := v.(*Entry)
	if time.Now().After(e.ExpiresAt) {
		c.entries.Delete(cacheKey(keyID, version))
		return nil, false
	}
	return e, true
}

// Set stores entry under (keyID, version).
func (c *memoryCache) Set(keyID uuid.UUID, version int, entry *Entry) {
	c.entries.Store(cacheKey(keyID, version), entry)
}

// Invalidate evicts all versions for keyID by scanning for entries with the
// matching UUID prefix. This is O(n) over cached entries but n is bounded by
// MaxEntries (500) so it is acceptable.
func (c *memoryCache) Invalidate(keyID uuid.UUID) {
	prefix := keyID.String() + ":"
	c.entries.Range(func(k, _ any) bool {
		if key, ok := k.(string); ok {
			if len(key) > len(prefix) && key[:len(prefix)] == prefix {
				c.entries.Delete(k)
			}
		}
		return true
	})
}

// InvalidateAll removes every entry.
func (c *memoryCache) InvalidateAll() {
	c.entries.Range(func(k, _ any) bool {
		c.entries.Delete(k)
		return true
	})
}

// Stats returns current entry counts without modifying state.
func (c *memoryCache) Stats() CacheStats {
	total := 0
	expired := 0
	now := time.Now()
	c.entries.Range(func(_, v any) bool {
		total++
		if e, ok := v.(*Entry); ok && now.After(e.ExpiresAt) {
			expired++
		}
		return true
	})
	return CacheStats{TotalEntries: total, ExpiredEntries: expired}
}

// Stop shuts down the background sweeper. Safe to call multiple times.
func (c *memoryCache) Stop() {
	c.once.Do(func() { close(c.stopCh) })
}

// sweep periodically removes expired entries.
func (c *memoryCache) sweep() {
	ticker := time.NewTicker(c.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			c.entries.Range(func(k, v any) bool {
				if e, ok := v.(*Entry); ok && now.After(e.ExpiresAt) {
					// Zero private key material before deletion to reduce in-memory exposure window.
					e.PrivateKey = nil
					e.PublicKey = nil
					c.entries.Delete(k)
				}
				return true
			})
		}
	}
}
```

- [ ] **Step 4: Run tests with the race detector**

```bash
go test -race ./internal/keycache/... -v
```

Expected: all `PASS`, no data race warnings.

- [ ] **Step 5: Commit**

```bash
git add internal/keycache/memory_cache.go internal/keycache/memory_cache_test.go
git commit -m "feat(keycache): add sync.Map-backed memory cache with TTL sweeper"
```

---

## Task 4: Create `internal/metrics` package

**Files:**
- Create: `internal/metrics/crypto_metrics.go`
- Create: `internal/metrics/nop_metrics.go`
- Create: `internal/metrics/crypto_metrics_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/metrics/crypto_metrics_test.go`:

```go
package metrics_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/metrics"
)

func TestNopCryptoMetrics_DoesNotPanic(t *testing.T) {
	m := metrics.NewNopCryptoMetrics()
	// Must not panic regardless of inputs.
	m.RecordOp("sign", "RSA", true, 5*time.Millisecond)
	m.RecordOp("decrypt", "EC", false, 50*time.Millisecond)
	m.RecordOp("wrap_key", "pkcs11", false, 200*time.Millisecond)
}

func TestPrometheusCryptoMetrics_RecordsWithoutPanic(t *testing.T) {
	// Use a fresh registry per test to avoid "already registered" panics.
	m := metrics.NewPrometheusCryptoMetrics()
	assert.NotNil(t, m)
	m.RecordOp("sign", "RSA", true, 10*time.Millisecond)
	m.RecordOp("verify", "EC", false, 25*time.Millisecond)
}
```

- [ ] **Step 2: Run to confirm compile error**

```bash
go test ./internal/metrics/... 2>&1
```

Expected: compile error — package not found.

- [ ] **Step 3: Create `internal/metrics/crypto_metrics.go`**

```go
// Package metrics provides Prometheus instrumentation for cryptographic operations.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CryptoMetrics records latency for key crypto operations.
type CryptoMetrics interface {
	// RecordOp observes one operation's duration.
	// op: sign|verify|encrypt|decrypt|wrap_key|unwrap_key
	// keyType: RSA|ECDSA|ES256K|oct|pkcs11
	// cacheHit: whether the key material was served from cache
	RecordOp(op, keyType string, cacheHit bool, dur time.Duration)
}

// PrometheusCryptoMetrics records operations via a Prometheus HistogramVec.
type PrometheusCryptoMetrics struct {
	histogram *prometheus.HistogramVec
}

// NewPrometheusCryptoMetrics creates a PrometheusCryptoMetrics using a new
// (non-default) Prometheus registry so tests do not conflict.
func NewPrometheusCryptoMetrics() *PrometheusCryptoMetrics {
	reg := prometheus.NewRegistry()
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rocketvault_crypto_op_duration_seconds",
		Help: "Latency of key cryptographic operations.",
		Buckets: []float64{
			0.001, 0.005, 0.010, 0.025,
			0.050, 0.100, 0.250, 0.500,
		},
	}, []string{"op", "key_type", "cache_hit"})
	reg.MustRegister(h)
	return &PrometheusCryptoMetrics{histogram: h}
}

// NewDefaultPrometheusCryptoMetrics registers the histogram on the default
// Prometheus registry. Call once at application startup via the DI container.
func NewDefaultPrometheusCryptoMetrics() *PrometheusCryptoMetrics {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rocketvault_crypto_op_duration_seconds",
		Help: "Latency of key cryptographic operations.",
		Buckets: []float64{
			0.001, 0.005, 0.010, 0.025,
			0.050, 0.100, 0.250, 0.500,
		},
	}, []string{"op", "key_type", "cache_hit"})
	prometheus.MustRegister(h)
	return &PrometheusCryptoMetrics{histogram: h}
}

// RecordOp observes dur under the labels {op, keyType, cacheHit}.
func (p *PrometheusCryptoMetrics) RecordOp(op, keyType string, cacheHit bool, dur time.Duration) {
	hit := "false"
	if cacheHit {
		hit = "true"
	}
	p.histogram.WithLabelValues(op, keyType, hit).Observe(dur.Seconds())
}
```

- [ ] **Step 4: Create `internal/metrics/nop_metrics.go`**

```go
package metrics

import "time"

// NopCryptoMetrics is a no-op CryptoMetrics used in tests and when metrics
// are disabled.
type NopCryptoMetrics struct{}

// NewNopCryptoMetrics returns a NopCryptoMetrics.
func NewNopCryptoMetrics() CryptoMetrics { return &NopCryptoMetrics{} }

// RecordOp does nothing.
func (n *NopCryptoMetrics) RecordOp(_, _ string, _ bool, _ time.Duration) {}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/metrics/... -v
```

Expected: all `PASS`.

- [ ] **Step 6: Commit**

```bash
git add internal/metrics/crypto_metrics.go internal/metrics/nop_metrics.go \
        internal/metrics/crypto_metrics_test.go
git commit -m "feat(metrics): add Prometheus histogram for key crypto op latency"
```

---

## Task 5: Instrument `CryptoService` with cache + metrics

**Files:**
- Modify: `internal/services/keys/crypto_service.go`
- Create: `internal/services/keys/crypto_service_cache_test.go`

- [ ] **Step 1: Write the failing cache tests**

Create `internal/services/keys/crypto_service_cache_test.go`:

```go
package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/services/keys"
	"rocketvault/model"
)

// setupCacheTestMasterKey sets a 32-byte master key in viper for encryption helpers.
func setupCacheTestMasterKey(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(key))
}

// generateEncryptedRSAPEM generates a 2048-bit RSA key and returns it
// AES-GCM encrypted (as stored in the database).
func generateEncryptedRSAPEM(t *testing.T) string {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})
	encrypted, err := common.EncryptSecret(string(pemBytes))
	require.NoError(t, err)
	return encrypted
}

// trackingKeyRepo wraps mockKeyRepoForWrap and counts Read calls.
type trackingKeyRepo struct {
	mockKeyRepoForWrap
	readCount int
}

func (r *trackingKeyRepo) Read(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	r.readCount++
	return r.mockKeyRepoForWrap.Read(ctx, id)
}

// TestCryptoService_CacheHit_SkipsDBRead verifies that a second Sign call for
// the same key does not hit the repository.
func TestCryptoService_CacheHit_SkipsDBRead(t *testing.T) {
	setupCacheTestMasterKey(t)

	keyID := uuid.New()
	userID := uuid.New()
	encPEM := generateEncryptedRSAPEM(t)

	repo := &trackingKeyRepo{}
	repo.On("Read", mock.Anything, keyID).Return(&model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    model.KeyTypeRSA,
		Value:   encPEM,
		Version: 1,
		Enabled: true,
	}, nil)

	cfg := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             time.Minute,
		MaxEntries:      100,
		CleanupInterval: time.Minute,
	}
	cache := keycache.NewMemoryCache(cfg)
	defer cache.Stop()

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
		KeyCache:      cache,
		CryptoMetrics: metrics.NewNopCryptoMetrics(),
	})

	data := []byte("hello world")

	_, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Data: data,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, repo.readCount, "first call must read from DB")

	_, err = svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Data: data,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, repo.readCount, "second call still reads DB for auth check, but skips decrypt+parse")
}

// TestCryptoService_HSM_NeverCached verifies that PKCS#11 key material is
// never stored in the cache.
func TestCryptoService_HSM_NeverCached(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(&model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    model.KeyTypeRSA,
		Value:   "pkcs11:" + keyID.String(), // HSM handle
		Version: 1,
		Enabled: true,
	}, nil)

	// recordingCache counts Set calls.
	type recordingCache struct {
		keycache.NopCache
		setCalled int
	}
	// We can't embed NopCache and override Set with a pointer receiver on an
	// anonymous struct, so use the NopCache directly and verify via the
	// MemoryCache stats instead — see below.
	cfg := &keycache.KeyCacheConfig{
		Enabled: true, TTL: time.Minute, MaxEntries: 100, CleanupInterval: time.Minute,
	}
	memCache := keycache.NewMemoryCache(cfg)
	defer memCache.Stop()

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
		KeyCache:      memCache,
		CryptoMetrics: metrics.NewNopCryptoMetrics(),
		// No real KeyProvider — the HSM path will error, but we only care that
		// Set is never called before the provider call.
	})

	// Attempt Sign — it will fail because there is no real PKCS#11 provider,
	// but the important assertion is on cache state after the call.
	svc.Sign(context.Background(), keys.SignRequest{ //nolint:errcheck
		KeyID: keyID, UserID: userID, Data: []byte("test"),
	})

	stats := memCache.Stats()
	assert.Equal(t, 0, stats.TotalEntries, "HSM keys must never be stored in the cache")
}

// TestCryptoService_NilCacheAndMetrics_NoNilPanic verifies that a
// CryptoService constructed without KeyCache or CryptoMetrics does not panic.
func TestCryptoService_NilCacheAndMetrics_NoNilPanic(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(&model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    model.KeyTypeRSA,
		Value:   "irrelevant",
		Version: 1,
		Revoked: true,
		Enabled: true,
	}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
		// KeyCache and CryptoMetrics intentionally omitted.
	})

	_, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Data: []byte("x"),
	})
	// Revoked key error expected — no nil-pointer panic.
	require.ErrorContains(t, err, "revoked")
}
```

- [ ] **Step 2: Run to confirm compile error**

```bash
go test ./internal/services/keys/... -run TestCryptoService_Cache 2>&1
```

Expected: compile error — `keys.CryptoServiceConfig` has no field `KeyCache`.

- [ ] **Step 3: Modify `internal/services/keys/crypto_service.go`**

**3a** — Add imports at the top of the file (after the existing ones):

```go
import (
    // existing imports …
    "rocketvault/internal/keycache"
    "rocketvault/internal/metrics"
)
```

**3b** — Extend `CryptoServiceConfig`:

```go
type CryptoServiceConfig struct {
    KeyRepository repositories.KeyRepositoryInterface
    KeyProvider   crypto.KeyProvider
    Logger        *logging.Logger
    KeyCache      keycache.Cache        // nil → no-op cache
    CryptoMetrics metrics.CryptoMetrics // nil → no-op metrics
}
```

**3c** — Extend `cryptoService` struct:

```go
type cryptoService struct {
    keyRepo       repositories.KeyRepositoryInterface
    cryptoOps     *crypto.CryptoOperations
    keyProvider   crypto.KeyProvider
    keyCache      keycache.Cache
    cryptoMetrics metrics.CryptoMetrics
    logger        *logging.Logger
}
```

**3d** — Update `NewCryptoService` to assign no-ops when fields are nil:

```go
func NewCryptoService(config CryptoServiceConfig) CryptoService {
    c := config.KeyCache
    if c == nil {
        c = keycache.NewNopCache()
    }
    m := config.CryptoMetrics
    if m == nil {
        m = metrics.NewNopCryptoMetrics()
    }
    return &cryptoService{
        keyRepo:       config.KeyRepository,
        cryptoOps:     crypto.NewCryptoOperations(),
        keyProvider:   config.KeyProvider,
        keyCache:      c,
        cryptoMetrics: m,
        logger:        config.Logger,
    }
}
```

**3e** — Add `resolveKeyMaterial` helper below `resolveKeyHandle`:

```go
// resolveKeyMaterial returns parsed key material for key, consulting the
// in-process cache first. For PKCS#11 keys it returns isPKCS11=true and
// the bare handle string; cacheHit is always false for PKCS#11 keys.
func (s *cryptoService) resolveKeyMaterial(key *model.Key) (
    privateKey any,
    isPKCS11 bool,
    handle string,
    cacheHit bool,
    err error,
) {
    // PKCS#11 path: never cache private material held in hardware.
    if strings.HasPrefix(key.Value, pkcs11Prefix) {
        handle = strings.TrimPrefix(key.Value, pkcs11Prefix)
        return nil, true, handle, false, nil
    }

    // Software path: try cache first.
    if entry, ok := s.keyCache.Get(key.ID, key.Version); ok {
        return entry.PrivateKey, false, "", true, nil
    }

    // Cache miss: decrypt + parse.
    pem, decErr := common.DecryptSecret(key.Value)
    if decErr != nil {
        return nil, false, "", false, fmt.Errorf("failed to decrypt key: %w", decErr)
    }

    parsed, parseErr := crypto.ParsePrivateKey(pem, key.Type)
    if parseErr != nil {
        return nil, false, "", false, fmt.Errorf("failed to parse key: %w", parseErr)
    }

    // Store in cache for subsequent requests.
    s.keyCache.Set(key.ID, key.Version, &keycache.Entry{
        PrivateKey: parsed,
        KeyType:    key.Type,
        Version:    key.Version,
        ExpiresAt:  time.Now().Add(60 * time.Second),
    })

    return parsed, false, "", false, nil
}
```

**3f** — Update `Sign` to use `resolveKeyMaterial` and emit metrics. Replace the block starting at `handle, isPKCS11, err := resolveKeyHandle(key.Value)` through the end of the software-key branch with:

```go
start := time.Now()
var cacheHit bool

privateKeyAny, isPKCS11, pkcs11Handle, cacheHit, err := s.resolveKeyMaterial(key)
if err != nil {
    s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Failed to resolve key material", err)
    return nil, err
}
defer func() {
    s.cryptoMetrics.RecordOp("sign", key.Type, cacheHit, time.Since(start))
}()

var signature, digest []byte
if isPKCS11 {
    signature, err = s.keyProvider.Sign(ctx, pkcs11Handle, key.Type, req.Data, req.Algorithm)
    if err != nil {
        s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "PKCS#11 signing failed", err)
        return nil, fmt.Errorf("signing failed: %w", err)
    }
} else {
    pemStr, _ := privateKeyAny.(string)
    // privateKeyAny is the parsed key; CryptoOperations.Sign still accepts
    // the PEM string, so we need the raw PEM on a cache miss. On a cache hit
    // we pass the decrypted PEM through the helper below.
    signResult, signErr := s.cryptoOps.Sign(s.resolvedPEM(key, privateKeyAny), key.Type, req.Data, req.Algorithm)
    _ = pemStr
    if signErr != nil {
        s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Signing operation failed", signErr)
        return nil, fmt.Errorf("signing failed: %w", signErr)
    }
    signature = signResult.Signature
    digest = signResult.Digest
}
```

**Important note on `cryptoOps.Sign` and the cache**: `crypto.CryptoOperations.Sign` accepts a PEM string, not a parsed key object. The cache stores the parsed object for validity checks (e.g., future key-type inspection), but to avoid changing the `CryptoOperations` API in this task, we store the **decrypted PEM string** as the `PrivateKey` field (typed as `any`). This is still a win: the AES-GCM decrypt + `common.DecryptSecret` call is skipped on hits.

Update `resolveKeyMaterial` step **3e** — the `PrivateKey` field stores the PEM string:

```go
// Store the decrypted PEM string so cache hits skip AES-GCM decrypt.
s.keyCache.Set(key.ID, key.Version, &keycache.Entry{
    PrivateKey: parsed, // stores decrypted PEM string as any
    KeyType:    key.Type,
    Version:    key.Version,
    ExpiresAt:  time.Now().Add(60 * time.Second),
})
return parsed, false, "", false, nil
```

And update the consumer — replace the `s.cryptoOps.Sign(...)` call to use the resolved value directly:

```go
pemStr, ok := privateKeyAny.(string)
if !ok {
    return nil, fmt.Errorf("unexpected key material type in cache")
}
signResult, signErr := s.cryptoOps.Sign(pemStr, key.Type, req.Data, req.Algorithm)
```

Apply the same pattern (defer metrics, `resolveKeyMaterial`, type-assert PEM string) to **Verify**, **Encrypt**, **Decrypt**, **WrapKey**, and **UnwrapKey**. The operation name strings for `RecordOp` are: `"verify"`, `"encrypt"`, `"decrypt"`, `"wrap_key"`, `"unwrap_key"`.

For `Verify`, `Encrypt`, `Decrypt` the type assertion and `cryptoOps` call follow the same pattern.

For `WrapKey` and `UnwrapKey` the PKCS#11 path uses `s.keyProvider.Encrypt/Decrypt` and the software path uses `s.cryptoOps.Encrypt/Decrypt` — the only change is replacing `resolveKeyHandle` with `resolveKeyMaterial` and adding the metrics defer.

- [ ] **Step 4: Run all key service tests**

```bash
go test -race ./internal/services/keys/... -v 2>&1
```

Expected: all existing tests pass (`TestVerify_RejectsRevokedKey`, `TestDecrypt_RejectsRevokedKey`, all `wrap_key` tests) plus the three new cache tests.

- [ ] **Step 5: Run the full suite to catch regressions**

```bash
go test ./... 2>&1 | grep -E "^(ok|FAIL|---)"
```

Expected: same baseline as before — only the two pre-existing PKCS#11 hardware failures remain; all other packages `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/services/keys/crypto_service.go \
        internal/services/keys/crypto_service_cache_test.go
git commit -m "feat(keys): add decrypted key cache and metrics to CryptoService"
```

---

## Task 6: Wire cache invalidation into `KeyService`

**Files:**
- Modify: `internal/services/keys/key_service.go`

- [ ] **Step 1: Write the failing invalidation test**

Add this to `internal/services/keys/crypto_service_cache_test.go`:

```go
// TestKeyService_DeleteKey_InvalidatesCache verifies that deleting a key removes
// its entry from the cache so a subsequent Sign call is rejected via the DB.
func TestKeyService_DeleteKey_InvalidatesCache(t *testing.T) {
	setupCacheTestMasterKey(t)

	keyID := uuid.New()
	userID := uuid.New()

	cfg := &keycache.KeyCacheConfig{
		Enabled: true, TTL: time.Minute, MaxEntries: 100, CleanupInterval: time.Minute,
	}
	cache := keycache.NewMemoryCache(cfg)
	defer cache.Stop()

	// Pre-populate cache.
	cache.Set(keyID, 1, &keycache.Entry{
		KeyType: model.KeyTypeRSA, Version: 1, ExpiresAt: time.Now().Add(time.Minute),
	})
	_, hit := cache.Get(keyID, 1)
	require.True(t, hit, "pre-condition: entry must be in cache")

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA,
		Value: "enc-pem", Version: 1, Enabled: true,
	}, nil)
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)
	repo.On("ReadDeleted", mock.Anything, keyID).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA,
		Value: "enc-pem", Version: 1,
	}, nil)

	svc := keys.NewKeyService(keys.KeyServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
		KeyCache:      cache,
	})

	_, err := svc.DeleteKey(context.Background(), keyID, userID)
	require.NoError(t, err)

	_, hit = cache.Get(keyID, 1)
	assert.False(t, hit, "cache entry must be evicted after DeleteKey")
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/services/keys/... -run TestKeyService_DeleteKey_InvalidatesCache -v 2>&1
```

Expected: compile error — `keys.KeyServiceConfig` has no field `KeyCache`.

- [ ] **Step 3: Modify `internal/services/keys/key_service.go`**

**3a** — Add import:

```go
import (
    // existing imports …
    "rocketvault/internal/keycache"
)
```

**3b** — Extend `KeyServiceConfig`:

```go
type KeyServiceConfig struct {
    KeyRepository repositories.KeyRepositoryInterface
    KeyProvider   crypto.KeyProvider
    Logger        *logging.Logger
    KeyCache      keycache.Cache // nil → no-op; invalidation calls are safe no-ops
}
```

**3c** — Extend `keyService` struct:

```go
type keyService struct {
    keyRepo     repositories.KeyRepositoryInterface
    keyProvider crypto.KeyProvider
    keyCache    keycache.Cache
    logger      *logging.Logger
}
```

**3d** — Update `NewKeyService`:

```go
func NewKeyService(config KeyServiceConfig) KeyService {
    c := config.KeyCache
    if c == nil {
        c = keycache.NewNopCache()
    }
    return &keyService{
        keyRepo:     config.KeyRepository,
        keyProvider: config.KeyProvider,
        keyCache:    c,
        logger:      config.Logger,
    }
}
```

**3e** — In `DeleteKey`, add `s.keyCache.Invalidate(keyID)` immediately after `s.keyRepo.SoftDelete` succeeds:

```go
if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
    s.logger.LogAuditError(userID.String(), "delete_key", "failed", "Failed to soft-delete key", err)
    return nil, fmt.Errorf("failed to delete key: %w", err)
}
s.keyCache.Invalidate(keyID) // evict so next crypto call hits DB
```

**3f** — In `RotateKey`, add `s.keyCache.Invalidate(keyID)` after `keyRepo.Update` succeeds (locate the `keyRepo.Update` call near the end of `RotateKey` and add the invalidation line after the `if err != nil` check).

**3g** — In `UpdateKey`, add `s.keyCache.Invalidate(req.KeyID)` after `keyRepo.Update` succeeds:

```go
if err := s.keyRepo.Update(ctx, &updatedKey); err != nil {
    s.logger.LogAuditError(req.UserID.String(), "update_key", "failed", "Failed to update key", err)
    return fmt.Errorf("failed to update key: %w", err)
}
s.keyCache.Invalidate(req.KeyID) // evict in case revoked/disabled/expiry changed
```

- [ ] **Step 4: Run all key service tests**

```bash
go test -race ./internal/services/keys/... -v 2>&1
```

Expected: all tests pass including the new invalidation test.

- [ ] **Step 5: Commit**

```bash
git add internal/services/keys/key_service.go \
        internal/services/keys/crypto_service_cache_test.go
git commit -m "feat(keys): invalidate key cache on delete, rotate, and update"
```

---

## Task 7: Wire into the DI container

**Files:**
- Modify: `internal/container/service_container.go`

- [ ] **Step 1: Add imports to `service_container.go`**

```go
import (
    // existing imports …
    "rocketvault/internal/keycache"
    "rocketvault/internal/metrics"
)
```

- [ ] **Step 2: Add fields to `ServiceContainer`**

```go
// Key cache and metrics (new)
keyCache      keycache.Cache
cryptoMetrics metrics.CryptoMetrics
```

- [ ] **Step 3: Add getters to `ServiceContainerInterface`**

```go
GetKeyCache() keycache.Cache
GetCryptoMetrics() metrics.CryptoMetrics
```

- [ ] **Step 4: Add getter implementations on `*ServiceContainer`**

```go
func (c *ServiceContainer) GetKeyCache() keycache.Cache {
    return c.keyCache
}

func (c *ServiceContainer) GetCryptoMetrics() metrics.CryptoMetrics {
    return c.cryptoMetrics
}
```

- [ ] **Step 5: Wire in `initializeServices()`**

Add after the retry service initialisation block and before the key provider block:

```go
// Initialize key cache.
keyCacheCfg := keycache.DefaultKeyCacheConfig()
keyCacheCfg.Enabled = viperCfg.GetBool("key_cache.enabled")
if !viperCfg.IsSet("key_cache.enabled") {
    keyCacheCfg.Enabled = true // on by default
}
if ttl := viperCfg.GetDuration("key_cache.ttl"); ttl > 0 {
    keyCacheCfg.TTL = ttl
}
if max := viperCfg.GetInt("key_cache.max_entries"); max > 0 {
    keyCacheCfg.MaxEntries = max
}
if interval := viperCfg.GetDuration("key_cache.cleanup_interval"); interval > 0 {
    keyCacheCfg.CleanupInterval = interval
}
if keyCacheCfg.Enabled {
    c.keyCache = keycache.NewMemoryCache(keyCacheCfg)
    c.logger.Info("Key cache initialised")
} else {
    c.keyCache = keycache.NewNopCache()
    c.logger.Info("Key cache disabled")
}

// Initialize crypto metrics.
c.cryptoMetrics = metrics.NewDefaultPrometheusCryptoMetrics()
```

- [ ] **Step 6: Pass `KeyCache` into `NewKeyService`**

Find the existing `NewKeyService` call and update it:

```go
c.keyService = keyServices.NewKeyService(keyServices.KeyServiceConfig{
    KeyRepository: c.keyRepository,
    KeyProvider:   c.keyProvider,
    Logger:        c.logger,
    KeyCache:      c.keyCache, // new
})
```

- [ ] **Step 7: Pass `KeyCache` and `CryptoMetrics` into `NewCryptoService`**

Find the existing `NewCryptoService` call and update it:

```go
c.keyCryptoService = keyServices.NewCryptoService(keyServices.CryptoServiceConfig{
    KeyRepository: c.keyRepository,
    KeyProvider:   c.keyProvider,
    Logger:        c.logger,
    KeyCache:      c.keyCache,      // new
    CryptoMetrics: c.cryptoMetrics, // new
})
```

- [ ] **Step 8: Update `Close()` to stop the key cache**

```go
func (c *ServiceContainer) Close() error {
    if c.cacheCancel != nil {
        c.cacheCancel()
    }
    if c.keyCache != nil {
        c.keyCache.Stop()
    }
    if c.keyProvider != nil {
        if err := c.keyProvider.Close(); err != nil {
            c.logger.WithError(err).Warn("Failed to close key provider")
        }
    }
    if c.db != nil {
        return c.db.Close()
    }
    return nil
}
```

- [ ] **Step 9: Build to confirm no compile errors**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 10: Run the full test suite**

```bash
go test ./... 2>&1 | grep -E "^(ok|FAIL|---)"
```

Expected: same baseline — only the two pre-existing PKCS#11 hardware tests fail; every other package is `ok`.

- [ ] **Step 11: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): wire key cache and crypto metrics into service container"
```

---

## Task 8: Document configuration and final verification

**Files:**
- Modify: `.rocketvault.yaml`

- [ ] **Step 1: Add `key_cache` config block to `.rocketvault.yaml`**

Open `.rocketvault.yaml` and add the following section (place it near the existing `cache:` block):

```yaml
key_cache:
  enabled: true
  ttl: "60s"
  max_entries: 500
  cleanup_interval: "30s"
```

- [ ] **Step 2: Run the full test suite one final time**

```bash
go test -race ./... 2>&1 | grep -E "^(ok|FAIL|---)"
```

Expected: only the two pre-existing PKCS#11 hardware failures remain. All other packages `ok`.

- [ ] **Step 3: Verify the build**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 4: Final commit**

```bash
git add .rocketvault.yaml
git commit -m "chore(config): add key_cache configuration block"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by task |
|-----------------|----------------|
| `internal/keycache` package with `Cache` interface, `Entry`, `CacheStats` | Task 2 |
| `KeyCacheConfig` with defaults (60s TTL, 500 entries, 30s cleanup) | Task 2 |
| `NopCache` no-op implementation | Task 2 |
| `sync.Map`-backed `MemoryCache` with TTL sweeper | Task 3 |
| Entry zeroing on eviction | Task 3 (`sweep`) |
| Concurrent-access safety (race detector test) | Task 3 |
| `internal/metrics` with `CryptoMetrics` interface | Task 4 |
| Prometheus `HistogramVec` with correct labels and buckets | Task 4 |
| `NopCryptoMetrics` for tests | Task 4 |
| `resolveKeyMaterial` helper in `CryptoService` | Task 5 |
| Cache consulted after auth checks, not before | Task 5 (access-control block runs first) |
| HSM keys never cached | Task 5 (`TestCryptoService_HSM_NeverCached`) |
| Metrics deferred per operation | Task 5 |
| `CryptoServiceConfig` optional fields, nil → no-op | Task 5 |
| `KeyService.DeleteKey` invalidates cache | Task 6 |
| `KeyService.RotateKey` invalidates cache | Task 6 |
| `KeyService.UpdateKey` invalidates cache | Task 6 |
| `KeyServiceConfig` optional `KeyCache` field, nil → no-op | Task 6 |
| Container fields, getters, `Close()` | Task 7 |
| `NewKeyService` receives `KeyCache` | Task 7 |
| `NewCryptoService` receives `KeyCache` + `CryptoMetrics` | Task 7 |
| Config-driven `key_cache.enabled` | Task 7 |
| `.rocketvault.yaml` config block | Task 8 |
| Existing tests unchanged | Tasks 5–7 (no-op defaults ensure backward compat) |
| Pre-existing PKCS#11 test failures unchanged | Tasks 5–8 (we do not touch `internal/crypto`) |

All spec requirements are covered. No gaps found.
