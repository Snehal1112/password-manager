# Rocket-mem Tiered Cache — Plan 03: rocketmemcache Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `internal/rocketmemcache` package providing a `go-redis/v9`-backed implementation of `cachekit.L2`, confined so that `go-redis` is imported nowhere else in the repo.

**Architecture:** One `Client` struct wrapping a `*redis.Client`, translating `cachekit.L2`'s four methods to RESP commands (`GET`/`SET .. EX`/`DEL`/`KEYS`), with every error swallowed per the spec's fail-open contract. Tested against the project's existing `//go:build integration` convention (same tag `internal/backup/pg_integration_test.go` uses for "needs a live external service") — no fake-server library is introduced.

**Tech Stack:** `github.com/redis/go-redis/v9` (new dependency), Go 1.25 stdlib `crypto/tls`.

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (see "L2 client and failure handling" section)

## Global Constraints

- `go-redis/v9` is imported **only** inside `internal/rocketmemcache` — no other package (including `internal/cachekit`) may import it.
- Every method degrades on error exactly like the spec requires: `Get` → `(nil, false)`, `Set`/`Invalidate` → silent no-op, `Keys` → `nil`. No method returns an error, no method panics.
- Integration tests require a live rocket-mem instance and are gated behind `//go:build integration`, matching this repo's existing convention (`internal/backup/pg_integration_test.go`, `internal/mcpserver/integration_test.go`) — the default `go test ./...` run must stay green and must not require rocket-mem to be running.
- This plan's default (non-integration) build must not regress anything: `go build ./...` and `go test ./...` (no tags) must be identical in outcome to before this plan started, since `internal/rocketmemcache` is not yet imported by any other package.

---

### Task 1: `Config` + `Client` — Get/Set/Invalidate

**Files:**
- Create: `internal/rocketmemcache/client.go`
- Test: `internal/rocketmemcache/client_integration_test.go` (build-tagged `integration`)
- Modify: `go.mod`, `go.sum` (via `go get`)

**Interfaces:**
- Consumes: none (this is the lowest new layer).
- Produces: `rocketmemcache.Config` struct, `rocketmemcache.New(cfg Config) *Client`, `(*Client).Get/Set/Invalidate` satisfying the relevant three methods of `cachekit.L2`.

- [ ] **Step 1: Write the failing test**

The user's local rocket-mem instance is already running at `127.0.0.1:6379` (started via `./target/release/rocket-mem`, no ACL user configured yet, so it currently accepts unauthenticated connections — fine for this local dev/integration test, which talks to `rocketmemcache.Client` directly and does not go through the app-level TLS/auth startup guard Plan 04 adds).

```go
// internal/rocketmemcache/client_integration_test.go
//go:build integration

// Package rocketmemcache integration suite proves Client's RESP calls
// actually work against a live rocket-mem instance. Run with:
//
//	go test -tags=integration ./internal/rocketmemcache/...
//
// Requires a rocket-mem instance reachable at ROCKETMEM_TEST_ADDR (defaults
// to 127.0.0.1:6379, matching a locally-started `rocket-mem` binary). The
// default `go test ./...` run skips this file.
package rocketmemcache_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/rocketmemcache"
)

func testAddr() string {
	if a := os.Getenv("ROCKETMEM_TEST_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6379"
}

func newTestClient(t *testing.T) *rocketmemcache.Client {
	t.Helper()
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         testAddr(),
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		PoolSize:     5,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClient_SetGet_RoundTrip(t *testing.T) {
	c := newTestClient(t)
	key := "rocketmemcache_test:roundtrip:" + t.Name()

	c.Set(key, []byte("hello-world"), 30*time.Second)
	got, ok := c.Get(key)
	require.True(t, ok)
	assert.Equal(t, "hello-world", string(got))

	c.Invalidate(key)
	_, ok = c.Get(key)
	assert.False(t, ok, "Get after Invalidate must miss")
}

func TestClient_Get_MissingKey_ReturnsFalseNotError(t *testing.T) {
	c := newTestClient(t)
	_, ok := c.Get("rocketmemcache_test:definitely-does-not-exist")
	assert.False(t, ok)
}

func TestClient_Get_Unreachable_DegradesToMiss(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         "127.0.0.1:1", // nothing listens here
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolSize:     1,
	})
	defer c.Close()

	assert.NotPanics(t, func() {
		_, ok := c.Get("anything")
		assert.False(t, ok)
	})
	assert.NotPanics(t, func() {
		c.Set("anything", []byte("x"), time.Minute) // must not panic or block past the dial timeout
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go get github.com/redis/go-redis/v9 && go test -tags=integration ./internal/rocketmemcache/... -v`
Expected: FAIL (build error — `rocketmemcache.Config`/`rocketmemcache.New`/`Client` do not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/rocketmemcache/client.go
package rocketmemcache

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds connection settings for one shared Rocket-mem instance,
// backing the L2 tier for all four RocketVault domain caches. See
// config.LoadRocketMemConfig (Plan 04) for how this is populated from
// cache.rocket_mem.* in .rocketvault.yaml.
type Config struct {
	Addr         string
	TLS          bool
	Username     string
	Password     string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
}

// Client implements cachekit.L2 against a real Rocket-mem (or any
// RESP2/3-compatible) server. Every method swallows errors per the
// design spec's fail-open contract: an unreachable or misbehaving
// Rocket-mem must degrade to a cache miss, never break a caller.
type Client struct {
	rdb *redis.Client
}

// New constructs a Client. The underlying connection is lazy (go-redis
// dials on first use), so New itself never blocks or fails.
func New(cfg Config) *Client {
	opts := &redis.Options{
		Addr:         cfg.Addr,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &Client{rdb: redis.NewClient(opts)}
}

// Get returns the value stored under wireKey. Any error -- key-not-found
// (redis.Nil), network failure, or timeout -- degrades to (nil, false).
func (c *Client) Get(wireKey string) ([]byte, bool) {
	val, err := c.rdb.Get(context.Background(), wireKey).Bytes()
	if err != nil {
		return nil, false
	}
	return val, true
}

// Set stores payload under wireKey with the given TTL. Any error is
// silently dropped -- a failed cache write must never surface to the
// caller (see cachekit.L2's contract).
func (c *Client) Set(wireKey string, payload []byte, ttl time.Duration) {
	_ = c.rdb.Set(context.Background(), wireKey, payload, ttl).Err()
}

// Invalidate deletes wireKey. Errors are silently dropped, same reasoning
// as Set.
func (c *Client) Invalidate(wireKey string) {
	_ = c.rdb.Del(context.Background(), wireKey).Err()
}

// Close releases the underlying connection pool. Owned and called exactly
// once by the container (see the design spec's "L2 connection lifecycle"
// note) -- never by an individual TieredCache.
func (c *Client) Close() error {
	return c.rdb.Close()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -tags=integration ./internal/rocketmemcache/... -v`
Expected: PASS (requires the local rocket-mem instance to be running at `127.0.0.1:6379`; if it isn't, start it first per the project's own instructions before running this)

- [ ] **Step 5: Commit**

```bash
git add internal/rocketmemcache/client.go internal/rocketmemcache/client_integration_test.go go.mod go.sum
git commit -m "feat(rocketmemcache): add go-redis-backed L2 client (Get/Set/Invalidate)"
```

---

### Task 2: `Keys` + `cachekit.L2` conformance + default-build safety net

**Files:**
- Modify: `internal/rocketmemcache/client.go`
- Test: `internal/rocketmemcache/client_integration_test.go`, `internal/rocketmemcache/client_test.go` (new, untagged — runs in the default `go test ./...`)

**Interfaces:**
- Produces: `(*Client).Keys(prefix string) []string`, completing `cachekit.L2` conformance; a compile-time assertion proving it.

- [ ] **Step 1: Write the failing test**

```go
// internal/rocketmemcache/client_test.go — no build tag: this must run in
// the default `go test ./...`, proving the package at least builds and
// satisfies cachekit.L2 even when no rocket-mem instance is reachable.
package rocketmemcache_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/rocketmemcache"
)

var _ cachekit.L2 = (*rocketmemcache.Client)(nil)

func TestClient_Unreachable_KeysDegradesToEmpty(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         "127.0.0.1:1",
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolSize:     1,
	})
	defer c.Close()

	var keys []string
	assert.NotPanics(t, func() { keys = c.Keys("rocketvault:secret:") })
	assert.Empty(t, keys)
}

func TestClient_Close_Idempotent(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{Addr: "127.0.0.1:1"})
	assert.NoError(t, c.Close())
}
```

Add to `client_integration_test.go` (still tagged `integration`, needs the live instance):

```go
func TestClient_Keys_ReturnsMatchingPrefix(t *testing.T) {
	c := newTestClient(t)
	prefix := "rocketmemcache_test:keys:" + t.Name() + ":"
	c.Set(prefix+"a", []byte("1"), 30*time.Second)
	c.Set(prefix+"b", []byte("2"), 30*time.Second)
	defer c.Invalidate(prefix + "a")
	defer c.Invalidate(prefix + "b")

	keys := c.Keys(prefix)
	assert.ElementsMatch(t, []string{prefix + "a", prefix + "b"}, keys)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rocketmemcache/... -v`
Expected: FAIL (build error — `Client.Keys` does not exist, so `var _ cachekit.L2 = (*rocketmemcache.Client)(nil)` fails to compile)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/rocketmemcache/client.go

// Keys returns every live key matching prefix* (Rocket-mem's KEYS
// supports a basic prefix-wildcard glob -- verified against a live
// instance in this package's integration suite). Any error degrades to an
// empty slice, same fail-open reasoning as every other method here.
func (c *Client) Keys(prefix string) []string {
	keys, err := c.rdb.Keys(context.Background(), prefix+"*").Result()
	if err != nil {
		return nil
	}
	return keys
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rocketmemcache/... -v` (default, no tag)
Expected: PASS

Run: `go test -tags=integration ./internal/rocketmemcache/... -v`
Expected: PASS (requires the local rocket-mem instance running)

Run: `go build ./... && go vet ./... && go test ./...` (whole repo, no tags)
Expected: identical outcome to before this plan started — `internal/rocketmemcache` is new and not yet imported anywhere else, so nothing else can regress.

- [ ] **Step 5: Commit**

```bash
git add internal/rocketmemcache/client.go internal/rocketmemcache/client_test.go internal/rocketmemcache/client_integration_test.go
git commit -m "feat(rocketmemcache): add Keys and cachekit.L2 conformance check"
```
