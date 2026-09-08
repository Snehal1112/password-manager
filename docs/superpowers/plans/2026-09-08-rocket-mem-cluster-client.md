# Rocket-mem Cluster-Aware L2 Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `internal/rocketmemcache.Client` (RocketVault's L2 cache tier) talk to a real 3-node rocket-mem cluster via `go-redis`'s `ClusterClient`, instead of a single node, without breaking the existing single-node deployment path.

**Architecture:** Add an opt-in `cluster_mode` flag alongside a new `addrs` (seed list) config field. `rocketmemcache.New` branches between `redis.NewClient` (today's behavior, unchanged) and `redis.NewClusterClient` (new) based on that flag. `Get`/`Set`/`Invalidate`/`Ping` work unchanged against either client type through a small structural interface. `Keys` — the one method with cluster-specific behavior — fans out across every master shard via `ClusterClient.ForEachMaster` and aggregates results, because a plain `KEYS` call against a cluster client only queries one shard's connection.

**Tech Stack:** Go 1.25, `github.com/redis/go-redis/v9` (`v9.22.0`, already a dependency), Viper for config, testify for tests.

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (the original L2 tier design — its "Non-goals / deferred" section explicitly scoped clustering out: *"Rocket-mem clustering, replication, or failover — out of scope; RocketVault treats it as a single logical L2 endpoint regardless of how it's deployed behind that address."* This plan is the follow-up that picks that deferred item back up, now that rocket-mem's cluster mode is confirmed to support `CLUSTER SLOTS`/`SHARDS` topology discovery and `MOVED` redirects — verified directly against `rocket-mem`'s `crates/server/src/cluster.rs`/`dispatcher.rs` source, which is what makes `go-redis`'s `ClusterClient` usable here with no protocol gaps.)

## Global Constraints

- Every existing single-node deployment (`cluster_mode` unset or `false`) must be byte-for-byte unaffected — this mirrors the original spec's own non-goal ("purely additive and optional").
- Keep the existing fail-open contract: any L2 error (including a partial cluster fan-out failure) degrades to a miss/no-op, logged at `Warn`, never returned to the caller as an error.
- Keep the existing fail-closed startup validation pattern: an invalid/incomplete `cluster_mode` config aborts startup with a clear error, the same way a missing TLS/credential config does today.
- `cachekit` must still not import `go-redis` — all cluster-awareness stays inside `internal/rocketmemcache`.
- No new dependency — `go-redis/v9`'s `ClusterClient`/`ClusterOptions`/`ForEachMaster` are already available in the vendored version (`v9.22.0`).
- Match existing code conventions exactly: comments in short, complete sentences ending in a period; Warn-level logging (never Error) for degraded-but-handled L2 failures; `t.Helper()` in test helpers; `resetRocketMemViperKeys`-style viper cleanup in config tests.

---

## Task 1: Add `cluster_mode`/`addrs` to `RocketMemConfig`

**Files:**
- Modify: `config/config.go:392-418` (the `RocketMemConfig` struct)
- Modify: `config/config.go:428-489` (`LoadRocketMemConfig`)
- Test: `config/config_test.go` (alongside the existing `TestLoadRocketMemConfig_*` tests, ~line 346-425)

**Interfaces:**
- Produces: `RocketMemConfig.ClusterMode bool`, `RocketMemConfig.Addrs []string` — consumed by Task 2 (`rocketmemcache.Config`) and Task 4 (container wiring).

- [ ] **Step 1: Write the failing tests**

Add to `config/config_test.go`, near the other `TestLoadRocketMemConfig_*` tests:

```go
func TestLoadRocketMemConfig_ClusterModeDefaultsFalse(t *testing.T) {
	resetRocketMemViperKeys(t)
	cfg, err := LoadRocketMemConfig()
	require.NoError(t, err)
	assert.False(t, cfg.ClusterMode)
	assert.Empty(t, cfg.Addrs)
}

func TestLoadRocketMemConfig_ClusterModeWithoutAddrs_FailsClosed(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.cluster_mode", true)
	viper.Set("cache.rocket_mem.tls", true)
	viper.Set("cache.rocket_mem.username", "vault")
	viper.Set("cache.rocket_mem.password", "secret")

	_, err := LoadRocketMemConfig()
	assert.Error(t, err, "cluster_mode without addrs must fail startup, not silently run single-node")
}

func TestLoadRocketMemConfig_ClusterModeWithAddrs_Succeeds(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.cluster_mode", true)
	viper.Set("cache.rocket_mem.addrs", []string{
		"numericlabs.lxd:16379", "numericlabs.lxd:16380", "numericlabs.lxd:16381",
	})
	viper.Set("cache.rocket_mem.tls", true)
	viper.Set("cache.rocket_mem.username", "rocketvault")
	viper.Set("cache.rocket_mem.password", "s3cret")

	cfg, err := LoadRocketMemConfig()
	require.NoError(t, err)
	assert.True(t, cfg.ClusterMode)
	assert.Equal(t, []string{
		"numericlabs.lxd:16379", "numericlabs.lxd:16380", "numericlabs.lxd:16381",
	}, cfg.Addrs)
}
```

Also add `"cache.rocket_mem.cluster_mode", "cache.rocket_mem.addrs"` to the key list in `resetRocketMemViperKeys` (`config/config_test.go:349-361`) so these tests don't leak state into each other.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/... -run TestLoadRocketMemConfig_ClusterMode -v`
Expected: FAIL — `cfg.ClusterMode`/`cfg.Addrs` don't exist yet (compile error).

- [ ] **Step 3: Add the fields and loading/validation logic**

In `config/config.go`, add two fields to `RocketMemConfig` (after `Addr`, config/config.go:394):

```go
	Addr string
	// ClusterMode, when true, treats Addrs as a rocket-mem cluster's seed
	// node addresses instead of using Addr for a single standalone node.
	// Rocket-mem's cluster topology is static (no gossip, no resharding), so
	// go-redis discovers the full node set once via CLUSTER SHARDS and
	// follows MOVED redirects itself -- no rediscovery polling needed.
	ClusterMode bool
	// Addrs holds the cluster's seed node addresses. Only used when
	// ClusterMode is true; any one live node is enough to seed topology
	// discovery, but listing all of them tolerates one seed being down at
	// startup.
	Addrs []string
```

In `LoadRocketMemConfig` (`config/config.go:428`), add loading right after the `addr` block (after line 445's closing brace):

```go
	if viper.IsSet("cache.rocket_mem.cluster_mode") {
		cfg.ClusterMode = viper.GetBool("cache.rocket_mem.cluster_mode")
	}
	if viper.IsSet("cache.rocket_mem.addrs") {
		cfg.Addrs = viper.GetStringSlice("cache.rocket_mem.addrs")
	}
```

And extend the existing fail-closed validation block (`config/config.go:483-487`) to also cover the new field:

```go
	if cfg.Enabled && (!cfg.TLS || cfg.Username == "" || cfg.Password == "") {
		return RocketMemConfig{}, fmt.Errorf(
			"cache.rocket_mem: enabled requires tls=true and a non-empty username/password " +
				"(rocket-mem defaults to a fully open ACL until a user is configured)")
	}
	if cfg.Enabled && cfg.ClusterMode && len(cfg.Addrs) == 0 {
		return RocketMemConfig{}, fmt.Errorf(
			"cache.rocket_mem: cluster_mode is true but addrs is empty " +
				"(list at least one cluster node's address)")
	}
	return cfg, nil
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/... -run TestLoadRocketMemConfig -v`
Expected: PASS (all `TestLoadRocketMemConfig_*` tests, old and new).

- [ ] **Step 5: Commit**

```bash
git add config/config.go config/config_test.go
git commit -m "feat(config): add cluster_mode/addrs to rocket-mem cache config"
```

---

## Task 2: Make `rocketmemcache.New` build a `ClusterClient` in cluster mode

**Files:**
- Modify: `internal/rocketmemcache/client.go` (the `Config` struct, `Client` struct, and `New`)
- Test: `internal/rocketmemcache/client_test.go`

**Interfaces:**
- Consumes: nothing new from Task 1 directly (this task's `Config` is separate from `config.RocketMemConfig` — Task 4 wires them together).
- Produces: `rocketmemcache.Config.ClusterMode bool`, `rocketmemcache.Config.Addrs []string`. `Client.rdb` becomes the unexported `rdbConn` interface (satisfied by both `*redis.Client` and `*redis.ClusterClient`) — Task 3 depends on being able to type-assert `c.rdb.(*redis.ClusterClient)`.

- [ ] **Step 1: Write the failing test**

Add to `internal/rocketmemcache/client_test.go`:

```go
func TestClient_ClusterMode_Unreachable_DegradesGracefully(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		ClusterMode:  true,
		Addrs:        []string{"127.0.0.1:1", "127.0.0.1:2"}, // nothing listens here
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
	assert.NotPanics(t, func() { c.Set("anything", []byte("x"), time.Minute) })
	assert.NotPanics(t, func() { c.Invalidate("anything") })
	assert.NotPanics(t, func() { assert.Error(t, c.Ping()) })
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rocketmemcache/... -run TestClient_ClusterMode -v`
Expected: FAIL — `Config.ClusterMode`/`Config.Addrs` don't exist yet (compile error).

- [ ] **Step 3: Implement cluster-mode construction**

In `internal/rocketmemcache/client.go`, add fields to `Config` (after `Addr string`, client.go:20):

```go
type Config struct {
	Addr string
	// ClusterMode, when true, builds a cluster-aware client against Addrs
	// (rocket-mem's static, gossip-free cluster: topology comes from one
	// CLUSTER SHARDS call at connect time, and go-redis follows MOVED
	// redirects itself from then on).
	ClusterMode bool
	// Addrs holds the cluster's seed node addresses. Only used when
	// ClusterMode is true.
	Addrs []string
	TLS   bool
```

Replace the concrete client field and add the new interface (client.go:48-51):

```go
// rdbConn is the subset of go-redis's Cmdable that Client actually calls.
// Both *redis.Client (standalone) and *redis.ClusterClient (cluster mode)
// satisfy it, so Client itself never needs to know which one it holds
// except in Keys, which needs cluster-specific fan-out (see Keys below).
type rdbConn interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Keys(ctx context.Context, pattern string) *redis.StringSliceCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
}

// Client implements cachekit.L2 against a real Rocket-mem (or any
// RESP2/3-compatible) server, standalone or clustered. Every method
// swallows errors per the design spec's fail-open contract: an unreachable
// or misbehaving Rocket-mem must degrade to a cache miss, never break a
// caller. Errors are not silently dropped anymore, though -- every degraded
// path logs a Warn (see Config.Logger) so an operator can tell a
// fully-broken L2 apart from a healthy one instead of both looking
// identical.
type Client struct {
	rdb    rdbConn
	logger *logrus.Logger
}
```

Note this requires adding `"context"` to the import block — it's already imported (client.go:4), so no change needed there.

Update `New` to branch on `cfg.ClusterMode` (client.go:56-86):

```go
func New(cfg Config) *Client {
	logger := cfg.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}

	var tlsConfig *tls.Config
	if cfg.TLS {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAPath != "" {
			if pemBytes, err := os.ReadFile(cfg.CAPath); err != nil {
				logger.WithError(err).WithField("ca_path", cfg.CAPath).
					Warn("rocketmemcache: failed to read CA cert, falling back to system trust store")
			} else if pool := x509.NewCertPool(); pool.AppendCertsFromPEM(pemBytes) {
				tlsConfig.RootCAs = pool
			} else {
				logger.WithField("ca_path", cfg.CAPath).
					Warn("rocketmemcache: CA cert file contained no valid certificates, falling back to system trust store")
			}
		}
	}

	var rdb rdbConn
	if cfg.ClusterMode {
		opts := &redis.ClusterOptions{
			Addrs:        cfg.Addrs,
			Username:     cfg.Username,
			Password:     cfg.Password,
			DialTimeout:  cfg.DialTimeout,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			PoolSize:     cfg.PoolSize,
		}
		if tlsConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		rdb = redis.NewClusterClient(opts)
	} else {
		opts := &redis.Options{
			Addr:         cfg.Addr,
			Username:     cfg.Username,
			Password:     cfg.Password,
			DialTimeout:  cfg.DialTimeout,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			PoolSize:     cfg.PoolSize,
		}
		if tlsConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		rdb = redis.NewClient(opts)
	}
	return &Client{rdb: rdb, logger: logger}
}
```

`pingCheck`, `Ping`, `Get`, `Set`, `Invalidate`, and `Close` are unchanged — they already only call methods `rdbConn` declares, so they compile against the interface with no edits.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/rocketmemcache/... -v`
Expected: PASS — every existing test (which never set `ClusterMode`, so `cfg.ClusterMode` defaults to `false` and behavior is identical to before) plus the new cluster-mode test.

- [ ] **Step 5: Commit**

```bash
git add internal/rocketmemcache/client.go internal/rocketmemcache/client_test.go
git commit -m "feat(rocketmemcache): build a ClusterClient when cluster_mode is set"
```

---

## Task 3: Fan out `Keys` across every cluster master

**Files:**
- Modify: `internal/rocketmemcache/client.go` (the `Keys` method)
- Test: `internal/rocketmemcache/client_test.go`

**Interfaces:**
- Consumes: `Client.rdb rdbConn` from Task 2; type-asserts it to `*redis.ClusterClient` to detect cluster mode.
- Produces: no new exported surface — `Keys(prefix string) []string`'s signature and cachekit.L2 contract are unchanged, only its cluster-mode behavior changes.

- [ ] **Step 1: Write the failing test**

A fully unit-testable fan-out requires two more listening (but non-cluster-protocol) ports so `ForEachMaster` has multiple nodes to iterate — a real fan-out round-trip is exercised by Task 5's live integration test instead. At the unit level, prove the single-node path (`ClusterMode: false`) is untouched, and that cluster-mode `Keys` against unreachable seeds still degrades to empty rather than panicking (this already passes after Task 2, since `Get`/`Set`/`Invalidate`/`Ping` were proven there — this step specifically covers `Keys`, which Task 2's test didn't call):

```go
func TestClient_ClusterMode_Unreachable_KeysDegradesToEmpty(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		ClusterMode:  true,
		Addrs:        []string{"127.0.0.1:1", "127.0.0.1:2"},
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rocketmemcache/... -run TestClient_ClusterMode_Unreachable_KeysDegradesToEmpty -v`
Expected: FAIL — with today's `Keys` (client.go:155-162), a `*redis.ClusterClient` with zero reachable nodes returns an error from a plain `c.rdb.Keys(...)` call, which the existing code already degrades to `nil` on error... actually re-check: this may already pass, since the existing single-path `Keys` logs+returns nil on any error regardless of client type. Run it first — if it already passes, this step confirms today's fallback path is safe, and Step 3 below is what actually changes the *reachable* cluster-mode fan-out behavior (covered by Task 5's live test, not a unit test). Either way, keep this test — it locks in the never-panic contract explicitly for cluster mode.

- [ ] **Step 3: Implement fan-out**

Replace `Keys` (client.go:150-162):

```go
// Keys returns every live key matching prefix* (Rocket-mem's KEYS supports a
// basic prefix-wildcard glob -- verified against a live instance in this
// package's integration suite). Any error degrades to an empty slice, same
// fail-open reasoning as every other method here, and is logged at Warn.
//
// In cluster mode, a plain KEYS call would only reach whichever single
// shard go-redis happens to route it to, silently missing every key that
// lives on the other masters -- so this fans out across every master via
// ForEachMaster and merges the results. Each live key lives on exactly one
// shard (Rocket-mem's slots are disjoint), so there's no need to
// deduplicate across shards.
func (c *Client) Keys(prefix string) []string {
	cc, ok := c.rdb.(*redis.ClusterClient)
	if !ok {
		keys, err := c.rdb.Keys(context.Background(), prefix+"*").Result()
		if err != nil {
			c.logger.WithError(err).WithField("prefix", prefix).Warn("rocketmemcache: Keys failed, degrading to empty")
			return nil
		}
		return keys
	}

	var all []string
	err := cc.ForEachMaster(context.Background(), func(ctx context.Context, shard *redis.Client) error {
		keys, err := shard.Keys(ctx, prefix+"*").Result()
		if err != nil {
			c.logger.WithError(err).WithField("prefix", prefix).WithField("shard", shard.Options().Addr).
				Warn("rocketmemcache: Keys failed on one shard, continuing with the rest")
			return nil // do not abort the other shards' fan-out over one shard's failure.
		}
		all = append(all, keys...)
		return nil
	})
	if err != nil {
		c.logger.WithError(err).WithField("prefix", prefix).Warn("rocketmemcache: cluster Keys fan-out failed, degrading to empty")
		return nil
	}
	return all
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/rocketmemcache/... -v`
Expected: PASS — all existing tests plus the new one.

- [ ] **Step 5: Commit**

```bash
git add internal/rocketmemcache/client.go internal/rocketmemcache/client_test.go
git commit -m "feat(rocketmemcache): fan Keys out across every cluster master"
```

---

## Task 4: Wire `cluster_mode`/`addrs` through the container and example config

**Files:**
- Modify: `internal/container/service_container.go:303-314` (the `rocketmemcache.New(...)` call)
- Modify: `.rocketvault.yaml.example:259-269` (the `rocket_mem:` block)

**Interfaces:**
- Consumes: `config.RocketMemConfig.ClusterMode`/`.Addrs` (Task 1), `rocketmemcache.Config.ClusterMode`/`.Addrs` (Task 2).
- Produces: nothing new — this is pure wiring, no new exported names.

- [ ] **Step 1: Update the container construction call**

In `internal/container/service_container.go`, add two lines to the existing `rocketmemcache.New(rocketmemcache.Config{...})` call (service_container.go:303-314):

```go
		container.rocketMemClient = rocketmemcache.New(rocketmemcache.Config{
			Addr:         config.RocketMemConfig.Addr,
			ClusterMode:  config.RocketMemConfig.ClusterMode,
			Addrs:        config.RocketMemConfig.Addrs,
			TLS:          config.RocketMemConfig.TLS,
			CAPath:       config.RocketMemConfig.CAPath,
			Username:     config.RocketMemConfig.Username,
			Password:     config.RocketMemConfig.Password,
			DialTimeout:  config.RocketMemConfig.DialTimeout,
			ReadTimeout:  config.RocketMemConfig.ReadTimeout,
			WriteTimeout: config.RocketMemConfig.WriteTimeout,
			PoolSize:     config.RocketMemConfig.PoolSize,
			Logger:       container.logger.Logger,
		})
```

- [ ] **Step 2: Update the example config**

In `.rocketvault.yaml.example`, replace the `rocket_mem:` block (lines 259-269) to document and default to the real 3-node cluster:

```yaml
  rocket_mem:
    enabled: false
    # cluster_mode/addrs target rocket-mem's cluster.conf-defined 3-node
    # cluster directly (see rocket-mem's cluster.conf: shard-a/b/c). Set
    # cluster_mode: false and use addr (singular) instead to point at one
    # standalone rocket-mem node.
    cluster_mode: true
    addrs:
      - "numericlabs.lxd:16379"
      - "numericlabs.lxd:16380"
      - "numericlabs.lxd:16381"
    addr: "numericlabs.lxd:16379"
    tls: true
    ca_path: ""
    username: ""
    password: ""
    dial_timeout: "1s"
    read_timeout: "500ms"
    write_timeout: "500ms"
    pool_size: 10
```

(Leave the reconnect-supervisor comment block and its three settings, lines 270-280, unchanged below this.)

- [ ] **Step 3: Build to verify it compiles**

Run: `go build ./...`
Expected: succeeds with no errors.

- [ ] **Step 4: Run the full non-integration test suite**

Run: `go test ./...`
Expected: PASS (no build-tagged live tests run here).

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go .rocketvault.yaml.example
git commit -m "feat(container): wire cluster_mode/addrs through to rocketmemcache.New"
```

---

## Task 5: Live integration tests against a real 3-node rocket-mem cluster

**Files:**
- Modify: `internal/rocketmemcache/client_integration_test.go` (add cluster-mode tests behind the existing `integration` build tag)

**Interfaces:**
- Consumes: `rocketmemcache.Config.ClusterMode`/`.Addrs` (Task 2), `Client.Keys` fan-out (Task 3).
- Produces: nothing new — test-only.

**Precondition (not part of this plan — a separate `rocket-mem` repo concern):** a real 3-node rocket-mem cluster reachable per `rocket-mem`'s `cluster.conf`/`.claude/manual-testing.md`, with matching ACL users provisioned on all three nodes and TLS configured consistently (per this session's earlier investigation, shard-b/c TLS wiring was still in progress at time of writing — confirm it's finished before running this task's tests).

- [ ] **Step 1: Add cluster env-var helper and round-trip test**

Add to `internal/rocketmemcache/client_integration_test.go`:

```go
func testClusterAddrs() []string {
	if a := os.Getenv("ROCKETMEM_TEST_CLUSTER_ADDRS"); a != "" {
		return strings.Split(a, ",")
	}
	return []string{"127.0.0.1:16379", "127.0.0.1:16380", "127.0.0.1:16381"}
}

func newTestClusterClient(t *testing.T) *rocketmemcache.Client {
	t.Helper()
	c := rocketmemcache.New(rocketmemcache.Config{
		ClusterMode:  true,
		Addrs:        testClusterAddrs(),
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		PoolSize:     5,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClusterClient_SetGet_RoundTrip(t *testing.T) {
	c := newTestClusterClient(t)
	key := "rocketmemcache_test:cluster_roundtrip:" + t.Name()

	c.Set(key, []byte("hello-cluster"), 30*time.Second)
	got, ok := c.Get(key)
	require.True(t, ok)
	assert.Equal(t, "hello-cluster", string(got))

	c.Invalidate(key)
	_, ok = c.Get(key)
	assert.False(t, ok, "Get after Invalidate must miss")
}
```

This proves go-redis is correctly following any `MOVED` redirects for whichever shard `key`'s slot happens to land on — the test never needs to know which node that is.

- [ ] **Step 2: Add a fan-out coverage test**

```go
func TestClusterClient_Keys_FansOutAcrossShards(t *testing.T) {
	c := newTestClusterClient(t)
	prefix := "rocketmemcache_test:cluster_keys:" + t.Name() + ":"

	// Enough distinct keys that, with 16384 slots spread across 3 shards,
	// at least one lands on each shard with overwhelming probability --
	// this is what actually exercises ForEachMaster's fan-out instead of
	// happening to pass against a single shard.
	var want []string
	for i := 0; i < 30; i++ {
		k := prefix + fmt.Sprintf("%d", i)
		c.Set(k, []byte("v"), 30*time.Second)
		want = append(want, k)
	}
	t.Cleanup(func() {
		for _, k := range want {
			c.Invalidate(k)
		}
	})

	got := c.Keys(prefix)
	assert.ElementsMatch(t, want, got)
}
```

Add `"fmt"` and `"strings"` to the file's import block alongside the existing `"os"`, `"testing"`, `"time"`.

- [ ] **Step 3: Run the integration suite against a live cluster**

Run: `ROCKETMEM_TEST_CLUSTER_ADDRS=numericlabs.lxd:16379,numericlabs.lxd:16380,numericlabs.lxd:16381 go test -tags=integration ./internal/rocketmemcache/... -run TestClusterClient -v`
Expected: PASS. If it fails with an ACL/auth error, the cluster's three nodes don't yet have matching credentials provisioned — that's a `rocket-mem`-side config step, not a code bug in this plan.

- [ ] **Step 4: Run the full integration suite once more to confirm no regression**

Run: `go test -tags=integration ./internal/rocketmemcache/... -v`
Expected: PASS (both the pre-existing standalone-node tests and the new cluster tests).

- [ ] **Step 5: Commit**

```bash
git add internal/rocketmemcache/client_integration_test.go
git commit -m "test(rocketmemcache): add live cluster-mode integration coverage"
```

---

## Final Verification

- [ ] `go build ./...` succeeds.
- [ ] `go test ./...` passes (full non-integration suite).
- [ ] `go vet ./...` is clean.
- [ ] Manually confirm `.rocketvault.yaml.example` still parses (`go run . serve --config .rocketvault.yaml.example --dry-run` if such a flag exists, otherwise a quick Viper unmarshal smoke test) with `cache.rocket_mem.enabled: false` (the shipped default) — the cluster wiring must never activate for anyone who hasn't explicitly turned it on.
