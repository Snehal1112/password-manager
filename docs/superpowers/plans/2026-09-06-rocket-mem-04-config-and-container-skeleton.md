# Rocket-mem Tiered Cache — Plan 04: Config + Container Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load `cache.rocket_mem.*` config with a fail-closed startup guard (enabled requires TLS + credentials), and construct one shared `rocketmemcache.Client` in the container when enabled — not yet wired into any domain cache.

**Architecture:** A standalone `config.LoadRocketMemConfig() (RocketMemConfig, error)`, mirroring this codebase's existing standalone loaders (`LoadSoftDeleteConfig`, `LoadCacheConfig`) rather than folding into `CacheConfig` (Rocket-mem isn't a per-domain cache, it's cross-cutting). The container calls it once, alongside `LoadCacheConfig`, and stores the resulting client unexported — no `ServiceContainerInterface` method is added, since nothing outside the container needs one yet (Plans 05-08 consume the field directly from within the same package), avoiding the mock/test-double fan-out cost this codebase's own knowledge base flags for every new interface method.

**Tech Stack:** Viper (existing config pattern), Go 1.25.

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (see "Configuration" section)

## Global Constraints

- `cache.rocket_mem.enabled: true` with `tls: false` or an empty `username`/`password` must fail `LoadRocketMemConfig` with a clear error — this is the fail-closed guard the spec requires, mirroring `master_key`'s existing validate-or-abort-startup pattern (`bootstrap.ConfigurationValidator.ValidateMasterKey`).
- `cache.rocket_mem.enabled` defaults to `false` — a deployment with no `cache.rocket_mem` section in `.rocketvault.yaml` must build, start, and behave identically to before this plan, with zero new fields on `ServiceContainerInterface`.
- `go build ./...` and `go test ./...` must stay green after every task.

---

### Task 1: `config.RocketMemConfig` + `LoadRocketMemConfig` with fail-closed validation

**Files:**
- Modify: `config/config.go`
- Test: `config/config_test.go`

**Interfaces:**
- Produces: `config.RocketMemConfig` struct (`Enabled bool`, `Addr string`, `TLS bool`, `Username string`, `Password string`, `DialTimeout/ReadTimeout/WriteTimeout time.Duration`, `PoolSize int`), `config.LoadRocketMemConfig() (RocketMemConfig, error)`.

- [ ] **Step 1: Write the failing test**

```go
// append to config/config_test.go
package config_test

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

func resetRocketMemViperKeys(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"cache.rocket_mem.enabled", "cache.rocket_mem.addr", "cache.rocket_mem.tls",
		"cache.rocket_mem.username", "cache.rocket_mem.password",
		"cache.rocket_mem.dial_timeout", "cache.rocket_mem.read_timeout",
		"cache.rocket_mem.write_timeout", "cache.rocket_mem.pool_size",
	} {
		viper.Set(k, nil)
	}
}

func TestLoadRocketMemConfig_DefaultsDisabled(t *testing.T) {
	resetRocketMemViperKeys(t)
	cfg, err := config.LoadRocketMemConfig()
	require.NoError(t, err)
	assert.False(t, cfg.Enabled)
}

func TestLoadRocketMemConfig_EnabledWithoutTLS_FailsClosed(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.tls", false)
	viper.Set("cache.rocket_mem.username", "vault")
	viper.Set("cache.rocket_mem.password", "secret")

	_, err := config.LoadRocketMemConfig()
	assert.Error(t, err, "enabling rocket_mem without TLS must fail startup, not degrade silently")
}

func TestLoadRocketMemConfig_EnabledWithoutCredentials_FailsClosed(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.tls", true)
	viper.Set("cache.rocket_mem.username", "")
	viper.Set("cache.rocket_mem.password", "")

	_, err := config.LoadRocketMemConfig()
	assert.Error(t, err, "enabling rocket_mem against a would-be-open ACL must fail startup")
}

func TestLoadRocketMemConfig_EnabledWithTLSAndCredentials_Succeeds(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.addr", "rocketmem.internal:6380")
	viper.Set("cache.rocket_mem.tls", true)
	viper.Set("cache.rocket_mem.username", "rocketvault")
	viper.Set("cache.rocket_mem.password", "s3cret")

	cfg, err := config.LoadRocketMemConfig()
	require.NoError(t, err)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "rocketmem.internal:6380", cfg.Addr)
	assert.True(t, cfg.TLS)
	assert.Equal(t, "rocketvault", cfg.Username)
	assert.Equal(t, "s3cret", cfg.Password)
}

func TestLoadRocketMemConfig_DefaultTimeoutsAndPoolSize(t *testing.T) {
	resetRocketMemViperKeys(t)
	cfg, err := config.LoadRocketMemConfig()
	require.NoError(t, err)
	assert.Equal(t, 100*time.Millisecond, cfg.DialTimeout)
	assert.Equal(t, 100*time.Millisecond, cfg.ReadTimeout)
	assert.Equal(t, 100*time.Millisecond, cfg.WriteTimeout)
	assert.Equal(t, 10, cfg.PoolSize)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/... -run TestLoadRocketMemConfig -v`
Expected: FAIL (build error — `config.RocketMemConfig`/`LoadRocketMemConfig` do not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// append to config/config.go

// RocketMemConfig holds connection settings for the optional shared
// Rocket-mem L2 cache tier (see internal/rocketmemcache and
// internal/cachekit.TieredCache). Disabled by default -- a deployment with
// no cache.rocket_mem section behaves identically to before this existed.
type RocketMemConfig struct {
	Enabled      bool
	Addr         string
	TLS          bool
	Username     string
	Password     string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
}

// LoadRocketMemConfig reads cache.rocket_mem.* from Viper. Fails closed:
// Rocket-mem defaults to a fully open ACL until at least one user is
// configured (verified against its source), so enabling this cache without
// both TLS and credentials would hand a network-adjacent attacker
// cache-poisoning/DoS capability even though cached payloads are
// encrypted. Mirrors this codebase's existing pattern of aborting startup
// on a bad security-relevant config (e.g. master_key) rather than
// degrading silently.
func LoadRocketMemConfig() (RocketMemConfig, error) {
	cfg := RocketMemConfig{
		Addr:         "127.0.0.1:6379",
		DialTimeout:  100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		PoolSize:     10,
	}
	if viper.IsSet("cache.rocket_mem.enabled") {
		cfg.Enabled = viper.GetBool("cache.rocket_mem.enabled")
	}
	if viper.IsSet("cache.rocket_mem.addr") {
		cfg.Addr = viper.GetString("cache.rocket_mem.addr")
	}
	if viper.IsSet("cache.rocket_mem.tls") {
		cfg.TLS = viper.GetBool("cache.rocket_mem.tls")
	}
	if viper.IsSet("cache.rocket_mem.username") {
		cfg.Username = viper.GetString("cache.rocket_mem.username")
	}
	if viper.IsSet("cache.rocket_mem.password") {
		cfg.Password = viper.GetString("cache.rocket_mem.password")
	}
	if viper.IsSet("cache.rocket_mem.dial_timeout") {
		cfg.DialTimeout = viper.GetDuration("cache.rocket_mem.dial_timeout")
	}
	if viper.IsSet("cache.rocket_mem.read_timeout") {
		cfg.ReadTimeout = viper.GetDuration("cache.rocket_mem.read_timeout")
	}
	if viper.IsSet("cache.rocket_mem.write_timeout") {
		cfg.WriteTimeout = viper.GetDuration("cache.rocket_mem.write_timeout")
	}
	if viper.IsSet("cache.rocket_mem.pool_size") {
		cfg.PoolSize = viper.GetInt("cache.rocket_mem.pool_size")
	}

	if cfg.Enabled && (!cfg.TLS || cfg.Username == "" || cfg.Password == "") {
		return RocketMemConfig{}, fmt.Errorf(
			"cache.rocket_mem: enabled requires tls=true and a non-empty username/password " +
				"(rocket-mem defaults to a fully open ACL until a user is configured)")
	}
	return cfg, nil
}
```

`fmt` and `time` are already imported in `config.go`; `viper` is already imported.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./config/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add config/config.go config/config_test.go
git commit -m "feat(config): add RocketMemConfig with fail-closed TLS/auth guard"
```

---

### Task 2: Container skeleton — construct + close the shared client

**Files:**
- Modify: `internal/container/service_container.go`
- Test: `internal/container/container_test.go`

**Interfaces:**
- Consumes: `config.LoadRocketMemConfig` (Task 1), `rocketmemcache.New`/`Client.Close` (Plan 03).
- Produces: unexported `ServiceContainer.rocketMemClient *rocketmemcache.Client` field, constructed in `NewServiceContainer` (nil when disabled), closed in `Close()`. No new `ServiceContainerInterface` method.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/container/container_test.go
package container_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/container"
)

func TestNewServiceContainer_RocketMemDisabledByDefault_NoClientConstructed(t *testing.T) {
	viper.Set("cache.rocket_mem.enabled", nil)
	c, err := container.NewServiceContainer(container.Config{
		Logger: testLogger(), // reuse whatever helper this test file already uses to build a *logging.Logger
	})
	require.NoError(t, err)
	assert.NotPanics(t, func() { _ = c.Close() }, "Close must be a no-op-safe even with rocket_mem disabled")
}

func TestNewServiceContainer_RocketMemEnabled_ClientConstructedAndClosed(t *testing.T) {
	rmCfg := config.RocketMemConfig{
		Enabled: true, Addr: "127.0.0.1:1", TLS: true, Username: "u", Password: "p",
	}
	cacheCfg, err := config.LoadCacheConfig()
	require.NoError(t, err)
	c, err := container.NewServiceContainer(container.Config{
		Logger:          testLogger(),
		CacheConfig:     &cacheCfg,
		RocketMemConfig: &rmCfg,
	})
	require.NoError(t, err)
	// go-redis dials lazily, so constructing against an unreachable address
	// (127.0.0.1:1) must not fail container construction -- only actual
	// Get/Set calls degrade (proven in Plan 03's tests).
	assert.NoError(t, c.Close())
}
```

Check `internal/container/container_test.go`'s existing top of file for the actual helper name this suite already uses to build a test logger/`Config` (e.g. it may already have a `testLogger()` or similar fixture — reuse it verbatim rather than inventing a second one; if none exists, add a small one following whatever pattern the file's other tests use to construct a `*logging.Logger`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/container/... -run TestNewServiceContainer_RocketMem -v`
Expected: FAIL (build error — `container.Config` has no `RocketMemConfig` field yet)

- [ ] **Step 3: Write minimal implementation**

In `internal/container/service_container.go`:

1. Add the import: `"rocketvault/internal/rocketmemcache"`.
2. Add a field to the container's config struct (the struct containing `CacheConfig *rvconfig.CacheConfig`, per the earlier grep at line ~235):

```go
// RocketMemConfig overrides the loaded cache.rocket_mem.* config, mirroring
// CacheConfig's own override field -- nil means "load from Viper".
RocketMemConfig *rvconfig.RocketMemConfig
```

3. Add a field to `ServiceContainer`:

```go
// rocketMemClient is the single shared L2 connection backing every
// domain's TieredCache (Plans 05-08). nil when cache.rocket_mem is
// disabled. Not exposed via ServiceContainerInterface -- nothing outside
// this package constructs a TieredCache, so no getter is needed yet.
rocketMemClient *rocketmemcache.Client
```

4. In `NewServiceContainer`, right after the existing `CacheConfig` load block (the `if config.CacheConfig == nil { ... }` block from the earlier read):

```go
if config.RocketMemConfig == nil {
	loaded, err := rvconfig.LoadRocketMemConfig()
	if err != nil {
		return nil, fmt.Errorf("load rocket_mem config: %w", err)
	}
	config.RocketMemConfig = &loaded
}
if config.RocketMemConfig.Enabled {
	container.rocketMemClient = rocketmemcache.New(rocketmemcache.Config{
		Addr:         config.RocketMemConfig.Addr,
		TLS:          config.RocketMemConfig.TLS,
		Username:     config.RocketMemConfig.Username,
		Password:     config.RocketMemConfig.Password,
		DialTimeout:  config.RocketMemConfig.DialTimeout,
		ReadTimeout:  config.RocketMemConfig.ReadTimeout,
		WriteTimeout: config.RocketMemConfig.WriteTimeout,
		PoolSize:     config.RocketMemConfig.PoolSize,
	})
}
```

5. In `Close()` (the method containing the existing `if c.secretCache != nil { c.secretCache.Stop() }`-style blocks around line 894-912):

```go
if c.rocketMemClient != nil {
	if err := c.rocketMemClient.Close(); err != nil {
		c.logger.WithError(err).Warn("Failed to close rocket-mem client")
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/container/... -v`
Expected: PASS

Run: `go build ./... && go vet ./... && go test ./...` (whole repo, no tags)
Expected: identical outcome to before this plan started — `rocketMemClient` is nil by default (config defaults `Enabled: false`), so every existing container-construction path is unaffected.

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go internal/container/container_test.go
git commit -m "feat(container): construct shared rocket-mem client when enabled"
```
