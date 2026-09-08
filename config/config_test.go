package config

import (
	"net"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reset clears all viper state before each test to ensure a clean slate.
func reset() {
	viper.Reset()
}

// ---------------------------------------------------------------------------
// TestLoadSoftDeleteConfig_Defaults
// ---------------------------------------------------------------------------

func TestLoadSoftDeleteConfig_Defaults(t *testing.T) {
	reset()

	cfg := LoadSoftDeleteConfig()

	assert.True(t, cfg.Enabled, "default Enabled should be true")
	assert.Equal(t, 30, cfg.RetentionDays, "default RetentionDays should be 30")
	assert.False(t, cfg.PurgeProtection, "default PurgeProtection should be false")
}

// ---------------------------------------------------------------------------
// TestLoadSoftDeleteConfig_AllSet
// ---------------------------------------------------------------------------

func TestLoadSoftDeleteConfig_AllSet(t *testing.T) {
	reset()

	viper.Set("soft_delete.enabled", false)
	viper.Set("soft_delete.retention_days", 90)
	viper.Set("soft_delete.purge_protection", true)

	cfg := LoadSoftDeleteConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, 90, cfg.RetentionDays)
	assert.True(t, cfg.PurgeProtection)
}

// ---------------------------------------------------------------------------
// TestLoadSoftDeleteConfig_PartialSet — only retention_days set
// ---------------------------------------------------------------------------

func TestLoadSoftDeleteConfig_PartialSet(t *testing.T) {
	reset()

	viper.Set("soft_delete.retention_days", 45)

	cfg := LoadSoftDeleteConfig()

	// Defaults for the unset keys.
	assert.True(t, cfg.Enabled, "Enabled should still use the default (true)")
	assert.Equal(t, 45, cfg.RetentionDays)
	assert.False(t, cfg.PurgeProtection, "PurgeProtection should still use the default (false)")
}

// ---------------------------------------------------------------------------
// TestLoadSoftDeleteConfig_EnabledFalse — only enabled set to false
// ---------------------------------------------------------------------------

func TestLoadSoftDeleteConfig_EnabledFalse(t *testing.T) {
	reset()

	viper.Set("soft_delete.enabled", false)

	cfg := LoadSoftDeleteConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, 30, cfg.RetentionDays, "RetentionDays should still be the default")
	assert.False(t, cfg.PurgeProtection)
}

// ---------------------------------------------------------------------------
// TestLoadSoftDeleteConfig_PurgeProtectionTrue — only purge_protection set
// ---------------------------------------------------------------------------

func TestLoadSoftDeleteConfig_PurgeProtectionTrue(t *testing.T) {
	reset()

	viper.Set("soft_delete.purge_protection", true)

	cfg := LoadSoftDeleteConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 30, cfg.RetentionDays)
	assert.True(t, cfg.PurgeProtection)
}

// ---------------------------------------------------------------------------
// TestSoftDeleteConfig_Struct — zero-value instantiation
// ---------------------------------------------------------------------------

func TestSoftDeleteConfig_Struct(t *testing.T) {
	var cfg SoftDeleteConfig
	// Zero-value booleans are false, zero-value int is 0.
	assert.False(t, cfg.Enabled)
	assert.Equal(t, 0, cfg.RetentionDays)
	assert.False(t, cfg.PurgeProtection)
}

// ---------------------------------------------------------------------------
// TestConfig_Struct — Config can be instantiated with ListenAddr
// ---------------------------------------------------------------------------

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		ListenAddr: ":8080",
	}
	assert.Equal(t, ":8080", cfg.ListenAddr)
	assert.Nil(t, cfg.Logger)
	assert.Nil(t, cfg.HTTPTransport)
	assert.Nil(t, cfg.TrustedProxyIPs)
	assert.Nil(t, cfg.TrustedProxyNets)
}

// ---------------------------------------------------------------------------
// TestConfig_TrustedProxyFields — verify IP/network fields work
// ---------------------------------------------------------------------------

func TestConfig_TrustedProxyFields(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")

	cfg := Config{
		ListenAddr:       ":9090",
		TrustedProxyIPs:  []*net.IP{&ip},
		TrustedProxyNets: []*net.IPNet{ipNet},
	}

	assert.Len(t, cfg.TrustedProxyIPs, 1)
	assert.Len(t, cfg.TrustedProxyNets, 1)
}

// ---------------------------------------------------------------------------
// TestConfig_SoftDeleteNested — SoftDelete field inside Config
// ---------------------------------------------------------------------------

func TestConfig_SoftDeleteNested(t *testing.T) {
	cfg := Config{
		SoftDelete: SoftDeleteConfig{
			Enabled:         true,
			RetentionDays:   60,
			PurgeProtection: true,
		},
	}
	assert.True(t, cfg.SoftDelete.Enabled)
	assert.Equal(t, 60, cfg.SoftDelete.RetentionDays)
	assert.True(t, cfg.SoftDelete.PurgeProtection)
}

// ---------------------------------------------------------------------------
// TestLoadSoftDeleteConfig_RetentionDaysZero — zero is a valid override
// ---------------------------------------------------------------------------

func TestLoadSoftDeleteConfig_RetentionDaysZero(t *testing.T) {
	reset()

	// Explicitly set retention_days to 0 — IsSet should return true.
	viper.Set("soft_delete.retention_days", 0)

	cfg := LoadSoftDeleteConfig()

	assert.Equal(t, 0, cfg.RetentionDays, "explicitly configured zero should be respected")
}

// ---------------------------------------------------------------------------
// TestLoadMonitoringConfig_Defaults
// ---------------------------------------------------------------------------

func TestLoadMonitoringConfig_Defaults(t *testing.T) {
	reset()

	cfg := LoadMonitoringConfig()

	assert.True(t, cfg.EnableMetrics, "default EnableMetrics should be true")
	assert.Equal(t, 60*time.Second, cfg.MetricsInterval, "default MetricsInterval should be 60s")
	assert.Equal(t, 100*time.Millisecond, cfg.SlowQueryThreshold, "default SlowQueryThreshold should be 100ms")
}

// ---------------------------------------------------------------------------
// TestLoadMonitoringConfig_AllSet
// ---------------------------------------------------------------------------

func TestLoadMonitoringConfig_AllSet(t *testing.T) {
	reset()

	viper.Set("monitoring.enable_metrics", false)
	viper.Set("monitoring.metrics_interval", "30s")
	viper.Set("monitoring.slow_query_threshold", "500ms")

	cfg := LoadMonitoringConfig()

	assert.False(t, cfg.EnableMetrics)
	assert.Equal(t, 30*time.Second, cfg.MetricsInterval)
	assert.Equal(t, 500*time.Millisecond, cfg.SlowQueryThreshold)
}

// ---------------------------------------------------------------------------
// TestLoadMonitoringConfig_PartialSet — only slow_query_threshold set
// ---------------------------------------------------------------------------

func TestLoadMonitoringConfig_PartialSet(t *testing.T) {
	reset()

	viper.Set("monitoring.slow_query_threshold", "2s")

	cfg := LoadMonitoringConfig()

	assert.True(t, cfg.EnableMetrics, "EnableMetrics should still use the default (true)")
	assert.Equal(t, 60*time.Second, cfg.MetricsInterval, "MetricsInterval should still use the default (60s)")
	assert.Equal(t, 2*time.Second, cfg.SlowQueryThreshold)
}

// ---------------------------------------------------------------------------
// TestLoadCacheConfig_Defaults
// ---------------------------------------------------------------------------

func TestLoadCacheConfig_Defaults(t *testing.T) {
	reset()

	cfg, err := LoadCacheConfig()
	require.NoError(t, err)

	assert.True(t, cfg.Secrets.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.Secrets.TTL)
	assert.Equal(t, time.Minute, cfg.Secrets.CleanupInterval)
	assert.Equal(t, 1000, cfg.Secrets.MaxEntries)

	assert.True(t, cfg.Keys.Enabled)
	assert.Equal(t, 60*time.Second, cfg.Keys.TTL)
	assert.Equal(t, 30*time.Second, cfg.Keys.CleanupInterval)
	assert.Equal(t, 500, cfg.Keys.MaxEntries)

	assert.True(t, cfg.Vaults.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.Vaults.TTL)
	assert.Equal(t, time.Minute, cfg.Vaults.CleanupInterval)
	assert.Equal(t, 500, cfg.Vaults.MaxEntries)

	assert.True(t, cfg.Certificates.Enabled, "certificates has a consumer (internal/certcache), must default on")
	assert.Equal(t, 5*time.Minute, cfg.Certificates.TTL)
	assert.Equal(t, time.Minute, cfg.Certificates.CleanupInterval)
	assert.Equal(t, 500, cfg.Certificates.MaxEntries)

	assert.False(t, cfg.Users.Enabled, "users has no consumer yet, must default off")
}

// ---------------------------------------------------------------------------
// TestLoadCacheConfig_OverridesRead
// ---------------------------------------------------------------------------

func TestLoadCacheConfig_OverridesRead(t *testing.T) {
	reset()
	viper.Set("cache.secrets.enabled", false)
	viper.Set("cache.keys.ttl", "45s")
	viper.Set("cache.vaults.max_entries", 999)
	viper.Set("cache.certificates.enabled", false)

	cfg, err := LoadCacheConfig()
	require.NoError(t, err)

	assert.False(t, cfg.Secrets.Enabled)
	assert.Equal(t, 45*time.Second, cfg.Keys.TTL)
	assert.Equal(t, 999, cfg.Vaults.MaxEntries)
	assert.False(t, cfg.Certificates.Enabled, "explicit override to false must win over the true default")
}

// ---------------------------------------------------------------------------
// TestLoadCacheConfig_InvalidTTLReturnsError
// ---------------------------------------------------------------------------

func TestLoadCacheConfig_InvalidTTLReturnsError(t *testing.T) {
	reset()
	viper.Set("cache.secrets.ttl", "0s")

	_, err := LoadCacheConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache.secrets")
}

// ---------------------------------------------------------------------------
// TestLoadRotationConfig_Defaults
// ---------------------------------------------------------------------------

func TestLoadRotationConfig_Defaults(t *testing.T) {
	reset()

	cfg := LoadRotationConfig()

	assert.True(t, cfg.Secrets.Enabled, "default Secrets.Enabled should be true")
	assert.Equal(t, time.Hour, cfg.Secrets.Interval, "default Secrets.Interval should be 1h")
	assert.True(t, cfg.Certificates.Enabled, "default Certificates.Enabled should be true")
	assert.Equal(t, 24*time.Hour, cfg.Certificates.Interval, "default Certificates.Interval should be 24h")
	assert.True(t, cfg.Keys.Enabled, "default Keys.Enabled should be true")
	assert.Equal(t, time.Hour, cfg.Keys.Interval, "default Keys.Interval should be 1h")
}

// ---------------------------------------------------------------------------
// TestLoadRotationConfig_OverridesFromViper
// ---------------------------------------------------------------------------

func TestLoadRotationConfig_OverridesFromViper(t *testing.T) {
	reset()

	viper.Set("rotation.secrets.enabled", false)
	viper.Set("rotation.keys.interval", "30m")
	viper.Set("rotation.certificates.enabled", false)

	cfg := LoadRotationConfig()

	assert.False(t, cfg.Secrets.Enabled, "Secrets.Enabled should be false when explicitly set")
	assert.Equal(t, time.Hour, cfg.Secrets.Interval, "untouched Secrets.Interval keeps its default (1h)")
	assert.Equal(t, 30*time.Minute, cfg.Keys.Interval, "Keys.Interval should be 30m when explicitly set")
	assert.False(t, cfg.Certificates.Enabled, "Certificates.Enabled should be false when explicitly set")
}

// ---------------------------------------------------------------------------
// TestLoadRotationConfig_PartialSet — only certificates.interval set
// ---------------------------------------------------------------------------

func TestLoadRotationConfig_PartialSet(t *testing.T) {
	reset()

	viper.Set("rotation.certificates.interval", "12h")

	cfg := LoadRotationConfig()

	assert.True(t, cfg.Secrets.Enabled, "Secrets.Enabled should still use the default (true)")
	assert.Equal(t, time.Hour, cfg.Secrets.Interval, "Secrets.Interval should still use the default (1h)")
	assert.True(t, cfg.Certificates.Enabled, "Certificates.Enabled should still use the default (true)")
	assert.Equal(t, 12*time.Hour, cfg.Certificates.Interval)
	assert.True(t, cfg.Keys.Enabled, "Keys.Enabled should still use the default (true)")
	assert.Equal(t, time.Hour, cfg.Keys.Interval, "Keys.Interval should still use the default (1h)")
}

// ---------------------------------------------------------------------------
// TestLoadRocketMemConfig_* tests
// ---------------------------------------------------------------------------

func resetRocketMemViperKeys(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"cache.rocket_mem.enabled", "cache.rocket_mem.addr", "cache.rocket_mem.tls",
		"cache.rocket_mem.username", "cache.rocket_mem.password",
		"cache.rocket_mem.dial_timeout", "cache.rocket_mem.read_timeout",
		"cache.rocket_mem.write_timeout", "cache.rocket_mem.pool_size",
		"cache.rocket_mem.reconnect_steady_state_interval", "cache.rocket_mem.reconnect_initial_backoff",
		"cache.rocket_mem.reconnect_max_backoff", "cache.rocket_mem.reconnect_backoff_multiplier",
		"cache.rocket_mem.cluster_mode", "cache.rocket_mem.addrs",
	} {
		viper.Set(k, nil)
	}
}

func TestLoadRocketMemConfig_DefaultsDisabled(t *testing.T) {
	resetRocketMemViperKeys(t)
	cfg, err := LoadRocketMemConfig()
	require.NoError(t, err)
	assert.False(t, cfg.Enabled)
}

func TestLoadRocketMemConfig_EnabledWithoutTLS_FailsClosed(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.tls", false)
	viper.Set("cache.rocket_mem.username", "vault")
	viper.Set("cache.rocket_mem.password", "secret")

	_, err := LoadRocketMemConfig()
	assert.Error(t, err, "enabling rocket_mem without TLS must fail startup, not degrade silently")
}

func TestLoadRocketMemConfig_EnabledWithoutCredentials_FailsClosed(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.tls", true)
	viper.Set("cache.rocket_mem.username", "")
	viper.Set("cache.rocket_mem.password", "")

	_, err := LoadRocketMemConfig()
	assert.Error(t, err, "enabling rocket_mem against a would-be-open ACL must fail startup")
}

func TestLoadRocketMemConfig_EnabledWithTLSAndCredentials_Succeeds(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.enabled", true)
	viper.Set("cache.rocket_mem.addr", "rocketmem.internal:6380")
	viper.Set("cache.rocket_mem.tls", true)
	viper.Set("cache.rocket_mem.username", "rocketvault")
	viper.Set("cache.rocket_mem.password", "s3cret")

	cfg, err := LoadRocketMemConfig()
	require.NoError(t, err)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "rocketmem.internal:6380", cfg.Addr)
	assert.True(t, cfg.TLS)
	assert.Equal(t, "rocketvault", cfg.Username)
	assert.Equal(t, "s3cret", cfg.Password)
}

func TestLoadRocketMemConfig_DefaultTimeoutsAndPoolSize(t *testing.T) {
	resetRocketMemViperKeys(t)
	cfg, err := LoadRocketMemConfig()
	require.NoError(t, err)
	assert.Equal(t, 100*time.Millisecond, cfg.DialTimeout)
	assert.Equal(t, 100*time.Millisecond, cfg.ReadTimeout)
	assert.Equal(t, 100*time.Millisecond, cfg.WriteTimeout)
	assert.Equal(t, 10, cfg.PoolSize)
}

func TestLoadRocketMemConfig_DefaultReconnectSettings(t *testing.T) {
	resetRocketMemViperKeys(t)
	cfg, err := LoadRocketMemConfig()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.ReconnectSteadyStateInterval)
	assert.Equal(t, 1*time.Second, cfg.ReconnectInitialBackoff)
	assert.Equal(t, 60*time.Second, cfg.ReconnectMaxBackoff)
	assert.Equal(t, 2.0, cfg.ReconnectBackoffMultiplier)
}

func TestLoadRocketMemConfig_OverrideReconnectSettings(t *testing.T) {
	resetRocketMemViperKeys(t)
	viper.Set("cache.rocket_mem.reconnect_max_backoff", "120s")
	cfg, err := LoadRocketMemConfig()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.ReconnectSteadyStateInterval, "unset fields should use defaults")
	assert.Equal(t, 1*time.Second, cfg.ReconnectInitialBackoff, "unset fields should use defaults")
	assert.Equal(t, 120*time.Second, cfg.ReconnectMaxBackoff)
	assert.Equal(t, 2.0, cfg.ReconnectBackoffMultiplier, "unset fields should use defaults")
}

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
