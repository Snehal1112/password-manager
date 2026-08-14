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

	assert.False(t, cfg.Certificates.Enabled, "certificates has no consumer yet, must default off")
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
	viper.Set("cache.certificates.enabled", true)

	cfg, err := LoadCacheConfig()
	require.NoError(t, err)

	assert.False(t, cfg.Secrets.Enabled)
	assert.Equal(t, 45*time.Second, cfg.Keys.TTL)
	assert.Equal(t, 999, cfg.Vaults.MaxEntries)
	assert.True(t, cfg.Certificates.Enabled)
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
