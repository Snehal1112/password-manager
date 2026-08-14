package config

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/logging"

	"github.com/spf13/viper"
)

// SoftDeleteConfig controls soft-delete and purge protection behaviour.
type SoftDeleteConfig struct {
	Enabled         bool `mapstructure:"enabled"`
	RetentionDays   int  `mapstructure:"retention_days"`
	PurgeProtection bool `mapstructure:"purge_protection"`
}

// LoadSoftDeleteConfig reads soft-delete settings from Viper.
// Falls back to safe defaults if keys are not set.
func LoadSoftDeleteConfig() SoftDeleteConfig {
	cfg := SoftDeleteConfig{
		Enabled:         true,
		RetentionDays:   30,
		PurgeProtection: false,
	}
	if viper.IsSet("soft_delete.enabled") {
		cfg.Enabled = viper.GetBool("soft_delete.enabled")
	}
	if viper.IsSet("soft_delete.retention_days") {
		cfg.RetentionDays = viper.GetInt("soft_delete.retention_days")
	}
	if viper.IsSet("soft_delete.purge_protection") {
		cfg.PurgeProtection = viper.GetBool("soft_delete.purge_protection")
	}
	return cfg
}

// MonitoringConfig controls Prometheus metrics exposure and slow-query detection.
type MonitoringConfig struct {
	EnableMetrics      bool          `mapstructure:"enable_metrics"`
	MetricsInterval    time.Duration `mapstructure:"metrics_interval"`
	SlowQueryThreshold time.Duration `mapstructure:"slow_query_threshold"`
}

// LoadMonitoringConfig reads monitoring settings from Viper.
// Falls back to safe defaults if keys are not set.
func LoadMonitoringConfig() MonitoringConfig {
	cfg := MonitoringConfig{
		EnableMetrics:      true,
		MetricsInterval:    60 * time.Second,
		SlowQueryThreshold: 100 * time.Millisecond,
	}
	if viper.IsSet("monitoring.enable_metrics") {
		cfg.EnableMetrics = viper.GetBool("monitoring.enable_metrics")
	}
	if viper.IsSet("monitoring.metrics_interval") {
		cfg.MetricsInterval = viper.GetDuration("monitoring.metrics_interval")
	}
	if viper.IsSet("monitoring.slow_query_threshold") {
		cfg.SlowQueryThreshold = viper.GetDuration("monitoring.slow_query_threshold")
	}
	return cfg
}

// CacheConfig holds cachekit.Config for every domain that caches records.
type CacheConfig struct {
	Secrets      cachekit.Config
	Keys         cachekit.Config
	Vaults       cachekit.Config
	Certificates cachekit.Config
	Users        cachekit.Config
}

// loadCacheDomainConfig reads one domain's cache.<prefix>.* keys from Viper,
// overriding def field-by-field for whichever keys are explicitly set.
func loadCacheDomainConfig(prefix string, def cachekit.Config) cachekit.Config {
	cfg := def
	if viper.IsSet(prefix + ".enabled") {
		cfg.Enabled = viper.GetBool(prefix + ".enabled")
	}
	if viper.IsSet(prefix + ".ttl") {
		cfg.TTL = viper.GetDuration(prefix + ".ttl")
	}
	if viper.IsSet(prefix + ".cleanup_interval") {
		cfg.CleanupInterval = viper.GetDuration(prefix + ".cleanup_interval")
	}
	if viper.IsSet(prefix + ".max_entries") {
		cfg.MaxEntries = viper.GetInt(prefix + ".max_entries")
	}
	return cfg
}

// LoadCacheConfig reads cache.<domain>.* settings from Viper for all five
// domains, falling back to safe per-domain defaults, and validates each one.
// certificates/users default Enabled: false — no cache wrapper consumes them
// yet (see docs/superpowers/specs/2026-08-14-generic-cache-config-design.md).
func LoadCacheConfig() (CacheConfig, error) {
	cfg := CacheConfig{
		Secrets:      loadCacheDomainConfig("cache.secrets", cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 1000}),
		Keys:         loadCacheDomainConfig("cache.keys", cachekit.Config{Enabled: true, TTL: 60 * time.Second, CleanupInterval: 30 * time.Second, MaxEntries: 500}),
		Vaults:       loadCacheDomainConfig("cache.vaults", cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
		Certificates: loadCacheDomainConfig("cache.certificates", cachekit.Config{Enabled: false, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
		Users:        loadCacheDomainConfig("cache.users", cachekit.Config{Enabled: false, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
	}

	domains := []struct {
		name string
		cfg  cachekit.Config
	}{
		{"secrets", cfg.Secrets}, {"keys", cfg.Keys}, {"vaults", cfg.Vaults},
		{"certificates", cfg.Certificates}, {"users", cfg.Users},
	}
	for _, d := range domains {
		if err := d.cfg.Validate(); err != nil {
			return CacheConfig{}, fmt.Errorf("cache.%s: %w", d.name, err)
		}
	}
	return cfg, nil
}

// Config holds the configuration settings for the vault service application.
// It includes settings for the server's listening address, logging, HTTP transport,
// and trusted proxy IPs and networks.
type Config struct {
	// ListenAddr is the address on which the server will listen for incoming requests.
	ListenAddr string

	// Logger is the logger used for logging messages.
	Logger *logging.Logger

	// HTTPTransport is the transport used for making HTTP requests.
	HTTPTransport http.RoundTripper

	// TrustedProxyIPs is a list of IP addresses that are considered trusted proxies.
	TrustedProxyIPs []*net.IP

	// TrustedProxyNets is a list of IP networks that are considered trusted proxies.
	TrustedProxyNets []*net.IPNet

	// SoftDelete holds soft-delete and purge protection settings.
	SoftDelete SoftDeleteConfig `mapstructure:"soft_delete"`
}
