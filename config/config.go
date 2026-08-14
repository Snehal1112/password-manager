package config

import (
	"net"
	"net/http"
	"time"

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
