package config

import (
	"net"
	"net/http"
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
