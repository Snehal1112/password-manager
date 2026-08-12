// Package cache provides configuration for the secret caching system.
package cache

import (
	"time"
)

// CacheConfig contains configuration for the secret cache.
type CacheConfig struct {
	// Enabled controls whether caching is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the time-to-live for cached secrets.
	TTL time.Duration `yaml:"ttl" json:"ttl"`

	// CleanupInterval is how often to clean up expired entries.
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`

	// MaxEntries is the maximum number of secrets to cache (0 = unlimited).
	MaxEntries int `yaml:"max_entries" json:"max_entries"`
}

// DefaultCacheConfig returns the default cache configuration.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute, // 5 minutes default TTL
		CleanupInterval: 1 * time.Minute, // Clean up every minute
		MaxEntries:      1000,            // Cache up to 1000 secrets
	}
}

// DevelopmentCacheConfig returns cache configuration for development.
func DevelopmentCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:         true,
		TTL:             1 * time.Minute,  // Shorter TTL for development
		CleanupInterval: 30 * time.Second, // More frequent cleanup
		MaxEntries:      100,              // Smaller cache for development
	}
}

// ProductionCacheConfig returns cache configuration for production.
func ProductionCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:         true,
		TTL:             10 * time.Minute, // Longer TTL for production
		CleanupInterval: 2 * time.Minute,  // Less frequent cleanup
		MaxEntries:      5000,             // Larger cache for production
	}
}

// Validate checks that the cache configuration is valid.
func (c *CacheConfig) Validate() error {
	if c.TTL <= 0 {
		return &CacheConfigError{Field: "ttl", Message: "TTL must be positive"}
	}

	if c.CleanupInterval <= 0 {
		return &CacheConfigError{Field: "cleanup_interval", Message: "cleanup interval must be positive"}
	}

	if c.CleanupInterval >= c.TTL {
		return &CacheConfigError{Field: "cleanup_interval", Message: "cleanup interval must be less than TTL"}
	}

	if c.MaxEntries < 0 {
		return &CacheConfigError{Field: "max_entries", Message: "max entries cannot be negative"}
	}

	return nil
}

// CacheConfigError represents a configuration validation error.
type CacheConfigError struct {
	Field   string
	Message string
}

func (e *CacheConfigError) Error() string {
	return "cache config validation failed: " + e.Field + " - " + e.Message
}
