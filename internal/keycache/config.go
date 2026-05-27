package keycache

import "time"

// KeyCacheConfig controls the in-process key cache behaviour.
type KeyCacheConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	TTL             time.Duration `yaml:"ttl" json:"ttl"`
	MaxEntries      int           `yaml:"max_entries" json:"max_entries"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
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
