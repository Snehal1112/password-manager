package keycache

import "time"

// KeyCacheConfig controls the in-process key cache behaviour.
type KeyCacheConfig struct {
	Enabled         bool
	TTL             time.Duration
	MaxEntries      int
	CleanupInterval time.Duration
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
