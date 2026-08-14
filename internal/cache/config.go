package cache

import "time"

// CacheConfig is retained only for ServiceContainerInterface.GetCacheConfig()'s
// pre-migration return type — real cache configuration now flows through
// cachekit.Config (see NewSecretCache). This type will be removed once
// ServiceContainerInterface's signature changes (a later part of this effort).
type CacheConfig struct {
	Enabled         bool
	TTL             time.Duration
	CleanupInterval time.Duration
	MaxEntries      int
}

// DefaultCacheConfig returns the default cache configuration. Still called by
// internal/container/service_container.go (as ServiceContainer's fallback
// when no CacheConfig is supplied) and container_test.go — out of scope for
// this task, left in place until Task 9 removes the CacheConfig type
// entirely.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute, // 5 minutes default TTL
		CleanupInterval: 1 * time.Minute, // Clean up every minute
		MaxEntries:      1000,            // Cache up to 1000 secrets
	}
}
