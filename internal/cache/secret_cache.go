// Package cache provides in-memory caching functionality for secrets
// with TTL support for performance optimization and reduced database load.
package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/model"
)

// SecretCache provides thread-safe in-memory caching for secrets with TTL support.
type SecretCache struct {
	cache map[string]*CachedSecret
	mu    sync.RWMutex
	ttl   time.Duration
	logger *logrus.Logger
}

// CachedSecret represents a cached secret with expiration time.
type CachedSecret struct {
	Secret    *model.Secret
	ExpiresAt time.Time
}

// NewSecretCache creates a new secret cache with the specified TTL.
func NewSecretCache(ttl time.Duration, logger *logrus.Logger) *SecretCache {
	return &SecretCache{
		cache:  make(map[string]*CachedSecret),
		ttl:    ttl,
		logger: logger,
	}
}

// Get retrieves a secret from cache if it exists and hasn't expired.
func (c *SecretCache) Get(ctx context.Context, secretID uuid.UUID) (*model.Secret, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := secretID.String()
	cached, exists := c.cache[key]

	if !exists {
		c.logger.WithField("secret_id", secretID).Debug("Cache miss - secret not found")
		return nil, false
	}

	if time.Now().After(cached.ExpiresAt) {
		c.logger.WithField("secret_id", secretID).Debug("Cache miss - secret expired")
		return nil, false
	}

	c.logger.WithField("secret_id", secretID).Debug("Cache hit")
	return cached.Secret, true
}

// Set stores a secret in cache with TTL expiration.
func (c *SecretCache) Set(ctx context.Context, secret *model.Secret) error {
	if secret == nil {
		return fmt.Errorf("cannot cache nil secret")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := secret.ID.String()
	cached := &CachedSecret{
		Secret:    secret,
		ExpiresAt: time.Now().Add(c.ttl),
	}

	c.cache[key] = cached
	c.logger.WithFields(logrus.Fields{
		"secret_id": secret.ID,
		"ttl":       c.ttl,
	}).Debug("Secret cached successfully")

	return nil
}

// Delete removes a secret from cache.
func (c *SecretCache) Delete(ctx context.Context, secretID uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := secretID.String()
	delete(c.cache, key)

	c.logger.WithField("secret_id", secretID).Debug("Secret removed from cache")
	return nil
}

// Clear removes all expired entries from cache.
func (c *SecretCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, cached := range c.cache {
		if now.After(cached.ExpiresAt) {
			delete(c.cache, key)
			removed++
		}
	}

	c.logger.WithField("removed_count", removed).Debug("Expired cache entries cleared")
	return nil
}

// Flush removes every entry from the cache unconditionally, live or
// expired. Unlike Clear, which only prunes expired entries, Flush is the
// correct primitive for callers that need a guaranteed-empty cache (e.g.
// bulk import, where secrets may change or be removed outside their TTL).
func (c *SecretCache) Flush(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := len(c.cache)
	c.cache = make(map[string]*CachedSecret)

	c.logger.WithField("removed_count", removed).Debug("Cache flushed")
	return nil
}

// StartCleanup starts a background goroutine that periodically clears expired entries.
func (c *SecretCache) StartCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				c.logger.Info("Cache cleanup stopped")
				return
			case <-ticker.C:
				if err := c.Clear(ctx); err != nil {
					c.logger.WithError(err).Error("Failed to clear expired cache entries")
				}
			}
		}
	}()
}

// GetStats returns cache statistics.
func (c *SecretCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	expired := 0
	now := time.Now()
	for _, cached := range c.cache {
		if now.After(cached.ExpiresAt) {
			expired++
		}
	}

	return map[string]interface{}{
		"total_entries": len(c.cache),
		"expired_entries": expired,
		"ttl":           c.ttl.String(),
	}
}