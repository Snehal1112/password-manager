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

// SecretCache provides thread-safe in-memory caching for secrets with TTL
// support. Entries are keyed by (scope, secret id), so a value admitted under
// one scope can never satisfy a read under another. A byID reverse index lets
// a single mutation evict every scoped view of a secret.
type SecretCache struct {
	cache  map[string]*CachedSecret
	byID   map[uuid.UUID]map[string]struct{}
	mu     sync.RWMutex
	ttl    time.Duration
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
		byID:   make(map[uuid.UUID]map[string]struct{}),
		ttl:    ttl,
		logger: logger,
	}
}

// scopeCacheKey builds the compound cache key for a scoped read. It reports
// false for scopes that must never be cached: ScopeAdmin, which has no
// predicate, and any invalid scope.
func scopeCacheKey(secretID uuid.UUID, scope model.Scope) (string, bool) {
	if scope.Validate() != nil {
		return "", false
	}
	switch scope.Kind() {
	case model.ScopeVault:
		return "v|" + scope.VaultID().String() + "|" + secretID.String(), true
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		if !ok {
			return "", false
		}
		return "o|" + ownerID.String() + "|" + secretID.String(), true
	default:
		return "", false
	}
}

// Get retrieves a secret cached under the given scope, if it has not expired.
func (c *SecretCache) Get(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, bool) {
	key, cacheable := scopeCacheKey(secretID, scope)
	if !cacheable {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

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

// Set stores a secret under the given scope with TTL expiration. Scopes that
// must not be cached are a silent no-op.
func (c *SecretCache) Set(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	if secret == nil {
		return fmt.Errorf("cannot cache nil secret")
	}

	key, cacheable := scopeCacheKey(secret.ID, scope)
	if !cacheable {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = &CachedSecret{Secret: secret, ExpiresAt: time.Now().Add(c.ttl)}
	if c.byID[secret.ID] == nil {
		c.byID[secret.ID] = make(map[string]struct{})
	}
	c.byID[secret.ID][key] = struct{}{}

	c.logger.WithFields(logrus.Fields{
		"secret_id": secret.ID,
		"scope":     scope.String(),
		"ttl":       c.ttl,
	}).Debug("Secret cached successfully")

	return nil
}

// DeleteByID evicts every scoped view of a secret. It is the invalidation
// primitive: a mutation authorized under one scope must not leave a stale
// entry visible under another.
func (c *SecretCache) DeleteByID(ctx context.Context, secretID uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key := range c.byID[secretID] {
		delete(c.cache, key)
	}
	delete(c.byID, secretID)

	c.logger.WithField("secret_id", secretID).Debug("Secret removed from cache")
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
	c.byID = make(map[uuid.UUID]map[string]struct{})

	c.logger.WithField("removed_count", removed).Debug("Cache flushed")
	return nil
}

// Clear removes only expired entries. It is the background-cleanup primitive
// and is deliberately NOT a flush -- see Flush.
func (c *SecretCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, cached := range c.cache {
		if now.After(cached.ExpiresAt) {
			delete(c.cache, key)
			if keys := c.byID[cached.Secret.ID]; keys != nil {
				delete(keys, key)
				if len(keys) == 0 {
					delete(c.byID, cached.Secret.ID)
				}
			}
			removed++
		}
	}

	c.logger.WithField("removed_count", removed).Debug("Expired cache entries cleared")
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
		"total_entries":   len(c.cache),
		"expired_entries": expired,
		"ttl":             c.ttl.String(),
	}
}
