// Package cache provides in-memory caching functionality for secrets
// with TTL support for performance optimization and reduced database load.
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// SecretCache provides thread-safe in-memory caching for secrets with TTL
// support. Entries are keyed by (scope, secret id), so a value admitted under
// one scope can never satisfy a read under another. DeleteByID enumerates
// cachekit's live entries directly rather than maintaining a separate
// reverse index, so it can never drift out of sync with core's own TTL/LRU
// eviction. Wraps cachekit.Cache for storage/TTL/LRU; the scope-key logic
// here is secret-domain-specific composition on top.
type SecretCache struct {
	core   cachekit.Interface[string, *model.Secret]
	logger *logrus.Logger
}

// NewSecretCache creates a SecretCache from cfg. Always returns a usable
// cache: a real one (self-managing its own TTL sweep from construction) when
// cfg.Enabled, a no-op one otherwise.
func NewSecretCache(cfg cachekit.Config, logger *logrus.Logger) *SecretCache {
	return &SecretCache{
		core:   cachekit.NewFromConfig[string, *model.Secret](cfg),
		logger: logger,
	}
}

// NewSecretCacheWithL2 creates a SecretCache backed by a TieredCache: cfg's
// in-process cache as L1, l2 as the shared Rocket-mem tier (l2TTL is that
// tier's own entry lifetime). GetSecret hands this cache already-decrypted
// plaintext (see cache_integration.go), so values are JSON-marshaled and
// then encrypted via common.EncryptSecret/DecryptSecret -- the same
// primitive already used for this secret's DB-at-rest encryption -- before
// ever reaching l2 (see the design spec's Problem Statement table: this is
// the mandatory case, never PlainJSONCodec). Used only when
// cache.rocket_mem is enabled; NewSecretCache's behavior is unchanged.
//
// Mirrors cachekit.NewFromConfig's own enabled/valid branching exactly: if
// this domain's own cache is disabled or its config is invalid, this falls
// back to the plain NewSecretCache path instead of building a live
// TieredCache -- an operator's cache.secrets.enabled: false must not be
// silently overridden by cache.rocket_mem.enabled: true.
func NewSecretCacheWithL2(cfg cachekit.Config, logger *logrus.Logger, l2 cachekit.L2, l2TTL time.Duration) *SecretCache {
	if !cfg.Enabled || cfg.Validate() != nil {
		return NewSecretCache(cfg, logger)
	}
	l1 := cachekit.NewFromConfig[string, *model.Secret](cfg)
	codec := cachekit.EncryptedJSONCodec[*model.Secret]{
		Encrypt: common.EncryptSecret,
		Decrypt: common.DecryptSecret,
	}
	keys := cachekit.KeyCodec[string]{
		ToWire:   func(k string) string { return k },
		FromWire: func(w string) (string, bool) { return w, true },
	}
	return &SecretCache{
		core:   cachekit.NewTieredCache[string, *model.Secret](l1, l2, codec, keys, "rocketvault:secret:", l2TTL),
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
	secret, ok := c.core.Get(key)
	if !ok {
		c.logger.WithField("secret_id", secretID).Debug("Cache miss")
		return nil, false
	}
	c.logger.WithField("secret_id", secretID).Debug("Cache hit")
	return secret, true
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
	c.core.Set(key, secret)
	c.logger.WithFields(logrus.Fields{"secret_id": secret.ID, "scope": scope.String()}).Debug("Secret cached successfully")
	return nil
}

// DeleteByID evicts every scoped view of a secret. It is the invalidation
// primitive: a mutation authorized under one scope must not leave a stale
// entry visible under another. Enumerates cachekit's live entries directly
// (bounded by MaxEntries, same O(n) tradeoff already accepted for
// keycache.cacheImpl.Invalidate) rather than maintaining a separate reverse
// index that could drift out of sync with core's own TTL/LRU eviction.
func (c *SecretCache) DeleteByID(ctx context.Context, secretID uuid.UUID) error {
	var toRemove []string
	c.core.Range(func(key string, v *model.Secret) bool {
		if v.ID == secretID {
			toRemove = append(toRemove, key)
		}
		return true
	})
	for _, key := range toRemove {
		c.core.Invalidate(key)
	}
	c.logger.WithField("secret_id", secretID).Debug("Secret removed from cache")
	return nil
}

// Flush removes every entry from the cache unconditionally, live or
// expired — the correct primitive for callers that need a guaranteed-empty
// cache (e.g. a vault delete/recover cascade that writes secrets directly).
func (c *SecretCache) Flush(ctx context.Context) error {
	c.core.InvalidateAll()
	c.logger.Debug("Cache flushed")
	return nil
}

// GetStats returns cache statistics.
func (c *SecretCache) GetStats() map[string]interface{} {
	s := c.core.Stats()
	return map[string]interface{}{
		"total_entries":   s.TotalEntries,
		"expired_entries": s.ExpiredEntries,
	}
}

// Stop shuts down the background TTL sweep. Safe to call more than once.
func (c *SecretCache) Stop() {
	c.core.Stop()
}
