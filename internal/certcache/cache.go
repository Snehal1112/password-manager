// Package certcache provides in-memory caching functionality for
// certificates with TTL support for performance optimization and reduced
// database load. Mirrors internal/cache's SecretCache: certificates carry
// the same (scope, id)-authorized read shape as secrets, so the same
// scope-composite key discipline applies. Unlike secrets and keys, nothing
// decrypted ever enters this cache — CertificateService.GetCertificate never
// decrypts Certificate.PrivateKey (that only happens transiently in the
// CA-signing path), so cached entries hold ciphertext plus public data only,
// same as vaultcache. model.Certificate therefore does not implement
// cachekit.Zeroable, and none is needed here.
package certcache

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// Cache provides thread-safe in-memory caching for certificates with TTL
// support. Entries are keyed by (scope, certificate id), so a value admitted
// under one scope can never satisfy a read under another. DeleteByID
// enumerates cachekit's live entries directly rather than maintaining a
// separate reverse index, so it can never drift out of sync with core's own
// TTL/LRU eviction. Wraps cachekit.Cache for storage/TTL/LRU; the scope-key
// logic here is certificate-domain-specific composition on top.
type Cache struct {
	core   cachekit.Interface[string, *model.Certificate]
	logger *logrus.Logger
}

// NewCache creates a Cache from cfg. Always returns a usable cache: a real
// one (self-managing its own TTL sweep from construction) when cfg.Enabled,
// a no-op one otherwise.
func NewCache(cfg cachekit.Config, logger *logrus.Logger) *Cache {
	return &Cache{
		core:   cachekit.NewFromConfig[string, *model.Certificate](cfg),
		logger: logger,
	}
}

// scopeCacheKey builds the compound cache key for a scoped read. It reports
// false for scopes that must never be cached: ScopeAdmin, which has no
// predicate, and any invalid scope.
func scopeCacheKey(certID uuid.UUID, scope model.Scope) (string, bool) {
	if scope.Validate() != nil {
		return "", false
	}
	switch scope.Kind() {
	case model.ScopeVault:
		return "v|" + scope.VaultID().String() + "|" + certID.String(), true
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		if !ok {
			return "", false
		}
		return "o|" + ownerID.String() + "|" + certID.String(), true
	default:
		return "", false
	}
}

// Get retrieves a certificate cached under the given scope, if it has not expired.
func (c *Cache) Get(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, bool) {
	key, cacheable := scopeCacheKey(certID, scope)
	if !cacheable {
		return nil, false
	}
	cert, ok := c.core.Get(key)
	if !ok {
		c.logger.WithField("cert_id", certID).Debug("Cache miss")
		return nil, false
	}
	c.logger.WithField("cert_id", certID).Debug("Cache hit")
	return cert, true
}

// Set stores a certificate under the given scope with TTL expiration. Scopes
// that must not be cached are a silent no-op.
func (c *Cache) Set(ctx context.Context, cert *model.Certificate, scope model.Scope) error {
	if cert == nil {
		return fmt.Errorf("cannot cache nil certificate")
	}
	key, cacheable := scopeCacheKey(cert.ID, scope)
	if !cacheable {
		return nil
	}
	c.core.Set(key, cert)
	c.logger.WithFields(logrus.Fields{"cert_id": cert.ID, "scope": scope.String()}).Debug("Certificate cached successfully")
	return nil
}

// DeleteByID evicts every scoped view of a certificate. It is the
// invalidation primitive: a mutation authorized under one scope must not
// leave a stale entry visible under another. Enumerates cachekit's live
// entries directly (bounded by MaxEntries, same O(n) tradeoff already
// accepted for SecretCache.DeleteByID) rather than maintaining a separate
// reverse index that could drift out of sync with core's own TTL/LRU
// eviction.
func (c *Cache) DeleteByID(ctx context.Context, certID uuid.UUID) error {
	var toRemove []string
	c.core.Range(func(key string, v *model.Certificate) bool {
		if v.ID == certID {
			toRemove = append(toRemove, key)
		}
		return true
	})
	for _, key := range toRemove {
		c.core.Invalidate(key)
	}
	c.logger.WithField("cert_id", certID).Debug("Certificate removed from cache")
	return nil
}

// Flush removes every entry from the cache unconditionally, live or
// expired — the correct primitive for callers that need a guaranteed-empty
// cache (e.g. a bulk operation touching many certificates at once).
func (c *Cache) Flush(ctx context.Context) error {
	c.core.InvalidateAll()
	c.logger.Debug("Cache flushed")
	return nil
}

// GetStats returns cache statistics.
func (c *Cache) GetStats() map[string]interface{} {
	s := c.core.Stats()
	return map[string]interface{}{
		"total_entries":   s.TotalEntries,
		"expired_entries": s.ExpiredEntries,
	}
}

// Stop shuts down the background TTL sweep. Safe to call more than once.
func (c *Cache) Stop() {
	c.core.Stop()
}
