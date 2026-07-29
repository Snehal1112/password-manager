// Package cache provides integration between the cache layer and service layer.
// It implements a caching decorator pattern for secret operations.
package cache

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// CachedSecretService wraps a SecretService with caching functionality.
// It implements the SecretService interface while adding transparent caching.
type CachedSecretService struct {
	secretService secrets.SecretService
	cache         *SecretCache
	logger        *logrus.Logger
}

// NewCachedSecretService creates a new cached secret service wrapper.
func NewCachedSecretService(secretService secrets.SecretService, cache *SecretCache, logger *logrus.Logger) *CachedSecretService {
	return &CachedSecretService{
		secretService: secretService,
		cache:         cache,
		logger:        logger,
	}
}

// GetSecret retrieves a scoped secret, using cache when available. The
// entry is keyed by (scope, id), so a value admitted under one scope can never
// satisfy a read under another, and the hit path rechecks IsAccessible so a
// secret that expired or was disabled while cached is not served anyway.
func (s *CachedSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	if cached, found := s.cache.Get(ctx, secretID, scope); found {
		if cached.IsAccessible() {
			s.logger.WithFields(logrus.Fields{
				"secret_id": secretID,
				"scope":     scope.String(),
			}).Debug("Cache hit for secret")
			return cached, nil
		}
		if err := s.cache.DeleteByID(ctx, secretID); err != nil {
			s.logger.WithError(err).Warn("Failed to evict inaccessible cached secret")
		}
	}

	secret, err := s.secretService.GetSecret(ctx, secretID, scope)
	if err != nil {
		return nil, err
	}

	if err := s.cache.Set(ctx, secret, scope); err != nil {
		s.logger.WithError(err).Warn("Failed to cache secret")
	}

	return secret, nil
}

// ListSecrets lists scoped secrets (not cached).
func (s *CachedSecretService) ListSecrets(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	return s.secretService.ListSecrets(ctx, scope, tags)
}

// DeleteSecret soft-deletes a scoped secret and evicts it from cache.
func (s *CachedSecretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.DeleteSecret(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove deleted secret from cache")
	}
	return nil
}

// ListDeletedSecrets lists scoped soft-deleted secrets (not cached).
func (s *CachedSecretService) ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	return s.secretService.ListDeletedSecrets(ctx, scope)
}

// CreateSecret creates a new secret. The reading scope is not known at write
// time, so the cache is left to be populated by the first read.
func (s *CachedSecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
	// Create through underlying service
	secret, err := s.secretService.CreateSecret(ctx, req)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// UpdateSecret updates a scoped secret and invalidates the cache entry.
func (s *CachedSecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if err := s.secretService.UpdateSecret(ctx, req); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, req.SecretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
	}
	return nil
}

// GetSecretVersions retrieves all versions of a secret.
func (s *CachedSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	return s.secretService.GetSecretVersions(ctx, secretID, scope)
}

// GetSecretVersion retrieves a specific version of a secret.
func (s *CachedSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	return s.secretService.GetSecretVersion(ctx, secretID, version, scope)
}

// GetLatestSecretVersion retrieves the latest version of a secret.
func (s *CachedSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	return s.secretService.GetLatestSecretVersion(ctx, secretID, scope)
}

// GenerateSecret generates a secret. The reading scope is not known at write
// time, so the cache is left to be populated by the first read.
func (s *CachedSecretService) GenerateSecret(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error) {
	// Generate through underlying service
	secret, err := s.secretService.GenerateSecret(ctx, req)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// ExportSecrets exports secrets (not cached due to bulk operation).
func (s *CachedSecretService) ExportSecrets(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
	// Export operations are not cached due to bulk nature
	return s.secretService.ExportSecrets(ctx, req)
}

// ImportSecrets imports secrets and flushes the cache to ensure consistency.
func (s *CachedSecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	// Import through underlying service
	result, err := s.secretService.ImportSecrets(ctx, req)
	if err != nil {
		return nil, err
	}

	// Flush (not Clear) so live, non-expired cache entries are also
	// removed -- a bulk import can change or delete secrets that are
	// still cached.
	if err := s.cache.Flush(ctx); err != nil {
		s.logger.WithError(err).Warn("Failed to flush cache after import")
		// Don't fail the operation if cache flush fails.
	}

	return result, nil
}

// RecoverSecret recovers a scoped soft-deleted secret and evicts it from cache.
func (s *CachedSecretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.RecoverSecret(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
	}
	return nil
}

// PurgeSecret purges a scoped soft-deleted secret and evicts it from cache.
func (s *CachedSecretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.PurgeSecret(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove purged secret from cache")
	}
	return nil
}

// GetCacheStats returns cache statistics for monitoring.
func (s *CachedSecretService) GetCacheStats() map[string]interface{} {
	return s.cache.GetStats()
}

// ClearCache removes every cached secret.
func (s *CachedSecretService) ClearCache(ctx context.Context) error {
	return s.cache.Flush(ctx)
}

// StartCacheCleanup starts the background cache cleanup process.
func (s *CachedSecretService) StartCacheCleanup(ctx context.Context, interval time.Duration) {
	s.cache.StartCleanup(ctx, interval)
	s.logger.WithField("interval", interval).Info("Started cache cleanup process")
}
