// Package cache provides integration between the cache layer and service layer.
// It implements a caching decorator pattern for secret operations.
package cache

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/domain"
	"rocketvault/internal/services/secrets"
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

// GetSecret retrieves a secret, using cache when available.
func (s *CachedSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.Secret, error) {
	// Try cache first
	if cached, found := s.cache.Get(ctx, secretID); found {
		// Verify the cached secret belongs to the requesting user
		if cached.UserID == userID {
			s.logger.WithFields(logrus.Fields{
				"secret_id": secretID,
				"user_id":   userID,
			}).Debug("Cache hit for secret")
			return cached, nil
		}
	}

	// Cache miss - get from service
	secret, err := s.secretService.GetSecret(ctx, secretID, userID)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if err := s.cache.Set(ctx, secret); err != nil {
		s.logger.WithError(err).Warn("Failed to cache secret")
		// Don't fail the operation if caching fails
	}

	return secret, nil
}

// CreateSecret creates a new secret and updates cache.
func (s *CachedSecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*domain.Secret, error) {
	// Create through underlying service
	secret, err := s.secretService.CreateSecret(ctx, req)
	if err != nil {
		return nil, err
	}

	// Cache the new secret
	if err := s.cache.Set(ctx, secret); err != nil {
		s.logger.WithError(err).Warn("Failed to cache new secret")
		// Don't fail the operation if caching fails
	}

	return secret, nil
}

// UpdateSecret updates a secret and invalidates cache.
func (s *CachedSecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	// Update through underlying service
	err := s.secretService.UpdateSecret(ctx, req)
	if err != nil {
		return err
	}

	// Invalidate cache - the secret will be re-cached on next read
	if err := s.cache.Delete(ctx, req.SecretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
		// Don't fail the operation if cache invalidation fails
	}

	return nil
}

// DeleteSecret soft deletes a secret and removes from cache.
func (s *CachedSecretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) error {
	// Delete through underlying service
	err := s.secretService.DeleteSecret(ctx, secretID, userID)
	if err != nil {
		return err
	}

	// Remove from cache
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove deleted secret from cache")
		// Don't fail the operation if cache deletion fails
	}

	return nil
}

// ListSecrets lists secrets for a user (not cached due to filtering complexity).
func (s *CachedSecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
	// List operations are not cached due to filtering complexity
	// This could be optimized in the future with cache invalidation strategies
	return s.secretService.ListSecrets(ctx, userID, tags)
}

// GetSecretVersions retrieves all versions of a secret.
func (s *CachedSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]domain.SecretVersion, error) {
	return s.secretService.GetSecretVersions(ctx, secretID, userID)
}

// GetSecretVersion retrieves a specific version of a secret.
func (s *CachedSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error) {
	return s.secretService.GetSecretVersion(ctx, secretID, version, userID)
}

// GetLatestSecretVersion retrieves the latest version of a secret.
func (s *CachedSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*domain.SecretVersion, error) {
	return s.secretService.GetLatestSecretVersion(ctx, secretID, userID)
}

// GenerateSecret generates a secret and caches it.
func (s *CachedSecretService) GenerateSecret(ctx context.Context, req secrets.GenerateSecretRequest) (*domain.Secret, error) {
	// Generate through underlying service
	secret, err := s.secretService.GenerateSecret(ctx, req)
	if err != nil {
		return nil, err
	}

	// Cache the new secret
	if err := s.cache.Set(ctx, secret); err != nil {
		s.logger.WithError(err).Warn("Failed to cache generated secret")
		// Don't fail the operation if caching fails
	}

	return secret, nil
}

// ExportSecrets exports secrets (not cached due to bulk operation).
func (s *CachedSecretService) ExportSecrets(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
	// Export operations are not cached due to bulk nature
	return s.secretService.ExportSecrets(ctx, req)
}

// ImportSecrets imports secrets and clears cache to ensure consistency.
func (s *CachedSecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	// Import through underlying service
	result, err := s.secretService.ImportSecrets(ctx, req)
	if err != nil {
		return nil, err
	}

	// Clear cache to ensure consistency after bulk import
	if err := s.cache.Clear(ctx); err != nil {
		s.logger.WithError(err).Warn("Failed to clear cache after import")
		// Don't fail the operation if cache clear fails
	}

	return result, nil
}

// GetCacheStats returns cache statistics for monitoring.
func (s *CachedSecretService) GetCacheStats() map[string]interface{} {
	return s.cache.GetStats()
}

// ClearCache clears all cached secrets.
func (s *CachedSecretService) ClearCache(ctx context.Context) error {
	return s.cache.Clear(ctx)
}

// StartCacheCleanup starts the background cache cleanup process.
func (s *CachedSecretService) StartCacheCleanup(ctx context.Context, interval time.Duration) {
	s.cache.StartCleanup(ctx, interval)
	s.logger.WithField("interval", interval).Info("Started cache cleanup process")
}