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

// GetSecret retrieves a secret. Caching is disabled here from Phase 3 until
// Phase 5 lands the compound scopeCacheKey.
func (s *CachedSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.Secret, error) {
	return s.secretService.GetSecret(ctx, secretID, userID)
}

// GetSecretScoped retrieves a scoped secret. Caching is deliberately disabled
// here until Phase 5 introduces the compound scopeCacheKey: an ID-keyed cache
// would serve an owner-scoped caller a value admitted under a vault scope.
func (s *CachedSecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	return s.secretService.GetSecretScoped(ctx, secretID, scope)
}

// ListSecretsScoped lists scoped secrets (not cached).
func (s *CachedSecretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	return s.secretService.ListSecretsScoped(ctx, scope, tags)
}

// DeleteSecretScoped soft-deletes a scoped secret and evicts it from cache.
func (s *CachedSecretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.DeleteSecretScoped(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove deleted secret from cache")
	}
	return nil
}

// ListDeletedSecretsScoped lists scoped soft-deleted secrets (not cached).
func (s *CachedSecretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	return s.secretService.ListDeletedSecretsScoped(ctx, scope)
}

// CreateSecret creates a new secret and updates cache.
func (s *CachedSecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
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

// UpdateSecretScoped updates a scoped secret and invalidates the cache entry.
func (s *CachedSecretService) UpdateSecretScoped(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if err := s.secretService.UpdateSecretScoped(ctx, req); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, req.SecretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
	}
	return nil
}

// UpdateSecretInVault updates a vault-scoped secret and invalidates cache.
func (s *CachedSecretService) UpdateSecretInVault(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if err := s.secretService.UpdateSecretInVault(ctx, req); err != nil {
		return err
	}

	// Invalidate cache - the secret will be re-cached on next read.
	if err := s.cache.Delete(ctx, req.SecretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
		// Don't fail the operation if cache invalidation fails.
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
func (s *CachedSecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	// List operations are not cached due to filtering complexity
	// This could be optimized in the future with cache invalidation strategies
	return s.secretService.ListSecrets(ctx, userID, tags)
}

// GetSecretInVault retrieves a vault-scoped secret (delegated; not cached to keep
// vault scoping authoritative at the service layer).
func (s *CachedSecretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	return s.secretService.GetSecretInVault(ctx, secretID, vaultID)
}

// ListSecretsInVault lists vault-scoped secrets (not cached due to filtering complexity).
func (s *CachedSecretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return s.secretService.ListSecretsInVault(ctx, vaultID, tags)
}

// DeleteSecretInVault soft-deletes a vault-scoped secret and removes it from cache.
func (s *CachedSecretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	if err := s.secretService.DeleteSecretInVault(ctx, secretID, vaultID); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove deleted secret from cache")
	}
	return nil
}

// GetSecretVersions retrieves all versions of a secret.
func (s *CachedSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]model.SecretVersion, error) {
	return s.secretService.GetSecretVersions(ctx, secretID, userID)
}

// GetSecretVersion retrieves a specific version of a secret.
func (s *CachedSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	return s.secretService.GetSecretVersion(ctx, secretID, version, userID)
}

// GetLatestSecretVersion retrieves the latest version of a secret.
func (s *CachedSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.SecretVersion, error) {
	return s.secretService.GetLatestSecretVersion(ctx, secretID, userID)
}

// GetSecretVersionsInVault retrieves all versions of a secret scoped to a vault.
func (s *CachedSecretService) GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	return s.secretService.GetSecretVersionsInVault(ctx, secretID, vaultID)
}

// GetSecretVersionInVault retrieves a specific version of a secret scoped to a vault.
func (s *CachedSecretService) GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.secretService.GetSecretVersionInVault(ctx, secretID, version, vaultID)
}

// GetLatestSecretVersionInVault retrieves the latest version of a secret scoped to a vault.
func (s *CachedSecretService) GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.secretService.GetLatestSecretVersionInVault(ctx, secretID, vaultID)
}

// GetSecretVersionsScoped retrieves every version of a secret the scope authorizes (not cached).
func (s *CachedSecretService) GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	return s.secretService.GetSecretVersionsScoped(ctx, secretID, scope)
}

// GetSecretVersionScoped retrieves one version of a secret the scope authorizes (not cached).
func (s *CachedSecretService) GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	return s.secretService.GetSecretVersionScoped(ctx, secretID, version, scope)
}

// GetLatestSecretVersionScoped retrieves the newest version of a secret the scope authorizes (not cached).
func (s *CachedSecretService) GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	return s.secretService.GetLatestSecretVersionScoped(ctx, secretID, scope)
}

// GenerateSecret generates a secret and caches it.
func (s *CachedSecretService) GenerateSecret(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error) {
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

// RecoverSecretScoped recovers a scoped soft-deleted secret and evicts it from cache.
func (s *CachedSecretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.RecoverSecretScoped(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
	}
	return nil
}

// PurgeSecretScoped purges a scoped soft-deleted secret and evicts it from cache.
func (s *CachedSecretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.PurgeSecretScoped(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove purged secret from cache")
	}
	return nil
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
