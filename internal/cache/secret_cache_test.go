package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"password-manager/internal/domain"
)

// TestSecretCacheBasicOperations tests basic cache operations.
func TestSecretCacheBasicOperations(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(5*time.Minute, logger)
	ctx := context.Background()

	// Create a test secret
	secret := &domain.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "test-secret",
		Value:     "encrypted-value",
		Version:   1,
		Tags:      []string{"tag1", "tag2"},
		CreatedAt: time.Now(),
	}

	t.Run("Get returns false for non-existent secret", func(t *testing.T) {
		nonExistentID := uuid.New()
		cached, found := cache.Get(ctx, nonExistentID)
		assert.False(t, found)
		assert.Nil(t, cached)
	})

	t.Run("Set and Get work correctly", func(t *testing.T) {
		// Set the secret
		err := cache.Set(ctx, secret)
		assert.NoError(t, err)

		// Get the secret
		cached, found := cache.Get(ctx, secret.ID)
		assert.True(t, found)
		require.NotNil(t, cached)
		assert.Equal(t, secret.ID, cached.ID)
		assert.Equal(t, secret.Name, cached.Name)
		assert.Equal(t, secret.Value, cached.Value)
		assert.Equal(t, secret.Version, cached.Version)
		assert.Equal(t, secret.Tags, cached.Tags)
	})

	t.Run("Delete removes secret from cache", func(t *testing.T) {
		// Delete the secret
		err := cache.Delete(ctx, secret.ID)
		assert.NoError(t, err)

		// Verify it's gone
		cached, found := cache.Get(ctx, secret.ID)
		assert.False(t, found)
		assert.Nil(t, cached)
	})

	t.Run("Set nil secret returns error", func(t *testing.T) {
		err := cache.Set(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot cache nil secret")
	})
}

// TestSecretCacheExpiration tests TTL expiration functionality.
func TestSecretCacheExpiration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Use a very short TTL for testing
	cache := NewSecretCache(100*time.Millisecond, logger)
	ctx := context.Background()

	secret := &domain.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "expiring-secret",
		Value:     "encrypted-value",
		Version:   1,
		CreatedAt: time.Now(),
	}

	t.Run("Secret expires after TTL", func(t *testing.T) {
		// Set the secret
		err := cache.Set(ctx, secret)
		require.NoError(t, err)

		// Verify it's cached immediately
		cached, found := cache.Get(ctx, secret.ID)
		assert.True(t, found)
		assert.NotNil(t, cached)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Verify it's expired
		cached, found = cache.Get(ctx, secret.ID)
		assert.False(t, found)
		assert.Nil(t, cached)
	})
}

// TestSecretCacheClear tests the clear functionality.
func TestSecretCacheClear(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(5*time.Minute, logger)
	ctx := context.Background()

	// Create multiple test secrets
	secrets := make([]*domain.Secret, 5)
	for i := 0; i < 5; i++ {
		secrets[i] = &domain.Secret{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Name:      fmt.Sprintf("secret-%d", i),
			Value:     "encrypted-value",
			Version:   1,
			CreatedAt: time.Now(),
		}
		err := cache.Set(ctx, secrets[i])
		require.NoError(t, err)
	}

	t.Run("Clear removes expired entries", func(t *testing.T) {
		// Let some secrets expire
		time.Sleep(100 * time.Millisecond)

		// Clear expired entries
		err := cache.Clear(ctx)
		assert.NoError(t, err)

		// All secrets should still be there (none expired due to TTL)
		for _, secret := range secrets {
			cached, found := cache.Get(ctx, secret.ID)
			assert.True(t, found)
			assert.NotNil(t, cached)
		}
	})
}

// TestSecretCacheStats tests cache statistics.
func TestSecretCacheStats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(5*time.Minute, logger)
	ctx := context.Background()

	t.Run("Stats returns correct information", func(t *testing.T) {
		// Initially empty
		stats := cache.GetStats()
		assert.Equal(t, 0, stats["total_entries"])
		assert.Equal(t, 0, stats["expired_entries"])
		assert.Equal(t, "5m0s", stats["ttl"])

		// Add some secrets
		for i := 0; i < 3; i++ {
			secret := &domain.Secret{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				Name:      fmt.Sprintf("secret-%d", i),
				Value:     "encrypted-value",
				Version:   1,
				CreatedAt: time.Now(),
			}
			err := cache.Set(ctx, secret)
			require.NoError(t, err)
		}

		// Check stats again
		stats = cache.GetStats()
		assert.Equal(t, 3, stats["total_entries"])
		assert.Equal(t, 0, stats["expired_entries"])
	})
}

// TestSecretCacheConcurrentAccess tests concurrent access to the cache.
func TestSecretCacheConcurrentAccess(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(5*time.Minute, logger)
	ctx := context.Background()

	secretCount := 10
	secrets := make([]*domain.Secret, secretCount)
	for i := 0; i < secretCount; i++ {
		secrets[i] = &domain.Secret{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Name:      fmt.Sprintf("concurrent-secret-%d", i),
			Value:     "encrypted-value",
			Version:   1,
			CreatedAt: time.Now(),
		}
	}

	t.Run("Concurrent Set operations", func(t *testing.T) {
		// Run concurrent Set operations
		done := make(chan bool, secretCount)
		for i := 0; i < secretCount; i++ {
			go func(secret *domain.Secret) {
				err := cache.Set(ctx, secret)
				assert.NoError(t, err)
				done <- true
			}(secrets[i])
		}

		// Wait for all operations to complete
		for i := 0; i < secretCount; i++ {
			<-done
		}

		// Verify all secrets are cached
		for _, secret := range secrets {
			cached, found := cache.Get(ctx, secret.ID)
			assert.True(t, found)
			assert.NotNil(t, cached)
			assert.Equal(t, secret.ID, cached.ID)
		}
	})

	t.Run("Concurrent Get operations", func(t *testing.T) {
		// Pre-populate cache
		for _, secret := range secrets {
			err := cache.Set(ctx, secret)
			require.NoError(t, err)
		}

		// Run concurrent Get operations
		done := make(chan bool, secretCount)
		for i := 0; i < secretCount; i++ {
			go func(secretID uuid.UUID) {
				cached, found := cache.Get(ctx, secretID)
				assert.True(t, found)
				assert.NotNil(t, cached)
				assert.Equal(t, secretID, cached.ID)
				done <- true
			}(secrets[i].ID)
		}

		// Wait for all operations to complete
		for i := 0; i < secretCount; i++ {
			<-done
		}
	})

	t.Run("Mixed concurrent operations", func(t *testing.T) {
		// Run mixed operations concurrently
		done := make(chan bool, secretCount*2)

		// Half Get, half Set operations
		for i := 0; i < secretCount; i++ {
			if i%2 == 0 {
				// Get operation
				go func(secretID uuid.UUID) {
					cached, found := cache.Get(ctx, secretID)
					if found {
						assert.NotNil(t, cached)
					}
					done <- true
				}(secrets[i].ID)
			} else {
				// Set operation (update existing)
				go func(secret *domain.Secret) {
					err := cache.Set(ctx, secret)
					assert.NoError(t, err)
					done <- true
				}(secrets[i])
			}
		}

		// Wait for all operations to complete
		for i := 0; i < secretCount; i++ {
			<-done
		}
	})
}

// TestSecretCacheStartCleanup tests the background cleanup functionality.
func TestSecretCacheStartCleanup(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Use a short TTL and cleanup interval for testing
	cache := NewSecretCache(200*time.Millisecond, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret := &domain.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "cleanup-test-secret",
		Value:     "encrypted-value",
		Version:   1,
		CreatedAt: time.Now(),
	}

	t.Run("Background cleanup removes expired entries", func(t *testing.T) {
		// Set the secret
		err := cache.Set(ctx, secret)
		require.NoError(t, err)

		// Start background cleanup
		cache.StartCleanup(ctx, 100*time.Millisecond)

		// Verify secret is cached initially
		cached, found := cache.Get(ctx, secret.ID)
		assert.True(t, found)
		assert.NotNil(t, cached)

		// Wait for expiration and cleanup
		time.Sleep(350 * time.Millisecond)

		// Verify secret is removed by cleanup
		cached, found = cache.Get(ctx, secret.ID)
		assert.False(t, found)
		assert.Nil(t, cached)
	})
}

// TestSecretCacheEdgeCases tests edge cases and error conditions.
func TestSecretCacheEdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(5*time.Minute, logger)
	ctx := context.Background()

	t.Run("Delete non-existent secret is no-op", func(t *testing.T) {
		nonExistentID := uuid.New()
		err := cache.Delete(ctx, nonExistentID)
		assert.NoError(t, err) // Should not return error
	})

	t.Run("Clear on empty cache is no-op", func(t *testing.T) {
		err := cache.Clear(ctx)
		assert.NoError(t, err) // Should not return error
	})

	t.Run("GetStats on empty cache returns zeros", func(t *testing.T) {
		stats := cache.GetStats()
		assert.Equal(t, 0, stats["total_entries"])
		assert.Equal(t, 0, stats["expired_entries"])
	})

	t.Run("Zero TTL cache still works", func(t *testing.T) {
		zeroTTLCache := NewSecretCache(0, logger)
		secret := &domain.Secret{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Name:      "zero-ttl-secret",
			Value:     "encrypted-value",
			Version:   1,
			CreatedAt: time.Now(),
		}

		// Set should work
		err := zeroTTLCache.Set(ctx, secret)
		assert.NoError(t, err)

		// Get should immediately return not found due to zero TTL
		cached, found := zeroTTLCache.Get(ctx, secret.ID)
		assert.False(t, found)
		assert.Nil(t, cached)
	})
}

// TestSecretCacheWithSoftDelete tests cache behavior with soft-deleted secrets.
func TestSecretCacheWithSoftDelete(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(5*time.Minute, logger)
	ctx := context.Background()

	now := time.Now()
	secret := &domain.Secret{
		ID:              uuid.New(),
		UserID:          uuid.New(),
		Name:            "soft-deleted-secret",
		Value:           "encrypted-value",
		Version:         1,
		Tags:            []string{},
		CreatedAt:       now.Add(-time.Hour),
		DeletedAt:       &now,
		PurgeProtection: false,
	}

	t.Run("Cache handles soft-deleted secrets", func(t *testing.T) {
		// Set a soft-deleted secret
		err := cache.Set(ctx, secret)
		assert.NoError(t, err)

		// Should be retrievable from cache
		cached, found := cache.Get(ctx, secret.ID)
		assert.True(t, found)
		assert.NotNil(t, cached)
		assert.Equal(t, secret.DeletedAt, cached.DeletedAt)
		assert.Equal(t, secret.PurgeProtection, cached.PurgeProtection)
	})
}

// TestCacheConfigValidation tests cache configuration validation.
func TestCacheConfigValidation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := &CacheConfig{
			Enabled:         true,
			TTL:             5 * time.Minute,
			CleanupInterval: 1 * time.Minute,
			MaxEntries:      1000,
		}
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid TTL", func(t *testing.T) {
		config := &CacheConfig{
			TTL: 0,
		}
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TTL must be positive")
	})

	t.Run("Invalid cleanup interval", func(t *testing.T) {
		config := &CacheConfig{
			TTL:             5 * time.Minute,
			CleanupInterval: 0,
		}
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cleanup interval must be positive")
	})

	t.Run("Cleanup interval greater than TTL", func(t *testing.T) {
		config := &CacheConfig{
			TTL:             1 * time.Minute,
			CleanupInterval: 2 * time.Minute,
		}
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cleanup interval must be less than TTL")
	})

	t.Run("Negative max entries", func(t *testing.T) {
		config := &CacheConfig{
			TTL:             5 * time.Minute,
			CleanupInterval: 1 * time.Minute,
			MaxEntries:      -1,
		}
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max entries cannot be negative")
	})
}

// TestDefaultCacheConfigs tests default configuration generation.
func TestDefaultCacheConfigs(t *testing.T) {
	t.Run("Default cache config", func(t *testing.T) {
		config := DefaultCacheConfig()
		assert.True(t, config.Enabled)
		assert.Equal(t, 5*time.Minute, config.TTL)
		assert.Equal(t, 1*time.Minute, config.CleanupInterval)
		assert.Equal(t, 1000, config.MaxEntries)
	})

	t.Run("Development cache config", func(t *testing.T) {
		config := DevelopmentCacheConfig()
		assert.True(t, config.Enabled)
		assert.Equal(t, 1*time.Minute, config.TTL)
		assert.Equal(t, 30*time.Second, config.CleanupInterval)
		assert.Equal(t, 100, config.MaxEntries)
	})

	t.Run("Production cache config", func(t *testing.T) {
		config := ProductionCacheConfig()
		assert.True(t, config.Enabled)
		assert.Equal(t, 10*time.Minute, config.TTL)
		assert.Equal(t, 2*time.Minute, config.CleanupInterval)
		assert.Equal(t, 5000, config.MaxEntries)
	})
}