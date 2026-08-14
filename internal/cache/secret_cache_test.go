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

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

func TestNewSecretCache_GetSetDeleteByID(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	logger := logrus.New()
	c := NewSecretCache(cfg, logger)
	defer c.Stop()

	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	secret := &model.Secret{ID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "v1"}

	_, found := c.Get(context.Background(), secret.ID, scope)
	assert.False(t, found)

	require.NoError(t, c.Set(context.Background(), secret, scope))
	got, found := c.Get(context.Background(), secret.ID, scope)
	require.True(t, found)
	assert.Equal(t, "s1", got.Name)

	require.NoError(t, c.DeleteByID(context.Background(), secret.ID))
	_, found = c.Get(context.Background(), secret.ID, scope)
	assert.False(t, found, "DeleteByID must evict the entry")
}

// TestSecretCacheBasicOperations tests basic cache operations.
func TestSecretCacheBasicOperations(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	// Create a test secret
	secret := &model.Secret{
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
		cached, found := cache.Get(ctx, nonExistentID, scope)
		assert.False(t, found)
		assert.Nil(t, cached)
	})

	t.Run("Set and Get work correctly", func(t *testing.T) {
		// Set the secret
		err := cache.Set(ctx, secret, scope)
		assert.NoError(t, err)

		// Get the secret
		cached, found := cache.Get(ctx, secret.ID, scope)
		assert.True(t, found)
		require.NotNil(t, cached)
		assert.Equal(t, secret.ID, cached.ID)
		assert.Equal(t, secret.Name, cached.Name)
		assert.Equal(t, secret.Value, cached.Value)
		assert.Equal(t, secret.Version, cached.Version)
		assert.Equal(t, secret.Tags, cached.Tags)
	})

	t.Run("DeleteByID removes secret from cache", func(t *testing.T) {
		// Delete the secret
		err := cache.DeleteByID(ctx, secret.ID)
		assert.NoError(t, err)

		// Verify it's gone
		cached, found := cache.Get(ctx, secret.ID, scope)
		assert.False(t, found)
		assert.Nil(t, cached)
	})

	t.Run("Set nil secret returns error", func(t *testing.T) {
		err := cache.Set(ctx, nil, scope)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot cache nil secret")
	})
}

// TestSecretCacheExpiration tests TTL expiration functionality.
func TestSecretCacheExpiration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Use a very short TTL for testing
	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 100 * time.Millisecond, CleanupInterval: 10 * time.Millisecond, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "expiring-secret",
		Value:     "encrypted-value",
		Version:   1,
		CreatedAt: time.Now(),
	}

	t.Run("Secret expires after TTL", func(t *testing.T) {
		// Set the secret
		err := cache.Set(ctx, secret, scope)
		require.NoError(t, err)

		// Verify it's cached immediately
		cached, found := cache.Get(ctx, secret.ID, scope)
		assert.True(t, found)
		assert.NotNil(t, cached)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Verify it's expired
		cached, found = cache.Get(ctx, secret.ID, scope)
		assert.False(t, found)
		assert.Nil(t, cached)
	})
}

// TestSecretCacheStats tests cache statistics.
func TestSecretCacheStats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	t.Run("Stats returns correct information", func(t *testing.T) {
		// Initially empty
		stats := cache.GetStats()
		assert.Equal(t, 0, stats["total_entries"])
		assert.Equal(t, 0, stats["expired_entries"])

		// Add some secrets
		for i := 0; i < 3; i++ {
			secret := &model.Secret{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				Name:      fmt.Sprintf("secret-%d", i),
				Value:     "encrypted-value",
				Version:   1,
				CreatedAt: time.Now(),
			}
			err := cache.Set(ctx, secret, scope)
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
	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	secretCount := 10
	secrets := make([]*model.Secret, secretCount)
	for i := 0; i < secretCount; i++ {
		secrets[i] = &model.Secret{
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
			go func(secret *model.Secret) {
				err := cache.Set(ctx, secret, scope)
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
			cached, found := cache.Get(ctx, secret.ID, scope)
			assert.True(t, found)
			assert.NotNil(t, cached)
			assert.Equal(t, secret.ID, cached.ID)
		}
	})

	t.Run("Concurrent Get operations", func(t *testing.T) {
		// Pre-populate cache
		for _, secret := range secrets {
			err := cache.Set(ctx, secret, scope)
			require.NoError(t, err)
		}

		// Run concurrent Get operations
		done := make(chan bool, secretCount)
		for i := 0; i < secretCount; i++ {
			go func(secretID uuid.UUID) {
				cached, found := cache.Get(ctx, secretID, scope)
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
					cached, found := cache.Get(ctx, secretID, scope)
					if found {
						assert.NotNil(t, cached)
					}
					done <- true
				}(secrets[i].ID)
			} else {
				// Set operation (update existing)
				go func(secret *model.Secret) {
					err := cache.Set(ctx, secret, scope)
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

// TestSecretCacheBackgroundSweep proves the SecretCache wrapper calls through
// to cachekit's self-managed TTL sweep correctly. The sweep mechanics
// themselves (ticker cadence, concurrent-safe removal) are cachekit's own
// responsibility and are already covered by
// internal/cachekit/cache_test.go's TestCache_Get_MissAfterTTLExpiry and its
// sibling sweep tests -- this test only confirms SecretCache doesn't need a
// caller-driven StartCleanup/Clear step anymore.
func TestSecretCacheBackgroundSweep(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 50 * time.Millisecond, CleanupInterval: 10 * time.Millisecond, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "cleanup-test-secret",
		Value:     "encrypted-value",
		Version:   1,
		CreatedAt: time.Now(),
	}

	require.NoError(t, cache.Set(ctx, secret, scope))

	// Verify secret is cached initially, with no separate StartCleanup call.
	cached, found := cache.Get(ctx, secret.ID, scope)
	assert.True(t, found)
	assert.NotNil(t, cached)

	// Wait for the TTL to elapse; cachekit's own background sweep runs on
	// its own from construction.
	time.Sleep(150 * time.Millisecond)

	cached, found = cache.Get(ctx, secret.ID, scope)
	assert.False(t, found)
	assert.Nil(t, cached)
}

// TestSecretCacheEdgeCases tests edge cases and error conditions.
func TestSecretCacheEdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	t.Run("DeleteByID for non-existent secret is no-op", func(t *testing.T) {
		nonExistentID := uuid.New()
		err := cache.DeleteByID(ctx, nonExistentID)
		assert.NoError(t, err) // Should not return error
	})

	t.Run("GetStats on empty cache returns zeros", func(t *testing.T) {
		stats := cache.GetStats()
		assert.Equal(t, 0, stats["total_entries"])
		assert.Equal(t, 0, stats["expired_entries"])
	})

	t.Run("Zero TTL cache still works", func(t *testing.T) {
		zeroTTLCache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 0, CleanupInterval: time.Millisecond, MaxEntries: 1000}, logger)
		defer zeroTTLCache.Stop()
		secret := &model.Secret{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Name:      "zero-ttl-secret",
			Value:     "encrypted-value",
			Version:   1,
			CreatedAt: time.Now(),
		}

		// Set should work
		err := zeroTTLCache.Set(ctx, secret, scope)
		assert.NoError(t, err)

		// Get should immediately return not found due to zero TTL
		cached, found := zeroTTLCache.Get(ctx, secret.ID, scope)
		assert.False(t, found)
		assert.Nil(t, cached)
	})
}

// TestSecretCacheWithSoftDelete tests cache behavior with soft-deleted secrets.
func TestSecretCacheWithSoftDelete(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	now := time.Now()
	secret := &model.Secret{
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
		err := cache.Set(ctx, secret, scope)
		assert.NoError(t, err)

		// Should be retrievable from cache
		cached, found := cache.Get(ctx, secret.ID, scope)
		assert.True(t, found)
		assert.NotNil(t, cached)
		assert.Equal(t, secret.DeletedAt, cached.DeletedAt)
		assert.Equal(t, secret.PurgeProtection, cached.PurgeProtection)
	})
}

// TestSecretCacheFlush proves Flush empties the cache unconditionally, live
// or expired.
func TestSecretCacheFlush(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxEntries: 1000}, logger)
	defer cache.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	for i := 0; i < 5; i++ {
		secret := &model.Secret{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Name:      fmt.Sprintf("secret-%d", i),
			Value:     "encrypted-value",
			Version:   1,
			CreatedAt: time.Now(),
		}
		require.NoError(t, cache.Set(ctx, secret, scope))
	}

	err := cache.Flush(ctx)
	assert.NoError(t, err)

	stats := cache.GetStats()
	assert.Equal(t, 0, stats["total_entries"], "Flush must remove all live entries, not just expired ones")
}
