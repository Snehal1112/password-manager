package certcache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

func TestNewCache_GetSetDeleteByID(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	logger := logrus.New()
	c := NewCache(cfg, logger)
	defer c.Stop()

	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: uuid.New(), VaultID: vaultID, Name: "c1", Certificate: "pem", Enabled: true}

	_, found := c.Get(context.Background(), cert.ID, scope)
	assert.False(t, found)

	require.NoError(t, c.Set(context.Background(), cert, scope))
	got, found := c.Get(context.Background(), cert.ID, scope)
	require.True(t, found)
	assert.Equal(t, "c1", got.Name)

	require.NoError(t, c.DeleteByID(context.Background(), cert.ID))
	_, found = c.Get(context.Background(), cert.ID, scope)
	assert.False(t, found, "DeleteByID must evict the entry")
}

func TestCache_BasicOperations(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxEntries: 1000}, logger)
	defer c.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "test-cert",
		Certificate: "pem-body",
		PrivateKey:  "encrypted-key",
		Tags:        []string{"tag1", "tag2"},
		Enabled:     true,
		CreatedAt:   time.Now(),
	}

	t.Run("Get returns false for non-existent certificate", func(t *testing.T) {
		cached, found := c.Get(ctx, uuid.New(), scope)
		assert.False(t, found)
		assert.Nil(t, cached)
	})

	t.Run("Set and Get work correctly", func(t *testing.T) {
		require.NoError(t, c.Set(ctx, cert, scope))

		cached, found := c.Get(ctx, cert.ID, scope)
		assert.True(t, found)
		require.NotNil(t, cached)
		assert.Equal(t, cert.ID, cached.ID)
		assert.Equal(t, cert.Name, cached.Name)
		assert.Equal(t, cert.Certificate, cached.Certificate)
		assert.Equal(t, cert.PrivateKey, cached.PrivateKey, "PrivateKey must round-trip as ciphertext, unchanged")
		assert.Equal(t, cert.Tags, cached.Tags)
	})

	t.Run("DeleteByID removes certificate from cache", func(t *testing.T) {
		require.NoError(t, c.DeleteByID(ctx, cert.ID))
		cached, found := c.Get(ctx, cert.ID, scope)
		assert.False(t, found)
		assert.Nil(t, cached)
	})

	t.Run("Set nil certificate returns error", func(t *testing.T) {
		err := c.Set(ctx, nil, scope)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot cache nil certificate")
	})
}

func TestCache_ScopeIsolation(t *testing.T) {
	logger := logrus.New()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}, logger)
	defer c.Stop()
	ctx := context.Background()

	certID := uuid.New()
	vaultID := uuid.New()
	vaultScope := model.NewVaultScope(vaultID, uuid.New())
	otherVaultScope := model.NewVaultScope(uuid.New(), uuid.New())
	ownerScope := model.NewOwnerScope(vaultID, uuid.New())

	cert := &model.Certificate{ID: certID, VaultID: vaultID, Name: "scoped-cert", Enabled: true}
	require.NoError(t, c.Set(ctx, cert, vaultScope))

	_, found := c.Get(ctx, certID, vaultScope)
	assert.True(t, found, "a value admitted under one vault scope must satisfy a read under the same scope")

	_, found = c.Get(ctx, certID, otherVaultScope)
	assert.False(t, found, "a value admitted under one vault scope must never satisfy a read under a different vault scope")

	_, found = c.Get(ctx, certID, ownerScope)
	assert.False(t, found, "a value admitted under a vault scope must never satisfy a read under an owner scope")
}

func TestCache_AdminScopeNeverCached(t *testing.T) {
	logger := logrus.New()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}, logger)
	defer c.Stop()
	ctx := context.Background()

	cert := &model.Certificate{ID: uuid.New(), Name: "admin-cert", Enabled: true}
	adminScope := model.NewAdminScope(uuid.New())

	require.NoError(t, c.Set(ctx, cert, adminScope), "Set under ScopeAdmin must be a silent no-op, not an error")
	_, found := c.Get(ctx, cert.ID, adminScope)
	assert.False(t, found, "ScopeAdmin must never be cached")
}

func TestCache_Expiration(t *testing.T) {
	logger := logrus.New()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 100 * time.Millisecond, CleanupInterval: 10 * time.Millisecond, MaxEntries: 1000}, logger)
	defer c.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	cert := &model.Certificate{ID: uuid.New(), Name: "expiring-cert", Enabled: true}
	require.NoError(t, c.Set(ctx, cert, scope))

	_, found := c.Get(ctx, cert.ID, scope)
	assert.True(t, found)

	time.Sleep(150 * time.Millisecond)

	_, found = c.Get(ctx, cert.ID, scope)
	assert.False(t, found, "entry must expire after TTL")
}

func TestCache_ConcurrentAccess(t *testing.T) {
	logger := logrus.New()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 1000}, logger)
	defer c.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	certs := make([]*model.Certificate, 20)
	for i := range certs {
		certs[i] = &model.Certificate{ID: uuid.New(), Name: "concurrent-cert", Enabled: true}
	}

	done := make(chan struct{})
	for _, cert := range certs {
		go func(cert *model.Certificate) {
			defer func() { done <- struct{}{} }()
			require.NoError(t, c.Set(ctx, cert, scope))
			c.Get(ctx, cert.ID, scope)
		}(cert)
	}
	for range certs {
		<-done
	}

	stats := c.GetStats()
	assert.Equal(t, len(certs), stats["total_entries"])
}

func TestCache_Flush(t *testing.T) {
	logger := logrus.New()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}, logger)
	defer c.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	cert := &model.Certificate{ID: uuid.New(), Name: "flush-cert", Enabled: true}
	require.NoError(t, c.Set(ctx, cert, scope))

	require.NoError(t, c.Flush(ctx))
	_, found := c.Get(ctx, cert.ID, scope)
	assert.False(t, found)
}

func TestCache_DisabledIsNoOp(t *testing.T) {
	logger := logrus.New()
	c := NewCache(cachekit.Config{Enabled: false}, logger)
	defer c.Stop()
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	cert := &model.Certificate{ID: uuid.New(), Name: "disabled-cert", Enabled: true}
	require.NoError(t, c.Set(ctx, cert, scope))

	_, found := c.Get(ctx, cert.ID, scope)
	assert.False(t, found, "a disabled cache must never serve a hit")
}
