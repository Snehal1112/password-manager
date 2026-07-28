package cache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func newScopeCache(t *testing.T, ttl time.Duration) *SecretCache {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return NewSecretCache(ttl, l)
}

func TestScopeCacheKeyIsCompoundAndNeverCachesAdmin(t *testing.T) {
	secretID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()

	key, ok := scopeCacheKey(secretID, model.NewVaultScope(vaultID, uuid.New()))
	require.True(t, ok)
	assert.Equal(t, "v|"+vaultID.String()+"|"+secretID.String(), key)

	key, ok = scopeCacheKey(secretID, model.NewOwnerScope(vaultID, ownerID))
	require.True(t, ok)
	assert.Equal(t, "o|"+ownerID.String()+"|"+secretID.String(), key)

	_, ok = scopeCacheKey(secretID, model.NewAdminScope(uuid.New()))
	assert.False(t, ok, "admin reads are never cached")

	var zero model.Scope
	_, ok = scopeCacheKey(secretID, zero)
	assert.False(t, ok, "an invalid scope is never cached")
}

// TestVaultScopedEntryIsNotServedToAnOwnerScopedCaller is the security property
// the compound key exists for.
func TestVaultScopedEntryIsNotServedToAnOwnerScopedCaller(t *testing.T) {
	c := newScopeCache(t, time.Minute)
	ctx := context.Background()

	secretID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	secret := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true}

	require.NoError(t, c.Set(ctx, secret, model.NewVaultScope(vaultID, uuid.New())))

	_, found := c.Get(ctx, secretID, model.NewOwnerScope(vaultID, ownerID))
	assert.False(t, found, "a vault-scoped entry must not satisfy an owner-scoped read")

	_, found = c.Get(ctx, secretID, model.NewVaultScope(vaultID, uuid.New()))
	assert.True(t, found)
}

func TestDeleteByIDEvictsEveryScopedView(t *testing.T) {
	c := newScopeCache(t, time.Minute)
	ctx := context.Background()

	secretID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	secret := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true}
	vaultScope := model.NewVaultScope(vaultID, uuid.New())
	ownerScope := model.NewOwnerScope(vaultID, ownerID)

	require.NoError(t, c.Set(ctx, secret, vaultScope))
	require.NoError(t, c.Set(ctx, secret, ownerScope))

	require.NoError(t, c.DeleteByID(ctx, secretID))

	_, found := c.Get(ctx, secretID, vaultScope)
	assert.False(t, found)
	_, found = c.Get(ctx, secretID, ownerScope)
	assert.False(t, found)
}

func TestFlushRemovesLiveEntriesWhileClearOnlyPrunesExpired(t *testing.T) {
	ctx := context.Background()
	secretID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	secret := &model.Secret{ID: secretID, VaultID: vaultID, Value: "plaintext", Enabled: true}

	live := newScopeCache(t, time.Minute)
	require.NoError(t, live.Set(ctx, secret, scope))
	require.NoError(t, live.Clear(ctx))
	_, found := live.Get(ctx, secretID, scope)
	assert.True(t, found, "Clear only prunes expired entries")

	require.NoError(t, live.Flush(ctx))
	_, found = live.Get(ctx, secretID, scope)
	assert.False(t, found, "Flush removes live entries")
}

func TestExpiredEntryIsAMiss(t *testing.T) {
	c := newScopeCache(t, time.Nanosecond)
	ctx := context.Background()

	secretID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	require.NoError(t, c.Set(ctx, &model.Secret{ID: secretID, VaultID: vaultID, Enabled: true}, scope))

	time.Sleep(time.Millisecond)
	_, found := c.Get(ctx, secretID, scope)
	assert.False(t, found)
}
