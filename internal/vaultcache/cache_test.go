package vaultcache_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/vaultcache"
	"rocketvault/model"
)

func TestCache_SetThenGet_Hit(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	v := &model.Vault{ID: uuid.New(), Name: "myvault"}
	c.Set("myvault", v)

	got, ok := c.Get("myvault")
	require.True(t, ok)
	assert.Equal(t, "myvault", got.Name)
}

func TestCache_Get_MissForUnknownName(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	_, ok := c.Get("nonexistent")
	assert.False(t, ok)
}

func TestCache_Invalidate_RemovesEntry(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	c.Set("myvault", &model.Vault{ID: uuid.New(), Name: "myvault"})
	c.Invalidate("myvault")

	_, ok := c.Get("myvault")
	assert.False(t, ok)
}

func TestCache_Get_ReturnsClone(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	c.Set("myvault", &model.Vault{ID: uuid.New(), Name: "myvault", Enabled: true})

	got, _ := c.Get("myvault")
	got.Enabled = false // mutate the returned value

	again, _ := c.Get("myvault")
	assert.True(t, again.Enabled, "mutating a Get result must not affect the stored entry")
}

func TestCache_Disabled_NeverHits(t *testing.T) {
	c := vaultcache.NewCache(cachekit.Config{Enabled: false, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 100})
	defer c.Stop()

	c.Set("myvault", &model.Vault{ID: uuid.New(), Name: "myvault"})
	_, ok := c.Get("myvault")
	assert.False(t, ok)
}
