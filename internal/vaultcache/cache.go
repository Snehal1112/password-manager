// Package vaultcache caches vault records by name, closing the gap where
// VaultResolutionMiddleware resolved every request's vault by name with no
// caching layer at all — the single most-frequently-repeated DB lookup in
// the codebase.
package vaultcache

import (
	"time"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// Cache caches *model.Vault by name.
type Cache struct {
	core cachekit.Interface[string, *model.Vault]
}

// NewCache creates a Cache from cfg. Always returns a usable cache: a real
// one when cfg.Enabled, a no-op one otherwise.
func NewCache(cfg cachekit.Config) *Cache {
	return &Cache{core: cachekit.NewFromConfig[string, *model.Vault](cfg)}
}

// Get returns a clone of the vault cached under name, if present and unexpired.
func (c *Cache) Get(name string) (*model.Vault, bool) {
	return c.core.Get(name)
}

// Set stores a clone of v under name.
func (c *Cache) Set(name string, v *model.Vault) {
	c.core.Set(name, v)
}

// Invalidate evicts the entry cached under name, if any.
func (c *Cache) Invalidate(name string) {
	c.core.Invalidate(name)
}

// Stop shuts down the background TTL sweep. Safe to call more than once.
func (c *Cache) Stop() {
	c.core.Stop()
}

// NewCacheWithL2 creates a Cache backed by a TieredCache: cfg's in-process
// cache as L1, l2 as the shared Rocket-mem tier (l2TTL is that tier's own
// entry lifetime). Uses PlainJSONCodec -- model.Vault carries no secret
// material (see the design spec). Used only when cache.rocket_mem is
// enabled; NewCache's behavior is unchanged.
func NewCacheWithL2(cfg cachekit.Config, l2 cachekit.L2, l2TTL time.Duration) *Cache {
	l1 := cachekit.NewFromConfig[string, *model.Vault](cfg)
	var codec cachekit.PlainJSONCodec[*model.Vault]
	keys := cachekit.KeyCodec[string]{
		ToWire:   func(k string) string { return k },
		FromWire: func(w string) (string, bool) { return w, true },
	}
	return &Cache{core: cachekit.NewTieredCache[string, *model.Vault](l1, l2, codec, keys, "rocketvault:vault:", l2TTL)}
}
