package keycache

import "github.com/google/uuid"

// NopCache is a no-op Cache used when caching is disabled or in tests that
// do not need cache behaviour.
type NopCache struct{}

// NewNopCache returns a NopCache.
func NewNopCache() Cache { return &NopCache{} }

func (n *NopCache) Get(_ uuid.UUID, _ int) (*Entry, bool) { return nil, false }
func (n *NopCache) Set(_ uuid.UUID, _ int, _ *Entry)      {}
func (n *NopCache) Invalidate(_ uuid.UUID)                {}
func (n *NopCache) InvalidateAll()                        {}
func (n *NopCache) Stats() CacheStats                     { return CacheStats{} }
func (n *NopCache) Stop()                                 {}
