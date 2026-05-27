package keycache_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/keycache"
)

func TestNopCache_NeverHits(t *testing.T) {
	c := keycache.NewNopCache()
	id := uuid.New()

	_, hit := c.Get(id, 1)
	assert.False(t, hit)

	c.Set(id, 1, &keycache.Entry{KeyType: "RSA", Version: 1, ExpiresAt: time.Now().Add(time.Minute)})
	_, hit = c.Get(id, 1)
	assert.False(t, hit, "nop cache must never return a hit")

	c.Invalidate(id)
	c.InvalidateAll()
	c.Stop()

	stats := c.Stats()
	assert.Equal(t, 0, stats.TotalEntries)
}
