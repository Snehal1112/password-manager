// Package rocketmemcache default-build test suite proves Client builds,
// satisfies cachekit.L2, and degrades gracefully when unreachable. Run with:
//
//	go test ./internal/rocketmemcache/...
//
// (no build tag required — this is the default suite)
package rocketmemcache_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/rocketmemcache"
)

var _ cachekit.L2 = (*rocketmemcache.Client)(nil)

func TestClient_Unreachable_KeysDegradesToEmpty(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         "127.0.0.1:1",
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolSize:     1,
	})
	defer c.Close()

	var keys []string
	assert.NotPanics(t, func() { keys = c.Keys("rocketvault:secret:") })
	assert.Empty(t, keys)
}

func TestClient_Close_Idempotent(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{Addr: "127.0.0.1:1"})
	assert.NoError(t, c.Close())
}
