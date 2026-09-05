//go:build integration

// Package rocketmemcache integration suite proves Client's RESP calls
// actually work against a live rocket-mem instance. Run with:
//
//	go test -tags=integration ./internal/rocketmemcache/...
//
// Requires a rocket-mem instance reachable at ROCKETMEM_TEST_ADDR (defaults
// to 127.0.0.1:6379, matching a locally-started `rocket-mem` binary). The
// default `go test ./...` run skips this file.
package rocketmemcache_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/rocketmemcache"
)

func testAddr() string {
	if a := os.Getenv("ROCKETMEM_TEST_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6379"
}

func newTestClient(t *testing.T) *rocketmemcache.Client {
	t.Helper()
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         testAddr(),
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		PoolSize:     5,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClient_SetGet_RoundTrip(t *testing.T) {
	c := newTestClient(t)
	key := "rocketmemcache_test:roundtrip:" + t.Name()

	c.Set(key, []byte("hello-world"), 30*time.Second)
	got, ok := c.Get(key)
	require.True(t, ok)
	assert.Equal(t, "hello-world", string(got))

	c.Invalidate(key)
	_, ok = c.Get(key)
	assert.False(t, ok, "Get after Invalidate must miss")
}

func TestClient_Get_MissingKey_ReturnsFalseNotError(t *testing.T) {
	c := newTestClient(t)
	_, ok := c.Get("rocketmemcache_test:definitely-does-not-exist")
	assert.False(t, ok)
}

func TestClient_Get_Unreachable_DegradesToMiss(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         "127.0.0.1:1", // nothing listens here
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolSize:     1,
	})
	defer c.Close()

	assert.NotPanics(t, func() {
		_, ok := c.Get("anything")
		assert.False(t, ok)
	})
	assert.NotPanics(t, func() {
		c.Set("anything", []byte("x"), time.Minute) // must not panic or block past the dial timeout
	})
}
