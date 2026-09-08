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
	"fmt"
	"os"
	"strings"
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

func TestClient_Keys_ReturnsMatchingPrefix(t *testing.T) {
	c := newTestClient(t)
	prefix := "rocketmemcache_test:keys:" + t.Name() + ":"
	c.Set(prefix+"a", []byte("1"), 30*time.Second)
	c.Set(prefix+"b", []byte("2"), 30*time.Second)
	defer c.Invalidate(prefix + "a")
	defer c.Invalidate(prefix + "b")

	keys := c.Keys(prefix)
	assert.ElementsMatch(t, []string{prefix + "a", prefix + "b"}, keys)
}

func testClusterAddrs() []string {
	if a := os.Getenv("ROCKETMEM_TEST_CLUSTER_ADDRS"); a != "" {
		return strings.Split(a, ",")
	}
	return []string{"127.0.0.1:16379", "127.0.0.1:16380", "127.0.0.1:16381"}
}

func newTestClusterClient(t *testing.T) *rocketmemcache.Client {
	t.Helper()
	c := rocketmemcache.New(rocketmemcache.Config{
		ClusterMode:  true,
		Addrs:        testClusterAddrs(),
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		PoolSize:     5,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClusterClient_SetGet_RoundTrip(t *testing.T) {
	c := newTestClusterClient(t)
	key := "rocketmemcache_test:cluster_roundtrip:" + t.Name()

	c.Set(key, []byte("hello-cluster"), 30*time.Second)
	got, ok := c.Get(key)
	require.True(t, ok)
	assert.Equal(t, "hello-cluster", string(got))

	c.Invalidate(key)
	_, ok = c.Get(key)
	assert.False(t, ok, "Get after Invalidate must miss")
}

func TestClusterClient_Keys_FansOutAcrossShards(t *testing.T) {
	c := newTestClusterClient(t)
	prefix := "rocketmemcache_test:cluster_keys:" + t.Name() + ":"

	// Enough distinct keys that, with 16384 slots spread across 3 shards,
	// at least one lands on each shard with overwhelming probability --
	// this is what actually exercises ForEachMaster's fan-out instead of
	// happening to pass against a single shard.
	var want []string
	for i := 0; i < 30; i++ {
		k := prefix + fmt.Sprintf("%d", i)
		c.Set(k, []byte("v"), 30*time.Second)
		want = append(want, k)
	}
	t.Cleanup(func() {
		for _, k := range want {
			c.Invalidate(k)
		}
	})

	got := c.Keys(prefix)
	assert.ElementsMatch(t, want, got)
}
