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

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/rocketmemcache"
)

var _ cachekit.L2 = (*rocketmemcache.Client)(nil)

// unreachableConfig builds a Config pointed at an address nothing listens
// on, with short timeouts so tests fail fast rather than hanging.
func unreachableConfig(logger *logrus.Logger) rocketmemcache.Config {
	return rocketmemcache.Config{
		Addr:         "127.0.0.1:1",
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolSize:     1,
		Logger:       logger,
	}
}

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

// TestClient_NilLogger_DoesNotPanic proves a hand-constructed Config with no
// Logger set falls back to logrus's standard logger rather than nil-panicking
// on the first Warn call.
func TestClient_NilLogger_DoesNotPanic(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         "127.0.0.1:1",
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolSize:     1,
	})
	defer c.Close()

	assert.NotPanics(t, func() { c.Get("anything") })
	assert.NotPanics(t, func() { c.Set("anything", []byte("x"), time.Minute) })
	assert.NotPanics(t, func() { c.Invalidate("anything") })
	assert.NotPanics(t, func() { _ = c.Ping() })
}

// TestClient_Ping_Unreachable_ReturnsErrorAndLogsWarn proves the one-shot
// startup Ping degrades to a non-fatal error (never a panic) and logs a Warn
// with enough context to diagnose, per the Important fix wave item.
func TestClient_Ping_Unreachable_ReturnsErrorAndLogsWarn(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	c := rocketmemcache.New(unreachableConfig(logger))
	defer c.Close()

	var err error
	assert.NotPanics(t, func() { err = c.Ping() })
	assert.Error(t, err)

	entries := hook.AllEntries()
	require.NotEmpty(t, entries, "Ping failure must log a Warn")
	assert.Equal(t, logrus.WarnLevel, entries[len(entries)-1].Level)
}

// TestClient_Get_RealError_LogsWarn proves a real error (not a legitimate
// miss) on Get is logged at Warn -- the fix for L2 errors being silently
// dropped. Uses an unreachable server, which surfaces as a connection error
// rather than redis.Nil.
func TestClient_Get_RealError_LogsWarn(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	c := rocketmemcache.New(unreachableConfig(logger))
	defer c.Close()

	_, ok := c.Get("rocketvault:secret:some-key")
	assert.False(t, ok)

	found := false
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			found = true
			// Must carry the wire key for diagnosis, never a value/payload
			// (there is none passed to Get, so this only checks the field
			// is present and sane).
			assert.Equal(t, "rocketvault:secret:some-key", e.Data["wire_key"])
		}
	}
	assert.True(t, found, "a real Get error must log a Warn")
}

// TestClient_Set_LogsWarn_NeverLogsPayload proves a failed Set logs a Warn
// with the wire key but never the payload/value, so secret material is never
// written to logs even when L2 is broken.
func TestClient_Set_LogsWarn_NeverLogsPayload(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	c := rocketmemcache.New(unreachableConfig(logger))
	defer c.Close()

	c.Set("rocketvault:secret:some-key", []byte("TOP-SECRET-PAYLOAD"), time.Minute)

	found := false
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			for _, v := range e.Data {
				if s, ok := v.(string); ok {
					assert.NotContains(t, s, "TOP-SECRET-PAYLOAD")
				}
			}
			if e.Data["wire_key"] == "rocketvault:secret:some-key" {
				found = true
			}
		}
	}
	assert.True(t, found, "a failed Set must log a Warn carrying the wire key")
}

// TestClient_Set_NonPositiveTTL_DoesNotPanicAndWarns proves the defensive
// ttl<=0 guard: unreachable today via cachekit.Config.Validate() (which
// requires TTL > 0 everywhere it constructs a cachekit.Config), but a
// footgun for any future hand-constructed one. Set must not silently treat
// a non-positive ttl as "no expiry" -- it logs a Warn and substitutes a short
// sane default instead.
func TestClient_Set_NonPositiveTTL_DoesNotPanicAndWarns(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	c := rocketmemcache.New(unreachableConfig(logger))
	defer c.Close()

	assert.NotPanics(t, func() { c.Set("rocketvault:secret:zero-ttl", []byte("x"), 0) })
	assert.NotPanics(t, func() { c.Set("rocketvault:secret:neg-ttl", []byte("x"), -time.Second) })

	foundTTLWarn := false
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && e.Data["wire_key"] == "rocketvault:secret:zero-ttl" {
			foundTTLWarn = true
		}
	}
	assert.True(t, foundTTLWarn, "a non-positive ttl must log a Warn about the substituted default")
}

func TestClient_ClusterMode_Unreachable_DegradesGracefully(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		ClusterMode:  true,
		Addrs:        []string{"127.0.0.1:1", "127.0.0.1:2"}, // nothing listens here
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
	assert.NotPanics(t, func() { c.Set("anything", []byte("x"), time.Minute) })
	assert.NotPanics(t, func() { c.Invalidate("anything") })
	assert.NotPanics(t, func() { assert.Error(t, c.Ping()) })
}

// TestClient_ClusterMode_Unreachable_KeysDegradesToEmpty proves Keys in
// cluster mode degrades to empty rather than panicking when the cluster
// is unreachable.
func TestClient_ClusterMode_Unreachable_KeysDegradesToEmpty(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{
		ClusterMode:  true,
		Addrs:        []string{"127.0.0.1:1", "127.0.0.1:2"},
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
