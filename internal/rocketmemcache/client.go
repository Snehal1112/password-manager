package rocketmemcache

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds connection settings for one shared Rocket-mem instance,
// backing the L2 tier for all four RocketVault domain caches. See
// config.LoadRocketMemConfig (Plan 04) for how this is populated from
// cache.rocket_mem.* in .rocketvault.yaml.
type Config struct {
	Addr         string
	TLS          bool
	Username     string
	Password     string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
}

// Client implements cachekit.L2 against a real Rocket-mem (or any
// RESP2/3-compatible) server. Every method swallows errors per the
// design spec's fail-open contract: an unreachable or misbehaving
// Rocket-mem must degrade to a cache miss, never break a caller.
type Client struct {
	rdb *redis.Client
}

// New constructs a Client. The underlying connection is lazy (go-redis
// dials on first use), so New itself never blocks or fails.
func New(cfg Config) *Client {
	opts := &redis.Options{
		Addr:         cfg.Addr,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &Client{rdb: redis.NewClient(opts)}
}

// Get returns the value stored under wireKey. Any error -- key-not-found
// (redis.Nil), network failure, or timeout -- degrades to (nil, false).
func (c *Client) Get(wireKey string) ([]byte, bool) {
	val, err := c.rdb.Get(context.Background(), wireKey).Bytes()
	if err != nil {
		return nil, false
	}
	return val, true
}

// Set stores payload under wireKey with the given TTL. Any error is
// silently dropped -- a failed cache write must never surface to the
// caller (see cachekit.L2's contract).
func (c *Client) Set(wireKey string, payload []byte, ttl time.Duration) {
	_ = c.rdb.Set(context.Background(), wireKey, payload, ttl).Err()
}

// Invalidate deletes wireKey. Errors are silently dropped, same reasoning
// as Set.
func (c *Client) Invalidate(wireKey string) {
	_ = c.rdb.Del(context.Background(), wireKey).Err()
}

// Keys returns every live key matching prefix* (Rocket-mem's KEYS
// supports a basic prefix-wildcard glob -- verified against a live
// instance in this package's integration suite). Any error degrades to an
// empty slice, same fail-open reasoning as every other method here.
func (c *Client) Keys(prefix string) []string {
	keys, err := c.rdb.Keys(context.Background(), prefix+"*").Result()
	if err != nil {
		return nil
	}
	return keys
}

// Close releases the underlying connection pool. Owned and called exactly
// once by the container (see the design spec's "L2 connection lifecycle"
// note) -- never by an individual TieredCache.
func (c *Client) Close() error {
	return c.rdb.Close()
}
