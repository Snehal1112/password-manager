package rocketmemcache

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
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

	// Logger receives a Warn on every degraded L2 operation (a real error,
	// not a legitimate cache miss) and on a failed startup Ping. Never
	// logs payload/value material -- only operation, wire key/prefix, and
	// error. Falls back to logrus's standard logger if nil, so a
	// hand-constructed Config never panics on a nil-logger call.
	Logger *logrus.Logger
}

// Client implements cachekit.L2 against a real Rocket-mem (or any
// RESP2/3-compatible) server. Every method swallows errors per the
// design spec's fail-open contract: an unreachable or misbehaving
// Rocket-mem must degrade to a cache miss, never break a caller. Errors are
// not silently dropped anymore, though -- every degraded path logs a Warn
// (see Config.Logger) so an operator can tell a fully-broken L2 apart from a
// healthy one instead of both looking identical.
type Client struct {
	rdb    *redis.Client
	logger *logrus.Logger
}

// New constructs a Client. The underlying connection is lazy (go-redis
// dials on first use), so New itself never blocks or fails. Call Ping
// afterward for a one-shot, non-fatal reachability check.
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
	logger := cfg.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	return &Client{rdb: redis.NewClient(opts), logger: logger}
}

// Ping issues a single, one-shot connectivity check. Intended to be called
// once, right after New, by the container -- never on a hot path. Non-fatal
// by design (the spec requires an L2 outage to never break the data plane):
// callers should log a Warn on a non-nil return, not abort startup.
func (c *Client) Ping() error {
	err := c.rdb.Ping(context.Background()).Err()
	if err != nil {
		c.logger.WithError(err).Warn("rocketmemcache: startup PING failed -- L2 cache tier may be unreachable")
	}
	return err
}

// Get returns the value stored under wireKey. A legitimate miss (redis.Nil)
// degrades to (nil, false) silently; any other error (network failure,
// timeout, auth failure) also degrades to (nil, false) but is logged at
// Warn, since it means L2 is unreachable or misbehaving rather than simply
// not holding this key.
func (c *Client) Get(wireKey string) ([]byte, bool) {
	val, err := c.rdb.Get(context.Background(), wireKey).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			c.logger.WithError(err).WithField("wire_key", wireKey).Warn("rocketmemcache: Get failed, degrading to cache miss")
		}
		return nil, false
	}
	return val, true
}

// Set stores payload under wireKey with the given TTL. A ttl <= 0 is
// treated as a footgun, not a valid "no expiry" request -- see the design
// spec's Range/invalidation note on why every L2 entry must expire on its
// own; cachekit.Config.Validate() already requires TTL > 0 for every
// config-driven caller, so this only guards a hand-constructed Config with
// no such validation. Any write error is silently dropped except for a
// Warn log -- a failed cache write must never surface to the caller (see
// cachekit.L2's contract).
func (c *Client) Set(wireKey string, payload []byte, ttl time.Duration) {
	if ttl <= 0 {
		c.logger.WithField("wire_key", wireKey).Warn("rocketmemcache: Set called with non-positive ttl, defaulting to 1m")
		ttl = time.Minute
	}
	if err := c.rdb.Set(context.Background(), wireKey, payload, ttl).Err(); err != nil {
		c.logger.WithError(err).WithField("wire_key", wireKey).Warn("rocketmemcache: Set failed")
	}
}

// Invalidate deletes wireKey. Errors are logged at Warn and otherwise
// silently dropped, same reasoning as Set.
func (c *Client) Invalidate(wireKey string) {
	if err := c.rdb.Del(context.Background(), wireKey).Err(); err != nil {
		c.logger.WithError(err).WithField("wire_key", wireKey).Warn("rocketmemcache: Invalidate failed")
	}
}

// Keys returns every live key matching prefix* (Rocket-mem's KEYS
// supports a basic prefix-wildcard glob -- verified against a live
// instance in this package's integration suite). Any error degrades to an
// empty slice, same fail-open reasoning as every other method here, and is
// logged at Warn.
func (c *Client) Keys(prefix string) []string {
	keys, err := c.rdb.Keys(context.Background(), prefix+"*").Result()
	if err != nil {
		c.logger.WithError(err).WithField("prefix", prefix).Warn("rocketmemcache: Keys failed, degrading to empty")
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
