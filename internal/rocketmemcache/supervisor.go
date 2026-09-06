package rocketmemcache

import (
	"context"
	"math/rand"
	"time"
)

// ReconnectPolicy controls RunSupervisor's polling cadence. SteadyStateInterval
// <= 0 disables the supervisor entirely (RunSupervisor returns immediately).
type ReconnectPolicy struct {
	// SteadyStateInterval is how often the supervisor pings Rocket-mem while
	// it believes the connection is healthy.
	SteadyStateInterval time.Duration
	// InitialBackoff is the first retry delay once a ping fails.
	InitialBackoff time.Duration
	// MaxBackoff caps the growing retry delay.
	MaxBackoff time.Duration
	// BackoffMultiplier grows the delay after each failed retry
	// (delay *= BackoffMultiplier, capped at MaxBackoff).
	BackoffMultiplier float64
}

// RunSupervisor polls Rocket-mem's reachability in the background until ctx
// is cancelled -- it is meant to run in its own goroutine for the life of
// the process (started once, alongside the client, and stopped by
// cancelling ctx when the client is closed).
//
// While healthy, it polls at SteadyStateInterval. The first failed poll logs
// one Warn (the healthy -> unhealthy transition) and switches to a growing,
// jittered backoff (capped at MaxBackoff); it stays silent on every
// subsequent failed retry, so a sustained outage produces one log line, not
// one per attempt. The first successful poll after a failure logs one Info
// (the unhealthy -> healthy transition) and resets to SteadyStateInterval.
//
// This loop's view of health does not gate Get/Set/Invalidate/Keys -- those
// always attempt the network directly, regardless of what this loop
// currently believes, preserving the existing fail-open design. This exists
// purely so recovery is detected and logged even when no real cache traffic
// happens to rediscover it on its own.
func (c *Client) RunSupervisor(ctx context.Context, policy ReconnectPolicy) {
	if policy.SteadyStateInterval <= 0 {
		return
	}

	healthy := true
	delay := policy.InitialBackoff

	timer := time.NewTimer(policy.SteadyStateInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		err := c.pingCheck(ctx)
		if err == nil {
			if !healthy {
				c.logger.Info("rocketmemcache: reconnected to Rocket-mem")
			}
			healthy = true
			delay = policy.InitialBackoff
			timer.Reset(policy.SteadyStateInterval)
			continue
		}

		if healthy {
			c.logger.WithError(err).Warn("rocketmemcache: lost connection to Rocket-mem, retrying with backoff")
		}
		healthy = false
		timer.Reset(addJitter(delay))
		delay = growBackoff(delay, policy.BackoffMultiplier, policy.MaxBackoff)
	}
}

// addJitter adds up to 30% additive jitter to d, matching the jitter formula
// already used by internal/retry.calculateDelay elsewhere in this codebase
// (this package deliberately does not import that one -- see the package
// doc comment in client.go on keeping this package's only real dependency as
// go-redis).
func addJitter(d time.Duration) time.Duration {
	jitter := time.Duration(rand.Float64() * 0.3 * float64(d))
	return d + jitter
}

// growBackoff returns current * multiplier, capped at max.
func growBackoff(current time.Duration, multiplier float64, max time.Duration) time.Duration {
	next := time.Duration(float64(current) * multiplier)
	if next > max {
		return max
	}
	return next
}
