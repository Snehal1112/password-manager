package mcpserver

import (
	"golang.org/x/time/rate"

	"rocketvault/config"
)

// limiter bounds how fast tools may be called.
//
// Reads and everything else get separate budgets: a burst of listing must not
// exhaust the allowance a legitimate write needs, and the write budget is
// deliberately much smaller, because a runaway write loop does real damage
// where a runaway read loop only wastes time.
type limiter struct {
	reads  *rate.Limiter
	writes *rate.Limiter
}

// newLimiter builds the per-class buckets.
//
// Burst equals the per-minute rate, so a short flurry of calls is permitted
// and only sustained hammering trips the limit.
func newLimiter(cfg config.MCPRateLimit) *limiter {
	perMinute := func(n int) *rate.Limiter {
		return rate.NewLimiter(rate.Limit(float64(n)/60.0), n)
	}
	return &limiter{
		reads:  perMinute(cfg.ReadsPerMinute),
		writes: perMinute(cfg.WritesPerMinute),
	}
}

// allow reports whether a call in tier may proceed.
//
// It refuses immediately rather than waiting for a token. Blocking would
// leave a looping agent with an ever-growing queue of goroutines, each
// holding a deadline; refusing lets the model see an error and back off.
func (l *limiter) allow(tier Tier) bool {
	if tier == TierRead {
		return l.reads.Allow()
	}
	// Write, destructive, crypto and login share one budget: all four are
	// consequential in a way reads are not.
	return l.writes.Allow()
}
