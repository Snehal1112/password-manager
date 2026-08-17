// Package schedulerkit provides a generic ticker-based scheduler core,
// shared by every domain that runs a periodic background check (secret
// rotation, certificate renewal, key rotation). It has no knowledge of what
// any check function does.
package schedulerkit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"rocketvault/internal/logging"
)

// CheckFunc is one scheduled unit of work. A returned error is logged by the
// Runner and does not stop the loop — the next tick still runs. Domain-level
// per-item error handling (e.g. "one bad item must not abort the sweep")
// belongs inside CheckFunc; only a failure of the sweep itself (e.g. the
// due-item query failing) should be returned here.
type CheckFunc func(ctx context.Context) error

// Runner runs a CheckFunc once immediately on Start, then once per interval,
// until Stop is called.
type Runner struct {
	name     string
	checkFn  CheckFunc
	log      *logging.Logger
	ctx      context.Context
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	running  bool
}

// NewRunner creates a Runner. name identifies this runner in log lines
// (e.g. "secret rotation", "key rotation", "certificate renewal").
func NewRunner(name string, checkFn CheckFunc, log *logging.Logger) *Runner {
	return &Runner{name: name, checkFn: checkFn, log: log}
}

// Start launches the ticker loop in the background and returns immediately
// -- it does not block on the first check. Returns an error if already
// running, or if interval is not positive (time.NewTicker panics on
// interval <= 0; this defends every caller, including any that fail to
// guard a config-sourced interval themselves).
func (r *Runner) Start(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("%s scheduler: interval must be positive, got %s", r.name, interval)
	}

	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("%s scheduler is already running", r.name)
	}
	r.ctx = ctx
	r.running = true
	r.stopChan = make(chan struct{})
	r.ticker = time.NewTicker(interval)
	r.wg.Add(1)
	r.mu.Unlock()

	go r.run()

	r.log.WithField("interval", interval).Infof("%s scheduler started", r.name)
	return nil
}

// Stop signals the loop to exit and waits for any in-flight check to finish.
// Safe to call on a Runner that was never started.
func (r *Runner) Stop() error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = false
	close(r.stopChan)
	r.ticker.Stop()
	r.mu.Unlock()

	r.wg.Wait()
	r.log.Infof("%s scheduler stopped", r.name)
	return nil
}

// IsRunning returns whether the scheduler is currently running.
func (r *Runner) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

func (r *Runner) run() {
	defer r.wg.Done()

	r.runOnce() // Run once immediately, then on each subsequent tick.
	for {
		select {
		case <-r.ticker.C:
			r.runOnce()
		case <-r.stopChan:
			return
		case <-r.ctx.Done():
			// Mirrors the pre-schedulerkit certificate scheduler, which
			// exited its loop when its context was cancelled even without an
			// explicit Stop() call. Without this, an embedder that cancels
			// ctx but never calls Stop() leaks this goroutine forever.
			r.markStopped()
			return
		}
	}
}

// markStopped marks the runner as no longer running, matching the state
// Stop() would leave it in. Safe to call even if Stop() is concurrently
// racing it -- whichever runs first under the lock wins, and Stop() treats
// an already-stopped runner as a no-op (see Stop's own !r.running check).
func (r *Runner) markStopped() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return
	}
	r.running = false
	r.ticker.Stop()
}

func (r *Runner) runOnce() {
	if err := r.checkFn(r.ctx); err != nil {
		r.log.WithError(err).Errorf("%s scheduler tick failed", r.name)
	}
}
