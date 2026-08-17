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
// -- it does not block on the first check. Returns an error if already running.
func (r *Runner) Start(ctx context.Context, interval time.Duration) error {
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
		}
	}
}

func (r *Runner) runOnce() {
	if err := r.checkFn(r.ctx); err != nil {
		r.log.WithError(err).Errorf("%s scheduler tick failed", r.name)
	}
}
