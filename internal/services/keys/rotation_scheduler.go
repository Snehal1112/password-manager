package keys

import (
	"context"
	"time"

	"rocketvault/internal/logging"
	"rocketvault/internal/schedulerkit"
)

// RotationScheduler runs a RotationExecutor on a configurable interval.
type RotationScheduler struct {
	runner   *schedulerkit.Runner
	interval time.Duration
}

// NewRotationScheduler creates a scheduler with the given interval. If
// interval is <= 0 it defaults to 1 hour.
func NewRotationScheduler(executor *RotationExecutor, log *logging.Logger, interval time.Duration) *RotationScheduler {
	if interval <= 0 {
		interval = time.Hour
	}
	return &RotationScheduler{
		runner:   schedulerkit.NewRunner("key rotation", executor.Check, log),
		interval: interval,
	}
}

// Start launches the scheduler in a background goroutine.
func (s *RotationScheduler) Start(ctx context.Context) {
	_ = s.runner.Start(ctx, s.interval) // Runner logs its own start/error lines.
}

// Stop signals the scheduler to stop.
func (s *RotationScheduler) Stop() {
	_ = s.runner.Stop()
}
