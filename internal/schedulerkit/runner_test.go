package schedulerkit_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/schedulerkit"
)

func newTestLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func TestRunner_StartRunsCheckImmediately(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), time.Hour))
	defer r.Stop() //nolint:errcheck

	require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) >= 1 }, time.Second, 5*time.Millisecond)
}

func TestRunner_TicksTriggerCheck(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), 10*time.Millisecond))
	defer r.Stop() //nolint:errcheck

	require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) >= 3 }, time.Second, 5*time.Millisecond)
}

func TestRunner_DoubleStartErrors(t *testing.T) {
	check := func(ctx context.Context) error { return nil }
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), time.Hour))
	defer r.Stop() //nolint:errcheck

	require.Error(t, r.Start(context.Background(), time.Hour))
}

func TestRunner_StopWithoutStart_NoPanic(t *testing.T) {
	check := func(ctx context.Context) error { return nil }
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Stop())
}

func TestRunner_StopWaitsForInFlightCheck(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	check := func(ctx context.Context) error {
		close(started)
		<-release
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), time.Hour))

	<-started // The immediate first check is now blocked inside check().
	stopped := make(chan struct{})
	go func() {
		r.Stop() //nolint:errcheck
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Stop returned before the in-flight check finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after the in-flight check finished")
	}
}

func TestRunner_CheckErrorIsLoggedNotFatal(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			return errors.New("boom")
		}
		return nil
	}
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(context.Background(), 10*time.Millisecond))
	defer r.Stop() //nolint:errcheck

	// The loop must keep ticking after a checkFn error, not stop.
	require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) >= 2 }, time.Second, 5*time.Millisecond)
}

func TestRunner_IsRunning(t *testing.T) {
	check := func(ctx context.Context) error { return nil }
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.False(t, r.IsRunning())
	require.NoError(t, r.Start(context.Background(), time.Hour))
	require.True(t, r.IsRunning())
	require.NoError(t, r.Stop())
	require.False(t, r.IsRunning())
}

// TestRunner_StartRejectsNonPositiveInterval covers I3 from the final
// review: time.NewTicker panics on interval <= 0, and this codebase's
// config-driven rotation intervals (secrets/certificates/keys) can now come
// from arbitrary YAML. Runner.Start must reject a non-positive interval with
// an error instead of panicking, regardless of whether the caller (a
// scheduler wrapper) also guards it.
func TestRunner_StartRejectsNonPositiveInterval(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.Error(t, r.Start(context.Background(), -1*time.Second))
	require.False(t, r.IsRunning())

	require.Error(t, r.Start(context.Background(), 0))
	require.False(t, r.IsRunning())

	time.Sleep(20 * time.Millisecond)
	require.Equal(t, int32(0), atomic.LoadInt32(&calls), "checkFn must never run when Start is rejected")
}

// TestRunner_ContextCancelStopsLoop covers M4 from the final review: the
// pre-schedulerkit certificate scheduler exited its loop on ctx.Done() even
// without an explicit Stop() call. Runner.run must do the same, or an
// embedder that cancels ctx without calling Stop() leaks the goroutine.
func TestRunner_ContextCancelStopsLoop(t *testing.T) {
	var calls int32
	check := func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := schedulerkit.NewRunner("test", check, newTestLogger())
	require.NoError(t, r.Start(ctx, 10*time.Millisecond))

	require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) >= 1 }, time.Second, 5*time.Millisecond)
	cancel()

	require.Eventually(t, func() bool { return !r.IsRunning() }, time.Second, 5*time.Millisecond)

	countAtCancel := atomic.LoadInt32(&calls)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, countAtCancel, atomic.LoadInt32(&calls), "checkFn must not run again after context cancellation")

	// Stop() must remain safe to call afterward (matches the "safe on a
	// never-started/already-stopped runner" contract).
	require.NoError(t, r.Stop())
}
