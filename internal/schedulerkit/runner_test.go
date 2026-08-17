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
