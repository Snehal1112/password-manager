// Black-box tests for RunSupervisor, matching client_test.go's style: same
// package, same unreachableConfig helper, same logrustest.NewNullLogger()
// logging-assertion pattern.
package rocketmemcache_test

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/rocketmemcache"
)

// TestRunSupervisor_ZeroInterval_ReturnsImmediately proves SteadyStateInterval
// <= 0 disables the supervisor entirely rather than looping at some default
// cadence.
func TestRunSupervisor_ZeroInterval_ReturnsImmediately(t *testing.T) {
	c := rocketmemcache.New(rocketmemcache.Config{Addr: "127.0.0.1:1"})
	defer c.Close()

	done := make(chan struct{})
	go func() {
		c.RunSupervisor(context.Background(), rocketmemcache.ReconnectPolicy{SteadyStateInterval: 0})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("RunSupervisor did not return immediately for SteadyStateInterval <= 0")
	}
}

// TestRunSupervisor_SustainedFailure_LogsExactlyOneWarn is the specific
// behavior this whole feature exists to get right: a sustained outage must
// produce exactly one Warn (the healthy->unhealthy transition), never one
// per retry attempt.
func TestRunSupervisor_SustainedFailure_LogsExactlyOneWarn(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	c := rocketmemcache.New(unreachableConfig(logger))
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.RunSupervisor(ctx, rocketmemcache.ReconnectPolicy{
			SteadyStateInterval: 10 * time.Millisecond,
			InitialBackoff:      5 * time.Millisecond,
			MaxBackoff:          20 * time.Millisecond,
			BackoffMultiplier:   2.0,
		})
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("RunSupervisor did not stop after ctx cancellation")
	}

	warnCount := 0
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warnCount++
		}
	}
	assert.Equal(t, 1, warnCount, "a sustained outage must log exactly one Warn, not one per retry")
}

// TestRunSupervisor_ContextCancellation_StopsPromptly proves ctx cancellation
// interrupts the loop promptly even while it is mid-backoff-wait, not only
// when it happens to land between polls.
func TestRunSupervisor_ContextCancellation_StopsPromptly(t *testing.T) {
	logger, _ := logrustest.NewNullLogger()
	c := rocketmemcache.New(unreachableConfig(logger))
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.RunSupervisor(ctx, rocketmemcache.ReconnectPolicy{
			SteadyStateInterval: 10 * time.Millisecond,
			InitialBackoff:      50 * time.Millisecond,
			MaxBackoff:          500 * time.Millisecond,
			BackoffMultiplier:   2.0,
		})
		close(done)
	}()

	// Let the supervisor observe the initial failure and enter its long
	// backoff wait, so cancellation lands mid-retry-cycle rather than
	// between polls.
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("RunSupervisor did not stop within 50ms of ctx cancellation")
	}
	assert.Less(t, time.Since(start), 50*time.Millisecond)
}

// TestRunSupervisor_Recovery_LogsWarnThenInfo proves recovery is detected and
// logged even with no real cache traffic: a genuine healthy->unhealthy->
// healthy cycle against a real (minimal, fake) RESP server, asserting the
// Warn appears exactly once and precedes exactly one Info reconnect line.
func TestRunSupervisor_Recovery_LogsWarnThenInfo(t *testing.T) {
	// Reserve a fixed local port, then free it immediately so the
	// client's first several dial attempts genuinely fail with
	// connection-refused rather than connecting to a half-set-up
	// listener.
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := reserved.Addr().String()
	require.NoError(t, reserved.Close())

	logger, hook := logrustest.NewNullLogger()
	c := rocketmemcache.New(rocketmemcache.Config{
		Addr:         addr,
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolSize:     1,
		Logger:       logger,
	})
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.RunSupervisor(ctx, rocketmemcache.ReconnectPolicy{
			SteadyStateInterval: 10 * time.Millisecond,
			InitialBackoff:      10 * time.Millisecond,
			MaxBackoff:          30 * time.Millisecond,
			BackoffMultiplier:   2.0,
		})
		close(done)
	}()

	// go-redis's own dial-retry loop (5 attempts, 100ms backoff between
	// each by default -- see DialerRetries/DialerRetryTimeout in the
	// go-redis v9 source) dominates a single failed pingCheck call's real
	// wall-clock duration (roughly 400-450ms), far outweighing this
	// policy's own tiny intervals. Wait comfortably longer than that worst
	// case before starting the fake server, so the first outer call is a
	// genuine, complete failure (the healthy->unhealthy Warn) rather than
	// a race against the listener coming up mid-retry.
	time.Sleep(700 * time.Millisecond)

	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	defer ln.Close()
	go servePong(ln)

	require.Eventually(t, func() bool {
		for _, e := range hook.AllEntries() {
			if e.Level == logrus.InfoLevel {
				return true
			}
		}
		return false
	}, 4*time.Second, 10*time.Millisecond, "expected an Info-level reconnect log line")

	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("RunSupervisor did not stop after ctx cancellation")
	}

	warnCount := 0
	warnIdx, infoIdx := -1, -1
	for i, e := range hook.AllEntries() {
		switch e.Level {
		case logrus.WarnLevel:
			warnCount++
			if warnIdx == -1 {
				warnIdx = i
			}
		case logrus.InfoLevel:
			if infoIdx == -1 {
				infoIdx = i
			}
		}
	}
	assert.Equal(t, 1, warnCount, "exactly one Warn expected for the healthy->unhealthy transition")
	require.NotEqual(t, -1, infoIdx, "expected an Info-level reconnect log line")
	assert.Less(t, warnIdx, infoIdx, "the Warn must precede the Info reconnect line")
}

// respArrayHeader matches a RESP array header ("*<n>\r\n"), i.e. the start of
// one client request. go-redis pipelines its post-HELLO-fallback init
// commands (CLIENT SETINFO LIB-NAME/LIB-VER) together in a single write, so a
// batch received in one Read can hold more than one request; this lets
// servePong count how many replies a batch needs.
var respArrayHeader = regexp.MustCompile(`\*\d+\r\n`)

// servePong is a minimal fake RESP server. It does not implement full RESP
// semantics -- just enough of the go-redis v9 connection handshake for Ping
// to succeed:
//
//   - go-redis defaults to RESP3 and opens every connection with HELLO 3.
//     servePong replies with a RESP error (rather than attempting to satisfy
//     the real HELLO reply, a RESP3 map this minimal server does not build),
//     which go-redis interprets as "server predates HELLO" and falls back to
//     RESP2 -- see initConn in the go-redis v9 source for the isRedisError
//     branch this depends on.
//   - Falling back triggers a couple of CLIENT SETINFO housekeeping commands
//     (again, no auth/DB-select/tracking is configured here, so nothing else
//     is sent). servePong replies "+OK\r\n" once per request in the batch,
//     counted via respArrayHeader -- it does not need to interpret the
//     command itself, since go-redis's Ping only checks for a non-error
//     reply, not a specific value.
func servePong(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 512)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if n == 0 {
					continue
				}
				if bytes.Contains(bytes.ToLower(buf[:n]), []byte("hello")) {
					if _, err := c.Write([]byte("-ERR unknown command 'HELLO'\r\n")); err != nil {
						return
					}
					continue
				}
				numCmds := len(respArrayHeader.FindAll(buf[:n], -1))
				if numCmds < 1 {
					numCmds = 1
				}
				if _, err := c.Write(bytes.Repeat([]byte("+OK\r\n"), numCmds)); err != nil {
					return
				}
			}
		}(conn)
	}
}
