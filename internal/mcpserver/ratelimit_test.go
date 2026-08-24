package mcpserver

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

func TestLimiter_AllowsUpToTheBurst(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 5, WritesPerMinute: 2})

	for i := 0; i < 5; i++ {
		require.True(t, l.allow(TierRead), "call %d should be permitted", i+1)
	}
}

func TestLimiter_RefusesBeyondTheBurst(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 3, WritesPerMinute: 2})

	for i := 0; i < 3; i++ {
		require.True(t, l.allow(TierRead))
	}
	require.False(t, l.allow(TierRead),
		"a looping agent must degrade its own calls rather than the vault")
}

func TestLimiter_ReadsAndWritesHaveSeparateBudgets(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 2, WritesPerMinute: 2})

	require.True(t, l.allow(TierRead))
	require.True(t, l.allow(TierRead))
	require.False(t, l.allow(TierRead), "the read budget is now spent")

	require.True(t, l.allow(TierWrite),
		"a burst of reads must not consume the budget a legitimate write needs")
}

func TestLimiter_DestructiveAndCryptoDrawOnTheWriteBudget(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 10, WritesPerMinute: 2})

	require.True(t, l.allow(TierDestructive))
	require.True(t, l.allow(TierCrypto))
	require.False(t, l.allow(TierWrite),
		"the three non-read tiers share one budget, since all three are consequential")
}

func TestLimiter_RefusalDoesNotBlock(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 1, WritesPerMinute: 1})
	require.True(t, l.allow(TierRead))

	done := make(chan bool, 1)
	go func() { done <- l.allow(TierRead) }()

	select {
	case allowed := <-done:
		require.False(t, allowed)
	case <-time.After(time.Second):
		t.Fatal("allow() blocked; it must refuse immediately rather than queue")
	}
}

func TestLimiter_IsSafeUnderConcurrency(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 100, WritesPerMinute: 100})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.allow(TierRead)
			l.allow(TierWrite)
		}()
	}
	wg.Wait()
}
