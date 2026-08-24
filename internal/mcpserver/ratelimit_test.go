package mcpserver

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestRegister_RefusesCallsBeyondTheRateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.RateLimit = config.MCPRateLimit{ReadsPerMinute: 2, WritesPerMinute: 2}

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	var calls int
	registerIf(s, TierRead, "ping", "Echoes.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			calls++
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	call := func() *mcp.CallToolResult {
		result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "ping", Arguments: map[string]any{"message": "x"},
		})
		require.NoError(t, err)
		return result
	}

	require.False(t, call().IsError)
	require.False(t, call().IsError)

	refused := call()
	require.True(t, refused.IsError, "the third call exceeds the budget")
	require.Equal(t, 2, calls, "a refused call must not reach the handler at all")
}

func TestRegister_RateLimitMessageIsActionable(t *testing.T) {
	cfg := testConfig()
	cfg.RateLimit = config.MCPRateLimit{ReadsPerMinute: 1, WritesPerMinute: 1}

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	registerIf(s, TierRead, "ping", "Echoes.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	for i := 0; i < 2; i++ {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "ping", Arguments: map[string]any{"message": "x"},
		})
		require.NoError(t, err)
	}

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ping", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)

	var rendered strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			rendered.WriteString(text.Text)
		}
	}
	require.Contains(t, strings.ToLower(rendered.String()), "rate limit",
		"the model should be able to tell this apart from a permission failure and back off")
}

func TestRegister_ReadBurstDoesNotStarveWrites(t *testing.T) {
	cfg := testConfig()
	cfg.AllowWrite = true
	cfg.RateLimit = config.MCPRateLimit{ReadsPerMinute: 1, WritesPerMinute: 1}

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	noop := func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
		return nil, pingOut{}, nil
	}
	registerIf(s, TierRead, "read_tool", "Reads.", Annotations{ReadOnly: true}, noop)
	registerIf(s, TierWrite, "write_tool", "Writes.", Annotations{}, noop)

	cs := connect(t, s)
	callTool := func(name string) *mcp.CallToolResult {
		result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: name, Arguments: map[string]any{"message": "x"},
		})
		require.NoError(t, err)
		return result
	}

	require.False(t, callTool("read_tool").IsError)
	require.True(t, callTool("read_tool").IsError, "the read budget is spent")
	require.False(t, callTool("write_tool").IsError, "the write budget is untouched")
}
