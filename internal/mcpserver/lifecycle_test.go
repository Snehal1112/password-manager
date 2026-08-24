package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultapi"
)

func TestRegister_RecoversFromAPanic(t *testing.T) {
	s := newTestServer(t)
	register(s, "boom", "Panics on purpose.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			panic("deliberate panic")
		})

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "boom",
		Arguments: map[string]any{"message": "x"},
	})

	require.NoError(t, err, "a panic must not become a transport failure")
	require.True(t, result.IsError, "it must surface as a tool error the model can see")
}

func TestRegister_PanicDoesNotKillTheSession(t *testing.T) {
	s := newTestServer(t)
	register(s, "boom", "Panics on purpose.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			panic("deliberate panic")
		})
	register(s, "ping", "Echoes.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{Echo: in.Message}, nil
		})

	cs := connect(t, s)
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "boom", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)

	// The session must still work afterwards.
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ping", Arguments: map[string]any{"message": "still here"},
	})
	require.NoError(t, err)
	require.False(t, result.IsError, "one bad call must not poison the session")
}

func TestRegister_PanicMessageDoesNotLeakInternals(t *testing.T) {
	s := newTestServer(t)
	register(s, "boom", "Panics on purpose.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			panic("secret-value-in-panic-hunter2")
		})

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "boom", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)

	var rendered strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			rendered.WriteString(text.Text)
		}
	}
	require.NotContains(t, rendered.String(), "hunter2",
		"a panic value can carry anything and must not be echoed to the model")
	require.Contains(t, rendered.String(), "internal error")
}

func TestRegister_AppliesTheRequestTimeout(t *testing.T) {
	cfg := testConfig()
	cfg.RequestTimeout = 50 * time.Millisecond
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	register(s, "slow", "Sleeps past the deadline.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			select {
			case <-ctx.Done():
				return nil, pingOut{}, ctx.Err()
			case <-time.After(5 * time.Second):
				return nil, pingOut{Echo: "should not get here"}, nil
			}
		})

	cs := connect(t, s)
	start := time.Now()
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "slow", Arguments: map[string]any{"message": "x"},
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Less(t, elapsed, 2*time.Second, "the deadline must cut the call short")
}

func TestRegister_DeadlineIsVisibleToTheHandler(t *testing.T) {
	cfg := testConfig()
	cfg.RequestTimeout = 2 * time.Second
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	var hadDeadline bool
	register(s, "check", "Reports whether it has a deadline.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			_, hadDeadline = ctx.Deadline()
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	_, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)
	require.True(t, hadDeadline, "every handler runs under a deadline")
}

func TestRegister_AttachesACorrelationID(t *testing.T) {
	s := newTestServer(t)

	var seen string
	register(s, "check", "Reports its correlation id.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			seen = vaultapi.CorrelationIDFrom(ctx)
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, seen, "a correlation id ties a tool call to its API request and audit entry")
}

func TestRegister_CorrelationIDDiffersPerCall(t *testing.T) {
	s := newTestServer(t)

	var seen []string
	register(s, "check", "Reports its correlation id.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			seen = append(seen, vaultapi.CorrelationIDFrom(ctx))
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	for i := 0; i < 2; i++ {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "check", Arguments: map[string]any{"message": "x"},
		})
		require.NoError(t, err)
	}
	require.Len(t, seen, 2)
	require.NotEqual(t, seen[0], seen[1])
}

func TestErrorResult_IsMarkedAsAnError(t *testing.T) {
	result := errorResult("something went wrong: %s", "detail")
	require.True(t, result.IsError)
	require.Len(t, result.Content, 1)

	text, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	require.Equal(t, "something went wrong: detail", text.Text)
}
