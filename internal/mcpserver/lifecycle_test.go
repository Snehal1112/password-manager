package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
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

func TestNewStderrLogger_WritesToStderrNotStdout(t *testing.T) {
	logger := NewStderrLogger(slog.LevelInfo)
	require.NotNil(t, logger)

	// The handler must not be pointed at stdout. Capturing os.Stdout here
	// would be brittle, so assert the constructor's contract by writing a
	// record and confirming stdout stays clean.
	stdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = stdout })

	logger.Info("a diagnostic line")
	require.NoError(t, w.Close())

	captured, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, captured,
		"stdout is the JSON-RPC channel; a single stray byte corrupts the session")
}

func TestRegister_LogsOneLinePerCall(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	s, err := New(Deps{Config: testConfig(), Logger: logger, Version: "test"})
	require.NoError(t, err)

	register(s, "ping", "Echoes.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{Echo: in.Message}, nil
		})

	cs := connect(t, s)
	_, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ping", Arguments: map[string]any{"message": "hello"},
	})
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(firstJSONLine(t, logs.String()), &entry))
	require.Equal(t, "ping", entry["tool"])
	require.Equal(t, "ok", entry["outcome"])
	require.NotEmpty(t, entry["correlation_id"])
	require.NotNil(t, entry["duration_ms"])
}

func TestRegister_LogsFailureOutcome(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	s, err := New(Deps{Config: testConfig(), Logger: logger, Version: "test"})
	require.NoError(t, err)

	register(s, "failing", "Always fails.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return errorResult("no such secret"), pingOut{}, nil
		})

	cs := connect(t, s)
	_, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "failing", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(firstJSONLine(t, logs.String()), &entry))
	require.Equal(t, "error", entry["outcome"])
}

func TestRegister_LogLineNeverContainsArguments(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	s, err := New(Deps{Config: testConfig(), Logger: logger, Version: "test"})
	require.NoError(t, err)

	register(s, "ping", "Echoes.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	_, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ping", Arguments: map[string]any{"message": "hunter2-secret-argument"},
	})
	require.NoError(t, err)

	require.NotContains(t, logs.String(), "hunter2-secret-argument",
		"tool arguments can carry a secret value and must never be logged")
}

// firstJSONLine returns the first non-empty line of logs, as bytes.
func firstJSONLine(t *testing.T, logs string) []byte {
	t.Helper()
	for _, line := range strings.Split(logs, "\n") {
		if strings.TrimSpace(line) != "" {
			return []byte(line)
		}
	}
	t.Fatal("no log line was written")
	return nil
}
