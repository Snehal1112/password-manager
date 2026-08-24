package mcpserver

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// testConfig returns a valid, maximally restrictive configuration.
func testConfig() config.MCPConfig {
	return config.MCPConfig{
		Vault:              "default",
		ConfirmDestructive: true,
		MaxResults:         50,
		RequestTimeout:     30 * time.Second,
		RateLimit:          config.MCPRateLimit{ReadsPerMinute: 120, WritesPerMinute: 20},
	}
}

// discardLogger returns a logger that writes nowhere, for tests that are not
// asserting on log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// connect wires an in-memory client to s and returns the client session.
func connect(t *testing.T, s *Server) *mcp.ClientSession {
	t.Helper()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	ctx := context.Background()
	serverSession, err := s.MCP().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientSession.Close() })

	return clientSession
}

// toolNames returns the names the session sees, for assertions.
func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	result, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}
