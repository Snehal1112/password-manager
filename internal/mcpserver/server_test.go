package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

type pingIn struct {
	Message string `json:"message" jsonschema:"the message to echo"`
}

type pingOut struct {
	Echo string `json:"echo"`
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Deps{Config: testConfig(), Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)
	return s
}

func TestNew_RequiresAConfigAndLogger(t *testing.T) {
	_, err := New(Deps{Logger: discardLogger()})
	require.ErrorContains(t, err, "Config")
}

func TestServer_RegistersNoToolsByDefault(t *testing.T) {
	s := newTestServer(t)
	require.Empty(t, s.RegisteredTools(),
		"the skeleton registers nothing; tiers add tools in later plans")
}

func TestRegister_ExposesTheToolOverTheProtocol(t *testing.T) {
	s := newTestServer(t)
	register(s, "ping", "Echo a message back.", Annotations{ReadOnly: true, Idempotent: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{Echo: in.Message}, nil
		})

	cs := connect(t, s)
	require.Equal(t, []string{"ping"}, toolNames(t, cs))
	require.Equal(t, []string{"ping"}, s.RegisteredTools())
}

func TestRegister_RoundTripsTypedArgumentsAndResults(t *testing.T) {
	s := newTestServer(t)
	register(s, "ping", "Echo a message back.", Annotations{ReadOnly: true, Idempotent: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{Echo: "you said: " + in.Message}, nil
		})

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "ping",
		Arguments: map[string]any{"message": "hello"},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	structured, ok := result.StructuredContent.(map[string]any)
	require.True(t, ok, "the SDK populates StructuredContent from the typed Out value")
	require.Equal(t, "you said: hello", structured["echo"])
}

func TestRegister_InfersInputAndOutputSchemas(t *testing.T) {
	s := newTestServer(t)
	register(s, "ping", "Echo a message back.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	result, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Tools, 1)
	require.NotNil(t, result.Tools[0].InputSchema, "AddTool infers the input schema from In")
	require.NotNil(t, result.Tools[0].OutputSchema, "and the output schema from Out")
}

func TestRegister_ReadOnlyToolIsNotAdvertisedAsDestructive(t *testing.T) {
	s := newTestServer(t)
	register(s, "ping", "Echo a message back.", Annotations{ReadOnly: true, Idempotent: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	result, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	ann := result.Tools[0].Annotations
	require.NotNil(t, ann)
	require.True(t, ann.ReadOnlyHint)
	require.True(t, ann.IdempotentHint)
	require.NotNil(t, ann.DestructiveHint, "the SDK defaults this to true, so it must be set explicitly")
	require.False(t, *ann.DestructiveHint)
	require.NotNil(t, ann.OpenWorldHint)
	require.False(t, *ann.OpenWorldHint, "a vault is a closed world")
}

func TestRegister_DestructiveToolIsAdvertisedAsSuch(t *testing.T) {
	s := newTestServer(t)
	register(s, "purge", "Purge an item.", Annotations{Destructive: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	result, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	ann := result.Tools[0].Annotations
	require.False(t, ann.ReadOnlyHint)
	require.NotNil(t, ann.DestructiveHint)
	require.True(t, *ann.DestructiveHint, "hosts rely on this to prompt before a destructive call")
}

func TestRegister_KeepsRegisteredToolsSorted(t *testing.T) {
	s := newTestServer(t)
	for _, name := range []string{"zebra", "alpha", "middle"} {
		register(s, name, "A tool.", Annotations{ReadOnly: true},
			func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
				return nil, pingOut{}, nil
			})
	}
	require.Equal(t, []string{"alpha", "middle", "zebra"}, s.RegisteredTools(),
		"a stable order keeps the gating table test and --check output deterministic")
}
