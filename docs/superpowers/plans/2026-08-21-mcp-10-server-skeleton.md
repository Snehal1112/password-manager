# MCP Server Skeleton and Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create `internal/mcpserver` with a `Server` that wraps an `mcp.Server`, plus the single registration helper every tool must go through — one that applies a deadline, panic recovery and structured logging to every call.

**Architecture:** All cross-cutting behavior lives in one generic `register` function. A tool author writes only the handler; the deadline, recovery, correlation ID and log line come for free, and cannot be forgotten because there is no other way to register a tool.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0, `log/slog`, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — sections "Architecture > Package layout", "Production hardening > Lifecycle" and "> Observability".

**Plan-of-plans:** This is plan 10 of 31. Requires plans 01 and 09 committed.

## Global Constraints

- Go 1.25.0. **This plan adds the one new dependency:** `github.com/modelcontextprotocol/go-sdk v1.7.0`.
- **`internal/mcpserver` must never construct an HTTP request.** It calls `vaultapi` and nothing else. Its tests run against a fake client with no network.
- **stdout is the protocol channel.** Every log line goes to stderr.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified SDK API (v1.7.0)

Confirmed by inspecting the module, not assumed:

```go
func NewServer(impl *Implementation, options *ServerOptions) *Server
func AddTool[In, Out any](s *Server, t *Tool, h ToolHandlerFor[In, Out])
func (s *Server) Run(ctx context.Context, t Transport) error
func (s *Server) Connect(ctx context.Context, t Transport, opts *ServerSessionOptions) (*ServerSession, error)
func NewInMemoryTransports() (*InMemoryTransport, *InMemoryTransport)
func NewClient(impl *Implementation, options *ClientOptions) *Client

type ToolHandlerFor[In, Out any] func(context.Context, *CallToolRequest, In) (*CallToolResult, Out, error)
type Implementation struct { Name, Title, Description, Version, WebsiteURL string }
type Tool struct { Name, Description string; Annotations *ToolAnnotations; InputSchema, OutputSchema any; ... }
type ToolAnnotations struct { Title string; ReadOnlyHint bool; IdempotentHint bool; DestructiveHint, OpenWorldHint *bool }
type CallToolResult struct { Content []Content; StructuredContent any; IsError bool; ... }

func (cs *ClientSession) ListTools(ctx, *ListToolsParams) (*ListToolsResult, error)
func (cs *ClientSession) CallTool(ctx, *CallToolParams) (*CallToolResult, error)
```

Three consequences that shape the design:

1. **`AddTool` is generic and infers both schemas** from `In` and `Out` via `jsonschema-go`. Declaring typed argument and result structs therefore satisfies the spec's "tools declare output schemas" requirement automatically — there is no hand-written JSON Schema anywhere in this project.
2. **`DestructiveHint` and `OpenWorldHint` are `*bool` and default to `true`.** A read-only tool must set them to `false` explicitly, or it advertises itself as destructive and open-world. Task 1 handles this centrally so no tool author can get it wrong.
3. **`IsError` belongs in the result, not in a returned Go error.** The SDK's own documentation says a protocol-level error means "the LLM would not be able to see that an error occurred and self-correct". Handlers therefore return failures as results.

## Logging choice, and why it departs from the codebase

`internal/logging.InitLogger()` builds a logrus logger writing to a rotating **file**, with an optional audit persister. That is wrong for a stdio subprocess: the MCP server is a short-lived child process whose diagnostics belong on stderr, where the host captures them, and it must not open or rotate a shared log file.

This plan uses `log/slog` with a JSON handler on stderr. It is stdlib, adds no dependency, and matches the actual requirement. This is a deliberate, local departure from the project's logging convention, not an oversight.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/server.go` (new) | `Deps`, `Server`, `New`, `register`, `Run` |
| `internal/mcpserver/lifecycle.go` (new) | Deadline, panic recovery, correlation ID |
| `internal/mcpserver/server_test.go` (new) | Construction, registration, annotations |
| `internal/mcpserver/lifecycle_test.go` (new) | Timeout, recovery, logging |
| `internal/mcpserver/testhelpers_test.go` (new) | In-memory client/server pair |

---

### Task 1: `Server`, the registration helper, and correct annotations

**Files:**
- Create: `internal/mcpserver/server.go`
- Create: `internal/mcpserver/server_test.go`
- Create: `internal/mcpserver/testhelpers_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: `config.MCPConfig` (plan 09), `*vaultapi.Client` (plan 01).
- Produces — every tool plan (13-15, 21-22, 25, 27) registers through these:
  - `type Deps struct { Client *vaultapi.Client; Config config.MCPConfig; Logger *slog.Logger; Version string }`
  - `type Server struct { ... }` with `func New(deps Deps) (*Server, error)`
  - `func (s *Server) MCP() *mcp.Server`
  - `func (s *Server) RegisteredTools() []string` — sorted; plan 17's `--check` prints it, plan 28's gating table asserts on it.
  - `func (s *Server) Run(ctx context.Context, transport mcp.Transport) error`
  - `type Annotations struct { ReadOnly, Idempotent, Destructive bool }`
  - `func register[In, Out any](s *Server, name, description string, ann Annotations, h mcp.ToolHandlerFor[In, Out])`

**Why `register` exists rather than calling `mcp.AddTool` directly:** it is the only place that sets `DestructiveHint` and `OpenWorldHint`. Both are `*bool` defaulting to `true`, so a tool registered directly would advertise itself as destructive and open-world unless its author remembered to say otherwise. Centralising it makes the safe case automatic.

- [ ] **Step 1: Write the failing test**

First add the dependency:

```bash
go get github.com/modelcontextprotocol/go-sdk@v1.7.0
```

Create `internal/mcpserver/testhelpers_test.go`:

```go
package mcpserver

import (
	"context"
	"log/slog"
	"testing"

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
```

Add `"io"`, `"sort"` and `"time"` to that file's imports.

Create `internal/mcpserver/server_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -v`
Expected: FAIL — `undefined: New`, `undefined: Deps`, `undefined: register`, `undefined: Annotations`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/server.go`:

```go
// Package mcpserver exposes RocketVault through the Model Context Protocol.
//
// It never constructs an HTTP request: every call to the vault goes through
// internal/vaultapi, which is what keeps this package's tests free of network
// and keeps authorization enforced in exactly one place, server-side.
package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// Deps are everything the server needs to run.
type Deps struct {
	// Client talks to the RocketVault API. It may be nil only in tests that
	// register no vault-backed tools.
	Client *vaultapi.Client
	// Config governs which tools are registered and how they behave.
	Config config.MCPConfig
	// Logger writes diagnostics. It must write to stderr, never stdout,
	// which is the protocol channel.
	Logger *slog.Logger
	// Version is reported to the host during initialization.
	Version string
}

// Server is the RocketVault MCP server.
type Server struct {
	cfg    config.MCPConfig
	client *vaultapi.Client
	logger *slog.Logger

	mcpServer *mcp.Server
	// registered names every tool that was actually registered, which is a
	// function of the enabled capability tiers.
	registered []string
}

// New builds a server with no tools registered. Later plans add tools
// according to the enabled tiers.
func New(deps Deps) (*Server, error) {
	if err := deps.Config.Validate(); err != nil {
		return nil, fmt.Errorf("mcpserver: invalid Config: %w", err)
	}
	logger := deps.Logger
	if logger == nil {
		return nil, fmt.Errorf("mcpserver: Deps.Logger is required")
	}
	version := deps.Version
	if version == "" {
		version = "dev"
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:        "rocketvault",
		Title:       "RocketVault",
		Description: "Manage RocketVault secrets, keys, certificates and access.",
		Version:     version,
	}, nil)

	return &Server{
		cfg:       deps.Config,
		client:    deps.Client,
		logger:    logger,
		mcpServer: mcpServer,
	}, nil
}

// MCP returns the underlying SDK server, for transport wiring and tests.
func (s *Server) MCP() *mcp.Server { return s.mcpServer }

// RegisteredTools returns the registered tool names in sorted order.
//
// The order is stable so that --check output and the gating table test are
// deterministic.
func (s *Server) RegisteredTools() []string {
	names := make([]string, len(s.registered))
	copy(names, s.registered)
	sort.Strings(names)
	return names
}

// Run serves the protocol over transport until the context is cancelled.
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	return s.mcpServer.Run(ctx, transport)
}

// Annotations describes a tool's effects, in the terms a host needs to decide
// whether to prompt before calling it.
type Annotations struct {
	// ReadOnly means the tool does not modify the vault.
	ReadOnly bool
	// Idempotent means repeating the call has no additional effect.
	Idempotent bool
	// Destructive means the tool can remove or overwrite something.
	Destructive bool
}

// register adds a tool and is the only supported way to do so.
//
// It exists because DestructiveHint and OpenWorldHint are *bool that the SDK
// defaults to true. A tool added straight through mcp.AddTool would therefore
// advertise itself as destructive and open-world unless its author remembered
// to say otherwise. Centralising that here makes the safe case automatic.
func register[In, Out any](s *Server, name, description string, ann Annotations, h mcp.ToolHandlerFor[In, Out]) {
	destructive := ann.Destructive
	// A vault is a closed world: these tools touch only this server.
	openWorld := false

	tool := &mcp.Tool{
		Name:        name,
		Description: description,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    ann.ReadOnly,
			IdempotentHint:  ann.Idempotent,
			DestructiveHint: &destructive,
			OpenWorldHint:   &openWorld,
		},
	}

	mcp.AddTool(s.mcpServer, tool, h)
	s.registered = append(s.registered, name)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -v`
Expected: PASS — all eight tests.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/mcpserver/
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the server skeleton and tool registry

register() is the only supported way to add a tool, because DestructiveHint
and OpenWorldHint are *bool that the SDK defaults to true -- a tool added
straight through mcp.AddTool would advertise itself as destructive and
open-world unless its author remembered otherwise.

AddTool infers both schemas from the typed In and Out, so declaring argument
and result structs satisfies the output-schema requirement with no
hand-written JSON Schema anywhere."
```

---

### Task 2: Per-call deadline and panic recovery

**Files:**
- Create: `internal/mcpserver/lifecycle.go`
- Create: `internal/mcpserver/lifecycle_test.go`
- Modify: `internal/mcpserver/server.go` (`register` calls the wrapper)

**Interfaces:**
- Consumes: `Server`, `register` from Task 1.
- Produces: no new exported surface. Every registered tool gains a deadline and panic recovery.
  - `func errorResult(format string, args ...any) *mcp.CallToolResult` — later plans use it to return failures.

**Why a panic must not escape:** the SDK runs handlers on the session's goroutine. An unrecovered panic takes down the process, which for a stdio server means the host's session dies mid-conversation with no diagnostic. One malformed argument must not be able to do that.

**Why failures are results, not errors:** the SDK's own documentation on `IsError` says a protocol-level error means "the LLM would not be able to see that an error occurred and self-correct". Returning a result with `IsError: true` lets the model read the message and try something else.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/lifecycle_test.go`:

```go
package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
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
```

Add `"rocketvault/internal/vaultapi"` to the test file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestRegister_Recovers|TestRegister_Panic|TestRegister_Applies|TestRegister_Deadline|TestRegister_Attaches|TestRegister_Correlation|TestErrorResult_' -v`
Expected: FAIL — `undefined: errorResult`; the panic test crashes the test process, which is exactly the failure this task fixes.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/lifecycle.go`:

```go
package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

// errorResult builds a failed tool result.
//
// Failures are results rather than Go errors on purpose. The SDK's own
// documentation on IsError notes that a protocol-level error means "the LLM
// would not be able to see that an error occurred and self-correct".
func errorResult(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
	}
}

// withLifecycle wraps a handler with a deadline, a correlation id and panic
// recovery. register applies it to every tool, so no tool can opt out.
func withLifecycle[In, Out any](s *Server, name string, h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (result *mcp.CallToolResult, out Out, err error) {
		ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		defer cancel()

		correlationID := uuid.NewString()
		ctx = vaultapi.WithCorrelationID(ctx, correlationID)

		// A panic must not escape. The SDK runs handlers on the session's
		// goroutine, so an unrecovered panic would kill the process -- and
		// for a stdio server that means the host's session dies
		// mid-conversation with no diagnostic.
		defer func() {
			if recovered := recover(); recovered != nil {
				var zero Out
				// The panic value can carry anything, including a secret, so
				// it is logged but never returned to the model.
				s.logger.Error("tool panicked",
					"tool", name,
					"correlation_id", correlationID,
					"panic", fmt.Sprint(recovered))
				result, out, err = errorResult("%s failed with an internal error", name), zero, nil
			}
		}()

		result, out, err = h(ctx, req, in)

		// A handler that returned because its deadline expired should say so
		// in terms the model can act on.
		if err != nil && ctx.Err() != nil {
			var zero Out
			return errorResult("%s timed out after %s", name, s.cfg.RequestTimeout), zero, nil
		}
		return result, out, err
	}
}

// timeoutFor reports the configured per-call deadline.
func (s *Server) timeoutFor() time.Duration { return s.cfg.RequestTimeout }
```

In `internal/mcpserver/server.go`, change the `mcp.AddTool` call inside `register`:

```go
	mcp.AddTool(s.mcpServer, tool, withLifecycle(s, name, h))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test, race-clean. The panic test no longer crashes the run.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): give every tool a deadline, correlation id and panic recovery

The SDK runs handlers on the session goroutine, so an unrecovered panic kills
the process -- for a stdio server that means the host's session dies
mid-conversation with no diagnostic. Recovery is applied in register(), so no
tool can opt out. A panic value can carry anything, including a secret, so it
is logged and never echoed to the model.

Failures are results with IsError rather than protocol errors, which is what
lets the model read them and self-correct."
```

---

### Task 3: One structured stderr log line per call

**Files:**
- Modify: `internal/mcpserver/lifecycle.go`
- Modify: `internal/mcpserver/lifecycle_test.go` (append)
- Modify: `internal/mcpserver/server.go` (add `NewStderrLogger`)

**Interfaces:**
- Consumes: `withLifecycle` from Task 2.
- Produces:
  - `func NewStderrLogger(level slog.Level) *slog.Logger` — plan 16 uses it to wire `cmd/mcp.go`.

**The constraint that makes this non-obvious:** stdout is the JSON-RPC channel. A logger that defaults to stdout would corrupt every session on its first log line. `NewStderrLogger` exists so no caller has to remember that.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/lifecycle_test.go`:

```go
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
```

Add a helper to the same file:

```go
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
```

Add `"bytes"`, `"encoding/json"`, `"io"`, `"log/slog"` and `"os"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestNewStderrLogger_|TestRegister_Logs|TestRegister_LogLine' -v`
Expected: FAIL — `undefined: NewStderrLogger`, and no log line is written.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/server.go`, adding `"os"` to its imports:

```go
// NewStderrLogger builds the logger the MCP server should use.
//
// It writes to stderr because stdout is the JSON-RPC channel: a single stray
// byte there corrupts the session. This constructor exists so no caller has
// to remember that.
func NewStderrLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
```

In `internal/mcpserver/lifecycle.go`, add timing and the log line to `withLifecycle`. Replace the body after the panic-recovery block:

```go
		started := time.Now()
		result, out, err = h(ctx, req, in)

		if err != nil && ctx.Err() != nil {
			var zero Out
			result, out, err = errorResult("%s timed out after %s", name, s.cfg.RequestTimeout), zero, nil
		}

		// One line per call, on stderr. Arguments are deliberately absent:
		// they can carry a secret value.
		outcome := "ok"
		if err != nil || (result != nil && result.IsError) {
			outcome = "error"
		}
		s.logger.Info("tool call",
			"tool", name,
			"outcome", outcome,
			"correlation_id", correlationID,
			"duration_ms", time.Since(started).Milliseconds(),
			"vault", s.cfg.Vault)

		return result, out, err
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): log one structured line per tool call, on stderr

Each call logs tool, outcome, duration and correlation id, which is what ties
a tool call to its API request and the audit entry it produced. Arguments are
deliberately absent: they can carry a secret value.

NewStderrLogger exists so no caller has to remember that stdout is the
JSON-RPC channel and a single stray byte there corrupts the session."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

Confirm the dependency landed cleanly and nothing else moved:

```bash
git diff HEAD~3 --stat -- go.mod go.sum
go mod tidy && git diff --exit-code go.mod go.sum
```

Expected: `go.mod` gains exactly `github.com/modelcontextprotocol/go-sdk v1.7.0` plus its transitive requirements, and `go mod tidy` produces no further change.

The two hardening properties are worth confirming by eye:

```bash
go test ./internal/mcpserver/ -run 'TestRegister_PanicDoesNotKill|TestRegister_LogLineNeverContainsArguments' -v
```

## Notes for the next plan

Plan 11 adds gating and rate limiting on top of this skeleton. It introduces
the tier logic that decides *which* tools `register` is called for, and the
`allowed_vaults` guard.

Two things later plans must not undo:

- **`register` is the only way to add a tool.** A plan that reaches for
  `mcp.AddTool` directly loses the deadline, recovery, correlation id, log
  line, and correct annotations all at once.
- **Nothing writes to stdout.** Not `fmt.Println`, not a stray `log.Print`,
  not a debug statement left in a handler.
