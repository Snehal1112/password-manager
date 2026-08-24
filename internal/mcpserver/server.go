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
	"os"
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
	// limits bounds how fast tools may be called.
	limits *limiter
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
		limits:    newLimiter(deps.Config.RateLimit),
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
func register[In, Out any](s *Server, tier Tier, name, description string, ann Annotations, h mcp.ToolHandlerFor[In, Out]) {
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

	mcp.AddTool(s.mcpServer, tool, withLifecycle(s, tier, name, h))
	s.registered = append(s.registered, name)
}

// NewStderrLogger builds the logger the MCP server should use.
//
// It writes to stderr because stdout is the JSON-RPC channel: a single stray
// byte there corrupts the session. This constructor exists so no caller has
// to remember that.
func NewStderrLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
