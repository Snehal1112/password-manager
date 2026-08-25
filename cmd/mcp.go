/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/config"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/mcpserver"
	"rocketvault/internal/vaultapi"
)

// mcpDefaultListenAddr matches the shipped server.listen_addr.
const mcpDefaultListenAddr = ":8774"

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run a Model Context Protocol server over stdio",
	Long: `Serve RocketVault to an MCP client such as Claude Code or Claude Desktop.

The server talks to a RocketVault API server over HTTP, so authorization is
enforced by the same middleware every other API client goes through. It never
touches the database directly.

By default it exposes ten read-only tools and returns no secret values.
Capability tiers are enabled in the mcp section of .rocketvault.yaml -- see
allow_write, allow_destructive, allow_crypto and allow_secret_values.

Identity is resolved once at startup: a service account when mcp.client_id and
a secret are configured, otherwise the session cached by 'rocketvault users
login'. In production, set mcp.require_service_account so the agent cannot act
as you -- under a session its actions are indistinguishable from yours in the
audit log.

This command speaks JSON-RPC on stdout. All diagnostics go to stderr.`,
	Example: `  # Run against the local server, as the logged-in user
  rocketvault users login --username admin
  rocketvault mcp

  # Run against a remote server as a service account
  export ROCKETVAULT_MCP_CLIENT_SECRET=...
  rocketvault mcp --server https://vault.example.com`,

	// Replace the root PersistentPreRunE. The root pre-run is actively wrong
	// here on three counts: it refuses remote targets (cmd/root.go:358),
	// which is this command's normal operating mode; it opens a database and
	// builds a ServiceContainer this command never uses; and it starts a
	// rotating log file, when a stdio subprocess's diagnostics belong on
	// stderr. serveCmd overrides the root pre-run for the second reason
	// already -- see cmd/serve.go:75.
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error { return nil },

	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.Flags().Bool("check", false,
		"Validate configuration, connectivity and authentication, print the exposed tools, then exit")

	// Cobra writes usage and errors to stdout by default, which would
	// corrupt the protocol stream.
	mcpCmd.SetOut(os.Stderr)
	mcpCmd.SetErr(os.Stderr)
}

// resolveMCPBaseURL decides which server to talk to.
//
// cliclient.ResolveTarget returns (nil, nil) for local mode, but MCP has no
// local mode -- it needs a URL. When no remote target resolves, the locally
// configured listen address is used. The second return reports that fallback
// so the caller can log it: this codebase treats silent remote fallback as a
// bug (commit 795ecd4), and while falling back to loopback is far less
// dangerous, it is still stated rather than assumed.
func resolveMCPBaseURL(serverFlag string) (string, bool, error) {
	target, err := cliclient.ResolveTarget(serverFlag)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve the server target: %w", err)
	}
	if target != nil && target.Server != "" {
		return target.Server, false, nil
	}

	listen := viper.GetString("server.listen_addr")
	if listen == "" {
		listen = mcpDefaultListenAddr
	}
	// A bind address such as ":8774" or "0.0.0.0:8774" is reached over
	// loopback, not by its literal value.
	_, port, splitErr := net.SplitHostPort(listen)
	if splitErr != nil {
		port = strings.TrimPrefix(listen, ":")
	}
	if port == "" {
		port = strings.TrimPrefix(mcpDefaultListenAddr, ":")
	}
	return "http://127.0.0.1:" + port, true, nil
}

// resolveMCPTokenSource picks the identity the server acts as.
//
// The order is service account, then cached session, then failure. There is
// deliberately no fourth branch: a server that started without an identity
// would fail on its first tool call, several turns into a conversation and
// far from the actual problem.
func resolveMCPTokenSource(cfg config.MCPConfig, baseURL string, httpClient *http.Client) (vaultapi.TokenSource, string, error) {
	if cfg.ClientID != "" && cfg.ClientSecret != "" {
		source, err := vaultapi.NewServiceAccountSource(vaultapi.ServiceAccountConfig{
			BaseURL:      baseURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			HTTPClient:   httpClient,
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to configure the service account: %w", err)
		}
		// The description never includes the secret.
		return source, fmt.Sprintf("service account %q", cfg.ClientID), nil
	}

	if cfg.RequireServiceAccount {
		return nil, "", fmt.Errorf(
			"mcp.require_service_account is set but no service account is configured; " +
				"set mcp.client_id and ROCKETVAULT_MCP_CLIENT_SECRET")
	}

	source, err := vaultapi.NewSessionSource(vaultapi.SessionConfig{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
	})
	switch {
	case err == nil:
		return source, fmt.Sprintf("cached session for %q", source.Username()), nil
	case errors.Is(err, vaultapi.ErrNoSession):
		return nil, "", fmt.Errorf(
			"no identity is configured: run `rocketvault users login`, " +
				"or set mcp.client_id and ROCKETVAULT_MCP_CLIENT_SECRET to use a service account")
	default:
		return nil, "", fmt.Errorf("failed to read the cached session: %w", err)
	}
}

// buildMCPServer assembles everything the command needs.
func buildMCPServer(cmd *cobra.Command, logger *slog.Logger) (*mcpserver.Server, string, error) {
	cfg, err := config.LoadMCPConfig()
	if err != nil {
		return nil, "", fmt.Errorf("invalid mcp configuration: %w", err)
	}

	serverFlag, _ := cmd.Flags().GetString("server")
	baseURL, fellBack, err := resolveMCPBaseURL(serverFlag)
	if err != nil {
		return nil, "", err
	}
	if fellBack {
		logger.Info("no remote target configured; using the local server", "base_url", baseURL)
	}

	caCert, _ := cmd.Flags().GetString("ca-cert")
	insecure, _ := cmd.Flags().GetBool("insecure-skip-verify")
	tlsOpts := cliclient.HTTPClientOptions{CACertPath: caCert, InsecureSkipVerify: insecure}
	cliclient.WarnIfInsecure(tlsOpts)

	httpClient, err := cliclient.NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build the HTTP client: %w", err)
	}

	tokens, identity, err := resolveMCPTokenSource(cfg, baseURL, httpClient)
	if err != nil {
		return nil, "", err
	}

	// Wrapped so the login tool (see internal/mcpserver/tools_login.go) can
	// replace this server's identity at runtime without touching Client.
	swappable := vaultapi.NewSwappableSource(tokens)

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Tokens:     swappable,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to build the vault client: %w", err)
	}

	server, err := mcpserver.New(mcpserver.Deps{
		Client:  client,
		Config:  cfg,
		Logger:  logger,
		Version: rootCmd.Version,
		BaseURL: baseURL,

		Identity: swappable,
		// The same condition resolveMCPTokenSource already used to choose
		// the service-account branch, restated here rather than threaded
		// back through its return values -- it has no other caller that
		// would need the extra value, and every existing test of that
		// function stays unchanged.
		IsServiceAccountIdentity: cfg.ClientID != "" && cfg.ClientSecret != "",
		JWTExpiry:                viper.GetDuration("jwt.expiry"),
	})
	if err != nil {
		return nil, "", err
	}
	mcpserver.RegisterAllTools(server)
	return server, identity, nil
}

// runMCP serves the protocol over stdio until interrupted.
func runMCP(cmd *cobra.Command, _ []string) error {
	// Diagnostics go to stderr. stdout is the JSON-RPC channel, and a single
	// stray byte there corrupts the session.
	logger := mcpserver.NewStderrLogger(slog.LevelInfo)

	server, identity, err := buildMCPServer(cmd, logger)
	if err != nil {
		return err
	}

	if check, _ := cmd.Flags().GetBool("check"); check {
		return runMCPCheck(cmd, server, identity)
	}

	// Drain in-flight calls on interrupt rather than dropping them.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("mcp server starting",
		"identity", identity,
		"tools", len(server.RegisteredTools()),
		"vault", viper.GetString("mcp.vault"))

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		return fmt.Errorf("mcp server stopped: %w", err)
	}
	logger.Info("mcp server stopped")
	return nil
}
