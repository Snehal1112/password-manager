package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// fakeVault serves canned API responses so tests exercise the real vaultapi
// decode path.
//
// vaultapi.Client is a concrete struct rather than an interface, and adding
// an interface purely so tests could mock it would put indirection into
// production code to serve a test. Standing up the real shapes instead means
// a wrong wrapper key or field name fails here rather than in production.
type fakeVault struct {
	srv *httptest.Server
	// routes maps a request path to its JSON response body.
	routes map[string]string
	// requested records every path that was hit, in order.
	requested []string
	// status overrides the response status for a given path.
	status map[string]int
	// writeResponse is returned for non-GET requests.
	writeResponse string
	// lastWriteBody records the decoded body of the most recent write.
	lastWriteBody map[string]any
}

func newFakeVault(t *testing.T, routes map[string]string) *fakeVault {
	t.Helper()

	f := &fakeVault{routes: routes, status: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requested = append(f.requested, r.URL.Path)

		if r.Method != http.MethodGet {
			_ = json.NewDecoder(r.Body).Decode(&f.lastWriteBody)
			if code, ok := f.status[r.URL.Path]; ok {
				w.WriteHeader(code)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if f.writeResponse != "" {
				_, _ = w.Write([]byte(f.writeResponse))
			}
			return
		}

		if code, ok := f.status[r.URL.Path]; ok {
			w.WriteHeader(code)
			return
		}
		body, ok := f.routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// failWith makes path respond with the given status.
func (f *fakeVault) failWith(path string, code int) { f.status[path] = code }

// hit reports whether path was requested.
func (f *fakeVault) hit(path string) bool {
	for _, p := range f.requested {
		if p == path {
			return true
		}
	}
	return false
}

// server builds an mcpserver wired to this fake vault.
func (f *fakeVault) server(t *testing.T, cfg config.MCPConfig) *Server {
	t.Helper()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:      f.srv.URL,
		HTTPClient:   f.srv.Client(),
		Tokens:       staticTestToken("test-token"),
		DisableRetry: true,
	})
	require.NoError(t, err)

	s, err := New(Deps{Client: client, Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)
	return s
}

// serverWithLogger is server() with diagnostics captured, for tests that
// assert on log output.
func (f *fakeVault) serverWithLogger(t *testing.T, cfg config.MCPConfig, out io.Writer) *Server {
	t.Helper()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:      f.srv.URL,
		HTTPClient:   f.srv.Client(),
		Tokens:       staticTestToken("test-token"),
		DisableRetry: true,
	})
	require.NoError(t, err)

	logger := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := New(Deps{Client: client, Config: cfg, Logger: logger, Version: "test"})
	require.NoError(t, err)
	return s
}

// staticTestToken is a vaultapi.TokenSource returning a fixed token.
type staticTestToken string

func (s staticTestToken) Token(ctx context.Context) (string, error) { return string(s), nil }

// structured decodes a tool result's StructuredContent into target.
func structured(t *testing.T, result *mcp.CallToolResult, target any) {
	t.Helper()
	require.False(t, result.IsError, "tool returned an error: %s", renderContent(result))

	encoded, err := json.Marshal(result.StructuredContent)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, target))
}

// renderContent flattens a result's text content, for assertions on errors.
func renderContent(result *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			sb.WriteString(text.Text)
		}
	}
	return sb.String()
}
