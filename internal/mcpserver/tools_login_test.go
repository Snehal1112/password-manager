package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// serverWithIdentity builds a Server wired to f, with swap as both its
// Client's token source and its Deps.Identity -- exactly the relationship
// cmd/mcp.go will set up for real in Part 4.
func serverWithIdentity(t *testing.T, f *fakeVault, swap *vaultapi.SwappableSource, cfg config.MCPConfig) *Server {
	t.Helper()
	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: f.srv.URL, HTTPClient: f.srv.Client(), Tokens: swap, DisableRetry: true,
	})
	require.NoError(t, err)
	s, err := New(Deps{
		Client: client, Config: cfg, Logger: discardLogger(), Version: "test",
		Identity: swap,
		// A real expiry, so a login-issued session is live afterwards and a
		// Token() call reads the cached token instead of silently refreshing.
		JWTExpiry: time.Hour,
	})
	require.NoError(t, err)
	return s
}

func loginEnabledConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowInteractiveLogin = true
	return cfg
}

func TestHandleLogin_Success(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	// fakeVault's handler treats every non-GET request the same way: decode
	// the body, then respond with writeResponse. Client.Login's POST is the
	// only write this test performs, so this is enough to serve it.
	f.writeResponse = `{"token":"access-new","refresh_token":"refresh-new","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`

	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, loginEnabledConfig())
	RegisterAllTools(s)
	cs := connect(t, s)

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "admin", "password": "hunter2", "totp_code": "123456"},
	})
	require.NoError(t, err)

	var out loginResult
	structured(t, result, &out)
	require.Equal(t, "admin", out.Username)
	require.Equal(t, []string{"admin"}, out.Roles)
	require.NotEmpty(t, out.ExpiresAt)

	// The caller supplied the credentials, so echoing them back would put
	// them in the transcript a second time for no reason.
	require.NotContains(t, renderContent(result), "hunter2")
	encoded, err := json.Marshal(out)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "hunter2")

	tok, err := swap.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-new", tok, "the server's identity must now be the logged-in session")
}

func TestHandleLogin_MissingArgumentIsAnError(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, loginEnabledConfig())
	RegisterAllTools(s)
	cs := connect(t, s)

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "admin", "password": "hunter2"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "totp_code")
}

func TestHandleLogin_UpstreamFailureDoesNotSwapIdentity(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/users/login", http.StatusUnauthorized)

	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, loginEnabledConfig())
	RegisterAllTools(s)
	cs := connect(t, s)

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "login",
		Arguments: map[string]any{"username": "admin", "password": "wrong", "totp_code": "000000"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)

	tok, err := swap.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "startup-token", tok, "a failed login must not change the server's identity")
}

func TestHandleLogin_AbsentWhenTierDisabled(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	swap := vaultapi.NewSwappableSource(staticTestToken("startup-token"))
	s := serverWithIdentity(t, f, swap, testConfig()) // AllowInteractiveLogin left false
	RegisterAllTools(s)

	require.False(t, contains(s.RegisteredTools(), "login"))
}
