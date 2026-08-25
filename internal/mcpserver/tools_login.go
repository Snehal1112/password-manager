package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// loginArgs are the arguments to login.
type loginArgs struct {
	Username string `json:"username" jsonschema:"the RocketVault username to authenticate as"`
	Password string `json:"password" jsonschema:"the account's password"`
	TOTPCode string `json:"totp_code" jsonschema:"the current 6-digit TOTP code from the account's authenticator"`
}

// loginResult confirms who the server is now acting as. It deliberately
// never includes the token: the caller supplied the credentials, so echoing
// back a bearer token would put one in the transcript for no reason.
type loginResult struct {
	Username  string   `json:"username"`
	Roles     []string `json:"roles"`
	ExpiresAt string   `json:"expires_at"`
}

// registerLoginTools adds the login-tier tool.
func registerLoginTools(s *Server) {
	registerIf(s, TierLogin, "login",
		"Authenticate as a RocketVault user with a username, password and current TOTP code, "+
			"replacing this server's identity for the rest of its process lifetime. Every later "+
			"tool call in this conversation acts as this user until the process restarts or login "+
			"is called again. Credentials are arguments only -- they are never logged and the "+
			"resulting token is never echoed back. Unavailable when this server is running under "+
			"a service account.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleLogin)
}

func (s *Server) handleLogin(ctx context.Context, _ *mcp.CallToolRequest, args loginArgs) (*mcp.CallToolResult, loginResult, error) {
	if args.Username == "" || args.Password == "" || args.TOTPCode == "" {
		return errorResult("login requires username, password and totp_code"), loginResult{}, nil
	}

	source, identity, err := s.client.Login(ctx, args.Username, args.Password, args.TOTPCode, s.jwtExpiry)
	if err != nil {
		return errorResult(
			"login failed: %s. Check the username and password, and that the TOTP code is current.",
			err), loginResult{}, nil
	}
	s.identity.Set(source)

	return nil, loginResult{
		Username:  identity.Username,
		Roles:     identity.Roles,
		ExpiresAt: identity.ExpiresAt.Format(time.RFC3339),
	}, nil
}
