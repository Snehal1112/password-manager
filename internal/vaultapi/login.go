package vaultapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
)

// defaultLoginExpiry is the access-token lifetime assumed when the caller
// supplies none -- typically a caller with no config file loaded, which is
// normal in remote mode.
//
// It is deliberately shorter than the 1h both shipped configs set for
// jwt.expiry. Assuming too short a lifetime only triggers an early refresh;
// assuming too long a one lets a caller send a token the server has already
// rejected. So this is a conservative floor, not a mirror of the config.
const defaultLoginExpiry = 15 * time.Minute

// LoginIdentity describes who Login authenticated as. It never carries the
// token itself -- a caller that needs to act as this identity uses the
// TokenSource Login also returns.
type LoginIdentity struct {
	Username  string
	Roles     []string
	ExpiresAt time.Time
}

// LoginOptions carries the caller-specific parts of a login: how long the
// access token lives, and whether the resulting session is persisted.
//
// SaveSession is nil for an in-memory login (the MCP server's in-chat
// login tool) and common.SaveSession for the CLI, which caches the session
// so later commands run without credentials. It is called once with the
// session Login creates, and again by the SessionSource on every refresh,
// so the two paths cannot drift.
type LoginOptions struct {
	// Expiry is the access-token lifetime (jwt.expiry). Zero or negative
	// uses defaultLoginExpiry -- which is what a caller with no config
	// file loaded passes, so the session is not born already expired.
	Expiry time.Duration
	// SaveSession persists the session. Nil means this login is
	// memory-only and writes nothing.
	SaveSession func(*common.SessionCache) error
}

// Login exchanges a username, password and TOTP code for a session, and
// returns a TokenSource seeded with it plus display information.
//
// Unlike every other Client method, it sends no bearer token: the endpoint
// is unauthenticated by design, the same way the refresh endpoint
// SessionSource.refresh calls is. opts.Expiry is the access-token lifetime
// (jwt.expiry), used to compute ExpiresAt the same way the CLI's own login
// command does in cmd/root.go -- the login response itself carries no
// expiry.
func (c *Client) Login(ctx context.Context, username, password, totpCode string, opts LoginOptions) (TokenSource, LoginIdentity, error) {
	// A caller with no config file loaded passes viper's zero duration, which
	// would make the session born already expired.
	expiry := opts.Expiry
	if expiry <= 0 {
		expiry = defaultLoginExpiry
	}

	payload, err := json.Marshal(map[string]string{
		"username": username, "password": password, "totp_code": totpCode,
	})
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: encode login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/users/login", bytes.NewReader(payload))
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Login builds its own request rather than going through newRequest, so
	// the correlation header has to be set here to match every other call.
	if id := CorrelationIDFrom(ctx); id != "" {
		req.Header.Set(CorrelationHeader, id)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: login request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// The body is not surfaced: a generic message avoids leaking
		// whether the username exists or which factor was wrong.
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: login failed (HTTP %d)", resp.StatusCode)
	}

	var decoded struct {
		Token        string   `json:"token"`
		RefreshToken string   `json:"refresh_token"`
		UserID       string   `json:"user_id"`
		Username     string   `json:"username"`
		Roles        []string `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: decode login response: %w", err)
	}
	if decoded.Token == "" || decoded.RefreshToken == "" {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: login response was missing a token")
	}

	// UserID is display-only here -- Token()/refresh() never use it -- so a
	// malformed value falls back to the zero UUID rather than failing login.
	userID, _ := uuid.Parse(decoded.UserID)
	session := &common.SessionCache{
		Token:        decoded.Token,
		RefreshToken: decoded.RefreshToken,
		UserID:       userID,
		Username:     decoded.Username,
		Roles:        decoded.Roles,
		ExpiresAt:    time.Now().Add(expiry),
		// Set even though this session is in-memory only: if a caller ever
		// opts into persistence, a blank key would write a malformed
		// "|<username>" current-session pointer over the operator's real one.
		ServerKey: common.SanitizeServerKey(c.baseURL),
	}

	// The explicit save matters: SessionSource only writes on refresh, so
	// without it nothing reaches disk until the first token expiry.
	if opts.SaveSession != nil {
		if err := opts.SaveSession(session); err != nil {
			return nil, LoginIdentity{}, fmt.Errorf("vaultapi: authenticated but failed to cache session: %w", err)
		}
	}

	source, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:     c.baseURL,
		HTTPClient:  c.http,
		SaveSession: opts.SaveSession, // nil keeps the no-op default
	}, session)
	if err != nil {
		return nil, LoginIdentity{}, fmt.Errorf("vaultapi: seed session from login: %w", err)
	}

	return source, LoginIdentity{
		Username:  session.Username,
		Roles:     session.Roles,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
