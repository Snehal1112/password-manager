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
// supplies none. It matches the jwt.expiry the shipped .rocketvault.yaml.example
// configures.
const defaultLoginExpiry = 15 * time.Minute

// LoginIdentity describes who Login authenticated as. It never carries the
// token itself -- a caller that needs to act as this identity uses the
// TokenSource Login also returns.
type LoginIdentity struct {
	Username  string
	Roles     []string
	ExpiresAt time.Time
}

// Login exchanges a username, password and TOTP code for a session, and
// returns a TokenSource seeded with it plus display information.
//
// Unlike every other Client method, it sends no bearer token: the endpoint
// is unauthenticated by design, the same way the refresh endpoint
// SessionSource.refresh calls is. expiry is the access-token lifetime
// (jwt.expiry), used to compute ExpiresAt the same way the CLI's own login
// command does in cmd/root.go -- the login response itself carries no
// expiry.
func (c *Client) Login(ctx context.Context, username, password, totpCode string, expiry time.Duration) (TokenSource, LoginIdentity, error) {
	// A caller with no config file loaded passes viper's zero duration, which
	// would make the session born already expired.
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

	source, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:    c.baseURL,
		HTTPClient: c.http,
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
