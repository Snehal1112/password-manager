package vaultapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"rocketvault/common"
)

// ErrNoSession reports that no CLI session is cached. Callers turn this into
// an instruction to run `rocketvault users login`.
var ErrNoSession = errors.New("vaultapi: no cached session")

// SessionConfig configures a TokenSource backed by the CLI session cache.
type SessionConfig struct {
	// BaseURL is the server root, e.g. "https://vault.example.com".
	BaseURL string
	// HTTPClient is the transport used for refreshes. Required.
	HTTPClient *http.Client
	// Skew overrides how early the access token is considered expired. Zero
	// uses defaultTokenSkew.
	Skew time.Duration
	// LoadSession reads the cached session. Nil uses
	// common.LoadCurrentSession. Tests inject a stub so they never touch the
	// real ~/.rocketvault directory.
	LoadSession func() (*common.SessionCache, error)
	// SaveSession persists a refreshed session. Nil uses common.SaveSession.
	SaveSession func(*common.SessionCache) error
}

// SessionSource serves the cached CLI session's access token, refreshing it
// when it expires.
//
// This is the local-development identity path. Under it the agent acts as the
// logged-in human, so its actions are indistinguishable from theirs in the
// audit log. Production should use ServiceAccountSource instead.
type SessionSource struct {
	cfg  SessionConfig
	skew time.Duration
	save func(*common.SessionCache) error
	load func() (*common.SessionCache, error)

	mu      sync.Mutex
	session *common.SessionCache

	// inflight is non-nil while a refresh is running, so concurrent callers
	// share it rather than each calling the refresh endpoint.
	inflight *tokenFetch
}

// NewSessionSource loads the cached session and returns a source. It returns
// ErrNoSession when nothing is cached.
func NewSessionSource(cfg SessionConfig) (*SessionSource, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultapi: SessionConfig.BaseURL is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vaultapi: SessionConfig.HTTPClient is required")
	}

	load := cfg.LoadSession
	if load == nil {
		load = common.LoadCurrentSession
	}
	save := cfg.SaveSession
	if save == nil {
		save = common.SaveSession
	}

	session, err := load()
	if err != nil {
		return nil, fmt.Errorf("vaultapi: read cached session: %w", err)
	}
	// A nil session with a nil error means "nothing cached", which is the
	// documented contract of common.LoadCurrentSession.
	if session == nil {
		return nil, ErrNoSession
	}

	skew := cfg.Skew
	if skew == 0 {
		skew = defaultTokenSkew
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	return &SessionSource{cfg: cfg, skew: skew, save: save, load: load, session: session}, nil
}

// Username reports who this source acts as.
func (s *SessionSource) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.Username
}

// Token returns the cached access token, refreshing it first when it has
// expired. Concurrent callers share one in-flight refresh.
func (s *SessionSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()

	if time.Now().Before(s.session.ExpiresAt.Add(-s.skew)) {
		token := s.session.Token
		s.mu.Unlock()
		return token, nil
	}

	if s.inflight != nil {
		fetch := s.inflight
		s.mu.Unlock()
		select {
		case <-fetch.done:
			return fetch.token, fetch.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	fetch := &tokenFetch{done: make(chan struct{})}
	s.inflight = fetch
	refreshToken := s.session.RefreshToken
	s.mu.Unlock()

	refreshed, err := s.refresh(ctx, refreshToken)
	if err != nil {
		// The cached refresh token can be stale if a newer CLI login
		// happened, in a different process, after this source was
		// constructed. Reload once and retry with whatever is actually on
		// disk before giving up -- this is what lets a running MCP
		// subprocess pick up a fresh `rocketvault users login` without a
		// restart.
		if reloaded, loadErr := s.load(); loadErr == nil && reloaded != nil && reloaded.RefreshToken != refreshToken {
			s.mu.Lock()
			s.session = reloaded
			s.mu.Unlock()
			refreshed, err = s.refresh(ctx, reloaded.RefreshToken)
		}
	}

	s.mu.Lock()
	if err == nil {
		s.session = refreshed
	}
	s.inflight = nil
	s.mu.Unlock()

	if err == nil {
		fetch.token = refreshed.Token
	}
	fetch.err = err
	close(fetch.done)

	if err != nil {
		return "", err
	}
	return fetch.token, nil
}

// refresh exchanges refreshToken for a new pair and persists the result.
//
// The endpoint rotates the refresh token, so the new one must be written back
// or the next refresh fails with a stale token.
func (s *SessionSource) refresh(ctx context.Context, refreshToken string) (*common.SessionCache, error) {
	payload, err := json.Marshal(map[string]string{"refresh_token": refreshToken})
	if err != nil {
		return nil, fmt.Errorf("vaultapi: encode refresh request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.BaseURL+"/api/v1/users/refresh", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("vaultapi: build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: refresh request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// The body is not surfaced: it can echo the request, which carries
		// the refresh token.
		return nil, fmt.Errorf(
			"vaultapi: session refresh rejected (HTTP %d) — run `rocketvault users login` to sign in again",
			resp.StatusCode)
	}

	var decoded struct {
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		Username     string    `json:"username"`
		Roles        []string  `json:"roles"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("vaultapi: decode refresh response: %w", err)
	}
	if decoded.Token == "" || decoded.RefreshToken == "" {
		return nil, fmt.Errorf("vaultapi: refresh response was missing a token")
	}

	// Copy the existing session so fields the endpoint does not return, such
	// as ServerKey and UserID, survive the refresh.
	s.mu.Lock()
	updated := *s.session
	s.mu.Unlock()

	updated.Token = decoded.Token
	updated.RefreshToken = decoded.RefreshToken
	updated.ExpiresAt = decoded.ExpiresAt
	if decoded.Username != "" {
		updated.Username = decoded.Username
	}
	if len(decoded.Roles) > 0 {
		updated.Roles = decoded.Roles
	}

	if err := s.save(&updated); err != nil {
		return nil, fmt.Errorf("vaultapi: persist refreshed session: %w", err)
	}
	return &updated, nil
}
