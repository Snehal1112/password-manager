package vaultapi

import (
	"context"
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

	mu      sync.Mutex
	session *common.SessionCache
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

	return &SessionSource{cfg: cfg, skew: skew, save: save, session: session}, nil
}

// Username reports who this source acts as.
func (s *SessionSource) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.Username
}

// Token returns the cached access token while it is live. Task 2 adds
// refresh.
func (s *SessionSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Now().Before(s.session.ExpiresAt.Add(-s.skew)) {
		return s.session.Token, nil
	}
	return "", fmt.Errorf("vaultapi: cached session expired")
}
