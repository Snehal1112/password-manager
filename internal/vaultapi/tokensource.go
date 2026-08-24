package vaultapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// defaultTokenSkew is how far before real expiry a cached token is treated as
// expired, so a request never races the boundary.
const defaultTokenSkew = 30 * time.Second

// ServiceAccountConfig configures token acquisition for a service account.
type ServiceAccountConfig struct {
	// BaseURL is the server root, e.g. "https://vault.example.com".
	BaseURL string
	// ClientID and ClientSecret are the service-account credentials. They are
	// sent as HTTP Basic, never in the form body.
	ClientID     string
	ClientSecret string
	// HTTPClient is the transport. Required.
	HTTPClient *http.Client
	// Skew overrides how early a token is considered expired. Zero uses
	// defaultTokenSkew.
	Skew time.Duration
}

// ServiceAccountSource obtains bearer tokens with the client-credentials
// grant and caches them until shortly before they expire.
type ServiceAccountSource struct {
	cfg  ServiceAccountConfig
	skew time.Duration

	mu        sync.Mutex
	token     string
	expiresAt time.Time

	// inflight is non-nil while a fetch is running. Callers arriving during
	// a fetch wait on it rather than issuing their own request.
	inflight *tokenFetch
}

// tokenFetch is one in-flight token acquisition shared by every caller that
// arrives while it runs.
type tokenFetch struct {
	done  chan struct{}
	token string
	err   error
}

// NewServiceAccountSource validates cfg and returns a source.
func NewServiceAccountSource(cfg ServiceAccountConfig) (*ServiceAccountSource, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.BaseURL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.ClientSecret is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vaultapi: ServiceAccountConfig.HTTPClient is required")
	}

	skew := cfg.Skew
	if skew == 0 {
		skew = defaultTokenSkew
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &ServiceAccountSource{cfg: cfg, skew: skew}, nil
}

// Token returns a cached token when one is still valid, otherwise fetches a
// new one. Concurrent callers arriving during a fetch share its result rather
// than each issuing a request, so an expiry does not stampede the token
// endpoint.
func (s *ServiceAccountSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()

	if s.token != "" && time.Now().Before(s.expiresAt.Add(-s.skew)) {
		token := s.token
		s.mu.Unlock()
		return token, nil
	}

	// Join a fetch already in progress.
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

	// Become the fetcher for everyone else.
	fetch := &tokenFetch{done: make(chan struct{})}
	s.inflight = fetch
	s.mu.Unlock()

	token, expiresIn, err := s.fetch(ctx)

	s.mu.Lock()
	if err == nil {
		s.zeroToken()
		s.token = token
		s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	s.inflight = nil
	s.mu.Unlock()

	fetch.token, fetch.err = token, err
	close(fetch.done)
	return token, err
}

// zeroToken clears the cached token. Task 3 gives it a real body.
func (s *ServiceAccountSource) zeroToken() {}

// tokenResponse mirrors the success body documented at api/oauth2.go:54.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// tokenErrorResponse mirrors the RFC 6749 section 5.2 error body.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// fetch performs one client-credentials request.
//
// The client secret travels only in the Authorization header. It is never
// placed in the form body and never included in a returned error.
func (s *ServiceAccountSource) fetch(ctx context.Context) (string, int, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.BaseURL+"/api/v1/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("vaultapi: build token request: %w", err)
	}
	req.SetBasicAuth(s.cfg.ClientID, s.cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vaultapi: token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var apiErr tokenErrorResponse
		// A decode failure is not itself interesting; the status still is.
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return "", 0, fmt.Errorf("vaultapi: token request rejected (HTTP %d): %s", resp.StatusCode, apiErr.Error)
		}
		return "", 0, fmt.Errorf("vaultapi: token request rejected (HTTP %d)", resp.StatusCode)
	}

	var decoded tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", 0, fmt.Errorf("vaultapi: decode token response: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", 0, fmt.Errorf("vaultapi: token response contained no access_token")
	}
	return decoded.AccessToken, decoded.ExpiresIn, nil
}
