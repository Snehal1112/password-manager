package vaultclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"rocketvault/internal/retry"
)

// SecretMapping maps a logical name to a RocketVault secret UUID and Viper key.
type SecretMapping struct {
	Name     string `yaml:"name"      mapstructure:"name"`
	UUID     string `yaml:"uuid"      mapstructure:"uuid"`
	ViperKey string `yaml:"viper_key" mapstructure:"viper_key"`
}

// Logger is the minimal logging interface accepted by Client for
// observability into retries and auth failures. A nil Logger (the Config
// zero value) disables all logging — the client always works without one.
type Logger interface {
	Warn(msg string, keysAndValues ...any)
}

// Config holds credentials and secret mappings for the vault client.
type Config struct {
	URL          string          `yaml:"url"           mapstructure:"url"`
	ClientID     string          `yaml:"client_id"     mapstructure:"client_id"`
	ClientSecret string          `yaml:"client_secret" mapstructure:"client_secret"`
	Secrets      []SecretMapping `yaml:"secrets"       mapstructure:"secrets"`
	// Logger receives Warn calls on retries and auth failures. Optional; nil
	// disables all logging. Not settable via YAML/viper (interface value).
	Logger Logger
}

type tokenCache struct {
	token     string
	expiresAt time.Time
}

// Client authenticates to RocketVault and fetches secrets.
type Client struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	token      *tokenCache
	nameIndex  map[string]string
	logger     Logger
}

// New creates a Client from an explicit Config.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("vaultclient: Config.URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("vaultclient: Config.ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("vaultclient: Config.ClientSecret is required")
	}
	index := make(map[string]string, len(cfg.Secrets))
	for _, m := range cfg.Secrets {
		index[m.Name] = m.UUID
	}
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		nameIndex:  index,
		logger:     cfg.Logger,
	}, nil
}

// logRetry logs a retryable failure if a Logger is configured; a no-op otherwise.
func (c *Client) logRetry(msg string, err error) {
	if c.logger == nil {
		return
	}
	c.logger.Warn(msg, "error", err)
}

// NewFromEnv creates a Client from VAULT_URL, VAULT_CLIENT_ID, VAULT_CLIENT_SECRET env vars.
func NewFromEnv() (*Client, error) {
	return New(Config{
		URL:          os.Getenv("VAULT_URL"),
		ClientID:     os.Getenv("VAULT_CLIENT_ID"),
		ClientSecret: os.Getenv("VAULT_CLIENT_SECRET"),
	})
}

// NewFromViper creates a Client from the vault_client Viper config section.
// client_secret falls back to VAULT_CLIENT_SECRET env var if absent from config.
func NewFromViper() (*Client, error) {
	var mappings []SecretMapping
	if err := viper.UnmarshalKey("vault_client.secrets", &mappings); err != nil {
		return nil, fmt.Errorf("vaultclient: failed to parse vault_client.secrets: %w", err)
	}
	secret := viper.GetString("vault_client.client_secret")
	if secret == "" {
		secret = os.Getenv("VAULT_CLIENT_SECRET")
	}
	return New(Config{
		URL:          viper.GetString("vault_client.url"),
		ClientID:     viper.GetString("vault_client.client_id"),
		ClientSecret: secret,
		Secrets:      mappings,
	})
}

// Get fetches a secret by UUID. Retries on transient network errors; fails fast on 401/404.
func (c *Client) Get(ctx context.Context, uuid string) (string, error) {
	// terminalErr captures errors that must not be retried and must be returned as-is.
	var terminalErr error
	// lastAttemptErr tracks the most recent retryable failure so its sentinel chain
	// (ErrNetwork/ErrUnexpectedStatus) survives even after retries are exhausted —
	// WithExponentialBackoff re-wraps its own return value with %v, not %w, which
	// would otherwise break errors.Is checks (see the retryErr handling below).
	var lastAttemptErr error
	var value string

	retryErr := retry.WithExponentialBackoff(ctx, retry.ExternalServicePolicy(), func() error {
		tok, err := c.ensureToken(ctx)
		if err != nil {
			// Auth failures are terminal — stop retrying immediately.
			if errors.Is(err, ErrAuthFailed) {
				terminalErr = err
				return retry.NonRetryable(err)
			}
			lastAttemptErr = err
			return retry.Retryable(err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			c.cfg.URL+"/api/v1/secrets/"+uuid, nil)
		if err != nil {
			terminalErr = fmt.Errorf("vaultclient: build request: %w", err)
			return retry.NonRetryable(terminalErr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastAttemptErr = fmt.Errorf("%w: %v", ErrNetwork, err)
			c.logRetry("vaultclient: secret fetch network error, may retry", lastAttemptErr)
			return retry.Retryable(lastAttemptErr)
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var body struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				terminalErr = fmt.Errorf("%w: %v", ErrDecodeFailed, err)
				return retry.NonRetryable(terminalErr)
			}
			value = body.Value
			return nil
		case http.StatusUnauthorized:
			// Invalidate cached token so next attempt re-authenticates.
			c.mu.Lock()
			c.token = nil
			c.mu.Unlock()
			terminalErr = ErrAuthFailed
			c.logRetry("vaultclient: secret endpoint rejected the token, invalidating cache", ErrAuthFailed)
			return retry.NonRetryable(ErrAuthFailed)
		case http.StatusNotFound:
			terminalErr = ErrSecretNotFound
			return retry.NonRetryable(ErrSecretNotFound)
		default:
			lastAttemptErr = fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
			c.logRetry("vaultclient: secret endpoint returned unexpected status, may retry", lastAttemptErr)
			return retry.Retryable(lastAttemptErr)
		}
	})

	if terminalErr != nil {
		return "", terminalErr
	}
	if retryErr != nil {
		// A canceled/deadline-exceeded context is the true cause — don't mask it
		// behind a stale "retries exhausted" error from an earlier attempt.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if lastAttemptErr != nil {
			return "", fmt.Errorf("vaultclient: retries exhausted: %w", lastAttemptErr)
		}
		return "", retryErr
	}
	return value, nil
}

// GetByName fetches a secret by logical name, resolved to UUID via the config mapping.
func (c *Client) GetByName(ctx context.Context, name string) (string, error) {
	uuid, ok := c.nameIndex[name]
	if !ok {
		return "", fmt.Errorf("vaultclient: no UUID mapping found for secret name %q", name)
	}
	return c.Get(ctx, uuid)
}

// GetMany fetches multiple secrets by name and returns a name→value map.
func (c *Client) GetMany(ctx context.Context, names []string) (map[string]string, error) {
	result := make(map[string]string, len(names))
	for _, name := range names {
		val, err := c.GetByName(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("vaultclient: GetMany failed for %q: %w", name, err)
		}
		result[name] = val
	}
	return result, nil
}

// Fetcher is the interface satisfied by *Client, used for dependency injection in tests.
type Fetcher interface {
	GetMany(ctx context.Context, names []string) (map[string]string, error)
}

// ensureToken returns a valid access token, fetching a new one only when expired.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != nil && time.Now().Before(c.tokenExpiryCutoff()) {
		return c.token.token, nil
	}

	tok, expiresIn, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}
	// Enforce a minimum TTL so expires_in: 0 doesn't cause infinite re-fetches.
	ttl := time.Duration(expiresIn) * time.Second
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	c.token = &tokenCache{
		token:     tok,
		expiresAt: time.Now().Add(ttl),
	}
	return tok, nil
}

// tokenExpiryCutoff returns the point before which the cached token is still valid.
// For very short-lived tokens (≤ 60 s) we use the raw expiry to avoid always re-fetching.
func (c *Client) tokenExpiryCutoff() time.Time {
	const earlyRefresh = 60 * time.Second
	ttl := time.Until(c.token.expiresAt)
	if ttl <= earlyRefresh {
		return c.token.expiresAt
	}
	return c.token.expiresAt.Add(-earlyRefresh)
}

// fetchToken exchanges client credentials for an access token.
func (c *Client) fetchToken(ctx context.Context) (string, int, error) {
	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("client_id", c.cfg.ClientID)
	body.Set("client_secret", c.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.URL+"/api/v1/oauth2/token", strings.NewReader(body.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("vaultclient: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logRetry("vaultclient: token request failed, may retry", err)
		return "", 0, fmt.Errorf("%w: %v", ErrNetwork, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		c.logRetry("vaultclient: token request rejected — check client credentials", ErrAuthFailed)
		return "", 0, ErrAuthFailed
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
		c.logRetry("vaultclient: token endpoint returned unexpected status, may retry", err)
		return "", 0, err
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	if result.AccessToken == "" {
		c.logRetry("vaultclient: token endpoint returned an empty access token", ErrAuthFailed)
		return "", 0, ErrAuthFailed
	}
	return result.AccessToken, result.ExpiresIn, nil
}
