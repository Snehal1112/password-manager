// Package vaultapi is a typed REST client for the RocketVault HTTP API. It is
// deliberately independent of any consumer: the MCP server uses it today and
// the CLI's remote mode is expected to use it next, so nothing here may import
// internal/mcpserver or the MCP SDK.
package vaultapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CorrelationHeader carries a per-request identifier so a tool call can be
// traced to its API request and the audit entry it produced.
const CorrelationHeader = "X-RocketVault-Correlation-Id"

type correlationKey struct{}

// WithCorrelationID attaches a correlation identifier to ctx.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationIDFrom returns the correlation identifier attached to ctx, or the
// empty string when none is set.
func CorrelationIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// TokenSource yields a bearer token for the RocketVault API. Implementations
// are responsible for their own caching and refresh.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Config holds everything Client needs. All three fields are required.
type Config struct {
	// BaseURL is the server root, e.g. "https://vault.example.com". A
	// trailing slash is trimmed.
	BaseURL string
	// HTTPClient is the transport, normally built by cliclient.NewHTTPClient
	// so TLS trust flags are honored.
	HTTPClient *http.Client
	// Tokens supplies the bearer token for every request.
	Tokens TokenSource
}

// Client performs authenticated JSON requests against the RocketVault API.
type Client struct {
	baseURL string
	http    *http.Client
	tokens  TokenSource
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultapi: Config.BaseURL is required")
	}
	if cfg.Tokens == nil {
		return nil, fmt.Errorf("vaultapi: Config.Tokens is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vaultapi: Config.HTTPClient is required")
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		http:    cfg.HTTPClient,
		tokens:  cfg.Tokens,
	}, nil
}

// Do performs one request. body is JSON-encoded when non-nil; out is
// JSON-decoded from the response when non-nil. A non-2xx response becomes an
// *APIError and out is left untouched.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vaultapi: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("vaultapi: %s %s: unexpected status %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("vaultapi: decode %s %s response: %w", method, path, err)
	}
	return nil
}

// newRequest builds the authenticated request for one attempt.
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: encode request body: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: build request: %w", err)
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: obtain token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if id := CorrelationIDFrom(ctx); id != "" {
		req.Header.Set(CorrelationHeader, id)
	}
	return req, nil
}
