package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// SecretSummary is a secret as it appears in a list. The list route omits
// values (api/secrets.go:414), and this type has no field for one.
type SecretSummary struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Tags      []string  `json:"tags,omitempty"`
	Version   int       `json:"version"`
	CreatedAt string    `json:"created_at,omitempty"`
}

// Secret is a single secret with its metadata.
//
// Value is a SecretValue, so marshalling a Secret redacts it. The server
// returns the plaintext on every get and offers no way to suppress it, so the
// type is what keeps it from escaping.
type Secret struct {
	SecretSummary
	Value       SecretValue `json:"value"`
	ContentType string      `json:"content_type,omitempty"`
	Enabled     bool        `json:"enabled"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	NotBefore   *time.Time  `json:"not_before,omitempty"`
}

// secretsListResponse mirrors model.ListSecretsResponse (model/secret.go:257).
type secretsListResponse struct {
	Secrets []secretWire `json:"secrets"`
	Total   int          `json:"total"`
}

// secretWire is the raw response shape. It is decoded into the exported types
// so Value never exists as a bare string on an exported struct.
type secretWire struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Value       string     `json:"value"`
	Tags        []string   `json:"tags"`
	Version     int        `json:"version"`
	ContentType string     `json:"content_type"`
	CreatedAt   string     `json:"created_at"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at"`
	NotBefore   *time.Time `json:"not_before"`
}

func (w secretWire) summary() (SecretSummary, error) {
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return SecretSummary{}, fmt.Errorf("vaultapi: secret %q has an unparseable id: %w", w.Name, err)
	}
	return SecretSummary{
		ID:        id,
		Name:      w.Name,
		Tags:      w.Tags,
		Version:   w.Version,
		CreatedAt: w.CreatedAt,
	}, nil
}

// ListSecrets returns the secrets in vault, capped at limit. The bool reports
// whether the list was truncated, so a caller can say so rather than silently
// presenting a partial view. A limit of zero or less returns everything.
func (c *Client) ListSecrets(ctx context.Context, vault string, limit int) ([]SecretSummary, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list secrets")
	}

	var response secretsListResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets", vault)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.Secrets) > limit
	wires := response.Secrets
	if truncated {
		wires = wires[:limit]
	}

	summaries := make([]SecretSummary, 0, len(wires))
	for _, wire := range wires {
		summary, err := wire.summary()
		if err != nil {
			return nil, false, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, truncated, nil
}

// GetSecret fetches one secret by name or id.
//
// The response always carries the plaintext value; there is no server-side
// way to ask for metadata only. It lands in Secret.Value, which redacts on
// every path but Reveal.
func (c *Client) GetSecret(ctx context.Context, vault, name string) (*Secret, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a secret")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindSecrets, name)
	if err != nil {
		return nil, err
	}

	var wire secretWire
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets/%s", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, err
	}

	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Secret{
		SecretSummary: summary,
		Value:         SecretValue(wire.Value),
		ContentType:   wire.ContentType,
		Enabled:       wire.Enabled,
		ExpiresAt:     wire.ExpiresAt,
		NotBefore:     wire.NotBefore,
	}, nil
}
