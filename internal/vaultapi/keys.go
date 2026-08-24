package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// PublicJWK holds a key's public components.
//
// All four are empty for an HSM-backed key, whose material never left the
// token. That is expected, not a failure.
type PublicJWK struct {
	N string `json:"n,omitempty"` // RSA modulus, base64url.
	E string `json:"e,omitempty"` // RSA public exponent, base64url.
	X string `json:"x,omitempty"` // EC x coordinate, base64url.
	Y string `json:"y,omitempty"` // EC y coordinate, base64url.
}

// IsEmpty reports whether no public components were returned, which is the
// normal case for an HSM-backed key.
func (j PublicJWK) IsEmpty() bool {
	return j.N == "" && j.E == "" && j.X == "" && j.Y == ""
}

// KeySummary is a key as it appears in a list.
//
// Like every type in this file it has no field for private material, and none
// may be added. api.KeyResponse makes the same guarantee.
type KeySummary struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Tags      []string   `json:"tags,omitempty"`
	Enabled   bool       `json:"enabled"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// Key is a single key with its metadata and public components.
type Key struct {
	KeySummary
	Bits      int        `json:"bits,omitempty"`
	Curve     string     `json:"curve,omitempty"`
	PublicJWK PublicJWK  `json:"public_jwk"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// keyWire is the raw response shape (api/keys.go:70). It is decoded into the
// exported types so the server's field layout is never the public one.
type keyWire struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
	Tags      []string   `json:"tags"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at"`
	NotBefore *time.Time `json:"not_before"`
	Bits      int        `json:"bits"`
	Curve     string     `json:"curve"`
	N         string     `json:"n"`
	E         string     `json:"e"`
	X         string     `json:"x"`
	Y         string     `json:"y"`
}

type keysListResponse struct {
	Keys []keyWire `json:"keys"`
}

func (w keyWire) summary() (KeySummary, error) {
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return KeySummary{}, fmt.Errorf("vaultapi: key %q has an unparseable id: %w", w.Name, err)
	}
	return KeySummary{
		ID:        id,
		Name:      w.Name,
		Type:      w.Type,
		Tags:      w.Tags,
		Enabled:   w.Enabled,
		Revoked:   w.Revoked,
		CreatedAt: w.CreatedAt,
		ExpiresAt: w.ExpiresAt,
		NotBefore: w.NotBefore,
	}, nil
}

// ListKeys returns the keys in vault, capped at limit. The bool reports
// truncation. A limit of zero or less returns everything.
func (c *Client) ListKeys(ctx context.Context, vault string, limit int) ([]KeySummary, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list keys")
	}

	var response keysListResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/keys", vault)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.Keys) > limit
	wires := response.Keys
	if truncated {
		wires = wires[:limit]
	}

	summaries := make([]KeySummary, 0, len(wires))
	for _, wire := range wires {
		summary, err := wire.summary()
		if err != nil {
			return nil, false, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, truncated, nil
}

// GetKey fetches one key by name or id, including its public JWK components.
func (c *Client) GetKey(ctx context.Context, vault, name string) (*Key, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a key")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wire keyWire
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, err
	}

	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Key{
		KeySummary: summary,
		Bits:       wire.Bits,
		Curve:      wire.Curve,
		PublicJWK:  PublicJWK{N: wire.N, E: wire.E, X: wire.X, Y: wire.Y},
		UpdatedAt:  wire.UpdatedAt,
	}, nil
}
