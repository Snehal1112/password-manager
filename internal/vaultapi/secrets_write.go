package vaultapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// SetSecretRequest describes a secret to create or update.
//
// Value is a SecretValue rather than a string so the request struct is as
// safe to log or marshal as a response is. A plaintext secret in a request
// body is exactly as sensitive as one in a response.
type SetSecretRequest struct {
	Name        string      `json:"name"`
	Value       SecretValue `json:"value,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	ContentType string      `json:"content_type,omitempty"`
	Enabled     *bool       `json:"enabled,omitempty"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	NotBefore   *time.Time  `json:"not_before,omitempty"`
}

// createSecretBody mirrors model.CreateSecretRequest (model/secret.go:178).
// Value is a plain string here because this struct exists only to be
// marshalled onto the wire.
type createSecretBody struct {
	Name        string     `json:"name"`
	Value       string     `json:"value"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType string     `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

// updateSecretBody mirrors model.UpdateSecretRequest (model/secret.go:195).
// Every field is omitempty, so an update can change expiry or tags without
// touching the value.
type updateSecretBody struct {
	Value       string     `json:"value,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType *string    `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

// SetSecret creates a secret, or updates it when the name already exists.
// The bool reports which happened.
//
// Upserting is deliberate: a caller asking to set a secret does not
// necessarily know whether one exists, and forcing a check first costs a
// round trip and invites a race between the check and the write.
func (c *Client) SetSecret(ctx context.Context, vault string, req SetSecretRequest) (*Secret, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to set a secret")
	}
	if req.Name == "" {
		return nil, false, fmt.Errorf("vaultapi: secret name is required")
	}

	existingID, resolveErr := c.Resolver().Resolve(ctx, vault, KindSecrets, req.Name)
	exists := resolveErr == nil
	if resolveErr != nil && !errors.Is(resolveErr, ErrResourceNotFound) {
		// A missing name means "create". Anything else -- a denial, an
		// ambiguous name, an unreachable server -- is a real failure and
		// must not be silently treated as absence.
		return nil, false, resolveErr
	}

	if exists {
		body := updateSecretBody{
			Value:     req.Value.Reveal(),
			Tags:      req.Tags,
			Enabled:   req.Enabled,
			ExpiresAt: req.ExpiresAt,
			NotBefore: req.NotBefore,
		}
		if req.ContentType != "" {
			body.ContentType = &req.ContentType
		}

		var updated secretWire
		path := fmt.Sprintf("/api/v1/vaults/%s/secrets/%s", vault, existingID)
		if err := c.Do(ctx, http.MethodPut, path, body, &updated); err != nil {
			return nil, false, err
		}
		secret, err := secretFromWire(updated)
		return secret, false, err
	}

	if req.Value == "" {
		return nil, false, fmt.Errorf("vaultapi: a value is required to create secret %q", req.Name)
	}

	body := createSecretBody{
		Name:        req.Name,
		Value:       req.Value.Reveal(),
		Tags:        req.Tags,
		ContentType: req.ContentType,
		Enabled:     req.Enabled,
		ExpiresAt:   req.ExpiresAt,
		NotBefore:   req.NotBefore,
	}

	var created secretWire
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets", vault)
	if err := c.Do(ctx, http.MethodPost, path, body, &created); err != nil {
		return nil, false, err
	}
	secret, err := secretFromWire(created)
	return secret, true, err
}
