package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// VaultWebhookConfig is a vault's webhook notification target. One row per
// vault, enforced by UNIQUE(vault_id).
//
// The signing secret is stored encrypted (common.EncryptSecret) and this type
// deliberately carries no json tags: it must never be marshaled into an API
// response. Responses are built from the separate, secret-less
// VaultWebhookConfigResponse below, so "the API shape cannot carry the secret"
// is true by construction rather than by remembering to clear a field.
type VaultWebhookConfig struct {
	ID                     uuid.UUID
	VaultID                uuid.UUID
	URL                    string
	SigningSecretEncrypted string
	Enabled                bool
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// ToResponse builds the API-facing shape, dropping the encrypted secret and
// formatting timestamps as RFC3339 strings to match VaultResponse.
func (c *VaultWebhookConfig) ToResponse() VaultWebhookConfigResponse {
	return VaultWebhookConfigResponse{
		URL:       c.URL,
		Enabled:   c.Enabled,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
	}
}

// VaultWebhookConfigResponse is the API-facing shape. It has no field for the
// signing secret in any form, encrypted or plain.
type VaultWebhookConfigResponse struct {
	URL       string `json:"url"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ToJson serializes the response.
func (r *VaultWebhookConfigResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// VaultWebhookConfigCreatedResponse is returned exactly once, from the PUT
// that creates the config or rotates its secret. It is the only shape in this
// feature that ever carries SigningSecret in plaintext.
type VaultWebhookConfigCreatedResponse struct {
	VaultWebhookConfigResponse
	SigningSecret string `json:"signing_secret"`
}

// ToJson serializes the create/rotate response.
func (r *VaultWebhookConfigCreatedResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// UpsertVaultWebhookRequest is the PUT body.
//
// Enabled is a pointer so an omitted field is distinguishable from an explicit
// false: with a bare bool, PUT {"url": "..."} would silently disable the
// webhook. Nil means "keep the current value" (true on create).
//
// There is no client-supplied secret field. The server mints the secret; set
// RotateSecret to replace an existing one.
type UpsertVaultWebhookRequest struct {
	URL          string `json:"url"`
	RotateSecret bool   `json:"rotate_secret"`
	Enabled      *bool  `json:"enabled"`
}

// UpsertVaultWebhookRequestFromJson decodes a PUT body.
func UpsertVaultWebhookRequestFromJson(r io.Reader) (*UpsertVaultWebhookRequest, error) {
	var req UpsertVaultWebhookRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}
