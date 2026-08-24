package vaultapi

import (
	"context"
	"fmt"
	"net/http"
)

// CreateVaultRequest describes a vault to create.
//
// The optional fields are pointers, mirroring model.CreateVaultRequest
// (model/vault.go:95), so that omitting one means "use the server's default"
// rather than "false" or "zero". Sending purge_protection: false explicitly
// is a different statement from not mentioning it, and a vault created with
// retention silently set to zero would be an unpleasant surprise.
type CreateVaultRequest struct {
	Name            string            `json:"name"`
	Enabled         *bool             `json:"enabled,omitempty"`
	PurgeProtection *bool             `json:"purge_protection,omitempty"`
	RetentionDays   *int              `json:"retention_days,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// CreateVault creates a vault.
func (c *Client) CreateVault(ctx context.Context, req CreateVaultRequest) (*Vault, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("vaultapi: vault name is required")
	}

	var wire vaultWire
	if err := c.Do(ctx, http.MethodPost, "/api/v1/vaults", req, &wire); err != nil {
		return nil, err
	}

	vault, err := wire.toVault()
	if err != nil {
		return nil, err
	}
	return &vault, nil
}
