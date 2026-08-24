package vaultapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// Vault is a vault's metadata.
//
// Timestamps are strings, not time.Time, because VaultResponse renders them
// that way (model/vault.go:122). A live vault carries an empty deleted_at,
// which would fail to decode into a time.Time. This is the one place vaultapi
// does not normalise a timestamp, and it is deliberate.
//
// Tags is a map here, unlike the []string every other domain uses.
type Vault struct {
	ID               uuid.UUID         `json:"id"`
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	PurgeProtection  bool              `json:"purge_protection"`
	RetentionDays    int               `json:"retention_days"`
	Tags             map[string]string `json:"tags,omitempty"`
	CreatedAt        string            `json:"created_at,omitempty"`
	DeletedAt        string            `json:"deleted_at,omitempty"`
	ScheduledPurgeAt string            `json:"scheduled_purge_at,omitempty"`
}

// vaultWire is the raw response shape (model/vault.go:122).
type vaultWire struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	PurgeProtection  bool              `json:"purge_protection"`
	RetentionDays    int               `json:"retention_days"`
	Tags             map[string]string `json:"tags"`
	CreatedAt        string            `json:"created_at"`
	DeletedAt        string            `json:"deleted_at"`
	ScheduledPurgeAt string            `json:"scheduled_purge_at"`
}

type vaultsListResponse struct {
	Vaults []vaultWire `json:"vaults"`
	Total  int         `json:"total"`
}

func (w vaultWire) toVault() (Vault, error) {
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return Vault{}, fmt.Errorf("vaultapi: vault %q has an unparseable id: %w", w.Name, err)
	}
	return Vault{
		ID:               id,
		Name:             w.Name,
		Enabled:          w.Enabled,
		PurgeProtection:  w.PurgeProtection,
		RetentionDays:    w.RetentionDays,
		Tags:             w.Tags,
		CreatedAt:        w.CreatedAt,
		DeletedAt:        w.DeletedAt,
		ScheduledPurgeAt: w.ScheduledPurgeAt,
	}, nil
}

// ListVaults returns the vaults the principal can see, capped at limit. The
// bool reports truncation. Setting includeDeleted surfaces soft-deleted
// vaults, which is how an operator finds one to recover.
func (c *Client) ListVaults(ctx context.Context, includeDeleted bool, limit int) ([]Vault, bool, error) {
	path := "/api/v1/vaults"
	if includeDeleted {
		path += "?include_deleted=true"
	}

	var response vaultsListResponse
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.Vaults) > limit
	wires := response.Vaults
	if truncated {
		wires = wires[:limit]
	}

	vaults := make([]Vault, 0, len(wires))
	for _, wire := range wires {
		vault, err := wire.toVault()
		if err != nil {
			return nil, false, err
		}
		vaults = append(vaults, vault)
	}
	return vaults, truncated, nil
}

// GetVault fetches one vault by name.
//
// A vault's name is its identifier, so there is no resolution step here and
// Resolver is deliberately not involved.
func (c *Client) GetVault(ctx context.Context, name string) (*Vault, error) {
	if name == "" {
		return nil, fmt.Errorf("vaultapi: vault name is required")
	}

	var wire vaultWire
	if err := c.Do(ctx, http.MethodGet, "/api/v1/vaults/"+name, nil, &wire); err != nil {
		return nil, err
	}

	vault, err := wire.toVault()
	if err != nil {
		return nil, err
	}
	return &vault, nil
}
