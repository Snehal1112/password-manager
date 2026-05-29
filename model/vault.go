package model

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// DefaultVaultName is the reserved name of the vault that holds pre-multi-vault data.
const DefaultVaultName = "default"

// DefaultVaultID is the fixed, well-known UUID of the default vault.
// It is shared by the migration, the fresh-DB schema default, and the resolver.
const DefaultVaultID = "00000000-0000-0000-0000-00000000efa1"

// vaultNameRe enforces Azure's vault naming rule: lowercase alphanumeric and
// hyphens, 3-63 chars, no leading or trailing hyphen.
var vaultNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`)

// Vault represents a named container for secrets, keys, and certificates.
type Vault struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Enabled          bool       `json:"enabled"`
	PurgeProtection  bool       `json:"purge_protection"`
	RetentionDays    int        `json:"retention_days"`
	CreatedBy        uuid.UUID  `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

// ValidateVaultName returns an error if name violates the vault naming rule.
func ValidateVaultName(name string) error {
	if !vaultNameRe.MatchString(name) {
		return fmt.Errorf("invalid vault name %q: must be 3-63 lowercase alphanumerics or hyphens, no leading/trailing hyphen", name)
	}
	return nil
}

// CreateVaultRequest is the body of a create-vault API call.
type CreateVaultRequest struct {
	Name            string `json:"name"`
	Enabled         *bool  `json:"enabled,omitempty"`
	PurgeProtection *bool  `json:"purge_protection,omitempty"`
	RetentionDays   *int   `json:"retention_days,omitempty"`
}

// UpdateVaultRequest is the body of an update-vault API call. Nil fields are unchanged.
type UpdateVaultRequest struct {
	Enabled         *bool `json:"enabled,omitempty"`
	PurgeProtection *bool `json:"purge_protection,omitempty"`
	RetentionDays   *int  `json:"retention_days,omitempty"`
}

func CreateVaultRequestFromJson(data io.Reader) (*CreateVaultRequest, error) {
	var r CreateVaultRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

func UpdateVaultRequestFromJson(data io.Reader) (*UpdateVaultRequest, error) {
	var r UpdateVaultRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

// VaultResponse is the API representation of a vault.
type VaultResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	PurgeProtection  bool   `json:"purge_protection"`
	RetentionDays    int    `json:"retention_days"`
	CreatedBy        string `json:"created_by"`
	CreatedAt        string `json:"created_at"`
	DeletedAt        string `json:"deleted_at,omitempty"`
	ScheduledPurgeAt string `json:"scheduled_purge_at,omitempty"`
}

func (v *Vault) ToResponse() VaultResponse {
	resp := VaultResponse{
		ID:              v.ID.String(),
		Name:            v.Name,
		Enabled:         v.Enabled,
		PurgeProtection: v.PurgeProtection,
		RetentionDays:   v.RetentionDays,
		CreatedBy:       v.CreatedBy.String(),
		CreatedAt:       v.CreatedAt.Format(time.RFC3339),
	}
	if v.DeletedAt != nil {
		resp.DeletedAt = v.DeletedAt.Format(time.RFC3339)
	}
	if v.ScheduledPurgeAt != nil {
		resp.ScheduledPurgeAt = v.ScheduledPurgeAt.Format(time.RFC3339)
	}
	return resp
}

// ListVaultsResponse is the API representation of a vault list.
type ListVaultsResponse struct {
	Vaults []VaultResponse `json:"vaults"`
	Total  int             `json:"total"`
}

func (r *ListVaultsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *VaultResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
